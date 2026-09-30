use async_trait::async_trait;
use bytes::Bytes;
use futures::ready;
use h2::{RecvStream, SendStream};
use http::Request;
use std::{
    cmp::min,
    collections::HashMap,
    fmt::{self, Debug},
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    spawn,
};
use tracing::error;

use super::Transport;
use crate::{common::errors::map_io_error, proxy::AnyStream};

pub struct Client {
    pub hosts: Vec<String>,
    pub headers: HashMap<String, String>,
    pub method: http::Method,
    pub path: http::uri::PathAndQuery,
}

impl Client {
    pub fn new(
        hosts: Vec<String>,
        headers: HashMap<String, String>,
        method: http::Method,
        path: http::uri::PathAndQuery,
    ) -> Self {
        Self {
            hosts,
            headers,
            method,
            path,
        }
    }

    fn req(&self) -> io::Result<Request<()>> {
        let uri_idx = rand::random_range(0..self.hosts.len());
        let uri = {
            http::Uri::builder()
                .scheme("https")
                .authority(self.hosts[uri_idx].as_str())
                .path_and_query(self.path.clone())
                .build()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        };
        let mut request = Request::builder()
            .uri(uri)
            .method(self.method.clone())
            .version(http::Version::HTTP_2);
        for (k, v) in self.headers.iter() {
            if k != "Host" {
                request = request.header(k, v);
            }
        }

        Ok(request.body(()).expect("build req"))
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let (mut client, h2) =
            h2::client::handshake(stream).await.map_err(map_io_error)?;
        let req = self.req()?;
        let (resp, send_stream) =
            client.send_request(req, false).map_err(map_io_error)?;
        spawn(async move {
            if let Err(e) = h2.await {
                error!("h2 error: {}", e);
            }
        });

        let recv_stream = resp.await.map_err(map_io_error)?.into_body();

        Ok(Box::new(Http2Stream::new(recv_stream, send_stream)))
    }
}

pub struct Http2Stream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    buffer: Bytes,
}

impl crate::proxy::ProxyStream for Http2Stream {}

impl Debug for Http2Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http2Stream")
            .field("recv", &self.recv)
            .field("send", &self.send)
            .field("buffer", &self.buffer)
            .finish()
    }
}

impl Http2Stream {
    pub fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            buffer: Bytes::new(),
        }
    }
}

impl AsyncRead for Http2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !self.buffer.is_empty() {
            let to_read = min(self.buffer.len(), buf.remaining());
            let data = self.buffer.split_to(to_read);
            buf.put_slice(&data);
            return Poll::Ready(Ok(()));
        }
        Poll::Ready(match ready!(self.recv.poll_data(cx)) {
            Some(Ok(data)) => {
                let to_read = min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_read]);
                if to_read < data.len() {
                    self.buffer = data.slice(to_read..);
                }
                // Release capacity for the entire received frame, including
                // bytes saved to self.buffer.  This keeps the H2 flow-control
                // window open so the remote end can send the next frame
                // immediately rather than stalling until the application reads
                // the buffered bytes.
                self.recv
                    .flow_control()
                    .release_capacity(data.len())
                    .map_or_else(
                        |e| Err(io::Error::new(io::ErrorKind::ConnectionReset, e)),
                        |_| Ok(()),
                    )
            }
            Some(Err(e)) => Err(map_io_error(e)),
            None => Ok(()),
        })
    }
}

impl AsyncWrite for Http2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.send.reserve_capacity(buf.len());
        Poll::Ready(match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(to_write)) => self
                .send
                .send_data(Bytes::from(buf[..to_write].to_owned()), false)
                .map_or_else(
                    |e| Err(io::Error::new(io::ErrorKind::BrokenPipe, e)),
                    |_| Ok(to_write),
                ),
            _ => Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe")),
        })
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.send.reserve_capacity(0);
        Poll::Ready(ready!(self.send.poll_capacity(cx)).map_or(
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe")),
            |_| {
                self.send.send_data(Bytes::new(), true).map_or_else(
                    |e| Err(io::Error::new(io::ErrorKind::BrokenPipe, e)),
                    |_| Ok(()),
                )
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::poll_fn;
    use http::Response;
    use std::time::Duration;
    use tokio::{
        io::{AsyncReadExt, duplex},
        time::timeout,
    };

    #[tokio::test]
    async fn small_reads_preserve_frames_and_release_flow_control() {
        timeout(Duration::from_secs(10), async {
            let (client, server) = duplex(4096);
            let expected: Vec<u8> = (0..131072).map(|i| (i % 251) as u8).collect();
            let payload = Bytes::from(expected.clone());
            let server_task = spawn(async move {
                let mut connection = h2::server::handshake(server).await.unwrap();
                let (_, mut respond) = connection.accept().await.unwrap().unwrap();
                let mut send =
                    respond.send_response(Response::new(()), false).unwrap();
                let writer = spawn(async move {
                    let mut payload = payload;
                    while !payload.is_empty() {
                        send.reserve_capacity(payload.len());
                        let capacity = poll_fn(|cx| send.poll_capacity(cx))
                            .await
                            .unwrap()
                            .unwrap();
                        let n = capacity.min(payload.len());
                        if n > 0 {
                            let chunk = payload.split_to(n);
                            send.send_data(chunk, payload.is_empty()).unwrap();
                        }
                    }
                });
                while connection.accept().await.is_some() {}
                writer.await.unwrap();
            });
            let (mut client, connection) =
                h2::client::handshake(client).await.unwrap();
            let client_task = spawn(async move { connection.await });
            let request = Request::builder()
                .uri("https://example.org/")
                .body(())
                .unwrap();
            let (response, send) = client.send_request(request, true).unwrap();
            let recv = response.await.unwrap().into_body();
            let mut stream = Http2Stream::new(recv, send);
            assert_eq!(stream.read(&mut []).await.unwrap(), 0);
            let mut received = Vec::new();
            let mut chunk = [0; 137];
            loop {
                let n = stream.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..n]);
            }
            assert_eq!(received, expected);
            drop(stream);
            drop(client);
            client_task.abort();
            server_task.abort();
        })
        .await
        .unwrap();
    }
}
