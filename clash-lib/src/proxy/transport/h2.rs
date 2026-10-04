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
};

use super::{Transport, h2_common::{ConnectionDriver, client_builder, poll_send_capacity, release_receive_capacity, shutdown_h2_send}};
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
            client_builder().handshake(stream).await.map_err(map_io_error)?;
        let req = self.req()?;
        let (resp, send_stream) =
            client.send_request(req, false).map_err(map_io_error)?;
        let driver = ConnectionDriver::spawn(h2, None);

        let recv_stream = resp.await.map_err(map_io_error)?.into_body();

        Ok(AnyStream::new(Http2Stream::new(recv_stream, send_stream, driver)))
    }
}

pub struct Http2Stream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    buffer: Bytes,
    write_closed: bool,
    _driver: ConnectionDriver,
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
    pub(crate) fn new(recv: RecvStream, send: SendStream<Bytes>, driver: ConnectionDriver) -> Self {
        Self {
            recv,
            send,
            buffer: Bytes::new(),
            write_closed: false,
            _driver: driver,
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
                release_receive_capacity(&mut self.recv, data.len())
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
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe, "H2 stream write side is closed",
            )));
        }
        if buf.is_empty() { return Poll::Ready(Ok(0)); }
        let length = ready!(poll_send_capacity(&mut self.send, cx, buf.len()))?;
        self.send.send_data(Bytes::copy_from_slice(&buf[..length]), false)
            .map_err(map_io_error)?;
        Poll::Ready(Ok(length))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        shutdown_h2_send(&mut this.send, &mut this.write_closed, cx)
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
        spawn,
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
            let driver = ConnectionDriver::spawn(connection, None);
            let request = Request::builder()
                .uri("https://example.org/")
                .body(())
                .unwrap();
            let (response, send) = client.send_request(request, true).unwrap();
            let recv = response.await.unwrap().into_body();
            let mut stream = Http2Stream::new(recv, send, driver);
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
            server_task.abort();
        })
        .await
        .unwrap();
    }
}
