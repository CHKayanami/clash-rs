use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proxy::{AnyStream, transport::Transport};

pub struct Client {
    host: String,
    port: u16,
    method: String,
    path: Vec<String>,
    headers: HashMap<String, Vec<String>>,
}

impl Client {
    pub fn new(
        host: String,
        port: u16,
        method: String,
        path: Vec<String>,
        headers: HashMap<String, Vec<String>>,
    ) -> Self {
        Self {
            host,
            port,
            method,
            path: if path.is_empty() {
                vec!["/".to_string()]
            } else {
                path
            },
            headers,
        }
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        Ok(HttpStream::new(
            stream,
            self.host.clone(),
            self.port,
            self.method.clone(),
            self.path.clone(),
            self.headers.clone(),
        )
        .into())
    }
}

pub struct HttpStream {
    inner: AnyStream,
    host: String,
    port: u16,
    method: String,
    path: Vec<String>,
    headers: HashMap<String, Vec<String>>,

    first_request: bool,
    first_response: bool,
    write_buf: Vec<u8>,
    write_pos: usize,
    write_committed: usize,
    read_buf: BytesMut,
}

impl crate::proxy::ProxyStream for HttpStream {}

fn drain_write_buf(
    this: &mut HttpStream,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while this.write_pos < this.write_buf.len() {
        let n = ready!(
            Pin::new(&mut this.inner)
                .poll_write(cx, &this.write_buf[this.write_pos..])
        )?;
        if n == 0 {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
        }
        this.write_pos += n;
    }
    Poll::Ready(Ok(()))
}

impl AsyncWrite for HttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if this.write_committed > 0 {
            ready!(drain_write_buf(this, cx))?;
            let committed = this.write_committed;
            this.write_committed = 0;
            return Poll::Ready(Ok(committed));
        }

        if this.first_request {
            let method = if this.method.is_empty() {
                "GET"
            } else {
                this.method.as_str()
            };

            let path_idx = rand::random_range(0..this.path.len());
            let raw_path = &this.path[path_idx];
            let path = if raw_path.starts_with('/') {
                raw_path.to_string()
            } else {
                format!("/{}", raw_path)
            };

            let mut buffer = Vec::new();
            buffer.put_slice(format!("{} {} HTTP/1.1\r\n", method, path).as_bytes());

            let mut has_host = false;
            let mut has_user_agent = false;
            let mut has_accept_encoding = false;
            let mut has_connection = false;
            let mut has_pragma = false;

            for (key, values) in &this.headers {
                if key.eq_ignore_ascii_case("host") {
                    has_host = true;
                } else if key.eq_ignore_ascii_case("user-agent") {
                    has_user_agent = true;
                } else if key.eq_ignore_ascii_case("accept-encoding") {
                    has_accept_encoding = true;
                } else if key.eq_ignore_ascii_case("connection") {
                    has_connection = true;
                } else if key.eq_ignore_ascii_case("pragma") {
                    has_pragma = true;
                }

                if !values.is_empty() {
                    let val_idx = rand::random_range(0..values.len());
                    buffer.put_slice(
                        format!("{}: {}\r\n", key, values[val_idx]).as_bytes(),
                    );
                }
            }

            if !has_host {
                let host_header = if this.port != 80 && this.port != 443 {
                    format!("{}:{}", this.host, this.port)
                } else {
                    this.host.clone()
                };
                buffer.put_slice(format!("Host: {}\r\n", host_header).as_bytes());
            }

            if !has_user_agent {
                buffer.put_slice(
                    b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n",
                );
            }

            if !has_accept_encoding {
                buffer.put_slice(b"Accept-Encoding: gzip, deflate\r\n");
            }

            if !has_connection {
                buffer.put_slice(b"Connection: keep-alive\r\n");
            }

            if !has_pragma {
                buffer.put_slice(b"Pragma: no-cache\r\n");
            }

            buffer.put_slice(b"\r\n");
            buffer.put_slice(buf);

            let n = buf.len();
            this.first_request = false;
            this.write_buf = buffer;
            this.write_pos = 0;
            this.write_committed = n;

            ready!(drain_write_buf(this, cx))?;
            this.write_committed = 0;
            Poll::Ready(Ok(n))
        } else {
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        ready!(drain_write_buf(this, cx))?;
        this.write_committed = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        ready!(drain_write_buf(this, cx))?;
        this.write_committed = 0;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for HttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.read_buf.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), this.read_buf.len());
            let data = this.read_buf.split_to(to_read);
            buf.put_slice(&data);
            return Poll::Ready(Ok(()));
        }

        if this.first_response {
            let needle = b"\r\n\r\n";
            loop {
                let mut tmp = [0u8; 4096];
                let mut tmp_buf = ReadBuf::new(&mut tmp);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let filled = tmp_buf.filled();
                        if filled.is_empty() {
                            return Poll::Ready(Err(io::Error::from(
                                io::ErrorKind::UnexpectedEof,
                            )));
                        }
                        this.read_buf.put_slice(filled);

                        let idx = this
                            .read_buf
                            .windows(needle.len())
                            .position(|w| w == needle);

                        if let Some(idx) = idx {
                            this.first_response = false;
                            let _ = this.read_buf.split_to(idx + needle.len());
                            let to_read =
                                std::cmp::min(buf.remaining(), this.read_buf.len());
                            if to_read > 0 {
                                let data = this.read_buf.split_to(to_read);
                                buf.put_slice(&data);
                            }
                            return Poll::Ready(Ok(()));
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        } else {
            Pin::new(&mut this.inner).poll_read(cx, buf)
        }
    }
}

impl HttpStream {
    pub fn new(
        inner: AnyStream,
        host: String,
        port: u16,
        method: String,
        path: Vec<String>,
        headers: HashMap<String, Vec<String>>,
    ) -> Self {
        Self {
            inner,
            host,
            port,
            method,
            path,
            headers,
            first_request: true,
            first_response: true,
            write_buf: Vec::new(),
            write_pos: 0,
            write_committed: 0,
            read_buf: BytesMut::new(),
        }
    }
}

impl From<HttpStream> for AnyStream {
    fn from(s: HttpStream) -> Self {
        Box::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_http_stream_roundtrip() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let mut headers = HashMap::new();
        headers.insert(
            "Host".to_string(),
            vec!["custom.host.com".to_string()],
        );

        let client = Client::new(
            "example.com".to_string(),
            80,
            "GET".to_string(),
            vec!["/test-path".to_string()],
            headers,
        );

        let mut stream = client.proxy_stream(Box::new(client_io)).await.unwrap();

        let write_task = tokio::spawn(async move {
            stream.write_all(b"hello payload").await.unwrap();
            stream.flush().await.unwrap();

            let mut response = [0u8; 12];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"pong payload");
        });

        // Server side reads HTTP request
        let mut server_buf = [0u8; 1024];
        let n = server_io.read(&mut server_buf).await.unwrap();
        let req_str = String::from_utf8_lossy(&server_buf[..n]);
        assert!(req_str.starts_with("GET /test-path HTTP/1.1\r\n"));
        assert!(req_str.contains("Host: custom.host.com\r\n"));
        assert!(req_str.ends_with("hello payload"));

        // Server responds with fake HTTP response headers + payload
        server_io
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\npong payload")
            .await
            .unwrap();

        write_task.await.unwrap();
    }
}
