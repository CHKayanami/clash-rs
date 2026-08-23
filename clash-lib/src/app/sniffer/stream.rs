use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::io::SlideBuffer;
use crate::proxy::ProxyStream;

pub struct PrefixedStream<S> {
    prefix: SlideBuffer,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: SlideBuffer, inner: S) -> Self {
        Self { prefix, inner }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let to_read = std::cmp::min(self.prefix.len(), buf.remaining());
            buf.put_slice(&self.prefix.as_slice()[..to_read]);
            self.prefix.consume(to_read);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: ProxyStream> ProxyStream for PrefixedStream<S> {
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn underlying_socket(&mut self) -> Option<&mut tokio::net::TcpStream> {
        if self.prefix.is_empty() {
            self.inner.underlying_socket()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_prefixed_stream() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut prefix = SlideBuffer::new(64);
        prefix.extend_from_slice(b"hello ");
        let mut prefixed = PrefixedStream::new(prefix, client);

        tokio::spawn(async move {
            server.write_all(b"world").await.unwrap();
        });

        let mut buf = vec![0u8; 11];
        prefixed.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello world");
    }
}
