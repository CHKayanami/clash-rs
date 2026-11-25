use std::{
    cmp::min,
    fmt::Debug,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc::{Receiver, Sender},
};
use tokio_util::sync::PollSender;
use tracing::trace;

#[derive(Debug)]
pub struct SocketPair {
    pub read: Receiver<Bytes>,
    write: PollSender<Bytes>,

    read_buf: BytesMut,
}

impl SocketPair {
    pub fn new(read: Receiver<Bytes>, write: Sender<Bytes>) -> Self {
        Self {
            read,
            write: PollSender::new(write),
            read_buf: BytesMut::new(),
        }
    }
}

impl crate::proxy::ProxyStream for SocketPair {}

impl AsyncRead for SocketPair {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buf.is_empty() {
            let len = min(self.read_buf.len(), buf.remaining());
            buf.put_slice(&self.read_buf.split_to(len));
            trace!(
                "reusing cached data sent {}, left {}",
                len,
                self.read_buf.len()
            );
            return Poll::Ready(Ok(()));
        }

        match self.read.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let len = min(data.len(), buf.remaining());
                buf.put_slice(&data[..len]);
                self.read_buf.extend_from_slice(&data[len..]);
                trace!(
                    "socket got {} data, sent {}, left {}",
                    data.len(),
                    len,
                    self.read_buf.len()
                );
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for SocketPair {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.write.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                if self.write.send_item(Bytes::copy_from_slice(buf)).is_ok() {
                    Poll::Ready(Ok(buf.len()))
                } else {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "wireguard tcp socket closed",
                    )))
                }
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wireguard tcp socket closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        // Closing the write channel lets the forwarding task drain every
        // previously accepted payload before signaling graceful TCP FIN.
        self.write.close();
        Poll::Ready(Ok(()))
    }
}
