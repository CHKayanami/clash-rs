use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proxy::{ProxyStream, utils::quic_stream::QuicBidiStream};

use super::types::TuicStreamLease;

pub struct TuicStream {
    inner: QuicBidiStream<TuicStreamLease>,
}

impl TuicStream {
    pub fn new(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        lease: TuicStreamLease,
    ) -> Self {
        Self {
            inner: QuicBidiStream::new(send, recv, lease),
        }
    }
}

impl AsyncRead for TuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner.poll_read_inner(cx, buf)
    }
}

impl AsyncWrite for TuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Some(poll) = self.inner.poll_write_raw(cx, buf) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tuic stream closed",
            )));
        };
        poll.map_err(Into::into)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner.poll_flush_io(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner.poll_shutdown_io(cx)
    }
}

impl ProxyStream for TuicStream {}
