use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use quinn_jls::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proxy::{ProxyStream, utils::quic_stream::QuicBidiStream};

use super::udp::ShadowQuicLease;

pub struct ShadowQuicStream {
    inner: QuicBidiStream<ShadowQuicLease, SendStream, RecvStream>,
}

impl ShadowQuicStream {
    pub(super) fn new(
        send: SendStream,
        recv: RecvStream,
        lease: ShadowQuicLease,
    ) -> Self {
        Self {
            inner: QuicBidiStream::new(send, recv, lease),
        }
    }
}

impl AsyncRead for ShadowQuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner.poll_read_inner(cx, buf)
    }
}

impl AsyncWrite for ShadowQuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_write_io(cx, buf)
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

impl ProxyStream for ShadowQuicStream {}
