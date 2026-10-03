use std::{io, pin::Pin, task::{Context, Poll}};

use futures::ready;
use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::protocol::{MIN_PADDING, MAX_PADDING};
use crate::proxy::{AnyStream, ProxyStream};

const FIRST_PADDINGS: usize = 16;

/// sing-mux frames the first sixteen writes independently in each direction.
pub struct PaddingStream {
    inner: AnyStream,
    header: [u8; 4],
    header_read: usize,
    read_frames: usize,
    data_remaining: usize,
    padding_remaining: usize,
    write_frames: usize,
    pending: Vec<u8>,
    written: usize,
    deferred_write_error: Option<io::Error>,
}

impl PaddingStream {
    pub fn new(inner: AnyStream) -> Self {
        Self {
            inner, header: [0; 4], header_read: 0, read_frames: 0,
            data_remaining: 0, padding_remaining: 0, write_frames: 0,
            pending: Vec::new(), written: 0, deferred_write_error: None,
        }
    }

    fn drain_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.deferred_write_error.take() {
            return Poll::Ready(Err(error));
        }
        while self.written < self.pending.len() {
            let n = ready!(Pin::new(&mut self.inner)
                .poll_write(cx, &self.pending[self.written..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        if self.write_frames >= FIRST_PADDINGS {
            self.pending = Vec::new();
        } else {
            self.pending.clear();
        }
        self.written = 0;
        Poll::Ready(Ok(()))
    }
}

impl ProxyStream for PaddingStream {}

impl AsyncRead for PaddingStream {
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.data_remaining > 0 {
                let limit = buf.remaining().min(this.data_remaining);
                let mut part = ReadBuf::new(&mut buf.initialize_unfilled()[..limit]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut part))?;
                let n = part.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.data_remaining -= n;
                buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.padding_remaining > 0 {
                let mut padding = [0; MAX_PADDING as usize];
                let limit = padding.len().min(this.padding_remaining);
                let mut part = ReadBuf::new(&mut padding[..limit]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut part))?;
                let n = part.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.padding_remaining -= n;
                continue;
            }
            if this.read_frames >= FIRST_PADDINGS {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            let mut part = ReadBuf::new(&mut this.header[this.header_read..]);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut part))?;
            let n = part.filled().len();
            if n == 0 {
                return if this.header_read == 0 {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                };
            }
            this.header_read += n;
            if this.header_read == 4 {
                this.data_remaining = u16::from_be_bytes([this.header[0], this.header[1]]) as usize;
                this.padding_remaining = u16::from_be_bytes([this.header[2], this.header[3]]) as usize;
                this.header_read = 0;
                this.read_frames += 1;
            }
        }
    }
}

impl AsyncWrite for PaddingStream {
    fn poll_write(
        self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain_write(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_frames >= FIRST_PADDINGS {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        let n = buf.len().min(u16::MAX as usize);
        let padding = rand::rng().random_range(MIN_PADDING..=MAX_PADDING);
        this.pending.reserve_exact(4 + n + padding as usize);
        this.pending.extend_from_slice(&(n as u16).to_be_bytes());
        this.pending.extend_from_slice(&padding.to_be_bytes());
        this.pending.extend_from_slice(&buf[..n]);
        this.pending.resize(4 + n + padding as usize, 0);
        this.write_frames += 1;
        // The payload is already accepted. Try to send it immediately, but
        // retain partial-write state and report any error on the next call.
        if let Poll::Ready(Err(error)) = this.drain_write(cx) {
            this.deferred_write_error = Some(error);
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain_write(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain_write(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "padding_tests.rs"]
mod tests;
