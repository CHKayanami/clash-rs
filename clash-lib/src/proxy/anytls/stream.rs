//! AnyTLS Stream implementation
//!
//! A Stream represents a single multiplexed connection within an AnyTLS Session.
//! It implements AsyncRead and AsyncWrite for transparent integration into clash-rs.

use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use super::session::OutgoingMessage;
use super::types::MAX_FRAME_DATA_SIZE;

/// Buffer size for bounded channels (number of messages, not bytes)
pub const STREAM_CHANNEL_BUFFER: usize = 16;

/// AnyTlsStream represents a multiplexed stream within an AnyTLS session
pub struct AnyTlsStream {
    /// Stream ID (unique within session)
    id: u32,

    /// Receiver for incoming data from session (bounded for backpressure)
    data_rx: mpsc::Receiver<Bytes>,

    /// Buffer for partial reads
    read_buffer: Bytes,

    /// Offset into read_buffer for partial consumption
    read_offset: usize,

    /// Poll-based sender for outgoing messages to the session writer.
    /// Wraps the session's bounded channel to provide poll-compatible
    /// backpressure without an intermediate forwarder task.
    outgoing_tx: PollSender<OutgoingMessage>,

    /// Shared flag indicating session closure
    session_closed: Arc<AtomicBool>,

    /// Local stream closed flag
    stream_closed: bool,

    /// Flag indicating shutdown is in progress (FIN being sent)
    shutdown_in_progress: bool,

    /// Flag to track if we've received EOF
    eof: bool,

    /// Keepalive reference to the session (client-side only)
    _session_keepalive: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

impl crate::proxy::ProxyStream for AnyTlsStream {}

impl AnyTlsStream {
    /// Create a new AnyTlsStream with a session keepalive reference
    pub(super) fn with_keepalive<S: Send + Sync + 'static>(
        id: u32,
        data_rx: mpsc::Receiver<Bytes>,
        outgoing_tx: mpsc::Sender<OutgoingMessage>,
        session_closed: Arc<AtomicBool>,
        session: Arc<S>,
    ) -> Self {
        Self {
            id,
            data_rx,
            read_buffer: Bytes::new(),
            read_offset: 0,
            outgoing_tx: PollSender::new(outgoing_tx),
            session_closed,
            stream_closed: false,
            shutdown_in_progress: false,
            eof: false,
            _session_keepalive: Some(session),
        }
    }

    /// Get the stream ID
    #[allow(dead_code)]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Best-effort FIN send for Drop
    fn send_fin_best_effort(&mut self) {
        if let Some(sender) = self.outgoing_tx.get_ref() {
            let _ = sender.try_send(OutgoingMessage::Fin {
                stream_id: self.id,
            });
        }
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.stream_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }

        let remaining_in_buffer = self.read_buffer.len() - self.read_offset;
        if self.eof && remaining_in_buffer == 0 {
            return Poll::Ready(Ok(()));
        }

        if remaining_in_buffer > 0 {
            let n = std::cmp::min(remaining_in_buffer, buf.remaining());
            buf.put_slice(&self.read_buffer[self.read_offset..self.read_offset + n]);
            self.read_offset += n;

            if self.read_offset >= self.read_buffer.len() {
                self.read_buffer = Bytes::new();
                self.read_offset = 0;
            }

            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.data_rx).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                if data.is_empty() {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }

                let n = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..n]);

                if n < data.len() {
                    self.read_buffer = data;
                    self.read_offset = n;
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.stream_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }

        if self.shutdown_in_progress {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream is shutting down",
            )));
        }

        if self.session_closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session closed",
            )));
        }

        match self.outgoing_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let write_len = buf.len().min(MAX_FRAME_DATA_SIZE);
                let mut pooled = clash_common::PooledBuffer::acquire(write_len);
                pooled.extend_from_slice(&buf[..write_len]);
                let id = self.id;
                match self.outgoing_tx.send_item(OutgoingMessage::Data {
                    stream_id: id,
                    data: pooled,
                }) {
                    Ok(()) => Poll::Ready(Ok(write_len)),
                    Err(_) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "session channel closed",
                    ))),
                }
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Always ready.
    ///
    /// Writes are handed to the session's writer loop, which flushes the shared
    /// transport after every message; there is no per-stream acknowledgement to
    /// wait on, so this cannot report when bytes actually reached the wire.
    /// Callers relying on flush for ordering against the peer will not get it.
    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.stream_closed {
            return Poll::Ready(Ok(()));
        }

        if self.session_closed.load(Ordering::Relaxed) {
            self.stream_closed = true;
            return Poll::Ready(Ok(()));
        }

        self.shutdown_in_progress = true;

        match self.outgoing_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let id = self.id;
                match self.outgoing_tx.send_item(OutgoingMessage::Fin {
                    stream_id: id,
                }) {
                    Ok(()) => {
                        self.stream_closed = true;
                        Poll::Ready(Ok(()))
                    }
                    Err(_) => {
                        self.stream_closed = true;
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "session channel closed during shutdown",
                        )))
                    }
                }
            }
            Poll::Ready(Err(_)) => {
                self.stream_closed = true;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "session channel closed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        if !self.stream_closed {
            self.stream_closed = true;
            self.send_fin_best_effort();
        }
    }
}
