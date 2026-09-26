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
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::PollSender;

use super::session::{AnyTlsClientSession, OutgoingMessage};
use super::types::MAX_FRAME_DATA_SIZE;

/// Buffer size for bounded channels (number of messages, not bytes)
pub const STREAM_CHANNEL_BUFFER: usize = 16;

/// AnyTlsStream represents a multiplexed stream within an AnyTLS session
pub struct AnyTlsStream {
    /// Stream ID (unique within session)
    id: u32,

    /// Receiver for incoming data/errors from session (bounded for backpressure)
    data_rx: mpsc::Receiver<io::Result<Bytes>>,

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

    /// Local stream write side closed flag
    write_closed: bool,

    /// Local stream read side closed flag
    read_closed: bool,

    /// Flag indicating shutdown is in progress (FIN being sent)
    shutdown_in_progress: bool,

    /// Flag to track if we've received EOF
    eof: bool,

    /// Reference to the session for unregistering on Drop and keepalive
    session: Arc<AnyTlsClientSession>,

    /// Receiver for stream error notification (e.g. remote SynAck rejection)
    err_rx: oneshot::Receiver<String>,

    /// Cached local error
    cached_error: Option<io::Error>,

    /// Flag indicating remote sent FIN and closed this stream
    peer_closed: Arc<AtomicBool>,
}

impl crate::proxy::ProxyStream for AnyTlsStream {}

impl std::fmt::Debug for AnyTlsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsStream")
            .field("id", &self.id)
            .finish()
    }
}

impl AnyTlsStream {
    /// Create a new AnyTlsStream with a session reference
    pub(super) fn new(
        id: u32,
        data_rx: mpsc::Receiver<io::Result<Bytes>>,
        outgoing_tx: mpsc::Sender<OutgoingMessage>,
        session_closed: Arc<AtomicBool>,
        session: Arc<AnyTlsClientSession>,
        err_rx: oneshot::Receiver<String>,
        peer_closed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            id,
            data_rx,
            read_buffer: Bytes::new(),
            read_offset: 0,
            outgoing_tx: PollSender::new(outgoing_tx),
            session_closed,
            write_closed: false,
            read_closed: false,
            shutdown_in_progress: false,
            eof: false,
            session,
            err_rx,
            cached_error: None,
            peer_closed,
        }
    }

    /// Get the stream ID
    #[allow(dead_code)]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Retrieve a cloned copy of the stream error, if any
    fn check_stream_error(&mut self) -> Option<io::Error> {
        if let Some(err) = self.cached_error.as_ref() {
            return Some(io::Error::new(err.kind(), err.to_string()));
        }

        match self.err_rx.try_recv() {
            Ok(msg) => {
                let err = io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("AnyTLS remote rejected stream: {msg}"),
                );
                let ret_err = io::Error::new(err.kind(), err.to_string());
                self.cached_error = Some(err);
                Some(ret_err)
            }
            Err(_) => None,
        }
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 1. 如果缓冲区中还有未消费的数据，必须优先交给应用，绝不能被任何后续错误或断开连接遮蔽！
        let remaining_in_buffer = self.read_buffer.len() - self.read_offset;
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

        // 2. 缓冲区排空后，检查远端是否有拒绝错误
        if let Some(err) = self.check_stream_error() {
            self.read_closed = true;
            return Poll::Ready(Err(err));
        }

        if self.read_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream read side closed",
            )));
        }

        if self.eof {
            return Poll::Ready(Ok(()));
        }

        // 3. 从 data_rx 正常异步读取
        match Pin::new(&mut self.data_rx).poll_recv(cx) {
            Poll::Ready(Some(Ok(data))) => {
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
            Poll::Ready(Some(Err(e))) => {
                let err_clone = io::Error::new(e.kind(), e.to_string());
                self.cached_error = Some(io::Error::new(e.kind(), e.to_string()));
                self.read_closed = true;
                Poll::Ready(Err(err_clone))
            }
            Poll::Ready(None) => {
                if let Some(err) = self.check_stream_error() {
                    self.read_closed = true;
                    return Poll::Ready(Err(err));
                }
                if self.eof || self.peer_closed.load(Ordering::Acquire) {
                    self.eof = true;
                    Poll::Ready(Ok(()))
                } else if self.session_closed.load(Ordering::Relaxed) {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "session closed",
                    )))
                } else {
                    self.eof = true;
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Pending => {
                if let Some(err) = self.check_stream_error() {
                    self.read_closed = true;
                    return Poll::Ready(Err(err));
                }
                if self.session_closed.load(Ordering::Relaxed) {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "session closed",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(err) = self.check_stream_error() {
            self.write_closed = true;
            return Poll::Ready(Err(err));
        }

        if self.peer_closed.load(Ordering::Acquire) || self.eof {
            self.write_closed = true;
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed by remote (received FIN)",
            )));
        }

        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream write side closed",
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
                let data = Bytes::copy_from_slice(&buf[..write_len]);
                let id = self.id;
                match self.outgoing_tx.send_item(OutgoingMessage::Data {
                    stream_id: id,
                    data,
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
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(err) = self.check_stream_error() {
            return Poll::Ready(Err(err));
        }
        // A remote FIN can follow a complete response while the caller is still
        // flushing a request. It closes the stream but does not retroactively
        // make previously accepted writes fail. The session writer owns those
        // writes and flushes them in order.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(err) = self.check_stream_error() {
            self.write_closed = true;
            return Poll::Ready(Err(err));
        }

        if self.write_closed {
            return Poll::Ready(Ok(()));
        }

        if self.session_closed.load(Ordering::Relaxed)
            || self.peer_closed.load(Ordering::Acquire)
            || self.eof
        {
            self.write_closed = true;
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
                        self.write_closed = true;
                        self.shutdown_in_progress = false;
                        Poll::Ready(Ok(()))
                    }
                    Err(_) => {
                        self.write_closed = true;
                        self.shutdown_in_progress = false;
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "session channel closed during shutdown",
                        )))
                    }
                }
            }
            Poll::Ready(Err(_)) => {
                self.write_closed = true;
                self.shutdown_in_progress = false;
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
        // 确保从 session 中注销流并释放 active_streams 容量
        self.session.unregister_stream(self.id);

        // 如果写端尚未发送 FIN 且远端尚未发送 FIN，向对端发送 FIN
        if !self.write_closed
            && !self.session_closed.load(Ordering::Relaxed)
            && !self.peer_closed.load(Ordering::Acquire)
        {
            self.write_closed = true;
            if let Some(sender) = self.outgoing_tx.get_ref().cloned() {
                let stream_id = self.id;
                match sender.try_send(OutgoingMessage::Fin { stream_id }) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(msg)) => {
                        tokio::spawn(async move {
                            let _ = sender.send(msg).await;
                        });
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {}
                }
            }
        }
    }
}
