use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use parking_lot::Mutex;
use quinn::Connection;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    runtime::Handle,
    select,
    time::{Instant, sleep, timeout},
};

/// Upper bound for waiting on QUIC stream drain so a dead peer cannot pin a
/// closing connection indefinitely.
pub(crate) const QUIC_STREAM_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Short grace window after `send.stopped()` when payload bytes were written on
/// a connection that is about to close: `send.stopped()` confirms the peer's
/// QUIC transport received our FIN, not that the peer application already read
/// our upload before a `CONNECTION_CLOSE` arrives.
pub(crate) const QUIC_HALF_CLOSED_DRAIN_GRACE: Duration = Duration::from_secs(1);

/// Connection-level deadline tracking the latest upload-FIN ACK grace window.
/// Recording the deadline on the connection itself guarantees that disabling
/// `keep_idle`, switching nodes, or retiring a handler shortly after an ACK
/// still respects the remaining grace window measured from that ACK.
#[derive(Default)]
pub(crate) struct QuicUploadGrace {
    deadline: Mutex<Option<Instant>>,
}

impl QuicUploadGrace {
    pub(crate) fn extend(&self, grace: Duration) {
        let candidate = Instant::now() + grace;
        let mut guard = self.deadline.lock();
        if guard.is_none_or(|prev| candidate > prev) {
            *guard = Some(candidate);
        }
    }

    pub(crate) fn remaining(&self) -> Option<Duration> {
        let deadline = (*self.deadline.lock())?;
        let now = Instant::now();
        (deadline > now).then(|| deadline - now)
    }
}

/// Closes `conn` once any remaining upload-FIN ACK grace window in `grace` has
/// elapsed (or immediately if no grace window is active). `keep_alive` is held
/// by the delayed close task until closing finishes so callers can pin
/// auxiliary resources (such as H3 control streams) across the grace window.
pub(crate) fn close_after_grace(
    runtime: &Handle,
    grace: &QuicUploadGrace,
    conn: &Connection,
    reason: &'static [u8],
    keep_alive: impl Send + 'static,
) {
    if conn.close_reason().is_some() {
        return;
    }
    if let Some(remaining) = grace.remaining() {
        let conn = conn.clone();
        runtime.spawn(async move {
            select! {
                _ = sleep(remaining) => {}
                _ = conn.closed() => {}
            }
            if conn.close_reason().is_none() {
                conn.close(0u32.into(), reason);
            }
            drop(keep_alive);
        });
        return;
    }
    conn.close(0u32.into(), reason);
}

/// Connection lease tracked by [`QuicBidiStream`].
pub(crate) trait QuicStreamLease: Send + Sync + 'static {
    /// Records an upload-FIN ACK grace period on the underlying connection.
    fn record_upload_ack_grace(&self, grace: Duration);
}

/// Shared QUIC bidirectional stream wrapper with bounded graceful upload drain
/// on `Drop`. Used by Hysteria2 and TUIC TCP streams so both protocols share
/// the exact same runtime-handle capture, `STOP_SENDING` handling, and upload
/// grace logic.
pub(crate) struct QuicBidiStream<L: QuicStreamLease> {
    send: Option<quinn::SendStream>,
    recv: Option<quinn::RecvStream>,
    recv_eof: bool,
    has_written: bool,
    runtime: Handle,
    lease: Option<L>,
}

impl<L: QuicStreamLease> QuicBidiStream<L> {
    pub(crate) fn new(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        lease: L,
    ) -> Self {
        Self {
            send: Some(send),
            recv: Some(recv),
            recv_eof: false,
            has_written: false,
            runtime: Handle::current(),
            lease: Some(lease),
        }
    }

    pub(crate) fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(recv) = self.recv.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let before = buf.filled().len();
        let remaining = buf.remaining();
        let poll = Pin::new(recv).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll
            && remaining > 0
            && buf.filled().len() == before
        {
            self.recv_eof = true;
        }
        poll
    }

    pub(crate) fn poll_write_raw(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Option<Poll<Result<usize, quinn::WriteError>>> {
        let send = self.send.as_mut()?;
        let poll = Pin::new(send).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll
            && *n > 0
        {
            self.has_written = true;
        }
        Some(poll)
    }

    pub(crate) fn poll_flush_io(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(send) = self.send.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        AsyncWrite::poll_flush(Pin::new(send), cx)
    }

    pub(crate) fn poll_shutdown_io(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(send) = self.send.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        AsyncWrite::poll_shutdown(Pin::new(send), cx)
    }
}

impl<L: QuicStreamLease> Drop for QuicBidiStream<L> {
    fn drop(&mut self) {
        // Once the local stream handle is dropped, no consumer can read further
        // downlink bytes. Explicitly issue STOP_SENDING when the peer has not
        // yet finished so the remote proxy cancels upstream downloads instead
        // of wasting bandwidth.
        if let Some(mut recv) = self.recv.take()
            && !self.recv_eof
        {
            let _ = recv.stop(0u32.into());
        }
        if let Some(mut send) = self.send.take() {
            let _ = send.finish();
            if self.has_written
                && let Some(lease) = self.lease.take()
            {
                self.runtime.spawn(async move {
                    let _ = timeout(QUIC_STREAM_DRAIN_TIMEOUT, async {
                        let _ = send.stopped().await;
                        lease.record_upload_ack_grace(QUIC_HALF_CLOSED_DRAIN_GRACE);
                    })
                    .await;
                    drop(lease);
                });
            }
        }
    }
}
