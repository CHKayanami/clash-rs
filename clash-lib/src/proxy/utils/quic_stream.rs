use std::{
    collections::HashMap,
    future::Future,
    hash::Hash,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use parking_lot::Mutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    runtime::Handle,
    select,
    sync::mpsc::Sender,
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

pub(crate) trait QuicConnectionOps: Clone + Send + Sync + 'static {
    fn is_closed(&self) -> bool;
    fn close_with_reason(&self, reason: &'static [u8]);
    fn wait_closed(&self) -> impl Future<Output = ()> + Send;
}

pub(crate) trait QuicSendStreamOps: AsyncWrite + Unpin + Send + 'static {
    type WriteErr;
    fn poll_write_stream(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Self::WriteErr>>;
    fn finish_stream(&mut self);
    fn wait_stopped(self) -> impl Future<Output = ()> + Send;
}

pub(crate) trait QuicRecvStreamOps: AsyncRead + Unpin + Send + 'static {
    fn stop_stream(&mut self);
}

impl<T: QuicConnectionOps> QuicConnectionOps for Arc<T> {
    fn is_closed(&self) -> bool {
        (**self).is_closed()
    }

    fn close_with_reason(&self, reason: &'static [u8]) {
        (**self).close_with_reason(reason);
    }

    fn wait_closed(&self) -> impl Future<Output = ()> + Send {
        (**self).wait_closed()
    }
}

impl QuicConnectionOps for quinn::Connection {
    fn is_closed(&self) -> bool {
        self.close_reason().is_some()
    }

    fn close_with_reason(&self, reason: &'static [u8]) {
        self.close(0u32.into(), reason);
    }

    async fn wait_closed(&self) {
        self.closed().await;
    }
}

impl QuicSendStreamOps for quinn::SendStream {
    type WriteErr = quinn::WriteError;

    fn poll_write_stream(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Self::WriteErr>> {
        quinn::SendStream::poll_write(self, cx, buf)
    }

    fn finish_stream(&mut self) {
        let _ = self.finish();
    }

    async fn wait_stopped(self) {
        let _ = self.stopped().await;
    }
}

impl QuicRecvStreamOps for quinn::RecvStream {
    fn stop_stream(&mut self) {
        let _ = self.stop(0u32.into());
    }
}

#[cfg(feature = "shadowquic")]
impl QuicConnectionOps for quinn_jls::Connection {
    fn is_closed(&self) -> bool {
        self.close_reason().is_some()
    }

    fn close_with_reason(&self, reason: &'static [u8]) {
        self.close(0u32.into(), reason);
    }

    async fn wait_closed(&self) {
        self.closed().await;
    }
}

#[cfg(feature = "shadowquic")]
impl QuicSendStreamOps for quinn_jls::SendStream {
    type WriteErr = quinn_jls::WriteError;

    fn poll_write_stream(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Self::WriteErr>> {
        quinn_jls::SendStream::poll_write(self, cx, buf)
    }

    fn finish_stream(&mut self) {
        let _ = self.finish();
    }

    async fn wait_stopped(self) {
        let _ = self.stopped().await;
    }
}

#[cfg(feature = "shadowquic")]
impl QuicRecvStreamOps for quinn_jls::RecvStream {
    fn stop_stream(&mut self) {
        let _ = self.stop(0u32.into());
    }
}

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
pub(crate) fn close_after_grace<C: QuicConnectionOps>(
    runtime: &Handle,
    grace: &QuicUploadGrace,
    conn: &C,
    reason: &'static [u8],
    keep_alive: impl Send + 'static,
) {
    if conn.is_closed() {
        return;
    }
    if let Some(remaining) = grace.remaining() {
        let conn = conn.clone();
        runtime.spawn(async move {
            select! {
                _ = sleep(remaining) => {}
                _ = conn.wait_closed() => {}
            }
            if !conn.is_closed() {
                conn.close_with_reason(reason);
            }
            drop(keep_alive);
        });
        return;
    }
    conn.close_with_reason(reason);
}

/// Per-connection UDP session map paired with a latched `closed` flag under
/// the same lock. Once the connection's receive loop exits (or the connection
/// is already closed), subsequent registrations fail and drop their sender
/// immediately so receivers wake with `None` instead of waiting forever.
pub(crate) struct UdpSessionTable<K, V> {
    sessions: HashMap<K, Sender<V>>,
    closed: bool,
}

impl<K: Eq + Hash, V> Default for UdpSessionTable<K, V> {
    fn default() -> Self {
        Self {
            sessions: HashMap::new(),
            closed: false,
        }
    }
}

impl<K: Eq + Hash, V> UdpSessionTable<K, V> {
    pub(crate) fn insert(&mut self, id: K, tx: Sender<V>) -> bool {
        if self.closed {
            return false;
        }
        self.sessions.insert(id, tx);
        true
    }

    pub(crate) fn get(&self, id: &K) -> Option<&Sender<V>> {
        self.sessions.get(id)
    }

    pub(crate) fn remove(&mut self, id: &K) -> Option<Sender<V>> {
        self.sessions.remove(id)
    }

    pub(crate) fn close(&mut self) {
        self.closed = true;
        self.sessions.clear();
    }

    #[cfg(test)]
    pub(crate) fn contains_key(&self, id: &K) -> bool {
        self.sessions.contains_key(id)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }
}

/// Connection lease tracked by [`QuicBidiStream`].
pub(crate) trait QuicStreamLease: Send + Sync + 'static {
    /// Records an upload-FIN ACK grace period on the underlying connection.
    fn record_upload_ack_grace(&self, grace: Duration);
}

/// Shared QUIC bidirectional stream wrapper with bounded graceful upload drain
/// on `Drop`. Used by Hysteria2, TUIC, and ShadowQUIC TCP streams so all
/// protocols share the exact same runtime-handle capture, `STOP_SENDING`
/// handling, and upload grace logic.
pub(crate) struct QuicBidiStream<
    L: QuicStreamLease,
    S: QuicSendStreamOps = quinn::SendStream,
    R: QuicRecvStreamOps = quinn::RecvStream,
> {
    send: Option<S>,
    recv: Option<R>,
    recv_eof: bool,
    has_written: bool,
    runtime: Handle,
    lease: Option<L>,
}

impl<L, S, R> QuicBidiStream<L, S, R>
where
    L: QuicStreamLease,
    S: QuicSendStreamOps,
    R: QuicRecvStreamOps,
{
    pub(crate) fn new(send: S, recv: R, lease: L) -> Self {
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
    ) -> Option<Poll<Result<usize, S::WriteErr>>> {
        let send = self.send.as_mut()?;
        let poll = Pin::new(send).poll_write_stream(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll
            && *n > 0
        {
            self.has_written = true;
        }
        Some(poll)
    }

    #[cfg(feature = "shadowquic")]
    pub(crate) fn poll_write_io(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Some(send) = self.send.as_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "quic stream closed",
            )));
        };
        let poll = AsyncWrite::poll_write(Pin::new(send), cx, buf);
        if let Poll::Ready(Ok(n)) = &poll
            && *n > 0
        {
            self.has_written = true;
        }
        poll
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

impl<L, S, R> Drop for QuicBidiStream<L, S, R>
where
    L: QuicStreamLease,
    S: QuicSendStreamOps,
    R: QuicRecvStreamOps,
{
    fn drop(&mut self) {
        // Once the local stream handle is dropped, no consumer can read further
        // downlink bytes. Explicitly issue STOP_SENDING when the peer has not
        // yet finished so the remote proxy cancels upstream downloads instead
        // of wasting bandwidth.
        if let Some(mut recv) = self.recv.take()
            && !self.recv_eof
        {
            recv.stop_stream();
        }
        if let Some(mut send) = self.send.take() {
            send.finish_stream();
            if self.has_written
                && let Some(lease) = self.lease.take()
            {
                self.runtime.spawn(async move {
                    let _ = timeout(QUIC_STREAM_DRAIN_TIMEOUT, async {
                        send.wait_stopped().await;
                        lease.record_upload_ack_grace(QUIC_HALF_CLOSED_DRAIN_GRACE);
                    })
                    .await;
                    drop(lease);
                });
            }
        }
    }
}
