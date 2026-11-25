//! AnyTLS Client Session Implementation
//!
//! Provides AnyTLS client session management for multiplexed outbound connections.

use bytes::{BufMut, Bytes, BytesMut};
use parking_lot::{Mutex, RwLock};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, OnceLock, Weak};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::runtime::Handle;
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot};
use tokio::time::{Instant, sleep_until, timeout, timeout_at};
use tracing::{debug, trace, warn};

use crate::proxy::AnyStream;
use crate::session::SocksAddr;

use super::padding::{IntoSharedPadding, PaddingFactory, SharedPaddingFactory};
use super::pool::SessionPoolInner;
use super::stream::{AnyTlsStream, STREAM_CHANNEL_BUFFER};
use super::types::{
    Command, FRAME_HEADER_SIZE, Frame, FrameCodec, MAX_FRAME_DATA_SIZE, StringMap,
};

/// Capacity of the shared outgoing message channel.
///
/// This bounds total in-flight messages across all streams on a session,
/// providing backpressure when the TLS writer cannot keep up. Sized to
/// match the old per-stream budget (STREAM_CHANNEL_BUFFER) times the
/// default max streams per connection.
const OUTGOING_CHANNEL_BUFFER: usize = STREAM_CHANNEL_BUFFER * 8;

pub(super) const PEER_VERSION_UNKNOWN: u8 = 0;
pub(super) const PEER_VERSION_V2: u8 = 2;

/// Highest bit of `stream_counts`: once set, no new stream may be reserved on
/// this session. Packing it with the stream counters makes idle reclamation
/// and stream reservation a single atomic transition.
const CLOSED_BIT: u64 = 1u64 << 63;

/// Upper bound for draining already-queued outgoing frames before forcing
/// transport shutdown during graceful idle reclamation.
const GRACEFUL_CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

#[inline]
fn unpack_stream_counts(val: u64) -> (bool, usize, usize) {
    let closed = (val & CLOSED_BIT) != 0;
    let active = ((val & !CLOSED_BIT) >> 32) as usize;
    let reserved = (val & 0xFFFF_FFFF) as usize;
    (closed, active, reserved)
}

#[inline]
fn pack_stream_counts(closed: bool, active: usize, reserved: usize) -> u64 {
    let flag = if closed { CLOSED_BIT } else { 0 };
    flag | (((active as u64) & 0x7FFF_FFFF) << 32) | (reserved as u64 & 0xFFFF_FFFF)
}

/// Outgoing message types for the unified writer channel
pub(super) enum OutgoingMessage {
    /// Buffered frames (Settings + SYN + destination) - sent as single TLS record
    Buffered { data: Bytes },
    /// Control frame (Settings, SYN, etc.)
    Control {
        cmd: Command,
        stream_id: u32,
        data: Bytes,
    },
    /// Data frame for a stream (PSH)
    Data {
        stream_id: u32,
        data: Bytes,
    },
    /// FIN frame for a stream
    Fin { stream_id: u32 },
}

/// Active stream entry maintained in the session
pub(super) struct StreamEntry {
    pub(super) data_tx: mpsc::Sender<io::Result<Bytes>>,
    pub(super) ack_tx: Option<oneshot::Sender<Result<(), String>>>,
    pub(super) err_tx: Option<oneshot::Sender<String>>,
    pub(super) peer_closed: Arc<AtomicBool>,
}

/// AnyTLS client session - manages multiplexed streams over a connection
pub struct AnyTlsClientSession {
    /// Active streams mapping (stream_id -> StreamEntry)
    streams: RwLock<HashMap<u32, StreamEntry>>,
    /// Packed stream counters: high 32 bits for active streams, low 32 bits for reserved streams.
    /// Packed into a single AtomicU64 to guarantee atomic updates and prevent race conditions.
    stream_counts: AtomicU64,
    stream_id_counter: AtomicU32,

    /// Channel for all outgoing messages (control and data).
    /// Bounded to provide backpressure when the writer cannot keep up.
    outgoing_tx: mpsc::Sender<OutgoingMessage>,

    /// Session closure flag
    is_closed: Arc<AtomicBool>,

    /// Fixed padding configuration captured at session creation.
    /// A session must strictly use the scheme it reported in its initial Settings frame
    /// throughout its entire lifecycle.
    session_padding: Arc<PaddingFactory>,

    /// Shared padding handle pointing to the Client/Handler's latest scheme.
    /// Updated when receiving Command::UpdatePaddingScheme so that subsequent
    /// new sessions adopt the updated scheme.
    shared_padding: SharedPaddingFactory,

    /// Negotiated protocol version
    peer_version: AtomicU8,

    /// Padding enabled state
    send_padding: AtomicBool,
    /// Packet counter for padding calculation
    pkt_counter: AtomicU32,

    /// Mutex protecting the initial Settings frame transmission.
    /// Ensures that the first stream's Settings frame is committed to outgoing_tx
    /// before any other concurrent streams can enqueue their SYN frames.
    initial_settings: AsyncMutex<Option<BytesMut>>,
    /// Flag indicating that the initial Settings frame has been committed to outgoing_tx
    settings_sent: AtomicBool,

    /// Monotonic origin for the session's relative timestamps.
    clock_origin: Instant,
    /// Idle start in nanoseconds since clock_origin, published before a zero count.
    idle_since: AtomicU64,

    /// Notify handle to break loops on session drop or hard close
    close_notify: Arc<Notify>,

    /// Graceful close state: writer drains queued messages and shuts down the
    /// transport before tearing down the session.
    draining: AtomicBool,
    drain_notify: Arc<Notify>,
    writer_exited: AtomicBool,
    drain_keepalive: Mutex<Option<Arc<Self>>>,
    drain_timeout_ms: AtomicU64,
    runtime: Handle,
    self_weak: OnceLock<Weak<Self>>,

    /// Back-reference to the owning pool for immediate idle reclamation when
    /// `keep_idle` is disabled.
    idle_pool: OnceLock<Weak<SessionPoolInner>>,
}

impl std::fmt::Debug for AnyTlsClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsClientSession")
            .field("is_closed", &self.is_closed.load(Ordering::Relaxed))
            .field("peer_version", &self.peer_version.load(Ordering::Relaxed))
            .finish()
    }
}

impl Drop for AnyTlsClientSession {
    fn drop(&mut self) {
        self.close_notify.notify_waiters();
        self.streams.write().clear();
    }
}

impl AnyTlsClientSession {
    /// Create a new client session on the given transport.
    pub async fn new<P: IntoSharedPadding>(
        mut transport: AnyStream,
        password: &str,
        padding: P,
    ) -> io::Result<Arc<Self>> {
        let shared_padding = padding.into_shared_padding();
        let session_padding = shared_padding.load_full();
        let password_hash = Sha256::digest(password.as_bytes());

        // Send authentication packet (packet 0)
        Self::send_auth(&mut transport, password_hash.as_slice(), &session_padding).await?;

        let (outgoing_tx, outgoing_rx) = mpsc::channel(OUTGOING_CHANNEL_BUFFER);
        let initial_buffer = Self::create_initial_buffer(&session_padding);

        let session = Arc::new(Self {
            streams: RwLock::new(HashMap::new()),
            stream_counts: AtomicU64::new(0),
            stream_id_counter: AtomicU32::new(0),
            outgoing_tx,
            is_closed: Arc::new(AtomicBool::new(false)),
            session_padding,
            shared_padding,
            peer_version: AtomicU8::new(PEER_VERSION_UNKNOWN),
            send_padding: AtomicBool::new(true),
            pkt_counter: AtomicU32::new(1),
            initial_settings: AsyncMutex::new(Some(initial_buffer)),
            settings_sent: AtomicBool::new(false),
            clock_origin: Instant::now(),
            idle_since: AtomicU64::new(0),
            close_notify: Arc::new(Notify::new()),
            draining: AtomicBool::new(false),
            drain_notify: Arc::new(Notify::new()),
            writer_exited: AtomicBool::new(false),
            drain_keepalive: Mutex::new(None),
            drain_timeout_ms: AtomicU64::new(
                GRACEFUL_CLOSE_DRAIN_TIMEOUT.as_millis() as u64,
            ),
            runtime: Handle::current(),
            self_weak: OnceLock::new(),
            idle_pool: OnceLock::new(),
        });
        let _ = session.self_weak.set(Arc::downgrade(&session));

        let (read_half, write_half) = tokio::io::split(transport);
        Self::spawn_tasks(Arc::clone(&session), read_half, write_half, outgoing_rx);

        Ok(session)
    }

    /// Check if the session is closed
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Acquire)
            || (self.stream_counts.load(Ordering::Acquire) & CLOSED_BIT) != 0
    }

    /// Explicitly mark session as closed and notify all listeners
    pub fn mark_closed(&self) {
        self.stream_counts.fetch_or(CLOSED_BIT, Ordering::AcqRel);
        self.is_closed.store(true, Ordering::Release);
        self.close_notify.notify_waiters();
        let mut streams = self.streams.write();
        streams.clear();
        drop(streams);
        self.release_stream_slot(|_, reserved| (0, reserved));
    }

    /// Mark the session as no longer accepting new streams (`CLOSED_BIT`) and
    /// signal the writer task to flush all already-queued frames (data + FIN)
    /// and shut down the transport before closing the session.
    pub(super) fn begin_graceful_close(&self) {
        self.stream_counts.fetch_or(CLOSED_BIT, Ordering::AcqRel);
        if self.is_closed.load(Ordering::Acquire) {
            return;
        }
        if let Some(strong) = self.self_weak.get().and_then(Weak::upgrade) {
            *self.drain_keepalive.lock() = Some(strong);
        }
        self.draining.store(true, Ordering::SeqCst);
        self.drain_notify.notify_one();
        // If the writer already exited before we stored `drain_keepalive`,
        // drop the self-reference immediately so the session cannot leak.
        if self.writer_exited.load(Ordering::SeqCst) {
            self.drain_keepalive.lock().take();
            self.mark_closed();
        }
    }

    /// Atomically claim an idle session (`active == 0 && reserved == 0`) for
    /// closure by setting `CLOSED_BIT`. Caller must invoke
    /// `begin_graceful_close()` outside the pool lock when this returns `true`.
    pub(super) fn try_claim_idle_close(&self) -> bool {
        self.stream_counts
            .compare_exchange(0, CLOSED_BIT, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    pub(super) fn attach_pool(&self, pool: Weak<SessionPoolInner>) {
        let _ = self.idle_pool.set(pool);
    }

    fn should_close_on_idle(&self) -> (Option<Arc<SessionPoolInner>>, bool) {
        match self.idle_pool.get() {
            Some(weak) => match weak.upgrade() {
                Some(pool) => {
                    let close = !pool.keep_idle();
                    (Some(pool), close)
                }
                // Owning pool has been dropped (e.g. config reload); never
                // keep an orphaned session alive after its last stream exits.
                None => (None, true),
            },
            None => (None, false),
        }
    }

    fn release_stream_slot(
        &self,
        decrement: impl Fn(usize, usize) -> (usize, usize),
    ) {
        let (pool, close_on_idle) = self.should_close_on_idle();

        let mut closed_now = false;
        let mut became_zero = false;
        let _ = self.stream_counts.try_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |val| {
                let (closed, active, reserved) = unpack_stream_counts(val);
                let (next_active, next_reserved) = decrement(active, reserved);
                let became_idle = !closed
                    && (active + reserved != 0)
                    && (next_active + next_reserved == 0);
                if became_idle {
                    // Publish the idle timestamp before the release CAS makes
                    // zero visible to pruning's acquire load. A failed CAS can
                    // conservatively refresh it; fetch_max prevents an older
                    // concurrent attempt from moving the timestamp backwards.
                    let elapsed = self.clock_origin.elapsed().as_nanos() as u64;
                    self.idle_since.fetch_max(elapsed, Ordering::Relaxed);
                }
                let next_closed = closed || (became_idle && close_on_idle);
                closed_now = !closed && next_closed;
                became_zero = became_idle && !next_closed;
                Some(pack_stream_counts(next_closed, next_active, next_reserved))
            },
        );

        if closed_now {
            self.begin_graceful_close();
            if let Some(pool) = pool {
                pool.prune_closed_sessions();
            }
        } else if became_zero {
            // Re-check `keep_idle` / pool liveness after publishing zero
            // (SeqCst) so a concurrent `set_keep_idle(false)` or pool drop
            // cannot miss this session.
            let (pool_after, close_after) = self.should_close_on_idle();
            if close_after && self.try_claim_idle_close() {
                self.begin_graceful_close();
                if let Some(pool) = pool_after {
                    pool.prune_closed_sessions();
                }
            }
        }
    }

    pub(super) fn decrement_active_streams(&self) {
        self.release_stream_slot(|active, reserved| {
            (active.saturating_sub(1), reserved)
        });
    }

    #[inline]
    fn drain_timeout(&self) -> Duration {
        Duration::from_millis(self.drain_timeout_ms.load(Ordering::Relaxed))
    }

    #[cfg(test)]
    pub(crate) fn set_drain_timeout_for_test(&self, timeout: Duration) {
        self.drain_timeout_ms
            .store(timeout.as_millis().max(1) as u64, Ordering::Relaxed);
    }

    /// Unregister a stream from active streams map and decrement active_streams counter.
    /// Returns true if the stream was present and removed (ensuring exactly-once decrement).
    pub(super) fn unregister_stream(&self, stream_id: u32) -> bool {
        let removed = {
            let mut streams = self.streams.write();
            streams.remove(&stream_id).is_some()
        };
        if removed {
            self.decrement_active_streams();
            true
        } else {
            false
        }
    }

    /// Queue a FIN frame (when requested) and unregister the stream. If the
    /// outgoing channel is full, keep the active stream slot held until the
    /// FIN enters the channel (or times out) so graceful idle drain cannot
    /// finish and close the transport before the FIN is queued.
    pub(super) fn enqueue_fin_and_unregister(&self, stream_id: u32, send_fin: bool) {
        if !send_fin || self.is_closed.load(Ordering::Acquire) {
            self.unregister_stream(stream_id);
            return;
        }
        match self.outgoing_tx.try_send(OutgoingMessage::Fin { stream_id }) {
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {
                self.unregister_stream(stream_id);
            }
            Err(mpsc::error::TrySendError::Full(msg)) => {
                let removed = {
                    let mut streams = self.streams.write();
                    streams.remove(&stream_id).is_some()
                };
                if !removed {
                    return;
                }
                if let Some(session) = self.self_weak.get().and_then(Weak::upgrade) {
                    let drain_timeout = session.drain_timeout();
                    self.runtime.spawn(async move {
                        let _ = timeout(
                            drain_timeout,
                            session.outgoing_tx.send(msg),
                        )
                        .await;
                        session.decrement_active_streams();
                    });
                } else {
                    self.decrement_active_streams();
                }
            }
        }
    }

    /// Try to reserve a stream slot if the session is open and
    /// `(active_streams + reserved_streams) < max_streams`.
    /// Uses a single packed AtomicU64 to guarantee that closed/active/reserved
    /// transitions are atomic without race conditions.
    pub fn try_reserve_stream(&self, max_streams: usize) -> bool {
        self.stream_counts
            .try_update(Ordering::AcqRel, Ordering::Relaxed, |val| {
                let (closed, active, reserved) = unpack_stream_counts(val);
                if !closed && active + reserved < max_streams {
                    Some(pack_stream_counts(false, active, reserved + 1))
                } else {
                    None
                }
            })
            .is_ok()
    }

    /// Explicitly reserve a stream slot without limit checking (used when pool
    /// is at max capacity). Fails if the session has already transitioned to
    /// closed.
    pub fn force_reserve_stream(&self) -> bool {
        self.stream_counts
            .try_update(Ordering::AcqRel, Ordering::Relaxed, |val| {
                let (closed, active, reserved) = unpack_stream_counts(val);
                if closed {
                    None
                } else {
                    Some(pack_stream_counts(false, active, reserved + 1))
                }
            })
            .is_ok()
    }

    /// Release a previously reserved stream slot without registering a stream
    pub fn release_reserved_stream(&self) {
        self.release_stream_slot(|active, reserved| {
            (active, reserved.saturating_sub(1))
        });
    }

    /// Atomically transition one reserved stream slot to an active stream
    pub(super) fn commit_reserved_stream(&self) {
        let _ = self.stream_counts.try_update(
            Ordering::AcqRel,
            Ordering::Relaxed,
            |val| {
                let (closed, active, reserved) = unpack_stream_counts(val);
                Some(pack_stream_counts(
                    closed,
                    active + 1,
                    reserved.saturating_sub(1),
                ))
            },
        );
    }

    /// Total allocated streams count (active + reserved)
    pub fn total_streams_count(&self) -> usize {
        let (_, active, reserved) =
            unpack_stream_counts(self.stream_counts.load(Ordering::Relaxed));
        active + reserved
    }

    #[cfg(test)]
    pub(crate) fn set_peer_version(&self, v: u8) {
        self.peer_version.store(v, Ordering::Relaxed);
    }

    /// Returns None while any active or reserved stream keeps the session busy.
    pub fn idle_duration(&self) -> Option<Duration> {
        let (_, active, reserved) =
            unpack_stream_counts(self.stream_counts.load(Ordering::Acquire));
        if active + reserved != 0 {
            return None;
        }
        let since = self.idle_since.load(Ordering::Relaxed);
        Some(self.clock_origin.elapsed().saturating_sub(Duration::from_nanos(since)))
    }

    #[cfg(test)]
    pub(crate) fn peer_version(&self) -> u8 {
        self.peer_version.load(Ordering::Relaxed)
    }

    /// Pre-encode Settings frame into initial buffer
    fn create_initial_buffer(padding: &PaddingFactory) -> BytesMut {
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert(
            "client",
            format!("clash-rs/{}", env!("CLASH_VERSION_OVERRIDE")),
        );
        settings.insert("padding-md5", padding.md5());

        let settings_frame =
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));

        let mut buffer = BytesMut::with_capacity(256);
        settings_frame.encode_into(&mut buffer);
        buffer
    }

    /// Send authentication packet (packet 0: password_hash + padding_len + padding)
    async fn send_auth<W>(
        writer: &mut W,
        password_hash: &[u8],
        padding: &PaddingFactory,
    ) -> io::Result<()>
    where
        W: AsyncWrite + Send + Unpin,
    {
        let sizes = padding.generate_record_payload_sizes(0);
        // clamped for the same reason as `write_with_padding`: the length is
        // written as a u16
        let padding_size = (sizes.first().copied().unwrap_or(0).max(0) as usize)
            .min(MAX_FRAME_DATA_SIZE);
        let mut buf =
            BytesMut::with_capacity(password_hash.len() + 2 + padding_size);

        buf.extend_from_slice(password_hash);
        buf.put_u16(padding_size as u16);
        if padding_size > 0 {
            buf.put_bytes(0, padding_size);
        }

        writer.write_all(&buf).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Spawn background reader and writer tasks
    fn spawn_tasks<R, W>(
        session: Arc<Self>,
        reader: R,
        writer: W,
        outgoing_rx: mpsc::Receiver<OutgoingMessage>,
    ) where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        struct WriterExitGuard {
            session_weak: Weak<AnyTlsClientSession>,
        }

        impl Drop for WriterExitGuard {
            fn drop(&mut self) {
                if let Some(session) = self.session_weak.upgrade() {
                    session.writer_exited.store(true, Ordering::SeqCst);
                    let _keepalive = session.drain_keepalive.lock().take();
                    session.is_closed.store(true, Ordering::Release);
                    session.close_notify.notify_waiters();
                    session.streams.write().clear();
                }
            }
        }

        struct ReaderExitGuard {
            session_weak: Weak<AnyTlsClientSession>,
        }

        impl Drop for ReaderExitGuard {
            fn drop(&mut self) {
                if let Some(session) = self.session_weak.upgrade() {
                    session.is_closed.store(true, Ordering::Release);
                    session.close_notify.notify_waiters();
                    session.streams.write().clear();
                }
            }
        }

        let session_weak_w = Arc::downgrade(&session);
        let close_notify_w = Arc::clone(&session.close_notify);
        let drain_notify_w = Arc::clone(&session.drain_notify);
        // Construct guards synchronously before spawning so their Drop runs
        // even if the Tokio runtime shuts down while draining or before the
        // spawned task is ever polled.
        let writer_exit_guard = WriterExitGuard {
            session_weak: session_weak_w.clone(),
        };
        tokio::spawn(async move {
            let _writer_exit_guard = writer_exit_guard;
            if let Err(e) = Self::writer_loop(
                session_weak_w,
                writer,
                outgoing_rx,
                close_notify_w,
                drain_notify_w,
            )
            .await
            {
                debug!("AnyTLS client writer ended: {}", e);
            }
        });

        let session_weak_r = Arc::downgrade(&session);
        let close_notify_r = Arc::clone(&session.close_notify);
        let reader_exit_guard = ReaderExitGuard {
            session_weak: session_weak_r.clone(),
        };
        tokio::spawn(async move {
            let _reader_exit_guard = reader_exit_guard;
            if let Err(e) =
                Self::reader_loop(session_weak_r, reader, close_notify_r).await
            {
                debug!("AnyTLS client reader ended: {}", e);
            }
        });
    }

    /// Writer loop: consumes OutgoingMessages and sends them over transport with optional padding
    async fn writer_loop<W>(
        session_weak: Weak<Self>,
        mut writer: W,
        mut outgoing_rx: mpsc::Receiver<OutgoingMessage>,
        close_notify: Arc<Notify>,
        drain_notify: Arc<Notify>,
    ) -> io::Result<()>
    where
        W: AsyncWrite + Send + Unpin,
    {
        let mut write_buf = BytesMut::with_capacity(256);
        let mut padding_buf = BytesMut::new();
        let mut drain_deadline: Option<Instant> = None;

        loop {
            // Upgrade only briefly to inspect flags and drop the strong Arc
            // before awaiting `outgoing_rx.recv()`. Holding a strong Arc across
            // the wait would keep `outgoing_tx` alive forever and prevent an
            // idle session from dropping when its pool is discarded.
            {
                let Some(session) = session_weak.upgrade() else {
                    return Ok(());
                };
                if session.is_closed.load(Ordering::Acquire) {
                    return Ok(());
                }
                if drain_deadline.is_none() && session.draining.load(Ordering::Acquire) {
                    drain_deadline = Some(Instant::now() + session.drain_timeout());
                }
            }

            let msg = if drain_deadline.is_some() {
                match outgoing_rx.try_recv() {
                    Ok(m) => Some(m),
                    Err(
                        mpsc::error::TryRecvError::Empty
                        | mpsc::error::TryRecvError::Disconnected,
                    ) => None,
                }
            } else {
                let closed = close_notify.notified();
                tokio::pin!(closed);
                closed.as_mut().enable();
                if session_weak
                    .upgrade()
                    .is_none_or(|s| s.is_closed.load(Ordering::Acquire))
                {
                    return Ok(());
                }
                tokio::select! {
                    biased;
                    m = outgoing_rx.recv() => m,
                    _ = &mut closed => return Ok(()),
                    _ = drain_notify.notified() => {
                        let Some(session) = session_weak.upgrade() else {
                            return Ok(());
                        };
                        drain_deadline =
                            Some(Instant::now() + session.drain_timeout());
                        continue;
                    }
                }
            };

            let Some(msg) = msg else {
                break;
            };

            let Some(session) = session_weak.upgrade() else {
                return Ok(());
            };
            if session.is_closed.load(Ordering::Acquire) {
                return Ok(());
            }

            // Race the write against hard close and the shared graceful-drain
            // deadline so a write that was already blocked before draining began
            // cannot pin the session beyond `drain_timeout`.
            let write_fut = Self::write_outgoing_message(
                &session,
                &mut writer,
                msg,
                &mut write_buf,
                &mut padding_buf,
            );
            tokio::pin!(write_fut);

            loop {
                let closed = close_notify.notified();
                tokio::pin!(closed);
                closed.as_mut().enable();
                if session.is_closed.load(Ordering::Acquire) {
                    return Ok(());
                }

                if let Some(deadline) = drain_deadline {
                    tokio::select! {
                        res = &mut write_fut => {
                            res?;
                            break;
                        }
                        _ = &mut closed => return Ok(()),
                        _ = sleep_until(deadline) => return Ok(()),
                    }
                } else {
                    tokio::select! {
                        res = &mut write_fut => {
                            res?;
                            break;
                        }
                        _ = &mut closed => return Ok(()),
                        _ = drain_notify.notified() => {
                            drain_deadline =
                                Some(Instant::now() + session.drain_timeout());
                        }
                    }
                }
            }
        }

        if let Some(deadline) = drain_deadline {
            let _ = timeout_at(deadline, writer.shutdown()).await;
        }
        Ok(())
    }

    async fn write_outgoing_message<W>(
        session: &Self,
        writer: &mut W,
        msg: OutgoingMessage,
        write_buf: &mut BytesMut,
        padding_buf: &mut BytesMut,
    ) -> io::Result<()>
    where
        W: AsyncWrite + Send + Unpin,
    {
        write_buf.clear();

        match msg {
            OutgoingMessage::Buffered { data } => {
                Self::write_with_padding(session, writer, &data, padding_buf).await?;
            }
            OutgoingMessage::Control {
                cmd,
                stream_id,
                data,
            } => {
                Frame::with_data(cmd, stream_id, data).encode_into(write_buf);
                Self::write_with_padding(session, writer, write_buf, padding_buf)
                    .await?;
            }
            OutgoingMessage::Data { stream_id, data } => {
                // Keep header and payload in one plaintext write: rustls
                // can emit a TLS record immediately on each write.
                Frame::encode_parts(
                    Command::Psh,
                    stream_id,
                    data.as_ref(),
                    write_buf,
                );
                Self::write_with_padding(session, writer, write_buf, padding_buf)
                    .await?;
            }
            OutgoingMessage::Fin { stream_id } => {
                Frame::control(Command::Fin, stream_id).encode_into(write_buf);
                Self::write_with_padding(session, writer, write_buf, padding_buf)
                    .await?;
                // AnyTLS 协议规范明确规定：收到 FIN 后关闭流，无需向对端回发 FIN。
                // 因此 AnyTLS 的 FIN 表示整条流的关闭（而非 TCP 半关闭）。本地 FIN 真正写出后，
                // 立即注销流并关闭接收通道（drop data_tx）。流读取侧在排空已经收到并入队的数据后
                // 会自然收到 None 并返回 EOF，既能交付已接收数据，又不会无限等待对端回发 FIN 导致挂起。
                session.unregister_stream(stream_id);
            }
        }
        Ok(())
    }

    /// Helper to write bytes with optional random padding
    async fn write_with_padding<W>(
        session: &Self,
        writer: &mut W,
        data: &[u8],
        padding_buf: &mut BytesMut,
    ) -> io::Result<()>
    where
        W: AsyncWrite + Send + Unpin,
    {
        if session.send_padding.load(Ordering::Relaxed) {
            let count = session.pkt_counter.fetch_add(1, Ordering::Relaxed);
            if count >= session.session_padding.stop() {
                session.send_padding.store(false, Ordering::Relaxed);
                writer.write_all(data).await?;
                writer.flush().await?;
                return Ok(());
            }

            let sizes = session.session_padding.generate_record_payload_sizes(count);
            if sizes.is_empty() {
                writer.write_all(data).await?;
                writer.flush().await?;
                return Ok(());
            }

            let mut offset = 0;
            for spec in sizes {
                if spec == super::padding::CHECK_MARK {
                    if offset >= data.len() {
                        return Ok(());
                    }
                    continue;
                }

                if spec <= 0 {
                    continue;
                }

                let target_size = spec as usize;
                let remaining = &data[offset..];

                if !remaining.is_empty() {
                    if remaining.len() >= target_size {
                        let chunk = &remaining[..target_size];
                        offset += target_size;
                        writer.write_all(chunk).await?;
                        writer.flush().await?;
                    } else {
                        let chunk = remaining;
                        offset = data.len();
                        if target_size >= chunk.len() + FRAME_HEADER_SIZE {
                            let padding_len =
                                (target_size - chunk.len() - FRAME_HEADER_SIZE).min(MAX_FRAME_DATA_SIZE);
                            padding_buf.clear();
                            padding_buf.reserve(chunk.len() + FRAME_HEADER_SIZE + padding_len);
                            padding_buf.extend_from_slice(chunk);
                            padding_buf.put_u8(Command::Waste as u8);
                            padding_buf.put_u32(0);
                            padding_buf.put_u16(padding_len as u16);
                            padding_buf.put_bytes(0, padding_len);
                            writer.write_all(padding_buf).await?;
                            writer.flush().await?;
                        } else {
                            writer.write_all(chunk).await?;
                            writer.flush().await?;
                        }
                    }
                } else if target_size >= FRAME_HEADER_SIZE {
                    let padding_len = (target_size - FRAME_HEADER_SIZE).min(MAX_FRAME_DATA_SIZE);
                    padding_buf.clear();
                    padding_buf.reserve(FRAME_HEADER_SIZE + padding_len);
                    padding_buf.put_u8(Command::Waste as u8);
                    padding_buf.put_u32(0);
                    padding_buf.put_u16(padding_len as u16);
                    padding_buf.put_bytes(0, padding_len);
                    writer.write_all(padding_buf).await?;
                    writer.flush().await?;
                }
            }

            // 若所有分包处理完后用户数据仍有剩余，直接将剩余数据发送完毕
            if offset < data.len() {
                writer.write_all(&data[offset..]).await?;
                writer.flush().await?;
            }
            return Ok(());
        }

        writer.write_all(data).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Reader loop: parses incoming frames and dispatches data to corresponding streams
    async fn reader_loop<R>(
        session_weak: Weak<Self>,
        mut reader: R,
        close_notify: Arc<Notify>,
    ) -> io::Result<()>
    where
        R: AsyncRead + Send + Unpin,
    {
        let mut buffer = BytesMut::with_capacity(8192);

        loop {
            let has_closed = {
                let session = match session_weak.upgrade() {
                    Some(s) => s,
                    None => return Ok(()),
                };

                if session.is_closed.load(Ordering::Relaxed) {
                    return Ok(());
                }

                while let Some(frame) = FrameCodec::decode(&mut buffer)? {
                    if let Err(e) = session.handle_frame(frame).await {
                        warn!("AnyTLS client error handling frame: {}", e);
                        return Err(e);
                    }
                }

                false
            };

            if has_closed {
                return Ok(());
            }

            let read_result = tokio::select! {
                res = reader.read_buf(&mut buffer) => res,
                _ = close_notify.notified() => {
                    return Ok(());
                }
            };

            let n = read_result?;
            if n == 0 {
                if let Some(session) = session_weak.upgrade() {
                    session.is_closed.store(true, Ordering::Relaxed);
                    session.close_notify.notify_waiters();
                    session.streams.write().clear();
                }
                return Ok(());
            }
        }
    }

    /// Handle received frame
    async fn handle_frame(&self, frame: Frame) -> io::Result<()> {
        match frame.cmd {
            Command::Psh => {
                if frame.data.is_empty() {
                    return Ok(());
                }

                // 收到流数据说明流已就绪（兼容不回发 SynAck 的情况），同时获取 data_tx
                let tx = {
                    let streams = self.streams.read();
                    if let Some(entry) = streams.get(&frame.stream_id) {
                        if entry.ack_tx.is_some() {
                            drop(streams);
                            let mut streams = self.streams.write();
                            if let Some(entry) = streams.get_mut(&frame.stream_id) {
                                if let Some(ack_tx) = entry.ack_tx.take() {
                                    let _ = ack_tx.send(Ok(()));
                                }
                                Some(entry.data_tx.clone())
                            } else {
                                None
                            }
                        } else {
                            Some(entry.data_tx.clone())
                        }
                    } else {
                        None
                    }
                };

                if let Some(tx) = tx {
                    // Awaiting here blocks the reader loop, and therefore every
                    // other stream on this session, while one consumer catches
                    // up. That is deliberate: AnyTLS has no per-stream flow
                    // control, so refusing to read the shared transport is the
                    // only backpressure available. Dropping instead would
                    // silently corrupt a reliable stream, and buffering instead
                    // would be unbounded. Head-of-line blocking is the
                    // protocol's cost, not a bug to code around here.
                    if tx.send(Ok(frame.data)).await.is_err() {
                        trace!("Stream {} channel closed", frame.stream_id);
                    }
                } else {
                    trace!("Data for unknown stream {}", frame.stream_id);
                }
            }

            Command::Fin => {
                let (had_stream, tx, peer_closed) = {
                    let mut streams = self.streams.write();
                    match streams.remove(&frame.stream_id) {
                        Some(entry) => {
                            (true, Some(entry.data_tx), Some(entry.peer_closed))
                        }
                        None => (false, None, None),
                    }
                };

                if let Some(pc) = peer_closed {
                    pc.store(true, Ordering::Release);
                }
                if let Some(tx) = tx {
                    let _ = tx.send(Ok(Bytes::new())).await;
                }
                if had_stream {
                    self.decrement_active_streams();
                }
            }

            Command::SynAck => {
                if self.peer_version.load(Ordering::Relaxed) < PEER_VERSION_V2 {
                    self.peer_version.store(PEER_VERSION_V2, Ordering::Relaxed);
                }

                let error = if frame.data.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(&frame.data).to_string())
                };

                if let Some(err_msg) = error {
                    let err = io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("AnyTLS remote rejected stream: {err_msg}"),
                    );
                    let (had_stream, ack_tx, data_tx, err_tx) = {
                        let mut streams = self.streams.write();
                        match streams.remove(&frame.stream_id) {
                            Some(entry) => (
                                true,
                                entry.ack_tx,
                                Some(entry.data_tx),
                                entry.err_tx,
                            ),
                            None => (false, None, None, None),
                        }
                    };

                    if let Some(sender) = err_tx {
                        let _ = sender.send(err_msg.clone());
                    }
                    if let Some(sender) = ack_tx {
                        let _ = sender.send(Err(err_msg.clone()));
                    }
                    if let Some(tx) = data_tx {
                        let _ = tx.send(Err(err)).await;
                    }
                    if had_stream {
                        self.decrement_active_streams();
                    }
                } else {
                    let ack_tx = {
                        let mut streams = self.streams.write();
                        streams
                            .get_mut(&frame.stream_id)
                            .and_then(|entry| entry.ack_tx.take())
                    };
                    if let Some(sender) = ack_tx {
                        let _ = sender.send(Ok(()));
                    }
                }
            }

            Command::ServerSettings => {
                let settings = StringMap::from_bytes(&frame.data);
                let v = settings
                    .get("v")
                    .and_then(|s| s.parse::<u8>().ok())
                    .unwrap_or(1);
                self.peer_version.store(v, Ordering::Relaxed);
                debug!("AnyTLS server version: {}", v);
                if v < 2 {
                    let mut streams = self.streams.write();
                    for entry in streams.values_mut() {
                        if let Some(sender) = entry.ack_tx.take() {
                            let _ = sender.send(Ok(()));
                        }
                    }
                }
            }

            Command::Alert => {
                let msg = String::from_utf8_lossy(&frame.data);
                warn!("AnyTLS server alert: {}", msg);
                self.is_closed.store(true, Ordering::Relaxed);
                self.close_notify.notify_waiters();
                self.streams.write().clear();
            }

            // Keep-alive. Silently dropping these left servers that use
            // heartbeats for liveness tearing sessions down under us.
            Command::HeartRequest => {
                trace!("AnyTLS heartbeat request, replying");
                if self
                    .outgoing_tx
                    .try_send(OutgoingMessage::Control {
                        cmd: Command::HeartResponse,
                        stream_id: frame.stream_id,
                        data: Bytes::new(),
                    })
                    .is_err()
                {
                    trace!("AnyTLS writer gone, cannot answer heartbeat");
                }
            }

            // 按 AnyTLS 协议规范：当收到服务端下发的 cmdUpdatePaddingScheme 时，
            // 客户端应在 Client 对象存储新的 paddingScheme，后续新建会话必须使用该方案。
            // 正在运行的当前会话必须固定使用创建时的方案，不得中途切换。
            Command::UpdatePaddingScheme => {
                match PaddingFactory::new(&frame.data) {
                    Ok(new_factory) => {
                        debug!(
                            "AnyTLS updated padding scheme from server (md5: {}, stop: {})",
                            new_factory.md5(),
                            new_factory.stop()
                        );
                        self.shared_padding.store(Arc::new(new_factory));
                    }
                    Err(e) => {
                        warn!(
                            "AnyTLS failed to parse server padding scheme ({} bytes): {}",
                            frame.data.len(),
                            e
                        );
                    }
                }
            }

            Command::Waste | Command::HeartResponse => {}

            Command::Syn | Command::Settings => {}
        }
        Ok(())
    }

    /// Open a new multiplexed stream to destination
    pub async fn open_stream(
        self: &Arc<Self>,
        destination: &SocksAddr,
    ) -> io::Result<AnyTlsStream> {
        self.open_stream_with_initial_data(destination, &[]).await
    }

    /// Send protocol setup bytes before waiting for the target-dial acknowledgement.
    pub(super) async fn open_stream_with_initial_data(
        self: &Arc<Self>,
        destination: &SocksAddr,
        initial_data: &[u8],
    ) -> io::Result<AnyTlsStream> {
        if self.is_closed.load(Ordering::Relaxed) {
            self.release_reserved_stream();
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "AnyTLS session is closed",
            ));
        }

        let stream_id = self.stream_id_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let (data_tx, data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (ack_tx, ack_rx) = oneshot::channel();
        let (err_tx, err_rx) = oneshot::channel();
        let peer_closed = Arc::new(AtomicBool::new(false));

        {
            let mut streams = self.streams.write();
            streams.insert(
                stream_id,
                StreamEntry {
                    data_tx,
                    ack_tx: Some(ack_tx),
                    err_tx: Some(err_tx),
                    peer_closed: Arc::clone(&peer_closed),
                },
            );
            self.commit_reserved_stream();
        }

        // RAII guard: ensures stream registration and capacity are rolled back
        // if this future is cancelled, times out, or errors before completion.
        struct OpenGuard<'a> {
            session: &'a AnyTlsClientSession,
            stream_id: u32,
            syn_sent: bool,
            committed: bool,
        }

        impl<'a> Drop for OpenGuard<'a> {
            fn drop(&mut self) {
                if !self.committed {
                    self.session
                        .enqueue_fin_and_unregister(self.stream_id, self.syn_sent);
                }
            }
        }

        let mut guard = OpenGuard {
            session: self,
            stream_id,
            syn_sent: false,
            committed: false,
        };

        let mut dest_data = BytesMut::new();
        destination.write_buf(&mut dest_data);
        dest_data.extend_from_slice(initial_data);
        if dest_data.len() > MAX_FRAME_DATA_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AnyTLS opening data exceeds frame capacity",
            ));
        }
        let dest_bytes = dest_data.freeze();

        // 确保 SETTINGS 帧的发送绝对先于任何其他流的 SYN：
        // 若 SETTINGS 尚未确认入队，并发调用必须串行等待握手锁，
        // 彻底杜绝“前序调用取走 SETTINGS 尚未入队，后序调用抢跑发送纯 SYN”导致的协议违规。
        if !self.settings_sent.load(Ordering::Acquire) {
            let mut init_guard = self.initial_settings.lock().await;
            if let Some(settings_buf) = init_guard.take() {
                // RAII 保护：若发送等待期间被取消，将 settings_buf 放回锁内以供下一个调用使用
                struct SettingsGuard<'b> {
                    slot: &'b mut Option<BytesMut>,
                    buf: Option<BytesMut>,
                    committed: bool,
                }
                impl<'b> Drop for SettingsGuard<'b> {
                    fn drop(&mut self) {
                        if !self.committed {
                            *self.slot = self.buf.take();
                        }
                    }
                }

                let mut s_guard = SettingsGuard {
                    slot: &mut *init_guard,
                    buf: Some(settings_buf),
                    committed: false,
                };

                let mut open_buf = BytesMut::with_capacity(
                    s_guard.buf.as_ref().unwrap().len() + FRAME_HEADER_SIZE * 2 + dest_bytes.len(),
                );
                open_buf.extend_from_slice(s_guard.buf.as_ref().unwrap());
                Frame::control(Command::Syn, stream_id).encode_into(&mut open_buf);
                Frame::data(stream_id, dest_bytes).encode_into(&mut open_buf);

                let open_message = OutgoingMessage::Buffered {
                    data: open_buf.freeze(),
                };

                // 在持有锁的情况下发送，确保排在所有并发流的 SYN 之前入队
                if self.outgoing_tx.send(open_message).await.is_err() {
                    self.is_closed.store(true, Ordering::Relaxed);
                    self.close_notify.notify_waiters();
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Session writer closed while opening stream",
                    ));
                }

                s_guard.committed = true;
                drop(s_guard);
                guard.syn_sent = true;
                self.settings_sent.store(true, Ordering::Release);
                drop(init_guard);
            } else {
                drop(init_guard);
                let mut open_buf =
                    BytesMut::with_capacity(FRAME_HEADER_SIZE * 2 + dest_bytes.len());
                Frame::control(Command::Syn, stream_id).encode_into(&mut open_buf);
                Frame::data(stream_id, dest_bytes).encode_into(&mut open_buf);

                if self
                    .outgoing_tx
                    .send(OutgoingMessage::Buffered {
                        data: open_buf.freeze(),
                    })
                    .await
                    .is_err()
                {
                    self.is_closed.store(true, Ordering::Relaxed);
                    self.close_notify.notify_waiters();
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Session writer closed while opening stream",
                    ));
                }
                guard.syn_sent = true;
            }
        } else {
            let mut open_buf =
                BytesMut::with_capacity(FRAME_HEADER_SIZE * 2 + dest_bytes.len());
            Frame::control(Command::Syn, stream_id).encode_into(&mut open_buf);
            Frame::data(stream_id, dest_bytes).encode_into(&mut open_buf);

            if self
                .outgoing_tx
                .send(OutgoingMessage::Buffered {
                    data: open_buf.freeze(),
                })
                .await
                .is_err()
            {
                self.is_closed.store(true, Ordering::Relaxed);
                self.close_notify.notify_waiters();
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Session writer closed while opening stream",
                ));
            }
            guard.syn_sent = true;
        }

        let mut ack_rx = ack_rx;
        // UoT routing can read the first datagram before acknowledging the stream.
        // Return after setup so the caller can send it; remote rejection still
        // reaches the stream through err_rx and is checked on reads and writes.
        if initial_data.is_empty()
            && self.peer_version.load(Ordering::Relaxed) >= PEER_VERSION_V2
        {
            // 确认是 v2 后，普通 TCP 流等待 SynAck
            match timeout(Duration::from_secs(10), &mut ack_rx).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(err_msg))) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("AnyTLS remote rejected stream: {err_msg}"),
                    ));
                }
                Ok(Err(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Session closed while waiting for stream SynAck",
                    ));
                }
                Err(_) => {
                    // A blackholed transport can stay writable after a network
                    // change. Retire it instead of reusing it for every request.
                    self.mark_closed();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Timeout waiting for AnyTLS stream SynAck",
                    ));
                }
            }
        }

        // 首流请求入队后即可返回；版本仍标为“未知”，不要因超时永久判定为 v1。
        // 若随后收到 v2 设置和拒绝，错误已通过 err_tx 发送，后续读和写都能看到它。
        guard.committed = true;

        let stream = AnyTlsStream::new(
            stream_id,
            data_rx,
            self.outgoing_tx.clone(),
            Arc::clone(&self.is_closed),
            Arc::clone(self),
            err_rx,
            peer_closed,
        );

        Ok(stream)
    }
}
