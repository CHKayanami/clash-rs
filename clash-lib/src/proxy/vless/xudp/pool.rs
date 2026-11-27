use crate::proxy::datagram::batch::{MAX_BATCH_PACKETS, MAX_BATCH_BYTES};
mod batch;
use bytes::{Bytes, BytesMut};
use futures::{Sink, Stream, ready};
use parking_lot::{Mutex, RwLock};
use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    runtime::Handle,
    sync::{
        Notify,
        mpsc::{self, error::{TryRecvError, TrySendError}},
        oneshot,
    },
    time::{Duration, Instant, interval, timeout, timeout_at},
};
use tokio_util::sync::{CancellationToken, PollSender};
use tracing::{debug, trace};

use super::frame::{
    SessionStatus, XudpFrame, decode_xudp_frame_from_buf,
};
use crate::{
    proxy::{AnyStream, datagram::UdpPacket},
    session::SocksAddr,
};

const DEFAULT_MAX_CARRIERS: usize = 4;
const DEFAULT_MAX_STREAMS_PER_CARRIER: usize = 256;
const UDP_BUFFER_CAPACITY: usize = 128;
const WRITER_QUEUE_CAPACITY: usize = 256;
const RECV_BUFFER_INITIAL_CAPACITY: usize = 64 * 1024;
const IDLE_CARRIER_TIMEOUT_MS: u64 = 120 * 1000;
const IDLE_CLEANUP_INTERVAL_MS: u64 = 30 * 1000;
const XUDP_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const XUDP_CLOSING_BIT: usize = 1usize << (usize::BITS - 1);

struct ChildSession {
    tx: mpsc::Sender<UdpPacket>,
    peer: SocksAddr,
}

struct XudpStreamLease {
    carrier: Arc<XudpCarrier>,
}

impl Drop for XudpStreamLease {
    fn drop(&mut self) {
        self.carrier.release_lease();
    }
}

pub struct XudpCarrier {
    carrier_id: u64,
    sessions: Arc<RwLock<HashMap<u16, ChildSession>>>,
    writer_tx: mpsc::Sender<Bytes>,
    active_streams: Arc<AtomicUsize>,
    clock_origin: Instant,
    idle_since_ms: Arc<AtomicU64>,
    next_session_id: AtomicU16,
    max_streams: usize,
    keep_idle: Arc<AtomicBool>,
    pool: Weak<XudpPoolInner>,
    drain_tx: Mutex<Option<oneshot::Sender<()>>>,
    drain_timeout_ms: Arc<AtomicU64>,
    idle_timeout_ms: u64,
    runtime: Handle,
    #[cfg(test)]
    before_remove_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl XudpCarrier {
    #[cfg(test)]
    pub fn new(stream: AnyStream, carrier_id: u64, max_streams: usize) -> Arc<Self> {
        Self::new_managed(
            stream,
            carrier_id,
            max_streams,
            Arc::new(AtomicBool::new(true)),
            Weak::new(),
            IDLE_CARRIER_TIMEOUT_MS,
        )
    }

    fn new_managed(
        stream: AnyStream,
        carrier_id: u64,
        max_streams: usize,
        keep_idle: Arc<AtomicBool>,
        pool: Weak<XudpPoolInner>,
        idle_timeout_ms: u64,
    ) -> Arc<Self> {
        let (read_half, write_half) = tokio::io::split(stream);
        let (writer_tx, writer_rx) = mpsc::channel(WRITER_QUEUE_CAPACITY);

        let sessions = Arc::new(RwLock::new(HashMap::new()));
        let active_streams = Arc::new(AtomicUsize::new(0));
        let clock_origin = Instant::now();
        let idle_since_ms = Arc::new(AtomicU64::new(0));
        let (drain_tx, drain_rx) = oneshot::channel();

        let drain_timeout_ms =
            Arc::new(AtomicU64::new(XUDP_DRAIN_TIMEOUT.as_millis() as u64));

        let carrier = Arc::new(Self {
            carrier_id,
            sessions: sessions.clone(),
            writer_tx,
            active_streams: active_streams.clone(),
            clock_origin,
            idle_since_ms: idle_since_ms.clone(),
            next_session_id: AtomicU16::new(1),
            max_streams,
            keep_idle,
            pool: pool.clone(),
            drain_tx: Mutex::new(Some(drain_tx)),
            drain_timeout_ms: drain_timeout_ms.clone(),
            idle_timeout_ms,
            runtime: Handle::current(),
            #[cfg(test)]
            before_remove_hook: Mutex::new(None),
        });

        // Spawn coalescing writer task
        let cancel = CancellationToken::new();
        let cancel_w = cancel.clone();
        let sessions_w = sessions.clone();
        let active_w = active_streams.clone();
        let pool_w = pool.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = cancel_w.cancelled() => {}
                result = Self::writer_loop(
                    write_half,
                    writer_rx,
                    drain_rx,
                    drain_timeout_ms,
                ) => {
                    if let Err(e) = result {
                        debug!("XUDP carrier [{}] writer error: {}", carrier_id, e);
                    }
                }
            }
            active_w.fetch_or(XUDP_CLOSING_BIT, Ordering::SeqCst);
            sessions_w.write().clear();
            cancel_w.cancel();
            if let Some(pool) = pool_w.upgrade() {
                pool.remove_carrier(carrier_id);
            }
        });

        // Spawn zero-allocation reader task
        let sessions_r = sessions.clone();
        let active_r = active_streams;
        let pool_r = pool;
        tokio::spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => {}
                result = Self::reader_loop(carrier_id, read_half, sessions_r.clone()) => {
                    if let Err(e) = result {
                        debug!("XUDP carrier [{}] reader error/EOF: {}", carrier_id, e);
                    }
                }
            }
            active_r.fetch_or(XUDP_CLOSING_BIT, Ordering::SeqCst);
            // Drop all senders to notify active child datagrams of stream closure
            sessions_r.write().clear();
            cancel.cancel();
            if let Some(pool) = pool_r.upgrade() {
                pool.remove_carrier(carrier_id);
            }
        });

        carrier
    }

    fn drain_timeout(&self) -> Duration {
        Duration::from_millis(self.drain_timeout_ms.load(Ordering::Relaxed))
    }

    #[cfg(test)]
    fn set_drain_timeout_for_test(&self, timeout: Duration) {
        self.drain_timeout_ms
            .store(timeout.as_millis().max(1) as u64, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn set_before_remove_hook_for_test<F: FnOnce() + Send + 'static>(&self, hook: F) {
        *self.before_remove_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn run_before_remove_hook_for_test(&self) {
        let hook = self.before_remove_hook.lock().take();
        if let Some(hook) = hook {
            hook();
        }
    }

    async fn write_batch(
        writer: &mut WriteHalf<AnyStream>,
        data: &[u8],
    ) -> io::Result<()> {
        writer.write_all(data).await?;
        writer.flush().await
    }

    async fn writer_loop(
        mut writer: WriteHalf<AnyStream>,
        mut rx: mpsc::Receiver<Bytes>,
        mut drain_rx: oneshot::Receiver<()>,
        drain_timeout_ms: Arc<AtomicU64>,
    ) -> io::Result<()> {
        let mut buffer = BytesMut::new();
        let mut deferred = None;
        let mut drain_deadline: Option<Instant> = None;
        let current_drain_timeout =
            || Duration::from_millis(drain_timeout_ms.load(Ordering::Relaxed));

        loop {
            let frame = match deferred.take() {
                Some(frame) => Some(frame),
                None => match drain_deadline {
                    Some(_) => match rx.try_recv() {
                        Ok(frame) => Some(frame),
                        Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
                    },
                    None => {
                        tokio::select! {
                            biased;
                            _ = &mut drain_rx => {
                                drain_deadline = Some(Instant::now() + current_drain_timeout());
                                continue;
                            }
                            frame = rx.recv() => match frame {
                                Some(frame) => Some(frame),
                                None => {
                                    drain_deadline = Some(Instant::now() + current_drain_timeout());
                                    None
                                }
                            },
                        }
                    }
                },
            };

            let Some(frame) = frame else {
                let deadline =
                    drain_deadline.unwrap_or_else(|| Instant::now() + current_drain_timeout());
                let _ = timeout_at(deadline, writer.shutdown()).await;
                break;
            };

            buffer.clear();
            for _ in 1..MAX_BATCH_PACKETS {
                let size = if buffer.is_empty() { frame.len() } else { buffer.len() };
                if size >= MAX_BATCH_BYTES { break; }
                let Ok(next) = rx.try_recv() else { break; };
                if size + next.len() > MAX_BATCH_BYTES {
                    deferred = Some(next);
                    break;
                }
                if buffer.is_empty() { buffer.extend_from_slice(&frame); }
                buffer.extend_from_slice(&next);
            }
            // Avoid a copy and buffer allocation on an idle carrier.
            let data = if buffer.is_empty() { &frame[..] } else { &buffer[..] };
            let write_fut = Self::write_batch(&mut writer, data);
            if let Some(deadline) = drain_deadline {
                timeout_at(deadline, write_fut)
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XUDP drain timed out"))??;
            } else {
                tokio::pin!(write_fut);
                tokio::select! {
                    biased;
                    _ = &mut drain_rx => {
                        let deadline = Instant::now() + current_drain_timeout();
                        drain_deadline = Some(deadline);
                        timeout_at(deadline, &mut write_fut)
                            .await
                            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XUDP drain timed out"))??;
                    }
                    res = &mut write_fut => res?,
                }
            }
        }
        Ok(())
    }

    async fn reader_loop(
        carrier_id: u64,
        mut reader: ReadHalf<AnyStream>,
        sessions: Arc<RwLock<HashMap<u16, ChildSession>>>,
    ) -> io::Result<()> {
        let mut recv_buf = BytesMut::with_capacity(RECV_BUFFER_INITIAL_CAPACITY);

        loop {
            // Drain and decode all fully received frames in buffer
            loop {
                match decode_xudp_frame_from_buf(&mut recv_buf) {
                    Ok(Some(frame)) => {
                        let session_id = frame.session_id;

                        if let Some(payload) = frame.payload {
                            let tx_and_peer = {
                                let map = sessions.read();
                                map.get(&session_id).map(|s| (s.tx.clone(), s.peer.clone()))
                            };

                            if let Some((tx, default_peer)) = tx_and_peer {
                                let peer = frame.peer_addr.unwrap_or(default_peer);
                                let packet = UdpPacket {
                                    data: payload,
                                    src_addr: peer,
                                    dst_addr: SocksAddr::any_ipv4(),
                                    inbound_user: None,
                                };
                                if let Err(e) = tx.try_send(packet) {
                                    trace!("XUDP carrier [{}] dropped packet for session {}: {}", carrier_id, session_id, e);
                                }
                            }
                        }

                        if frame.status == SessionStatus::End {
                            trace!("XUDP carrier [{}] session {} ended by server", carrier_id, session_id);
                            sessions.write().remove(&session_id);
                        }
                    }
                    Ok(None) => break, // Need more data from wire
                    Err(e) => {
                        debug!("XUDP carrier [{}] invalid frame: {}", carrier_id, e);
                        return Err(e);
                    }
                }
            }

            // Read more data into buffer from TCP stream
            let n = reader.read_buf(&mut recv_buf).await?;
            if n == 0 {
                trace!("XUDP carrier [{}] closed gracefully (EOF)", carrier_id);
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
            }
        }
    }

    pub fn is_closing(&self) -> bool {
        (self.active_streams.load(Ordering::Acquire) & XUDP_CLOSING_BIT) != 0
    }

    pub fn is_closed(&self) -> bool {
        self.is_closing()
    }

    #[cfg(test)]
    pub fn active_streams(&self) -> usize {
        self.active_streams.load(Ordering::SeqCst) & !XUDP_CLOSING_BIT
    }

    pub fn is_idle_expired(&self) -> bool {
        if self.active_streams.load(Ordering::Acquire) == 0 {
            let last = self.idle_since_ms.load(Ordering::Relaxed);
            let now = self.clock_origin.elapsed().as_millis() as u64;
            now.saturating_sub(last) >= self.idle_timeout_ms
        } else {
            false
        }
    }

    fn should_keep_idle(&self) -> bool {
        self.keep_idle.load(Ordering::SeqCst)
    }

    fn try_claim_idle_close(&self) -> bool {
        self.active_streams
            .compare_exchange(0, XUDP_CLOSING_BIT, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    fn begin_graceful_close(&self) {
        self.active_streams.fetch_or(XUDP_CLOSING_BIT, Ordering::SeqCst);
        if let Some(tx) = self.drain_tx.lock().take() {
            let _ = tx.send(());
        }
    }

    fn release_lease(&self) {
        let keep_idle = self.should_keep_idle();
        let mut closed_now = false;
        let mut became_zero = false;
        let _ = self.active_streams.try_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |val| {
                let closing = (val & XUDP_CLOSING_BIT) != 0;
                let count = (val & !XUDP_CLOSING_BIT).saturating_sub(1);
                if count == 0 {
                    let elapsed = self.clock_origin.elapsed().as_millis() as u64;
                    self.idle_since_ms.store(elapsed, Ordering::Relaxed);
                }
                let next_closing = closing || (!keep_idle && count == 0);
                closed_now = !closing && next_closing;
                became_zero = !next_closing && count == 0;
                Some(if next_closing {
                    XUDP_CLOSING_BIT | count
                } else {
                    count
                })
            },
        );
        if closed_now {
            #[cfg(test)]
            self.run_before_remove_hook_for_test();
            if let Some(pool) = self.pool.upgrade() {
                pool.remove_carrier(self.carrier_id);
            }
            self.begin_graceful_close();
        } else if became_zero && !self.should_keep_idle() && self.try_claim_idle_close() {
            // Re-check `keep_idle` / `evicted` after publishing zero (SeqCst)
            // so a concurrent `set_keep_idle(false)` or eviction cannot miss.
            #[cfg(test)]
            self.run_before_remove_hook_for_test();
            if let Some(pool) = self.pool.upgrade() {
                pool.remove_carrier(self.carrier_id);
            }
            self.begin_graceful_close();
        }
    }

    fn allocate_session_id(&self) -> io::Result<u16> {
        let sessions = self.sessions.read();
        for _ in 0..=u16::MAX as u32 {
            let id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
            if id != 0 && !sessions.contains_key(&id) {
                return Ok(id);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "no free XUDP session id on carrier",
        ))
    }

    pub fn open_child(
        self: &Arc<Self>,
        target: SocksAddr,
    ) -> io::Result<XudpChildDatagram> {
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "XUDP carrier is closed",
            ));
        }

        let mut closing = false;
        self.active_streams
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |active| {
                if (active & XUDP_CLOSING_BIT) != 0 {
                    closing = true;
                    return None;
                }
                if active < self.max_streams {
                    Some(active + 1)
                } else {
                    None
                }
            })
            .map_err(|_| {
                if closing {
                    io::Error::new(
                        io::ErrorKind::NotConnected,
                        "XUDP carrier is closing",
                    )
                } else {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "XUDP carrier stream limit reached",
                    )
                }
            })?;
        let lease = XudpStreamLease { carrier: self.clone() };

        let session_id = self.allocate_session_id()?;
        let (tx, rx) = mpsc::channel(UDP_BUFFER_CAPACITY);

        {
            let mut sessions = self.sessions.write();
            if self.is_closed() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "XUDP carrier is closed",
                ));
            }
            sessions.insert(session_id, ChildSession { tx, peer: target });
        }

        Ok(XudpChildDatagram {
            session_id,
            carrier: self.clone(),
            lease: Some(lease),
            writer_tx: PollSender::new(self.writer_tx.clone()),
            rx,
            first_packet: true,
            ended: false,
            pending_frame: None,
        })
    }

    fn remove_child(&self, session_id: u16) {
        self.sessions.write().remove(&session_id);
    }
}

pub struct XudpChildDatagram {
    session_id: u16,
    carrier: Arc<XudpCarrier>,
    lease: Option<XudpStreamLease>,
    writer_tx: PollSender<Bytes>,
    rx: mpsc::Receiver<UdpPacket>,
    first_packet: bool,
    ended: bool,
    pending_frame: Option<Bytes>,
}

impl Stream for XudpChildDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl Sink<UdpPacket> for XudpChildDatagram {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.ended {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XUDP session is already closed",
            )));
        }
        if self.pending_frame.is_some() {
            match self.as_mut().poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.carrier.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XUDP carrier connection closed",
            )));
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        if self.ended {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XUDP session is already closed",
            ));
        }
        let frame = XudpFrame::encode_data_frame(
            self.session_id,
            self.first_packet,
            Some(&item.dst_addr),
            &item.data,
        )?;
        self.first_packet = false;
        self.pending_frame = Some(frame);
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.pending_frame.is_none() {
            return Poll::Ready(Ok(()));
        }

        match self.writer_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let frame = self.pending_frame.take().unwrap();
                match self.writer_tx.send_item(frame) {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(_) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "XUDP carrier writer closed",
                    ))),
                }
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XUDP carrier writer closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if let Err(err) = ready!(self.as_mut().poll_flush(cx)) {
            self.lease.take();
            return Poll::Ready(Err(err));
        }

        if !self.ended {
            let end_frame = XudpFrame::encode_end_frame(self.session_id);
            self.pending_frame = Some(end_frame);
            self.ended = true;
            self.carrier.remove_child(self.session_id);
        }

        if let Err(err) = ready!(self.as_mut().poll_flush(cx)) {
            self.lease.take();
            return Poll::Ready(Err(err));
        }

        self.lease.take();
        Poll::Ready(Ok(()))
    }
}

impl Drop for XudpChildDatagram {
    fn drop(&mut self) {
        let (pending_data, end_frame) = if !self.ended {
            self.ended = true;
            self.carrier.remove_child(self.session_id);
            (
                self.pending_frame.take(),
                Some(XudpFrame::encode_end_frame(self.session_id)),
            )
        } else {
            (None, self.pending_frame.take())
        };
        let lease = self.lease.take();

        let frames_to_send: Vec<Bytes> = pending_data.into_iter().chain(end_frame).collect();
        if frames_to_send.is_empty() {
            drop(lease);
            return;
        }

        if let Some(tx) = self.writer_tx.get_ref().cloned() {
            let mut it = frames_to_send.into_iter();
            let mut remaining = Vec::new();
            while let Some(frame) = it.next() {
                match tx.try_send(frame) {
                    Ok(()) => {}
                    Err(TrySendError::Full(f)) => {
                        remaining.push(f);
                        remaining.extend(it);
                        break;
                    }
                    Err(TrySendError::Closed(_)) => {
                        drop(lease);
                        return;
                    }
                }
            }
            if !remaining.is_empty() {
                let drain_timeout = self.carrier.drain_timeout();
                let runtime = self.carrier.runtime.clone();
                let handle = Handle::try_current().unwrap_or(runtime);
                handle.spawn(async move {
                    let _lease = lease;
                    let _ = timeout(drain_timeout, async move {
                        for frame in remaining {
                            if tx.send(frame).await.is_err() {
                                break;
                            }
                        }
                    })
                    .await;
                });
            } else {
                drop(lease);
            }
        } else {
            drop(lease);
        }
    }
}

struct XudpPoolInner {
    carriers: Mutex<Vec<Arc<XudpCarrier>>>,
    max_carriers: usize,
    max_streams_per_carrier: usize,
    next_carrier_id: AtomicU64,
    dialing_carriers: AtomicUsize,
    dial_notify: Arc<Notify>,
    keep_idle: Arc<AtomicBool>,
    cleanup_running: AtomicBool,
    idle_timeout_ms: AtomicU64,
    cleanup_interval_ms: AtomicU64,
    #[cfg(test)]
    after_scan_gate: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
}

enum AcquireAction {
    Reuse(Arc<XudpCarrier>),
    Dial,
    Wait,
    Full,
}

impl XudpPoolInner {
    fn remove_carrier(&self, carrier_id: u64) {
        let mut carriers = self.carriers.lock();
        carriers.retain(|c| c.carrier_id != carrier_id && !c.is_closed());
    }

    fn collect_prunable_carriers_locked(
        &self,
        carriers: &mut Vec<Arc<XudpCarrier>>,
    ) -> Vec<Arc<XudpCarrier>> {
        let keep_idle = self.keep_idle.load(Ordering::SeqCst);
        let mut to_close = Vec::new();
        let mut i = 0;
        while i < carriers.len() {
            let c = &carriers[i];
            if c.is_closed() {
                carriers.swap_remove(i);
            } else if (!keep_idle || c.is_idle_expired()) && c.try_claim_idle_close() {
                to_close.push(carriers.swap_remove(i));
            } else {
                i += 1;
            }
        }
        to_close
    }

    fn prune_carriers(&self) {
        let to_close = {
            let mut carriers = self.carriers.lock();
            self.collect_prunable_carriers_locked(&mut carriers)
        };
        for carrier in to_close {
            carrier.begin_graceful_close();
        }
    }

    fn publish_carrier(&self, carrier: Arc<XudpCarrier>) {
        let to_close = {
            let mut carriers = self.carriers.lock();
            let to_close = self.collect_prunable_carriers_locked(&mut carriers);
            carriers.push(carrier);
            to_close
        };
        for old in to_close {
            old.begin_graceful_close();
        }
    }

    fn close_idle_connections(&self) {
        let mut to_close = Vec::new();
        {
            let mut carriers = self.carriers.lock();
            let mut i = 0;
            while i < carriers.len() {
                let c = &carriers[i];
                if c.is_closed() {
                    carriers.swap_remove(i);
                } else if c.try_claim_idle_close() {
                    to_close.push(carriers.swap_remove(i));
                } else {
                    i += 1;
                }
            }
        }
        for carrier in to_close {
            carrier.begin_graceful_close();
        }
    }
}

impl Drop for XudpPoolInner {
    fn drop(&mut self) {
        self.keep_idle.store(false, Ordering::SeqCst);
        let carriers = std::mem::take(self.carriers.get_mut());
        for carrier in carriers {
            if carrier.try_claim_idle_close() {
                carrier.begin_graceful_close();
            }
        }
    }
}

pub struct XudpPool {
    inner: Arc<XudpPoolInner>,
}

impl Drop for XudpPool {
    fn drop(&mut self) {
        self.inner.keep_idle.store(false, Ordering::SeqCst);
        self.inner.close_idle_connections();
    }
}

struct DialGuard<'a> {
    pool: &'a XudpPoolInner,
}

impl<'a> Drop for DialGuard<'a> {
    fn drop(&mut self) {
        self.pool.dialing_carriers.fetch_sub(1, Ordering::SeqCst);
        self.pool.dial_notify.notify_waiters();
    }
}

impl XudpPool {
    pub fn new(max_carriers: usize, max_streams_per_carrier: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(XudpPoolInner {
                carriers: Mutex::new(Vec::new()),
                max_carriers: if max_carriers == 0 {
                    DEFAULT_MAX_CARRIERS
                } else {
                    max_carriers
                },
                max_streams_per_carrier: if max_streams_per_carrier == 0 {
                    DEFAULT_MAX_STREAMS_PER_CARRIER
                } else {
                    max_streams_per_carrier
                },
                next_carrier_id: AtomicU64::new(1),
                dialing_carriers: AtomicUsize::new(0),
                dial_notify: Arc::new(Notify::new()),
                keep_idle: Arc::new(AtomicBool::new(true)),
                cleanup_running: AtomicBool::new(false),
                idle_timeout_ms: AtomicU64::new(IDLE_CARRIER_TIMEOUT_MS),
                cleanup_interval_ms: AtomicU64::new(IDLE_CLEANUP_INTERVAL_MS),
                #[cfg(test)]
                after_scan_gate: Mutex::new(None),
            }),
        })
    }

    pub fn set_keep_idle(&self, keep: bool) {
        self.inner.keep_idle.store(keep, Ordering::SeqCst);
        if !keep {
            self.close_idle_connections();
        }
    }

    pub fn close_idle_connections(&self) {
        self.inner.close_idle_connections();
    }

    #[cfg(test)]
    fn carrier_count_for_test(&self) -> usize {
        self.inner.carriers.lock().len()
    }

    #[cfg(test)]
    fn carriers_for_test(&self) -> Vec<Arc<XudpCarrier>> {
        self.inner.carriers.lock().clone()
    }

    #[cfg(test)]
    fn set_idle_policy_for_test(&self, idle_timeout: Duration, check_interval: Duration) {
        self.inner
            .idle_timeout_ms
            .store(idle_timeout.as_millis().max(1) as u64, Ordering::Relaxed);
        self.inner
            .cleanup_interval_ms
            .store(check_interval.as_millis().max(1) as u64, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn set_after_scan_gate_for_test(
        &self,
        entered_tx: oneshot::Sender<()>,
        resume_rx: oneshot::Receiver<()>,
    ) {
        *self.inner.after_scan_gate.lock() = Some((entered_tx, resume_rx));
    }

    fn ensure_cleanup_task(&self) {
        if self
            .inner
            .cleanup_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let inner_weak = Arc::downgrade(&self.inner);
        let check_interval = Duration::from_millis(
            self.inner.cleanup_interval_ms.load(Ordering::Relaxed),
        );
        tokio::spawn(async move {
            let mut ticker = interval(check_interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(inner) = inner_weak.upgrade() else {
                    break;
                };
                inner.prune_carriers();
                let carriers = inner.carriers.lock();
                if carriers.is_empty() && inner.dialing_carriers.load(Ordering::SeqCst) == 0 {
                    inner.cleanup_running.store(false, Ordering::Release);
                    drop(carriers);
                    break;
                }
            }
        });
    }

    pub async fn open_stream<F, Fut>(
        &self,
        destination: &SocksAddr,
        dial_carrier: F,
    ) -> io::Result<XudpChildDatagram>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: Future<Output = io::Result<AnyStream>> + Send,
    {
        loop {
            let notified = self.inner.dial_notify.notified();

            let (action, to_close) = {
                let mut carriers = self.inner.carriers.lock();
                let keep_idle = self.inner.keep_idle.load(Ordering::SeqCst);
                let mut to_close = Vec::new();
                let mut best: Option<Arc<XudpCarrier>> = None;
                let mut min_active = usize::MAX;
                let mut live_carriers = 0usize;

                // Prune closed/expired carriers, pick the least-loaded live
                // carrier, and decide reuse/dial/wait/full under a single lock pass
                // so neither a closing carrier nor a dial that finishes right after
                // unlocking can trigger a false full error.
                let mut i = 0;
                while i < carriers.len() {
                    let c = &carriers[i];
                    let raw = c.active_streams.load(Ordering::SeqCst);
                    if (raw & XUDP_CLOSING_BIT) != 0 {
                        carriers.swap_remove(i);
                        continue;
                    }
                    let active = raw;
                    if active == 0 && (!keep_idle || c.is_idle_expired()) {
                        if c.try_claim_idle_close() {
                            to_close.push(carriers.swap_remove(i));
                        }
                        // Re-check index `i` whether swapped or concurrently mutated.
                        continue;
                    }
                    live_carriers += 1;
                    if active < c.max_streams && active < min_active {
                        min_active = active;
                        best = Some(c.clone());
                    }
                    i += 1;
                }

                let action = if let Some(carrier) = best {
                    AcquireAction::Reuse(carrier)
                } else {
                    let dialing = self.inner.dialing_carriers.load(Ordering::SeqCst);
                    if live_carriers + dialing < self.inner.max_carriers {
                        self.inner.dialing_carriers.fetch_add(1, Ordering::SeqCst);
                        AcquireAction::Dial
                    } else if dialing > 0 {
                        AcquireAction::Wait
                    } else {
                        AcquireAction::Full
                    }
                };
                (action, to_close)
            };
            for carrier in to_close {
                carrier.begin_graceful_close();
            }

            #[cfg(test)]
            {
                let gate = self.inner.after_scan_gate.lock().take();
                if let Some((entered_tx, resume_rx)) = gate {
                    let _ = entered_tx.send(());
                    let _ = resume_rx.await;
                }
            }

            match action {
                AcquireAction::Reuse(carrier) => match carrier.open_child(destination.clone()) {
                    Ok(datagram) => return Ok(datagram),
                    Err(e) => {
                        debug!(
                            "failed to open child on XUDP carrier [{}]: {}, retrying",
                            carrier.carrier_id, e
                        );
                        continue;
                    }
                },
                AcquireAction::Dial => {
                    let _guard = DialGuard { pool: &self.inner };
                    debug!("dialing new carrier connection for XUDP pool");
                    let stream = dial_carrier().await?;
                    let cid = self.inner.next_carrier_id.fetch_add(1, Ordering::SeqCst);
                    let idle_timeout_ms = self.inner.idle_timeout_ms.load(Ordering::Relaxed);
                    let new_carrier = XudpCarrier::new_managed(
                        stream,
                        cid,
                        self.inner.max_streams_per_carrier,
                        self.inner.keep_idle.clone(),
                        Arc::downgrade(&self.inner),
                        idle_timeout_ms,
                    );
                    let datagram = match new_carrier.open_child(destination.clone()) {
                        Ok(datagram) => datagram,
                        Err(e) => {
                            new_carrier.begin_graceful_close();
                            return Err(e);
                        }
                    };

                    self.inner.publish_carrier(new_carrier.clone());
                    self.ensure_cleanup_task();

                    return Ok(datagram);
                }
                AcquireAction::Wait => {
                    notified.await;
                    continue;
                }
                AcquireAction::Full => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "XUDP carrier limit reached and all carriers are full",
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use std::collections::VecDeque;
    use tokio::{
        io::{AsyncRead, AsyncWrite, ReadBuf, duplex},
        task::yield_now,
        time::advance,
    };
    use tokio::time::{Duration, timeout};
    use crate::proxy::ProxyStream;

    struct FailedWriter(Arc<Notify>);

    impl ProxyStream for FailedWriter {}

    impl AsyncRead for FailedWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for FailedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        }

        fn poll_flush(
            self: Pin<&mut Self>, _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>, _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Drop for FailedWriter {
        fn drop(&mut self) {
            self.0.notify_one();
        }
    }

    #[tokio::test]
    async fn writer_failure_closes_children_and_releases_transport() {
        let dropped = Arc::new(Notify::new());
        let stream = AnyStream::Dynamic(Box::new(FailedWriter(dropped.clone())));
        let carrier = XudpCarrier::new(stream, 1, 8);
        let target: SocksAddr = "1.1.1.1:443".parse().unwrap();
        let mut child = carrier.open_child(target.clone()).unwrap();
        child.send(UdpPacket {
            data: Bytes::from_static(b"query"),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: target.clone(),
            inbound_user: None,
        }).await.unwrap();
        let packet = timeout(Duration::from_secs(1), child.next()).await.unwrap();
        assert!(packet.is_none());
        timeout(Duration::from_secs(1), dropped.notified()).await.unwrap();
        assert!(carrier.is_closed());
        assert!(carrier.open_child(target).is_err());
    }

    #[tokio::test]
    async fn reader_eof_cancels_waiting_writer() {
        let (client, mut server) = duplex(1024);
        let carrier = XudpCarrier::new(AnyStream::new(client), 1, 8);
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();
        let mut child = carrier.open_child(target).unwrap();
        server.shutdown().await.unwrap();
        let packet = timeout(Duration::from_secs(1), child.next()).await.unwrap();
        assert!(packet.is_none());
        let mut buf = [0; 1];
        let read = timeout(Duration::from_secs(1), server.read(&mut buf))
            .await.unwrap().unwrap();
        assert_eq!(read, 0);
        assert!(carrier.is_closed());
    }

    #[tokio::test]
    async fn test_xudp_pool_multiplexing_and_graceful_end() {
        let (client_stream, mut server_stream) = duplex(64 * 1024);
        let pool = XudpPool::new(2, 64);

        let target1: SocksAddr = "1.1.1.1:53".parse().unwrap();
        let target2: SocksAddr = "8.8.8.8:53".parse().unwrap();

        let client_holder =
            Arc::new(tokio::sync::Mutex::new(Some(AnyStream::new(client_stream))));
        let client_holder_clone = client_holder.clone();

        // 1. Open child 1
        let mut dgram1 = pool
            .open_stream(&target1, move || {
                let holder = client_holder_clone.clone();
                async move {
                    let mut guard = holder.lock().await;
                    guard.take().ok_or_else(|| io::Error::new(io::ErrorKind::Other, "stream already used"))
                }
            })
            .await
            .expect("open child 1");

        // 2. Open child 2 (should reuse the carrier)
        let mut dgram2 = pool
            .open_stream(&target2, || async { panic!("should not dial new carrier") })
            .await
            .expect("open child 2");

        // 3. Child 1 sends a packet
        let pkt1 = UdpPacket {
            data: Bytes::from_static(b"dns query 1"),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: target1.clone(),
            inbound_user: None,
        };
        dgram1.send(pkt1).await.expect("send pkt1");

        // Server reads frame 1
        let mut s_buf = BytesMut::with_capacity(4096);
        let mut frame1 = None;
        while frame1.is_none() {
            server_stream.read_buf(&mut s_buf).await.expect("read");
            frame1 = decode_xudp_frame_from_buf(&mut s_buf).expect("decode");
        }
        let frame1 = frame1.unwrap();
        assert_eq!(frame1.status, SessionStatus::New);
        assert_eq!(frame1.payload.unwrap().as_ref(), b"dns query 1");
        let session_id_1 = frame1.session_id;

        // 4. Child 2 sends a packet
        let pkt2 = UdpPacket {
            data: Bytes::from_static(b"dns query 2"),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: target2.clone(),
            inbound_user: None,
        };
        dgram2.send(pkt2).await.expect("send pkt2");

        // Server reads frame 2
        let mut frame2 = None;
        while frame2.is_none() {
            server_stream.read_buf(&mut s_buf).await.expect("read");
            frame2 = decode_xudp_frame_from_buf(&mut s_buf).expect("decode");
        }
        let frame2 = frame2.unwrap();
        assert_eq!(frame2.status, SessionStatus::New);
        assert_eq!(frame2.payload.unwrap().as_ref(), b"dns query 2");
        let session_id_2 = frame2.session_id;
        assert_ne!(session_id_1, session_id_2, "sessions must have different IDs");

        // 5. Server replies to child 1
        let reply1 = XudpFrame::encode_data_frame(
            session_id_1,
            false,
            None,
            b"dns response 1",
        ).unwrap();
        server_stream.write_all(&reply1).await.unwrap();

        let resp_pkt1 = dgram1.next().await.expect("dgram1 recv reply");
        assert_eq!(resp_pkt1.data.as_ref(), b"dns response 1");

        // 6. Drop child 1 -> Server should receive END frame for session 1
        drop(dgram1);
        let mut end_frame = None;
        while end_frame.is_none() {
            server_stream.read_buf(&mut s_buf).await.expect("read");
            end_frame = decode_xudp_frame_from_buf(&mut s_buf).expect("decode");
        }
        let end_frame = end_frame.unwrap();
        assert_eq!(end_frame.session_id, session_id_1);
        assert_eq!(end_frame.status, SessionStatus::End);

        // 7. Child 2 should still be able to communicate
        let reply2 = XudpFrame::encode_data_frame(
            session_id_2,
            false,
            None,
            b"dns response 2",
        ).unwrap();
        server_stream.write_all(&reply2).await.unwrap();

        let resp_pkt2 = dgram2.next().await.expect("dgram2 recv reply");
        assert_eq!(resp_pkt2.data.as_ref(), b"dns response 2");
    }

    #[tokio::test]
    async fn test_xudp_pool_carrier_limit_enforced() {
        let (client_stream, _server_stream) = duplex(64 * 1024);
        // max 1 carrier, 1 stream per carrier
        let pool = XudpPool::new(1, 1);

        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();
        let client_holder =
            Arc::new(tokio::sync::Mutex::new(Some(AnyStream::new(client_stream))));

        // 1. Open child 1 (takes the only slot on the only carrier)
        let _dgram1 = pool
            .open_stream(&target, {
                let holder = client_holder.clone();
                move || {
                    let holder = holder.clone();
                    async move {
                        let mut guard = holder.lock().await;
                        guard.take().ok_or_else(|| io::Error::new(io::ErrorKind::Other, "already dialed"))
                    }
                }
            })
            .await
            .expect("open child 1");

        // 2. Open child 2: carrier is full and max_carriers is reached.
        // It must fail without dialing a new carrier.
        let result = pool
            .open_stream(&target, || async {
                panic!("should not attempt to dial new carrier when limit reached");
            })
            .await;

        assert!(result.is_err(), "should return error when carrier limit reached and carriers are full");
    }

    #[tokio::test]
    async fn test_xudp_concurrent_dial_limit() {
        // max 1 carrier, 4 streams per carrier
        let pool = XudpPool::new(1, 4);
        let dial_count = Arc::new(AtomicUsize::new(0));
        let servers_holder = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();

        let mut handles = Vec::new();
        for _ in 0..10 {
            let pool = pool.clone();
            let dial_count = dial_count.clone();
            let servers = servers_holder.clone();
            let target = target.clone();
            handles.push(tokio::spawn(async move {
                pool.open_stream(&target, move || {
                    let dial_count = dial_count.clone();
                    let servers = servers.clone();
                    async move {
                        dial_count.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        let (client, server) = duplex(64 * 1024);
                        servers.lock().await.push(server);
                        Ok(AnyStream::new(client))
                    }
                })
                .await
            }));
        }

        let mut successes = 0;
        let mut dgrams = Vec::new();
        for h in handles {
            if let Ok(Ok(dgram)) = h.await {
                successes += 1;
                dgrams.push(dgram);
            }
        }

        // Must NEVER dial more than max_carriers (1)
        assert_eq!(
            dial_count.load(Ordering::SeqCst),
            1,
            "must not dial more than max_carriers times concurrently"
        );
        // Successes should be at most 4 (max_streams_per_carrier)
        assert!(successes <= 4, "successes must not exceed max streams");
        assert!(successes >= 1, "at least one stream must succeed");
    }

    #[tokio::test]
    async fn test_xudp_carrier_stream_limit_race() {
        let (client, _server) = duplex(64 * 1024);
        // max 2 streams
        let carrier = XudpCarrier::new(AnyStream::new(client), 1, 2);
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();

        let mut handles = Vec::new();
        for _ in 0..10 {
            let carrier = carrier.clone();
            let target = target.clone();
            handles.push(tokio::spawn(async move {
                carrier.open_child(target)
            }));
        }

        let mut success_count = 0;
        let mut err_count = 0;
        let mut dgrams = Vec::new();
        for h in handles {
            match h.await.unwrap() {
                Ok(dgram) => {
                    success_count += 1;
                    dgrams.push(dgram);
                }
                Err(_) => err_count += 1,
            }
        }

        assert_eq!(success_count, 2, "exactly max_streams children must succeed");
        assert_eq!(err_count, 8, "remaining children must fail due to limit");
        assert_eq!(carrier.active_streams(), 2, "active streams must not exceed max_streams");
    }

    #[tokio::test(start_paused = true)]
    async fn test_xudp_wait_carrier_dial_does_not_timeout_prematurely() {
        let pool = Arc::new(XudpPool::new(1, 4));
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();

        let servers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let servers_clone = servers.clone();

        // Task 1 dials slowly (takes 2 seconds)
        let pool_1 = pool.clone();
        let target_1 = target.clone();
        let h1 = tokio::spawn(async move {
            pool_1
                .open_stream(&target_1, || {
                    let servers_clone = servers_clone.clone();
                    async move {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        let (client, server) = duplex(64 * 1024);
                        servers_clone.lock().unwrap().push(server);
                        Ok(AnyStream::new(client))
                    }
                })
                .await
        });

        // Yield to allow Task 1 to start dialing and register dialing_carriers
        tokio::task::yield_now().await;

        // Task 2 concurrently tries to open stream, must wait for Task 1's dial without failing prematurely
        let pool_2 = pool.clone();
        let target_2 = target.clone();
        let h2 = tokio::spawn(async move {
            pool_2
                .open_stream(&target_2, || async {
                    panic!("task 2 should not dial since max_carriers is 1");
                })
                .await
        });

        let (res1, res2) = tokio::join!(h1, h2);
        assert!(res1.unwrap().is_ok());
        assert!(res2.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_xudp_poll_close_and_drop_send_end_frame_under_pressure() {
        let (client_stream, mut server_stream) = duplex(64 * 1024);
        let carrier = XudpCarrier::new(AnyStream::new(client_stream), 1, 10);
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();

        // 1. Test poll_close sends End frame
        let mut dgram1 = carrier.open_child(target.clone()).unwrap();
        let sid1 = dgram1.session_id;
        // Close explicitly
        dgram1.close().await.unwrap();

        // Server should receive End frame for sid1
        let mut buf = vec![0u8; 1024];
        let n = server_stream.read(&mut buf).await.unwrap();
        let frame = decode_xudp_frame_from_buf(&mut BytesMut::from(&buf[..n])).unwrap().unwrap();
        assert_eq!(frame.session_id, sid1);
        assert_eq!(frame.status, SessionStatus::End);

        // 2. Test Drop sends End frame even if writer queue was temporarily full
        let dgram2 = carrier.open_child(target.clone()).unwrap();
        let sid2 = dgram2.session_id;

        // Fill writer_tx capacity (WRITER_QUEUE_CAPACITY is 256)
        let tx = carrier.writer_tx.clone();
        let dummy_frame = XudpFrame::encode_end_frame(999);
        while tx.try_send(dummy_frame.clone()).is_ok() {}

        // Dropping dgram2 while channel is full: must spawn background send and eventually deliver
        drop(dgram2);

        // Drain the server stream to make room in the queue and verify sid2 End frame is received
        let mut received_sid2_end = false;
        let mut read_buf = BytesMut::new();
        let mut temp = [0u8; 4096];

        let start = tokio::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(2) {
            if let Ok(Ok(n)) = tokio::time::timeout(std::time::Duration::from_millis(100), server_stream.read(&mut temp)).await {
                if n > 0 {
                    read_buf.extend_from_slice(&temp[..n]);
                    while let Ok(Some(f)) = decode_xudp_frame_from_buf(&mut read_buf) {
                        if f.session_id == sid2 && f.status == SessionStatus::End {
                            received_sid2_end = true;
                            break;
                        }
                    }
                    if received_sid2_end {
                        break;
                    }
                }
            }
        }

        assert!(received_sid2_end, "End frame for sid2 must be delivered even when dropped under queue pressure");
    }

    #[tokio::test]
    async fn test_xudp_drop_with_pending_data_sends_both_data_and_end_frame() {
        let (client_stream, mut server_stream) = duplex(64 * 1024);
        let carrier = XudpCarrier::new(AnyStream::new(client_stream), 1, 10);
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();

        let mut dgram = carrier.open_child(target.clone()).unwrap();
        let sid = dgram.session_id;

        // Queue a packet via start_send without flushing
        let pkt = UdpPacket {
            data: Bytes::from_static(b"hello-before-drop"),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: target.clone(),
            inbound_user: None,
        };
        Pin::new(&mut dgram).start_send(pkt).unwrap();

        // Dropping dgram must send both the pending data frame AND the End frame
        drop(dgram);

        // Read frames on server side
        let mut read_buf = BytesMut::new();
        let mut temp = [0u8; 1024];

        let mut received_data = false;
        let mut received_end = false;

        let start = tokio::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(2) {
            if let Ok(Ok(n)) = tokio::time::timeout(std::time::Duration::from_millis(100), server_stream.read(&mut temp)).await {
                if n > 0 {
                    read_buf.extend_from_slice(&temp[..n]);
                    while let Ok(Some(f)) = decode_xudp_frame_from_buf(&mut read_buf) {
                        if f.session_id == sid {
                            if matches!(f.status, SessionStatus::New | SessionStatus::Keep) && f.payload.as_deref() == Some(&b"hello-before-drop"[..]) {
                                received_data = true;
                            } else if f.status == SessionStatus::End {
                                received_end = true;
                            }
                        }
                    }
                    if received_data && received_end {
                        break;
                    }
                }
            }
        }

        assert!(received_data, "pending data frame must be delivered on drop");
        assert!(received_end, "End frame must be delivered on drop");
    }

    #[tokio::test]
    async fn test_xudp_send_after_close_rejected() {
        let (client_stream, _server_stream) = duplex(64 * 1024);
        let carrier = XudpCarrier::new(AnyStream::new(client_stream), 1, 10);
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();

        let mut dgram = carrier.open_child(target.clone()).unwrap();
        dgram.close().await.unwrap();

        // After close, start_send and poll_ready must return BrokenPipe
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut dgram).poll_ready(&mut cx).is_ready());
        match Pin::new(&mut dgram).poll_ready(&mut cx) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
            other => panic!("expected BrokenPipe, got {:?}", other),
        }

        let pkt = UdpPacket {
            data: Bytes::from_static(b"fail"),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: target,
            inbound_user: None,
        };
        let send_res = Pin::new(&mut dgram).start_send(pkt);
        assert!(send_res.is_err());
        assert_eq!(send_res.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    struct NotifyDropStream {
        inner: tokio::io::DuplexStream,
        dropped: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl ProxyStream for NotifyDropStream {}

    impl tokio::io::AsyncRead for NotifyDropStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for NotifyDropStream {
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

    impl Drop for NotifyDropStream {
        fn drop(&mut self) {
            if let Some(tx) = self.dropped.take() {
                let _ = tx.send(());
            }
        }
    }

    struct StalledWriter(Option<tokio::sync::oneshot::Sender<()>>);

    impl ProxyStream for StalledWriter {}

    impl AsyncRead for StalledWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for StalledWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl Drop for StalledWriter {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }

    #[tokio::test]
    async fn test_xudp_keep_idle_false_health_check_and_ordered_drain_on_drop() {
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();
        let pool = XudpPool::new(2, 16);

        // 1. Health check only (keep_idle = false): drains & closes carrier on drop.
        pool.set_keep_idle(false);
        let (client1, mut server1) = duplex(64 * 1024);
        let (drop_tx1, drop_rx1) = tokio::sync::oneshot::channel();
        let stream1 = Arc::new(Mutex::new(Some(AnyStream::Dynamic(Box::new(
            NotifyDropStream { inner: client1, dropped: Some(drop_tx1) },
        )))));
        let mut probe = pool
            .open_stream(&target, || {
                let stream1 = stream1.clone();
                async move { Ok(stream1.lock().take().unwrap()) }
            })
            .await
            .unwrap();
        assert_eq!(pool.carrier_count_for_test(), 1);
        probe.send(UdpPacket {
            data: Bytes::from_static(b"probe"),
            dst_addr: target.clone(),
            ..Default::default()
        }).await.unwrap();
        drop(probe);

        let mut buf = BytesMut::new();
        let mut got = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = timeout(Duration::from_secs(2), server1.read(&mut tmp))
                .await
                .unwrap()
                .unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            while let Some(frame) = decode_xudp_frame_from_buf(&mut buf).unwrap() {
                got.push((frame.status, frame.payload));
            }
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, SessionStatus::New);
        assert_eq!(got[0].1.as_deref(), Some(&b"probe"[..]));
        assert_eq!(got[1].0, SessionStatus::End);
        timeout(Duration::from_secs(2), drop_rx1).await.unwrap().unwrap();

        // 2. Active session with pending data + channel pressure: switching away
        // keeps session alive until last child drops, then flushes data & End in order.
        pool.set_keep_idle(true);
        let (client2, mut server2) = duplex(64 * 1024);
        let (drop_tx2, drop_rx2) = tokio::sync::oneshot::channel();
        let stream2 = Arc::new(Mutex::new(Some(AnyStream::Dynamic(Box::new(
            NotifyDropStream { inner: client2, dropped: Some(drop_tx2) },
        )))));
        let mut child = pool
            .open_stream(&target, || {
                let stream2 = stream2.clone();
                async move { Ok(stream2.lock().take().unwrap()) }
            })
            .await
            .unwrap();
        assert_eq!(pool.carrier_count_for_test(), 1);
        let sid = child.session_id;

        pool.set_keep_idle(false);
        assert_eq!(pool.carrier_count_for_test(), 1);
        Pin::new(&mut child).start_send(UdpPacket {
            data: Bytes::from_static(b"last-word"),
            dst_addr: target.clone(),
            ..Default::default()
        }).unwrap();
        drop(child);

        let mut buf2 = BytesMut::new();
        let mut got2 = Vec::new();
        loop {
            let n = timeout(Duration::from_secs(2), server2.read(&mut tmp))
                .await
                .unwrap()
                .unwrap();
            if n == 0 {
                break;
            }
            buf2.extend_from_slice(&tmp[..n]);
            while let Some(frame) = decode_xudp_frame_from_buf(&mut buf2).unwrap() {
                if frame.session_id == sid {
                    got2.push((frame.status, frame.payload));
                }
            }
        }
        assert_eq!(got2.len(), 2);
        assert_eq!(got2[0].0, SessionStatus::New);
        assert_eq!(got2[0].1.as_deref(), Some(&b"last-word"[..]));
        assert_eq!(got2[1].0, SessionStatus::End);
        timeout(Duration::from_secs(2), drop_rx2).await.unwrap().unwrap();
        assert_eq!(pool.carrier_count_for_test(), 0);
    }

    #[tokio::test]
    async fn test_xudp_idle_eviction_reselect_concurrent_dial_and_bounded_drain() {
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();
        let pool = XudpPool::new(2, 16);

        // 1. Idle carrier evicted immediately on set_keep_idle(false) and rebuilt on reselect.
        let (client1, mut server1) = duplex(64 * 1024);
        let (drop_tx1, drop_rx1) = tokio::sync::oneshot::channel();
        let stream1 = Arc::new(Mutex::new(Some(AnyStream::Dynamic(Box::new(
            NotifyDropStream { inner: client1, dropped: Some(drop_tx1) },
        )))));
        let c1 = pool
            .open_stream(&target, || {
                let stream1 = stream1.clone();
                async move { Ok(stream1.lock().take().unwrap()) }
            })
            .await
            .unwrap();
        drop(c1);
        assert_eq!(pool.carrier_count_for_test(), 1);
        pool.set_keep_idle(false);
        assert_eq!(pool.carrier_count_for_test(), 0);
        let mut tmp = [0u8; 64];
        while timeout(Duration::from_secs(2), server1.read(&mut tmp)).await.unwrap().unwrap() > 0 {}
        timeout(Duration::from_secs(2), drop_rx1).await.unwrap().unwrap();

        // 2. Concurrent dial while keep_idle flips to false: must not retain carrier.
        pool.set_keep_idle(true);
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (client2, mut server2) = duplex(64 * 1024);
        let (drop_tx2, drop_rx2) = tokio::sync::oneshot::channel();
        let stream2 = Arc::new(Mutex::new(Some(AnyStream::Dynamic(Box::new(
            NotifyDropStream { inner: client2, dropped: Some(drop_tx2) },
        )))));
        let pool_dial = pool.clone();
        let target_dial = target.clone();
        let started_tx = started.clone();
        let release_rx = release.clone();
        let dial = tokio::spawn(async move {
            pool_dial
                .open_stream(&target_dial, || {
                    let started = started_tx.clone();
                    let release = release_rx.clone();
                    let stream2 = stream2.clone();
                    async move {
                        started.notify_one();
                        release.notified().await;
                        Ok(stream2.lock().take().unwrap())
                    }
                })
                .await
        });
        started.notified().await;
        pool.set_keep_idle(false);
        release.notify_one();
        let c2 = dial.await.unwrap().unwrap();
        assert_eq!(pool.carrier_count_for_test(), 1);
        drop(c2);
        while timeout(Duration::from_secs(2), server2.read(&mut tmp)).await.unwrap().unwrap() > 0 {}
        timeout(Duration::from_secs(2), drop_rx2).await.unwrap().unwrap();
        assert_eq!(pool.carrier_count_for_test(), 0);

        // 3. Stalled writer is bounded by drain_timeout and releases stream.
        pool.set_keep_idle(true);
        let (drop_tx3, drop_rx3) = tokio::sync::oneshot::channel();
        let stream3 = Arc::new(Mutex::new(Some(AnyStream::Dynamic(Box::new(
            StalledWriter(Some(drop_tx3)),
        )))));
        let mut c3 = pool
            .open_stream(&target, || {
                let stream3 = stream3.clone();
                async move { Ok(stream3.lock().take().unwrap()) }
            })
            .await
            .unwrap();
        pool.carriers_for_test()[0].set_drain_timeout_for_test(Duration::from_millis(50));
        c3.send(UdpPacket {
            data: Bytes::from_static(b"blocked"),
            dst_addr: target,
            ..Default::default()
        }).await.unwrap();
        pool.set_keep_idle(false);
        drop(c3);
        timeout(Duration::from_secs(2), drop_rx3)
            .await
            .expect("stalled XUDP carrier must close within drain timeout")
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn test_xudp_120s_idle_policy_actively_reclaims_when_selected() {
        let pool = XudpPool::new(2, 16);
        pool.set_idle_policy_for_test(
            Duration::from_secs(IDLE_CARRIER_TIMEOUT_MS / 1000),
            Duration::from_secs(10),
        );
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();
        let (client, mut server) = duplex(4096);
        let (drop_tx, drop_rx) = tokio::sync::oneshot::channel();
        let stream = Arc::new(Mutex::new(Some(AnyStream::Dynamic(Box::new(
            NotifyDropStream { inner: client, dropped: Some(drop_tx) },
        )))));
        let child = pool
            .open_stream(&target, || {
                let stream = stream.clone();
                async move { Ok(stream.lock().take().unwrap()) }
            })
            .await
            .unwrap();
        drop(child);
        assert_eq!(pool.carrier_count_for_test(), 1);

        // Before 120s, carrier remains kept alive.
        tokio::time::advance(Duration::from_secs(110)).await;
        tokio::task::yield_now().await;
        assert_eq!(pool.carrier_count_for_test(), 1);

        // Past 120s + cleanup interval tick, background cleanup closes idle carrier.
        tokio::time::advance(Duration::from_secs(25)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(pool.carrier_count_for_test(), 0);
        let mut tmp = [0u8; 64];
        while timeout(Duration::from_secs(1), server.read(&mut tmp)).await.unwrap().unwrap() > 0 {}
        timeout(Duration::from_secs(1), drop_rx).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_xudp_keep_idle_false_respects_carrier_and_stream_limits() {
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();
        let pool = XudpPool::new(1, 2);
        pool.set_keep_idle(false);

        let dial_count = Arc::new(AtomicUsize::new(0));
        let (client, mut server) = duplex(64 * 1024);
        let (drop_tx, drop_rx) = tokio::sync::oneshot::channel();
        let holder = Arc::new(Mutex::new(Some(AnyStream::Dynamic(Box::new(
            NotifyDropStream { inner: client, dropped: Some(drop_tx) },
        )))));

        let dial = || {
            let dial_count = dial_count.clone();
            let holder = holder.clone();
            async move {
                dial_count.fetch_add(1, Ordering::SeqCst);
                Ok(holder.lock().take().expect("must not dial past max_carriers"))
            }
        };

        let c1 = pool.open_stream(&target, dial).await.unwrap();
        let c2 = pool.open_stream(&target, dial).await.unwrap();
        assert_eq!(dial_count.load(Ordering::SeqCst), 1);
        assert_eq!(pool.carrier_count_for_test(), 1);

        // Third overlapping child must fail capacity check instead of bypassing max_carriers=1.
        assert!(pool.open_stream(&target, dial).await.is_err());
        assert_eq!(dial_count.load(Ordering::SeqCst), 1);

        drop(c1);
        tokio::task::yield_now().await;
        assert_eq!(pool.carrier_count_for_test(), 1);

        drop(c2);
        let mut tmp = [0u8; 64];
        while timeout(Duration::from_secs(2), server.read(&mut tmp)).await.unwrap().unwrap() > 0 {}
        timeout(Duration::from_secs(2), drop_rx).await.unwrap().unwrap();
        assert_eq!(pool.carrier_count_for_test(), 0);
    }

    #[tokio::test]
    async fn test_xudp_publish_new_carrier_gracefully_closes_expired_stalled_carrier() {
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();
        let pool = XudpPool::new(2, 1);
        // Short idle timeout with long cleanup interval so expiration is handled
        // specifically when publishing the newly dialed carrier.
        pool.set_idle_policy_for_test(
            Duration::from_millis(30),
            Duration::from_secs(60),
        );

        let (drop_tx1, drop_rx1) = tokio::sync::oneshot::channel();
        let stream1 = Arc::new(Mutex::new(Some(AnyStream::Dynamic(Box::new(
            StalledWriter(Some(drop_tx1)),
        )))));
        let mut c1 = pool
            .open_stream(&target, || {
                let stream1 = stream1.clone();
                async move { Ok(stream1.lock().take().unwrap()) }
            })
            .await
            .unwrap();
        let carrier1 = pool.carriers_for_test()[0].clone();
        carrier1.set_drain_timeout_for_test(Duration::from_millis(50));
        c1.send(UdpPacket {
            data: Bytes::from_static(b"stalled-last-batch"),
            dst_addr: target.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
        // Let writer_loop pick up the batch and block in `write_batch`.
        tokio::task::yield_now().await;

        // Start dialing a second carrier while carrier1 is full (max_streams=1).
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (client2, _server2) = duplex(4096);
        let stream2 = Arc::new(Mutex::new(Some(AnyStream::new(client2))));
        let dial_pool = pool.clone();
        let dial_target = target.clone();
        let started_tx = started.clone();
        let release_rx = release.clone();
        let dial_task = tokio::spawn(async move {
            dial_pool
                .open_stream(&dial_target, || {
                    let started = started_tx.clone();
                    let release = release_rx.clone();
                    let stream2 = stream2.clone();
                    async move {
                        started.notify_one();
                        release.notified().await;
                        Ok(stream2.lock().take().unwrap())
                    }
                })
                .await
        });
        started.notified().await;

        // While carrier2 is dialing, carrier1 becomes idle and exceeds idle_timeout
        // while its writer is still blocked in `write_batch`.
        drop(c1);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(carrier1.is_idle_expired());
        drop(carrier1);

        // Publishing carrier2 must put expired carrier1 through bounded graceful close.
        release.notify_one();
        let _c2 = dial_task.await.unwrap().unwrap();
        assert_eq!(pool.carrier_count_for_test(), 1);
        timeout(Duration::from_secs(2), drop_rx1)
            .await
            .expect("expired stalled carrier must enter bounded close when publishing new carrier")
            .unwrap();
    }

    #[tokio::test]
    async fn test_xudp_closing_carrier_not_yet_removed_does_not_reject_new_stream() {
        use std::{collections::VecDeque, sync::mpsc as std_mpsc, thread};
        use tokio::sync::oneshot;

        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();
        let pool = XudpPool::new(1, 2);
        pool.set_keep_idle(false);

        let dial_count = Arc::new(AtomicUsize::new(0));
        let (client1, mut server1) = duplex(64 * 1024);
        let (drop_tx1, drop_rx1) = oneshot::channel();
        let (client2, mut server2) = duplex(64 * 1024);
        let (drop_tx2, drop_rx2) = oneshot::channel();
        let streams = Arc::new(Mutex::new(VecDeque::from([
            AnyStream::Dynamic(Box::new(NotifyDropStream {
                inner: client1,
                dropped: Some(drop_tx1),
            })),
            AnyStream::Dynamic(Box::new(NotifyDropStream {
                inner: client2,
                dropped: Some(drop_tx2),
            })),
        ])));

        let dial = || {
            let dial_count = dial_count.clone();
            let streams = streams.clone();
            async move {
                dial_count.fetch_add(1, Ordering::SeqCst);
                Ok(streams
                    .lock()
                    .pop_front()
                    .expect("test stream available for dial"))
            }
        };

        let c1 = pool.open_stream(&target, dial).await.unwrap();
        assert_eq!(dial_count.load(Ordering::SeqCst), 1);
        assert_eq!(pool.carrier_count_for_test(), 1);

        // Pause `release_lease` after setting XUDP_CLOSING_BIT and before calling
        // `pool.remove_carrier`, freezing the exact race window.
        let (entered_tx, entered_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = std_mpsc::channel();
        let carrier1 = pool.carriers_for_test()[0].clone();
        carrier1.set_before_remove_hook_for_test(move || {
            let _ = entered_tx.send(());
            let _ = resume_rx.recv();
        });

        let drop_thread = thread::spawn(move || drop(c1));
        timeout(Duration::from_secs(2), entered_rx)
            .await
            .expect("release_lease must reach before-remove synchronization point")
            .unwrap();

        // Carrier1 is now marked CLOSING while still present in `pool.carriers`.
        assert!(carrier1.is_closing());
        assert_eq!(pool.carrier_count_for_test(), 1);

        // A new stream request with max_carriers=1 must NOT falsely fail as full;
        // it must evict the closing carrier and dial a replacement.
        let c2 = pool
            .open_stream(&target, dial)
            .await
            .expect("closing carrier still in pool must not block replacement dial");
        assert_eq!(dial_count.load(Ordering::SeqCst), 2);
        assert_eq!(pool.carrier_count_for_test(), 1);

        // Release the paused old lease drop and verify both carriers clean up.
        let _ = resume_tx.send(());
        drop_thread.join().unwrap();
        drop(carrier1);
        let mut tmp = [0u8; 64];
        while timeout(Duration::from_secs(2), server1.read(&mut tmp))
            .await
            .unwrap()
            .unwrap()
            > 0
        {}
        timeout(Duration::from_secs(2), drop_rx1).await.unwrap().unwrap();

        drop(c2);
        while timeout(Duration::from_secs(2), server2.read(&mut tmp))
            .await
            .unwrap()
            .unwrap()
            > 0
        {}
        timeout(Duration::from_secs(2), drop_rx2).await.unwrap().unwrap();
        assert_eq!(pool.carrier_count_for_test(), 0);
    }

    #[tokio::test]
    async fn test_xudp_concurrent_dial_finish_after_scan_does_not_falsely_report_full() {
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();
        let pool = XudpPool::new(1, 4);
        let dial_count = Arc::new(AtomicUsize::new(0));
        let dial_started = Arc::new(Notify::new());
        let dial_release = Arc::new(Notify::new());
        let servers = Arc::new(Mutex::new(Vec::new()));

        let pool1 = pool.clone();
        let target1 = target.clone();
        let dial_count1 = dial_count.clone();
        let dial_started1 = dial_started.clone();
        let dial_release1 = dial_release.clone();
        let servers1 = servers.clone();
        let task1 = tokio::spawn(async move {
            pool1
                .open_stream(&target1, || {
                    let dial_count = dial_count1.clone();
                    let dial_started = dial_started1.clone();
                    let dial_release = dial_release1.clone();
                    let servers = servers1.clone();
                    async move {
                        dial_count.fetch_add(1, Ordering::SeqCst);
                        dial_started.notify_one();
                        dial_release.notified().await;
                        let (client, server) = duplex(64 * 1024);
                        servers.lock().push(server);
                        Ok(AnyStream::new(client))
                    }
                })
                .await
        });

        dial_started.notified().await;

        // Pause task2 right after it releases the pool lock having observed
        // `dialing == 1`, before it acts on the decision.
        let (scan_done_tx, scan_done_rx) = oneshot::channel();
        let (resume_task2_tx, resume_task2_rx) = oneshot::channel();
        pool.set_after_scan_gate_for_test(scan_done_tx, resume_task2_rx);

        let pool2 = pool.clone();
        let target2 = target.clone();
        let task2 = tokio::spawn(async move {
            pool2
                .open_stream(&target2, || async {
                    panic!("task2 must reuse the carrier published by task1");
                })
                .await
        });

        timeout(Duration::from_secs(2), scan_done_rx)
            .await
            .expect("task2 must complete lock scan")
            .unwrap();

        // Let task1 finish dialing, publish the carrier with spare stream capacity,
        // decrement `dialing_carriers` to 0, and fire `dial_notify.notify_waiters()`.
        dial_release.notify_one();
        let c1 = timeout(Duration::from_secs(2), task1)
            .await
            .expect("task1 must finish dialing")
            .unwrap()
            .unwrap();

        // Now resume task2: it must neither falsely fail with pool-full nor miss
        // the wakeup, and must reuse the newly published carrier.
        let _ = resume_task2_tx.send(());
        let c2 = timeout(Duration::from_secs(2), task2)
            .await
            .expect("task2 must wake and reuse carrier instead of hanging")
            .unwrap()
            .expect("task2 must not falsely report pool full after dial finishes");

        assert_eq!(dial_count.load(Ordering::SeqCst), 1);
        assert_eq!(pool.carrier_count_for_test(), 1);
        drop((c1, c2));
    }

    enum WriteStep {
        Ready {
            on_write: Option<Box<dyn FnOnce() + Send + Sync>>,
        },
        Gated {
            entered: Option<oneshot::Sender<()>>,
            release: oneshot::Receiver<()>,
            on_write: Option<Box<dyn FnOnce() + Send + Sync>>,
            on_flush: Option<Box<dyn FnOnce() + Send + Sync>>,
        },
        Stall {
            entered: Option<oneshot::Sender<()>>,
        },
    }

    struct ScriptedDrainWriter {
        steps: VecDeque<WriteStep>,
        pending_flush_hook: Option<Box<dyn FnOnce() + Send + Sync>>,
        writes_completed: Arc<AtomicUsize>,
        dropped: Option<oneshot::Sender<()>>,
    }

    impl ProxyStream for ScriptedDrainWriter {}

    impl AsyncRead for ScriptedDrainWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for ScriptedDrainWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let Some(step) = self.steps.front_mut() else {
                return Poll::Pending;
            };
            match step {
                WriteStep::Ready { on_write } => {
                    if let Some(hook) = on_write.take() {
                        hook();
                    }
                    self.steps.pop_front();
                    self.writes_completed.fetch_add(1, Ordering::SeqCst);
                    Poll::Ready(Ok(buf.len()))
                }
                WriteStep::Gated { entered, release, on_write, on_flush } => {
                    if let Some(tx) = entered.take() {
                        let _ = tx.send(());
                    }
                    match Pin::new(release).poll(cx) {
                        Poll::Ready(_) => {
                            if let Some(hook) = on_write.take() {
                                hook();
                            }
                            self.pending_flush_hook = on_flush.take();
                            self.steps.pop_front();
                            self.writes_completed.fetch_add(1, Ordering::SeqCst);
                            Poll::Ready(Ok(buf.len()))
                        }
                        Poll::Pending => Poll::Pending,
                    }
                }
                WriteStep::Stall { entered } => {
                    if let Some(tx) = entered.take() {
                        let _ = tx.send(());
                    }
                    Poll::Pending
                }
            }
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(hook) = self.pending_flush_hook.take() {
                hook();
            }
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl Drop for ScriptedDrainWriter {
        fn drop(&mut self) {
            if let Some(tx) = self.dropped.take() {
                let _ = tx.send(());
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_xudp_drain_deadline_starts_on_signal_during_ready_backlog() {
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();
        let batch_frame = Bytes::from(vec![0u8; MAX_BATCH_BYTES]);

        // Case 1: drain arrives while the write select! is ready to resume.
        // The write select! must poll drain_rx before write_fut, capturing the
        // 100ms timeout before step 0 bumps drain_timeout_ms to 10s, and share
        // that single deadline across the remaining backlog and final stall.
        {
            let pool = XudpPool::new(1, 4);
            let (entered0_tx, entered0_rx) = oneshot::channel();
            let (gate0_tx, gate0_rx) = oneshot::channel();
            let (entered2_tx, entered2_rx) = oneshot::channel();
            let (gate2_tx, gate2_rx) = oneshot::channel();
            let (entered3_tx, entered3_rx) = oneshot::channel();
            let (drop_tx, mut drop_rx) = oneshot::channel();
            let writes_completed = Arc::new(AtomicUsize::new(0));
            let timeout_slot: Arc<Mutex<Option<Arc<AtomicU64>>>> = Arc::new(Mutex::new(None));
            let bump_timeout = timeout_slot.clone();

            let stream = Arc::new(Mutex::new(Some(AnyStream::Dynamic(Box::new(
                ScriptedDrainWriter {
                    steps: VecDeque::from([
                        WriteStep::Gated {
                            entered: Some(entered0_tx),
                            release: gate0_rx,
                            on_write: Some(Box::new(move || {
                                if let Some(ms) = bump_timeout.lock().as_ref() {
                                    ms.store(10_000, Ordering::Relaxed);
                                }
                            })),
                            on_flush: None,
                        },
                        WriteStep::Ready { on_write: None },
                        WriteStep::Gated {
                            entered: Some(entered2_tx),
                            release: gate2_rx,
                            on_write: None,
                            on_flush: None,
                        },
                        WriteStep::Stall { entered: Some(entered3_tx) },
                    ]),
                    pending_flush_hook: None,
                    writes_completed: writes_completed.clone(),
                    dropped: Some(drop_tx),
                },
            )))));

            let child = pool
                .open_stream(&target, || {
                    let stream = stream.clone();
                    async move { Ok(stream.lock().take().unwrap()) }
                })
                .await
                .unwrap();
            let carrier = pool.carriers_for_test()[0].clone();
            carrier.set_drain_timeout_for_test(Duration::from_millis(100));
            *timeout_slot.lock() = Some(carrier.drain_timeout_ms.clone());

            carrier.writer_tx.send(batch_frame.clone()).await.unwrap();
            entered0_rx.await.unwrap();

            for _ in 0..3 {
                carrier.writer_tx.try_send(batch_frame.clone()).unwrap();
            }
            drop(carrier);

            let t0 = Instant::now();
            pool.set_keep_idle(false);
            drop(child);
            let _ = gate0_tx.send(());

            entered2_rx.await.unwrap();
            assert_eq!(Instant::now(), t0);

            advance(Duration::from_millis(60)).await;
            yield_now().await;
            assert!(drop_rx.try_recv().is_err(), "carrier must not time out at 60ms");

            let _ = gate2_tx.send(());
            entered3_rx.await.unwrap();

            advance(Duration::from_millis(35)).await;
            yield_now().await;
            assert!(drop_rx.try_recv().is_err(), "carrier must still respect 100ms deadline at 95ms");

            advance(Duration::from_millis(10)).await;
            timeout(Duration::from_millis(1), &mut drop_rx)
                .await
                .expect("write-branch drain must expire at the original 100ms deadline")
                .unwrap();
            assert_eq!(writes_completed.load(Ordering::SeqCst), 3);
        }

        // Case 2: drain arrives during step 0 flush while a ready backlog is
        // already queued, so the next select! is the recv branch. The recv
        // select! must poll drain_rx before rx.recv(), locking the 100ms
        // deadline before step 1 bumps drain_timeout_ms to 10s.
        {
            let pool = XudpPool::new(1, 4);
            let (entered0_tx, entered0_rx) = oneshot::channel();
            let (gate0_tx, gate0_rx) = oneshot::channel();
            let (entered2_tx, entered2_rx) = oneshot::channel();
            let (gate2_tx, gate2_rx) = oneshot::channel();
            let (entered3_tx, entered3_rx) = oneshot::channel();
            let (drop_tx, mut drop_rx) = oneshot::channel();
            let writes_completed = Arc::new(AtomicUsize::new(0));
            let timeout_slot: Arc<Mutex<Option<Arc<AtomicU64>>>> = Arc::new(Mutex::new(None));
            let bump_timeout = timeout_slot.clone();
            let child_slot: Arc<Mutex<Option<XudpChildDatagram>>> = Arc::new(Mutex::new(None));
            let drop_child = child_slot.clone();
            let pool_for_flush = pool.clone();

            let stream = Arc::new(Mutex::new(Some(AnyStream::Dynamic(Box::new(
                ScriptedDrainWriter {
                    steps: VecDeque::from([
                        WriteStep::Gated {
                            entered: Some(entered0_tx),
                            release: gate0_rx,
                            on_write: None,
                            on_flush: Some(Box::new(move || {
                                pool_for_flush.set_keep_idle(false);
                                drop(drop_child.lock().take());
                            })),
                        },
                        WriteStep::Ready {
                            on_write: Some(Box::new(move || {
                                if let Some(ms) = bump_timeout.lock().as_ref() {
                                    ms.store(10_000, Ordering::Relaxed);
                                }
                            })),
                        },
                        WriteStep::Gated {
                            entered: Some(entered2_tx),
                            release: gate2_rx,
                            on_write: None,
                            on_flush: None,
                        },
                        WriteStep::Stall { entered: Some(entered3_tx) },
                    ]),
                    pending_flush_hook: None,
                    writes_completed: writes_completed.clone(),
                    dropped: Some(drop_tx),
                },
            )))));

            let child = pool
                .open_stream(&target, || {
                    let stream = stream.clone();
                    async move { Ok(stream.lock().take().unwrap()) }
                })
                .await
                .unwrap();
            let carrier = pool.carriers_for_test()[0].clone();
            carrier.set_drain_timeout_for_test(Duration::from_millis(100));
            *timeout_slot.lock() = Some(carrier.drain_timeout_ms.clone());

            carrier.writer_tx.send(batch_frame.clone()).await.unwrap();
            entered0_rx.await.unwrap();

            for _ in 0..3 {
                carrier.writer_tx.try_send(batch_frame.clone()).unwrap();
            }
            drop(carrier);
            *child_slot.lock() = Some(child);

            let t0 = Instant::now();
            let _ = gate0_tx.send(());

            entered2_rx.await.unwrap();
            assert_eq!(Instant::now(), t0);

            advance(Duration::from_millis(60)).await;
            yield_now().await;
            assert!(drop_rx.try_recv().is_err(), "carrier must not time out at 60ms");

            let _ = gate2_tx.send(());
            entered3_rx.await.unwrap();

            advance(Duration::from_millis(35)).await;
            yield_now().await;
            assert!(drop_rx.try_recv().is_err(), "carrier must still respect 100ms deadline at 95ms");

            advance(Duration::from_millis(10)).await;
            timeout(Duration::from_millis(1), &mut drop_rx)
                .await
                .expect("recv-branch drain must expire at the original 100ms deadline")
                .unwrap();
            assert_eq!(writes_completed.load(Ordering::SeqCst), 3);
        }
    }
}
