use std::{
    collections::{HashMap, hash_map::Entry},
    io,
    sync::{
        Arc, Once, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
#[cfg(test)]
use std::sync::atomic::AtomicU64;

use arc_swap::ArcSwapOption;
use bytes::{BufMut, Bytes, BytesMut};
use futures::{StreamExt, stream::FuturesUnordered};
use quinn_jls::{Connection, RecvStream, SendStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    runtime::Handle,
    sync::mpsc::{self, Receiver, Sender},
    task::JoinSet,
    time::{Instant, interval, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    common::errors::new_io_error,
    proxy::{
        datagram::UdpPacket,
        utils::quic_stream::{
            QUIC_HALF_CLOSED_DRAIN_GRACE, QUIC_STREAM_DRAIN_TIMEOUT,
            QuicStreamLease, QuicUploadGrace, close_after_grace,
        },
    },
    session::SocksAddr,
};

use super::{
    endpoint::ClientEndpoint,
    protocol::{ASSOCIATE_DATAGRAM, ASSOCIATE_STREAM, encode_addr, payload_len, write_request},
    registry::{Packet, REGISTER_TIMEOUT, Registry, Route},
};

/// Highest bit of `active_streams`: once set, the connection is closing
/// and must not accept any new stream leases.
const SQ_CLOSING_BIT: usize = 1usize << (usize::BITS - 1);

pub(super) struct ShadowQuicLease {
    state: Arc<ConnectionState>,
}

impl Drop for ShadowQuicLease {
    fn drop(&mut self) {
        self.state.release_lease();
    }
}

impl QuicStreamLease for ShadowQuicLease {
    fn record_upload_ack_grace(&self, grace: Duration) {
        self.state.upload_grace.extend(grace);
    }
}

#[derive(Clone)]
pub(super) struct ClientConnection(Arc<ConnectionState>);

pub(super) struct ConnectionState {
    conn: Connection,
    registry: Arc<Registry>,
    cancel: CancellationToken,
    receiver_started: Once,
    active_streams: AtomicUsize,
    keep_idle: Arc<AtomicBool>,
    evicted: AtomicBool,
    closed_notified: AtomicBool,
    upload_grace: QuicUploadGrace,
    runtime: Handle,
    endpoint: Option<Arc<ClientEndpoint>>,
    cache_slot: Weak<ArcSwapOption<ConnectionState>>,
    #[cfg(test)]
    udp_drain_timeout_ms: AtomicU64,
}

impl Drop for ConnectionState {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl ConnectionState {
    pub(super) fn try_acquire_lease(self: &Arc<Self>) -> Option<ShadowQuicLease> {
        self.active_streams
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |val| {
                if val & SQ_CLOSING_BIT != 0 {
                    None
                } else {
                    Some(val + 1)
                }
            })
            .ok()
            .map(|_| ShadowQuicLease { state: self.clone() })
    }

    pub(super) fn evict_from_cache(self: &Arc<Self>) {
        if let Some(cache_slot) = self.cache_slot.upgrade() {
            let _ = cache_slot.rcu(|current| match current {
                Some(cached) if Arc::ptr_eq(cached, self) => None,
                _ => current.clone(),
            });
        }
    }

    fn should_keep_idle(&self) -> bool {
        self.keep_idle.load(Ordering::SeqCst) && !self.evicted.load(Ordering::SeqCst)
    }

    pub(super) fn is_alive(&self) -> bool {
        self.conn.close_reason().is_none()
            && !self.closed_notified.load(Ordering::SeqCst)
    }

    pub(super) fn mark_evicted(self: &Arc<Self>) {
        self.evicted.store(true, Ordering::SeqCst);
        self.close_if_idle();
    }

    #[cfg(test)]
    pub(super) fn endpoint_for_test(&self) -> Option<Arc<ClientEndpoint>> {
        self.endpoint.clone()
    }

    fn release_lease(self: &Arc<Self>) {
        let keep_idle = self.should_keep_idle();
        let mut closed_now = false;
        let mut became_zero = false;
        let _ = self.active_streams.try_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |val| {
                let closing = (val & SQ_CLOSING_BIT) != 0;
                let count = (val & !SQ_CLOSING_BIT).saturating_sub(1);
                let next_closing = closing || (!keep_idle && count == 0);
                closed_now = !closing && next_closing;
                became_zero = !next_closing && count == 0;
                Some(if next_closing {
                    SQ_CLOSING_BIT | count
                } else {
                    count
                })
            },
        );
        if closed_now {
            self.evict_from_cache();
            self.close_with_grace();
        } else if became_zero && !self.should_keep_idle() {
            // Re-check `keep_idle` / `evicted` after publishing zero (SeqCst)
            // so a concurrent `set_keep_idle(false)` or eviction cannot miss.
            self.close_if_idle();
        }
    }

    pub(super) fn close_if_idle(self: &Arc<Self>) {
        if self
            .active_streams
            .compare_exchange(
                0,
                SQ_CLOSING_BIT,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            self.evict_from_cache();
            self.close_with_grace();
        }
    }

    fn udp_drain_timeout(&self) -> Duration {
        #[cfg(test)]
        {
            Duration::from_millis(self.udp_drain_timeout_ms.load(Ordering::Relaxed))
        }
        #[cfg(not(test))]
        {
            QUIC_STREAM_DRAIN_TIMEOUT
        }
    }

    fn close_with_grace(self: &Arc<Self>) {
        self.cancel.cancel();
        close_after_grace(
            &self.runtime,
            &self.upload_grace,
            &self.conn,
            b"idle",
            self.endpoint.clone(),
        );
    }
}

impl ClientConnection {
    #[cfg(test)]
    pub fn new(conn: Connection) -> Self {
        Self::new_managed(
            conn,
            None,
            Arc::new(AtomicBool::new(true)),
            Weak::new(),
        )
    }

    pub(super) fn from_state(state: Arc<ConnectionState>) -> Self {
        Self(state)
    }

    pub(super) fn state(&self) -> &Arc<ConnectionState> {
        &self.0
    }

    pub(super) fn new_managed(
        conn: Connection,
        endpoint: Option<Arc<ClientEndpoint>>,
        keep_idle: Arc<AtomicBool>,
        cache_slot: Weak<ArcSwapOption<ConnectionState>>,
    ) -> Self {
        let registry = Arc::new(Registry::default());
        let cancel = CancellationToken::new();
        let state = Arc::new(ConnectionState {
            conn: conn.clone(),
            registry,
            cancel: cancel.clone(),
            receiver_started: Once::new(),
            active_streams: AtomicUsize::new(0),
            keep_idle,
            evicted: AtomicBool::new(false),
            closed_notified: AtomicBool::new(false),
            upload_grace: QuicUploadGrace::default(),
            runtime: Handle::current(),
            endpoint,
            cache_slot,
            #[cfg(test)]
            udp_drain_timeout_ms: AtomicU64::new(
                QUIC_STREAM_DRAIN_TIMEOUT.as_millis() as u64,
            ),
        });
        let weak = Arc::downgrade(&state);
        tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = conn.closed() => {
                    if let Some(state) = weak.upgrade() {
                        state.closed_notified.store(true, Ordering::SeqCst);
                        state.cancel.cancel();
                        state.evict_from_cache();
                    }
                }
                _ = cancel.cancelled() => {
                    if let Some(state) = weak.upgrade()
                        && state.conn.close_reason().is_some()
                    {
                        state.closed_notified.store(true, Ordering::SeqCst);
                        state.evict_from_cache();
                    }
                }
            }
        });
        Self(state)
    }

    pub fn connection(&self) -> &Connection {
        &self.0.conn
    }

    pub(super) fn is_alive(&self) -> bool {
        self.0.is_alive()
    }

    pub(super) fn try_acquire_lease(&self) -> Option<ShadowQuicLease> {
        self.0.try_acquire_lease()
    }

    pub(super) fn mark_evicted(&self) {
        self.0.mark_evicted();
    }

    pub(super) fn close_if_idle(&self) {
        self.0.close_if_idle();
    }

    pub(super) fn evict_from_cache(&self) {
        self.0.evict_from_cache();
    }

    #[cfg(test)]
    pub(super) fn active_streams_for_test(&self) -> usize {
        self.0.active_streams.load(Ordering::Acquire) & !SQ_CLOSING_BIT
    }

    #[cfg(test)]
    pub(super) fn set_udp_drain_timeout_for_test(&self, drain_timeout: Duration) {
        self.0.udp_drain_timeout_ms.store(
            drain_timeout.as_millis().max(1) as u64,
            Ordering::Relaxed,
        );
    }

    #[cfg(test)]
    pub async fn associate(
        &self, addr: SocksAddr, over_stream: bool,
    ) -> io::Result<(Sender<UdpPacket>, Receiver<Packet>)> {
        let lease = self.try_acquire_lease();
        self.associate_with_lease(addr, over_stream, lease, CancellationToken::new()).await
    }

    pub(super) async fn associate_with_lease(
        &self,
        addr: SocksAddr,
        over_stream: bool,
        lease: Option<ShadowQuicLease>,
        upload_closed: CancellationToken,
    ) -> io::Result<(Sender<UdpPacket>, Receiver<Packet>)> {
        self.0.receiver_started.call_once(|| {
            tokio::spawn(receive_packets(
                self.0.conn.clone(), self.0.registry.clone(), self.0.cancel.clone(),
            ));
        });
        let (mut send, recv) = self.0.conn.open_bi().await.map_err(new_io_error)?;
        let command = if over_stream { ASSOCIATE_STREAM } else { ASSOCIATE_DATAGRAM };
        write_request(&mut send, command, &addr).await?;
        let (outgoing, input) = mpsc::channel(32);
        let (output, incoming) = mpsc::channel(32);
        let state = self.0.clone();
        let session = Association {
            id: state.registry.session(),
            registry: state.registry.clone(),
            send_ids: Vec::new(),
            cancel: state.cancel.child_token(),
        };
        tokio::spawn(async move {
            let _lease = lease;
            let cancel = session.cancel.clone();
            let result = run_association(
                &state.conn,
                send,
                recv,
                input,
                &output,
                over_stream,
                session,
                &state.cancel,
                &upload_closed,
                _lease.as_ref(),
                state.udp_drain_timeout(),
            )
            .await;
            cancel.cancel();
            if let Err(err) = result {
                tracing::debug!("shadowquic UDP association closed: {err}");
            }
        });
        Ok((outgoing, incoming))
    }
}

struct Association {
    id: u64,
    registry: Arc<Registry>,
    send_ids: Vec<u16>,
    cancel: CancellationToken,
}

impl Drop for Association {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.registry.remove_session(self.id, &self.send_ids);
    }
}

enum UdpSenderState {
    Stream {
        destinations: HashMap<SocksAddr, SendStream>,
        sent_any: bool,
    },
    Datagram {
        destinations: HashMap<SocksAddr, u16>,
        sent_any: bool,
    },
}

impl UdpSenderState {
    fn new(over_stream: bool) -> Self {
        if over_stream {
            Self::Stream {
                destinations: HashMap::new(),
                sent_any: false,
            }
        } else {
            Self::Datagram {
                destinations: HashMap::new(),
                sent_any: false,
            }
        }
    }

    fn sent_any(&self) -> bool {
        match self {
            Self::Stream { sent_any, .. } | Self::Datagram { sent_any, .. } => *sent_any,
        }
    }

    async fn send_packet(
        &mut self,
        conn: &Connection,
        control: &mut SendStream,
        session: &mut Association,
        packet: UdpPacket,
    ) -> io::Result<()> {
        match self {
            Self::Stream {
                destinations,
                sent_any,
            } => {
                let len = payload_len(packet.data.len())?;
                let stream = match destinations.entry(packet.dst_addr) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        let id =
                            register_destination(control, session, entry.key()).await?;
                        let mut stream = conn.open_uni().await.map_err(new_io_error)?;
                        stream.write_u16(id).await?;
                        entry.insert(stream)
                    }
                };
                stream.write_u16(len).await?;
                stream.write_all(&packet.data).await?;
                *sent_any = true;
                Ok(())
            }
            Self::Datagram {
                destinations,
                sent_any,
            } => {
                payload_len(packet.data.len())?;
                let id = match destinations.entry(packet.dst_addr) {
                    Entry::Occupied(entry) => *entry.get(),
                    Entry::Vacant(entry) => {
                        let id =
                            register_destination(control, session, entry.key()).await?;
                        *entry.insert(id)
                    }
                };
                let mut data = BytesMut::with_capacity(2 + packet.data.len());
                data.put_u16(id);
                data.extend_from_slice(&packet.data);
                conn.send_datagram(data.freeze()).map_err(new_io_error)?;
                *sent_any = true;
                Ok(())
            }
        }
    }

    async fn finish_streams(self, mut control: SendStream) {
        if let Self::Stream { destinations, .. } = self {
            let mut pending = FuturesUnordered::new();
            for mut stream in destinations.into_values() {
                let _ = stream.finish();
                pending.push(async move {
                    let _ = stream.stopped().await;
                });
            }
            while pending.next().await.is_some() {}
        }
        let _ = control.finish();
        let _ = control.stopped().await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_association(
    conn: &Connection,
    send: SendStream,
    mut recv: RecvStream,
    mut input: Receiver<UdpPacket>,
    output: &Sender<Packet>,
    over_stream: bool,
    session: Association,
    conn_cancel: &CancellationToken,
    upload_closed: &CancellationToken,
    lease: Option<&ShadowQuicLease>,
    drain_timeout: Duration,
) -> io::Result<()> {
    let registry = session.registry.clone();
    let cancel = session.cancel.clone();
    let session_id = session.id;
    let close_input = CancellationToken::new();

    let send_fut = async {
        let mut send = send;
        let mut session = session;
        let mut sender = UdpSenderState::new(over_stream);
        let mut input_closed = false;
        loop {
            let packet = if input_closed {
                input.recv().await
            } else if close_input.is_cancelled() {
                // Close `input` so `sender.closed()` wakes while keeping
                // already-queued tail packets available to drain.
                input.close();
                input_closed = true;
                input.recv().await
            } else {
                tokio::select! {
                    biased;
                    _ = close_input.cancelled() => {
                        input.close();
                        input_closed = true;
                        input.recv().await
                    }
                    packet = input.recv() => packet,
                }
            };
            match packet {
                Some(packet) => {
                    sender
                        .send_packet(conn, &mut send, &mut session, packet)
                        .await?;
                }
                None => break,
            }
        }
        let sent_any = sender.sent_any();
        let _ = timeout(drain_timeout, sender.finish_streams(send)).await;
        if sent_any && let Some(lease) = lease {
            lease.record_upload_ack_grace(QUIC_HALF_CLOSED_DRAIN_GRACE);
        }
        Ok::<(), io::Error>(())
    };
    tokio::pin!(send_fut);

    let receive_fut = receive_control(&mut recv, &registry, session_id, output, &cancel);
    tokio::pin!(receive_fut);

    tokio::select! {
        _ = conn_cancel.cancelled() => Ok(()),
        result = &mut receive_fut => result,
        result = &mut send_fut => result,
        _ = upload_closed.cancelled() => {
            let deadline = Instant::now() + drain_timeout;
            tokio::select! {
                _ = conn_cancel.cancelled() => Ok(()),
                result = &mut receive_fut => result,
                _ = output.closed() => {
                    close_input.cancel();
                    tokio::select! {
                        _ = conn_cancel.cancelled() => Ok(()),
                        res = timeout_at(deadline, &mut send_fut) => match res {
                            Ok(inner) => inner,
                            Err(_) => Ok(()),
                        },
                    }
                }
                res = timeout_at(deadline, &mut send_fut) => match res {
                    Ok(inner) => inner,
                    Err(_) => Ok(()),
                },
            }
        }
        _ = output.closed() => {
            close_input.cancel();
            let deadline = Instant::now() + drain_timeout;
            tokio::select! {
                _ = conn_cancel.cancelled() => Ok(()),
                res = timeout_at(deadline, &mut send_fut) => match res {
                    Ok(inner) => inner,
                    Err(_) => Ok(()),
                },
            }
        }
    }
}

async fn register_destination(
    send: &mut SendStream, session: &mut Association, addr: &SocksAddr,
) -> io::Result<u16> {
    let mut header = encode_addr(addr)?;
    let id = session.registry.allocate()?;
    session.send_ids.push(id);
    header.put_u16(id);
    send.write_all(&header).await?;
    Ok(id)
}

async fn receive_packets(
    conn: Connection, registry: Arc<Registry>, cancel: CancellationToken,
) {
    let mut streams = JoinSet::new();
    let mut expiry = interval(REGISTER_TIMEOUT);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = expiry.tick() => registry.expire(),
            Some(_) = streams.join_next() => {},
            packet = conn.read_datagram() => {
                let Ok(packet) = packet else { break };
                if packet.len() >= 2 {
                    let id = u16::from_be_bytes([packet[0], packet[1]]);
                    registry.deliver(id, packet.slice(2..));
                } else {
                    tracing::debug!("discarding shadowquic datagram without context ID");
                }
            }
            stream = conn.accept_uni(), if streams.len() < 500 => {
                let Ok(stream) = stream else { break };
                let registry = registry.clone();
                streams.spawn(async move {
                    if let Err(err) = receive_stream(stream, registry).await {
                        tracing::debug!("shadowquic UDP stream closed: {err}");
                    }
                });
            }
        }
    }
    cancel.cancel();
    // JoinSet aborts all outstanding receive tasks on drop.
}

async fn receive_stream(mut stream: RecvStream, registry: Arc<Registry>) -> io::Result<()> {
    let route: Route = timeout(REGISTER_TIMEOUT, async {
        let id = stream.read_u16().await?;
        loop {
            // Register before checking the table to avoid a lost notification.
            let changed = registry.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(route) = registry.route(id) {
                return Ok::<Route, io::Error>(route);
            }
            changed.await;
        }
    }).await.map_err(new_io_error)??;
    let receive = receive_payload(&mut stream, &route);
    tokio::select! {
        _ = route.cancel.cancelled() => Ok(()),
        result = receive => result,
    }
}

async fn receive_control(
    recv: &mut RecvStream, registry: &Registry, session: u64,
    output: &Sender<Packet>, cancel: &CancellationToken,
) -> io::Result<()> {
    loop {
        let addr = SocksAddr::read_from(recv).await?;
        let id = recv.read_u16().await?;
        registry.register(session, id, addr, output.clone(), cancel.clone())?;
    }
}

async fn receive_payload(stream: &mut RecvStream, route: &Route) -> io::Result<()> {
    loop {
        let len = stream.read_u16().await? as usize;
        let mut packet = vec![0; len];
        AsyncReadExt::read_exact(stream, &mut packet).await?;
        route.sender.send((Bytes::from(packet), route.addr.clone())).await
            .map_err(new_io_error)?;
    }
}
