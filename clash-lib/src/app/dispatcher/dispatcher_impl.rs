use crate::proxy::dispatch_datagram;
use crate::{
    app::{
        dns::ClashResolver, outbound::manager::ThreadSafeOutboundManager,
        router::ArcRouter,
    },
    common::io::copy_bidirectional,
    config::{
        def::RunMode,
        internal::proxy::{PROXY_DIRECT, PROXY_GLOBAL},
    },
    proxy::{
        AnyInboundDatagram, AnyOutboundDatagram, AnyStream, OutboundDatagram, OutboundType,
        datagram::UdpPacket,
    },
    session::{Session, SocksAddr},
};
use futures::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::task::AbortOnDropHandle;
use tokio_util::time::DelayQueue;
use tracing::{Instrument, debug, error, info, info_span, instrument, trace, warn};

use crate::app::dns::ThreadSafeDNSResolver;

use super::statistics_manager::{Manager, TrackGuard, TrackerInfo, TrafficTracker};

use crate::app::sniffer::ArcSniffer;

// SS2022 (AEAD-2022) MAX_PACKET_SIZE is 0xFFFF (65535 bytes). Using a relay
// buffer smaller than that forces the cipher to split every full packet into
// multiple smaller encrypted chunks, multiplying encrypt/decrypt overhead.
// Classic AEAD ciphers cap at 0x3FFF (16383 bytes) so they are unaffected.
const DEFAULT_BUFFER_SIZE: usize = 16 * 1024;
const DEFAULT_UDP_SESSION_TIMEOUT_SECS: u64 = 60;
const UDP_CHANNEL_CAPACITY: usize = 64;
const MAX_PENDING_SNIFF_PACKETS: usize = 4;
const MAX_CONNECTING_PACKETS: usize = 8;
const MAX_CONNECTING_SESSIONS: usize = 256;
/// Bound all resident UDP outbound state, not just concurrent connection
/// attempts. A permit is retained by an established session until it is
/// expired or otherwise removed.
const MAX_UDP_SESSIONS_PER_ACTOR: usize = 4096;
const MAX_GLOBAL_UDP_SESSIONS: usize = 4096;
const PENDING_SNIFF_TIMEOUT: Duration = Duration::from_millis(100);
const CONNECTING_SESSION_TIMEOUT: Duration = Duration::from_secs(10);
const SHORT_FLOW_INIT_TIMEOUT: Duration = Duration::from_secs(5);
const FAST_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

#[inline]
fn is_short_flow_port(port: u16) -> bool {
    matches!(port, 53 | 123 | 5353)
}

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    router: ArcRouter,
    resolver: ThreadSafeDNSResolver,
    mode: Arc<AtomicU8>,
    allow_quic: Arc<AtomicBool>,
    manager: Arc<Manager>,
    sniffer: Option<ArcSniffer>,
    tcp_buffer_size: usize,
    udp_session_semaphore: Arc<tokio::sync::Semaphore>,
}

type SessionKey = (SocketAddr, SocksAddr);
type OutboundPacketSender = tokio::sync::mpsc::Sender<UdpPacket>;

/// The relay has one writer and the actor only needs a timestamp, so no
/// associated state requires synchronization beyond a relaxed atomic access.
struct UdpReplyActivity {
    epoch: Instant,
    last_reply: AtomicU64,
}

impl UdpReplyActivity {
    fn new() -> Self {
        Self {
            epoch: Instant::now(),
            last_reply: AtomicU64::new(0),
        }
    }

    fn record(&self) {
        // Reserve zero for no reply. Nanoseconds cover over 584 years, well
        // beyond the lifetime of a UDP session.
        let elapsed = self.epoch.elapsed().as_nanos() as u64;
        self.last_reply.store(elapsed + 1, Ordering::Relaxed);
    }

    fn latest(&self) -> Option<Instant> {
        let elapsed = self.last_reply.load(Ordering::Relaxed);
        (elapsed != 0).then(|| self.epoch + Duration::from_nanos(elapsed - 1))
    }
}

struct OutboundSession {
    id: u64,
    dest: SocksAddr,
    sender: OutboundPacketSender,
    delay_key: tokio_util::time::delay_queue::Key,
    idle_deadline: Instant,
    scheduled_deadline: Instant,
    last_upload: Instant,
    reply_activity: Arc<UdpReplyActivity>,
    _relay_handle: JoinHandle<()>,
    _capacity_permit: tokio::sync::OwnedSemaphorePermit,
    upload_count: u32,
    is_short_flow: bool,
}

impl OutboundSession {
    fn refresh_idle(
        &mut self,
        delay_queue: &mut DelayQueue<UdpQueueEvent>,
        timeout: Duration,
    ) {
        self.last_upload = Instant::now();
        self.idle_deadline = self.last_upload + timeout;
        // Keep an earlier timer in place. When it fires, the actor will check
        // the latest activity and reschedule only if the flow is still active.
        if self.idle_deadline < self.scheduled_deadline {
            delay_queue.reset_at(&self.delay_key, self.idle_deadline);
            self.scheduled_deadline = self.idle_deadline;
        }
    }

    fn latest_idle_deadline(&self, timeout: Duration) -> Instant {
        match self.reply_activity.latest() {
            Some(reply) if reply > self.last_upload => {
                let reply_timeout = if self.is_short_flow {
                    FAST_RESPONSE_TIMEOUT
                } else {
                    timeout
                };
                reply + reply_timeout
            }
            _ => self.idle_deadline,
        }
    }
}

impl Drop for OutboundSession {
    fn drop(&mut self) {
        self._relay_handle.abort();
    }
}

struct EstablishedSession {
    session_key: SessionKey,
    sess_id: u64,
    dest: SocksAddr,
    sender: OutboundPacketSender,
    relay_handle: JoinHandle<()>,
    relay_start: tokio::sync::oneshot::Sender<()>,
    reply_activity: Arc<UdpReplyActivity>,
}

enum EstablishOutcome {
    Success(EstablishedSession, tokio::sync::OwnedSemaphorePermit),
    Failed(SessionKey, u64),
    Terminated(SessionKey, u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UdpQueueEvent {
    SessionIdle(SessionKey),
    PendingSniff(SessionKey),
    Connecting(SessionKey, u64),
}

struct PendingSniffSession {
    delay_key: tokio_util::time::delay_queue::Key,
    packets: Vec<UdpPacket>,
    sess: Session,
}

struct ConnectingSession {
    id: u64,
    delay_key: tokio_util::time::delay_queue::Key,
    packets: Vec<UdpPacket>,
    establish_handle: JoinHandle<()>,
}

impl Drop for ConnectingSession {
    fn drop(&mut self) {
        self.establish_handle.abort();
    }
}

#[derive(Clone)]
struct UdpDispatchContext {
    outbound_manager: ThreadSafeOutboundManager,
    router: ArcRouter,
    resolver: ThreadSafeDNSResolver,
    manager: Arc<Manager>,
    mode: Arc<AtomicU8>,
    reply_sender: OutboundPacketSender,
    allow_quic: Arc<AtomicBool>,
    session_semaphore: Arc<tokio::sync::Semaphore>,
}

fn make_udp_flow_session(
    sess_base: &Session,
    src_addr: SocketAddr,
    orig_inbound_dst: SocksAddr,
    dest: SocksAddr,
    mapped_domain: Option<String>,
    inbound_user: Option<Arc<str>>,
) -> Session {
    let mut sess = sess_base.clone();
    sess.id = crate::session::generate_session_id();
    sess.source = src_addr;
    sess.destination = dest;
    sess.orig_destination = Some(orig_inbound_dst);
    sess.inbound_user = inbound_user;
    sess.mapped_domain = mapped_domain;
    sess.proxy_chain = crate::session::ProxyChain::new();
    sess
}

impl Debug for Dispatcher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher").finish()
    }
}

impl Dispatcher {
    pub fn new(
        outbound_manager: ThreadSafeOutboundManager,
        router: ArcRouter,
        resolver: ThreadSafeDNSResolver,
        mode: RunMode,
        manager: Arc<Manager>,
        tcp_buffer_size: Option<usize>,
        sniffer: Option<ArcSniffer>,
        allow_quic: bool,
    ) -> Self {
        Self {
            outbound_manager,
            router,
            resolver,
            mode: Arc::new(AtomicU8::new(mode as u8)),
            allow_quic: Arc::new(AtomicBool::new(allow_quic)),
            manager,
            sniffer,
            tcp_buffer_size: tcp_buffer_size.unwrap_or(DEFAULT_BUFFER_SIZE),
            udp_session_semaphore: Arc::new(tokio::sync::Semaphore::new(
                MAX_GLOBAL_UDP_SESSIONS,
            )),
        }
    }

    pub fn set_mode(&self, mode: RunMode) {
        info!("run mode switched to {}", mode);

        self.mode.store(mode as u8, Ordering::Relaxed);
    }

    pub fn get_mode(&self) -> RunMode {
        decode_mode(self.mode.load(Ordering::Relaxed))
    }

    pub fn set_quic(&self, allow: bool) {
        info!("QUIC traffic {}", if allow { "allowed" } else { "blocked" });
        self.allow_quic.store(allow, Ordering::Relaxed);
    }

    pub fn get_quic(&self) -> bool {
        self.allow_quic.load(Ordering::Relaxed)
    }

    pub fn router(&self) -> &ArcRouter {
        &self.router
    }

    #[instrument(skip(self, sess, lhs), fields(trace_id = sess.id))]
    pub async fn dispatch_stream(&self, mut sess: Session, mut lhs: AnyStream) {
        let orig_dest = sess.destination.clone();
        sess.orig_destination = Some(orig_dest.clone());

        let force_dns_mapping = self
            .sniffer
            .as_ref()
            .map_or(false, |s| s.config.force_dns_mapping);
        let dest: SocksAddr = match reverse_lookup(
            &self.resolver,
            &sess.destination,
            force_dns_mapping,
        ) {
            Some(dest) => dest,
            None => {
                warn!("failed to resolve destination {}", sess);
                return;
            }
        };

        if !orig_dest.is_domain() {
            if let Some(domain) = dest.domain() {
                sess.mapped_domain = Some(domain.to_string());
            }
        }

        sess.destination = dest.clone();

        // Perform domain sniffing if sniffer is configured
        let mut override_dest = false;
        if let Some(sniffer) = &self.sniffer {
            let (sniffed_domain, new_lhs, should_override) =
                sniffer.sniff_stream(&sess, lhs).await;
            lhs = new_lhs;
            if let Some(domain) = sniffed_domain {
                let port = sess.destination.port();
                sess.sniffed_domain = Some(domain.clone());
                sess.destination = SocksAddr::Domain(domain.into(), port);
                override_dest = should_override;
            }
        }

        // Set resolved_ip if original destination was a real IP (not a Fake-IP)
        let is_real_ip = match orig_dest.ip() {
            Some(ip) => !self.resolver.is_fake_ip(ip),
            None => false,
        };
        if is_real_ip {
            sess.resolved_ip = orig_dest.ip();
        }

        let mode = self.get_mode();
        let (outbound_name, rule) = match mode {
            RunMode::Global => (PROXY_GLOBAL, None),
            RunMode::Rule => self.router.match_route(&mut sess).await,
            RunMode::Direct => (PROXY_DIRECT, None),
        };

        // If override_destination is not requested and original destination was a real IP,
        // restore original destination for outbound connection
        if !override_dest && is_real_ip {
            sess.destination = orig_dest.clone();
        }

        debug!("dispatching {} to {}[{}]", sess, outbound_name, mode);

        let mgr = self.outbound_manager.clone();
        let handler = match mgr.get_outbound(outbound_name) {
            Some(h) => h,
            None => {
                debug!("unknown rule: {}, fallback to direct", outbound_name);
                mgr.get_outbound(PROXY_DIRECT).unwrap()
            }
        };

        match handler
            .connect_stream(&sess, self.resolver.clone())
            .instrument(info_span!("connect_stream", outbound_name = outbound_name,))
            .await
        {
            Ok(rhs) => {
                debug!("remote connection established {}", sess);
                let tracker_info = Arc::new(TrackerInfo::new(&sess, rule));
                let (close_tx, close_rx) = tokio::sync::oneshot::channel();
                self.manager.track(sess.id, tracker_info.clone(), close_tx);
                let _track_guard = TrackGuard::new(sess.id, self.manager.clone());

                let tracker =
                    TrafficTracker::new(tracker_info, self.manager.clone());

                let copy_fut = copy_bidirectional(
                    lhs,
                    rhs,
                    self.tcp_buffer_size,
                    Duration::from_secs(10),
                    Duration::from_secs(10),
                    tracker,
                )
                .instrument(info_span!(
                    "copy_bidirectional",
                    outbound_name = outbound_name,
                ));

                tokio::select! {
                    res = copy_fut => {
                        match res {
                            Ok((up, down)) => {
                                debug!(
                                    "connection {} closed with {} bytes up, {} bytes down",
                                    sess, up, down
                                );
                            }
                            Err(err) => match err {
                                crate::common::io::CopyBidirectionalError::LeftClosed(
                                    err,
                                ) => match err.kind() {
                                    std::io::ErrorKind::UnexpectedEof
                                    | std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::BrokenPipe
                                    | std::io::ErrorKind::TimedOut
                                    | std::io::ErrorKind::NotConnected => {
                                        debug!(
                                            "connection {} closed with error {} by local",
                                            sess, err
                                        );
                                    }
                                    _ => {
                                        warn!(
                                            "connection {} closed with error {} by local",
                                            sess, err
                                        );
                                    }
                                },
                                crate::common::io::CopyBidirectionalError::RightClosed(
                                    err,
                                ) => match err.kind() {
                                    std::io::ErrorKind::UnexpectedEof
                                    | std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::BrokenPipe
                                    | std::io::ErrorKind::TimedOut
                                    | std::io::ErrorKind::NotConnected => {
                                        debug!(
                                            "connection {} closed with error {} by remote",
                                            sess, err
                                        );
                                    }
                                    _ => {
                                        warn!(
                                            "connection {} closed with error {} by remote",
                                            sess, err
                                        );
                                    }
                                },
                                crate::common::io::CopyBidirectionalError::Other(err) => {
                                    match err.kind() {
                                        std::io::ErrorKind::UnexpectedEof
                                        | std::io::ErrorKind::ConnectionReset
                                        | std::io::ErrorKind::BrokenPipe
                                        | std::io::ErrorKind::TimedOut
                                        | std::io::ErrorKind::NotConnected => {
                                            debug!(
                                                "connection {} closed with error {} by unknown",
                                                sess, err
                                            );
                                        }
                                        _ => {
                                            warn!(
                                                "connection {} closed with error {} by unknown",
                                                sess, err
                                            );
                                        }
                                    }
                                }
                            },
                        }
                    }
                    _ = close_rx => {
                        debug!("connection {} closed by manager signal", sess);
                    }
                }
            }
            Err(err) => {
                warn!(
                    "failed to establish remote connection for {}: {}",
                    sess, err
                );
            }
        }
    }

    #[instrument(skip(self, sess, udp_inbound), fields(trace_id = sess.id))]
    pub async fn dispatch_datagram(
        &self,
        sess: Session,
        udp_inbound: AnyInboundDatagram,
    ) -> tokio::sync::oneshot::Sender<u8> {
        let (mut local_w, mut local_r) = udp_inbound.split();
        let (local_sender, mut local_receiver) =
            tokio::sync::mpsc::channel::<UdpPacket>(UDP_CHANNEL_CAPACITY);
        let (session_established_tx, mut session_established_rx) =
            tokio::sync::mpsc::channel::<EstablishOutcome>(64);
        let (close_sender, mut close_receiver) =
            tokio::sync::oneshot::channel::<u8>();

        let ctx = UdpDispatchContext {
            outbound_manager: self.outbound_manager.clone(),
            router: self.router.clone(),
            resolver: self.resolver.clone(),
            manager: self.manager.clone(),
            mode: self.mode.clone(),
            reply_sender: local_sender,
            allow_quic: self.allow_quic.clone(),
            session_semaphore: self.udp_session_semaphore.clone(),
        };
        let sniffer = self.sniffer.clone();
        let force_dns_mapping = sniffer
            .as_ref()
            .map_or(false, |s| s.config.force_dns_mapping);
        let allow_quic = self.allow_quic.clone();

        let current_span = tracing::Span::current();

        tokio::spawn(
            async move {
                let mut sessions: HashMap<SessionKey, OutboundSession> = HashMap::new();
                let mut connecting_sessions: HashMap<SessionKey, ConnectingSession> = HashMap::new();
                let mut pending_sniff_sessions: HashMap<SessionKey, PendingSniffSession> = HashMap::new();
                let mut delay_queue: DelayQueue<UdpQueueEvent> = DelayQueue::new();
                let has_explicit_timeout = sess.udp_timeout.is_some();
                let timeout_duration = sess
                    .udp_timeout
                    .unwrap_or_else(|| Duration::from_secs(DEFAULT_UDP_SESSION_TIMEOUT_SECS));

                // Cancel inbound writes when the actor exits, even if the sink
                // remains backpressured. The queue bounds outstanding replies.
                let _local_writer = AbortOnDropHandle::new(tokio::spawn(async move {
                    while let Some(packet) = local_receiver.recv().await {
                        if let Err(err) = local_w.send(packet).await {
                            error!("failed to send packet to local: {}", err);
                        }
                    }
                }.instrument(tracing::Span::current())));

                loop {
                    tokio::select! {
                        // 1. Close signal from caller (explicit close or sender drop)
                        _ = &mut close_receiver => {
                            debug!("UDP close signal received for {}, closing session actor", sess);
                            break;
                        }

                        // Detect an unexpected writer exit even without reply traffic.
                        _ = ctx.reply_sender.closed() => {
                            warn!("UDP inbound reply writer stopped for {}, closing session actor", sess);
                            break;
                        }

                        // 2. Asynchronously established outbound session ready
                        Some(outcome) = session_established_rx.recv() => {
                            match outcome {
                                EstablishOutcome::Success(established, capacity_permit) => {
                                    let session_key = established.session_key.clone();
                                    let Some(mut connecting) = connecting_sessions.remove(&session_key) else {
                                        // The connect attempt timed out or was superseded while
                                        // its result was in flight. Do not resurrect the flow.
                                        established.relay_handle.abort();
                                        continue;
                                    };
                                    if connecting.id != established.sess_id {
                                        connecting_sessions.insert(session_key, connecting);
                                        established.relay_handle.abort();
                                        continue;
                                    }
                                    delay_queue.remove(&connecting.delay_key);
                                    let buffered_packets = std::mem::take(&mut connecting.packets);
                                    let EstablishedSession {
                                        sess_id,
                                        dest,
                                        sender,
                                        relay_handle,
                                        relay_start,
                                        reply_activity,
                                        ..
                                    } = established;

                                    let initial_upload_count = (buffered_packets.len() as u32).max(1);
                                    for packet in buffered_packets {
                                        let _ = forward_to_remote(&sender, packet, sess_id);
                                    }
                                    let is_short_flow = !has_explicit_timeout
                                        && initial_upload_count <= 2
                                        && is_short_flow_port(session_key.1.port());
                                    let initial_timeout = if is_short_flow {
                                        SHORT_FLOW_INIT_TIMEOUT
                                    } else {
                                        timeout_duration
                                    };

                                    let last_upload = Instant::now();
                                    let idle_deadline = last_upload + initial_timeout;
                                    // A first reply can shorten a short flow's timeout.
                                    // Check at the earliest possible deadline without
                                    // sending per-packet activity messages to the actor.
                                    let scheduled_deadline = if is_short_flow {
                                        last_upload + FAST_RESPONSE_TIMEOUT
                                    } else {
                                        idle_deadline
                                    };
                                    let delay_key = delay_queue.insert_at(
                                        UdpQueueEvent::SessionIdle(session_key.clone()),
                                        scheduled_deadline,
                                    );

                                    sessions.insert(
                                        session_key,
                                        OutboundSession {
                                            id: sess_id,
                                            dest,
                                            sender,
                                            delay_key,
                                            idle_deadline,
                                            scheduled_deadline,
                                            last_upload,
                                            reply_activity,
                                            _relay_handle: relay_handle,
                                            _capacity_permit: capacity_permit,
                                            upload_count: initial_upload_count,
                                            is_short_flow,
                                        },
                                    );
                                    let _ = relay_start.send(());
                                }
                                EstablishOutcome::Failed(session_key, sess_id) => {
                                    if connecting_sessions
                                        .get(&session_key)
                                        .is_some_and(|connecting| connecting.id == sess_id)
                                        && let Some(connecting) = connecting_sessions.remove(&session_key)
                                    {
                                        delay_queue.remove(&connecting.delay_key);
                                    }
                                }
                                EstablishOutcome::Terminated(session_key, sess_id) => {
                                    if sessions
                                        .get(&session_key)
                                        .is_some_and(|session| session.id == sess_id)
                                        && let Some(session) = sessions.remove(&session_key)
                                    {
                                        delay_queue.remove(&session.delay_key);
                                    }
                                }
                            }
                        }

                        // 3. Idle timeout expiration or pending sniff timeout from DelayQueue
                        Some(expired) = delay_queue.next() => {
                            match expired.into_inner() {
                                UdpQueueEvent::SessionIdle(key) => {
                                    if let Some(session) = sessions.get_mut(&key) {
                                        let deadline = session.latest_idle_deadline(timeout_duration);
                                        if deadline > Instant::now() {
                                            session.delay_key = delay_queue.insert_at(
                                                UdpQueueEvent::SessionIdle(key.clone()),
                                                deadline,
                                            );
                                            session.scheduled_deadline = deadline;
                                        } else {
                                            trace!("UDP session expired for src: {}, dst: {}", key.0, key.1);
                                            sessions.remove(&key);
                                        }
                                    }
                                }
                                UdpQueueEvent::PendingSniff(key) => {
                                    if let Some(pending) = pending_sniff_sessions.remove(&key) {
                                        trace!(
                                            "UDP pending sniff timed out for src: {}, dst: {}, flushing buffered packets",
                                            key.0, key.1
                                        );
                                        start_connecting_session(
                                            pending.sess,
                                            pending.packets,
                                            false,
                                            &ctx,
                                            &session_established_tx,
                                            sessions.len(),
                                            &mut connecting_sessions,
                                            &mut delay_queue,
                                        );
                                    }
                                }
                                UdpQueueEvent::Connecting(key, sess_id) => {
                                    if connecting_sessions
                                        .get(&key)
                                        .is_some_and(|connecting| connecting.id == sess_id)
                                    {
                                        trace!(
                                            "UDP outbound connection timed out for src: {}, dst: {}",
                                            key.0, key.1
                                        );
                                        connecting_sessions.remove(&key);
                                    }
                                }
                            }
                        }

                        // 4. Inbound packets from local_r -> route & forward to remote
                        inbound_opt = local_r.next() => {
                            let mut packet = match inbound_opt {
                                Some(pkt) => pkt,
                                None => {
                                    trace!("UDP session local_r closed for {}", sess);
                                    break;
                                }
                            };

                            if let SocksAddr::Ip(addr) = &mut packet.dst_addr {
                                addr.set_ip(addr.ip().to_canonical());
                            }
                            if let SocksAddr::Ip(addr) = &mut packet.src_addr {
                                addr.set_ip(addr.ip().to_canonical());
                            }

                            if !allow_quic.load(Ordering::Relaxed) && packet.dst_addr.port() == 443 {
                                trace!(
                                    "QUIC packet dropped (UDP 443) from {} to {}",
                                    packet.src_addr, packet.dst_addr
                                );
                                continue;
                            }

                            let Some(src_addr) = (match packet.src_addr {
                                SocksAddr::Ip(addr) => Some(addr),
                                SocksAddr::Domain(..) => None,
                            }) else {
                                warn!(
                                    "dropping inbound udp packet with non-ip source {}",
                                    packet.src_addr
                                );
                                continue;
                            };

                            let orig_inbound_dst = packet.dst_addr.clone();
                            let session_key = (src_addr, orig_inbound_dst.clone());

                            // Fast-path: Check if an active session already exists for this exact flow
                            if let Some(session) = sessions.get_mut(&session_key) {
                                debug!("reusing session #{} sent to remote {}", session.id, session.dest);
                                if session.is_short_flow {
                                    session.upload_count += 1;
                                    if session.upload_count > 2 {
                                        session.is_short_flow = false;
                                    }
                                }
                                let next_timeout = if session.is_short_flow {
                                    SHORT_FLOW_INIT_TIMEOUT
                                } else {
                                    timeout_duration
                                };
                                session.refresh_idle(&mut delay_queue, next_timeout);
                                if let Some(returned_packet) = forward_to_remote(
                                    &session.sender,
                                    packet,
                                    session.id,
                                ) {
                                    packet = returned_packet;
                                    let dead_session = sessions.remove(&session_key).unwrap();
                                    delay_queue.remove(&dead_session.delay_key);
                                } else {
                                    continue;
                                }
                            }

                            // If this flow is currently establishing an outbound session, buffer the packet
                            if let Some(buf) = connecting_sessions.get_mut(&session_key) {
                                if buf.packets.len() < MAX_CONNECTING_PACKETS {
                                    buf.packets.push(packet);
                                }
                                continue;
                            }

                            // Check if this flow is currently in the pending sniff buffer
                            if let Some(pending) = pending_sniff_sessions.get_mut(&session_key) {
                                let dst_sock = packet.dst_addr.clone().try_into_socket_addr();
                                let outcome = if let (Some(s), Some(dst_sock)) = (sniffer.as_ref(), dst_sock) {
                                    s.sniff_udp_datagram_full(src_addr, dst_sock, &packet.data)
                                } else {
                                    crate::app::sniffer::SniffUdpOutcome::NotMatched
                                };

                                match outcome {
                                    crate::app::sniffer::SniffUdpOutcome::Incomplete => {
                                        if pending.packets.len() < MAX_PENDING_SNIFF_PACKETS {
                                            pending.packets.push(packet);
                                            continue;
                                        }
                                        // Buffer full, flush with cached session
                                        let pending = pending_sniff_sessions.remove(&session_key).unwrap();
                                        delay_queue.remove(&pending.delay_key);
                                        let mut packets = pending.packets;
                                        packets.push(packet);

                                        start_connecting_session(
                                            pending.sess,
                                            packets,
                                            false,
                                            &ctx,
                                            &session_established_tx,
                                            sessions.len(),
                                            &mut connecting_sessions,
                                            &mut delay_queue,
                                        );
                                    }
                                    crate::app::sniffer::SniffUdpOutcome::Domain(domain, should_override) => {
                                        let mut pending = pending_sniff_sessions.remove(&session_key).unwrap();
                                        delay_queue.remove(&pending.delay_key);
                                        pending.sess.destination = SocksAddr::Domain(domain.clone().into(), orig_inbound_dst.port());
                                        pending.sess.sniffed_domain = Some(domain);

                                        let mut packets = pending.packets;
                                        packets.push(packet);

                                        start_connecting_session(
                                            pending.sess,
                                            packets,
                                            should_override,
                                            &ctx,
                                            &session_established_tx,
                                            sessions.len(),
                                            &mut connecting_sessions,
                                            &mut delay_queue,
                                        );
                                    }
                                    _ => {
                                        // CompleteNoDomain or NotMatched
                                        let pending = pending_sniff_sessions.remove(&session_key).unwrap();
                                        delay_queue.remove(&pending.delay_key);
                                        let mut packets = pending.packets;
                                        packets.push(packet);

                                        start_connecting_session(
                                            pending.sess,
                                            packets,
                                            false,
                                            &ctx,
                                            &session_established_tx,
                                            sessions.len(),
                                            &mut connecting_sessions,
                                            &mut delay_queue,
                                        );
                                    }
                                }
                                continue;
                            }

                            // Fresh flow (first packet):
                            // 1. DNS / Fake-IP reverse lookup to resolve destination (Fake-IP > original target)
                            let Some(target_dest) = reverse_lookup(
                                &ctx.resolver,
                                &orig_inbound_dst,
                                force_dns_mapping,
                            ) else {
                                warn!("failed to resolve UDP destination {}", orig_inbound_dst);
                                continue;
                            };
                            let mapped_domain = if !orig_inbound_dst.is_domain() {
                                target_dest.domain().map(|d| d.to_string())
                            } else {
                                None
                            };

                            let mut flow_sess = make_udp_flow_session(
                                &sess,
                                src_addr,
                                orig_inbound_dst.clone(),
                                target_dest.clone(),
                                mapped_domain,
                                packet.inbound_user.clone(),
                            );

                            // 2. Determine if sniffing is needed
                            let should_sniff = sniffer.as_ref().map_or(false, |s| {
                                if target_dest.is_domain() {
                                    // Known domain: only sniff if explicitly configured in force-domain
                                    s.should_force_sniff(&target_dest) || s.should_force_sniff(&orig_inbound_dst)
                                } else {
                                    // Pure IP: follow parse_pure_ip configuration
                                    s.parse_pure_ip()
                                }
                            });

                            // 3. Fast-path: no sniffing needed (Fake-IP / domain inbound / pure IP with parse_pure_ip=false)
                            if !should_sniff {
                                start_connecting_session(
                                    flow_sess,
                                    vec![packet],
                                    false,
                                    &ctx,
                                    &session_established_tx,
                                    sessions.len(),
                                    &mut connecting_sessions,
                                    &mut delay_queue,
                                );
                                continue;
                            }

                            // 4. Sniffing path: perform QUIC SNI sniffing
                            let mut override_dest = false;
                            let mut should_buffer = false;

                            if let Some(ref sniffer) = sniffer {
                                let outcome = if let Some(dst_sock) = packet.dst_addr.clone().try_into_socket_addr() {
                                    sniffer.sniff_udp_datagram_full(src_addr, dst_sock, &packet.data)
                                } else {
                                    match sniffer.sniff_datagram(packet.dst_addr.port(), &packet.data) {
                                        Some((d, o)) => crate::app::sniffer::SniffUdpOutcome::Domain(d, o),
                                        None => crate::app::sniffer::SniffUdpOutcome::NotMatched,
                                    }
                                };

                                match outcome {
                                    crate::app::sniffer::SniffUdpOutcome::Incomplete => {
                                        should_buffer = true;
                                    }
                                    crate::app::sniffer::SniffUdpOutcome::Domain(domain, should_override) => {
                                        flow_sess.sniffed_domain = Some(domain.clone());
                                        flow_sess.destination = SocksAddr::Domain(domain.into(), packet.dst_addr.port());
                                        override_dest = should_override;
                                    }
                                    _ => {}
                                }
                            }

                            if should_buffer {
                                trace!("buffering incomplete QUIC packet for {} -> {}", src_addr, orig_inbound_dst);
                                let delay_key = delay_queue.insert(
                                    UdpQueueEvent::PendingSniff(session_key.clone()),
                                    PENDING_SNIFF_TIMEOUT,
                                );
                                pending_sniff_sessions.insert(
                                    session_key,
                                    PendingSniffSession {
                                        delay_key,
                                        packets: vec![packet],
                                        sess: flow_sess,
                                    },
                                );
                                continue;
                            }

                            start_connecting_session(
                                flow_sess,
                                vec![packet],
                                override_dest,
                                &ctx,
                                &session_established_tx,
                                sessions.len(),
                                &mut connecting_sessions,
                                &mut delay_queue,
                            );
                        }
                    }
                }
                trace!("UDP session actor finished for {}", sess);
            }
            .instrument(current_span),
        );

        close_sender
    }
}

fn start_connecting_session(
    sess: Session,
    packets: Vec<UdpPacket>,
    override_dest: bool,
    ctx: &UdpDispatchContext,
    established_tx: &tokio::sync::mpsc::Sender<EstablishOutcome>,
    active_session_count: usize,
    connecting_sessions: &mut HashMap<SessionKey, ConnectingSession>,
    delay_queue: &mut DelayQueue<UdpQueueEvent>,
) {
    if connecting_sessions.len() >= MAX_CONNECTING_SESSIONS {
        debug!(
            "too many UDP outbound connections in progress, dropping flow {} -> {}",
            sess.source, sess.destination
        );
        return;
    }
    if active_session_count + connecting_sessions.len() >= MAX_UDP_SESSIONS_PER_ACTOR
    {
        debug!(
            "UDP outbound session limit reached for actor, dropping flow {} -> {}",
            sess.source, sess.destination
        );
        return;
    }
    let Ok(capacity_permit) = ctx.session_semaphore.clone().try_acquire_owned()
    else {
        debug!(
            "global UDP outbound session limit reached, dropping flow {} -> {}",
            sess.source, sess.destination
        );
        return;
    };

    let session_key = (
        sess.source,
        sess.orig_destination
            .clone()
            .unwrap_or_else(|| sess.destination.clone()),
    );
    let sess_id = sess.id;
    let delay_key = delay_queue.insert(
        UdpQueueEvent::Connecting(session_key.clone(), sess_id),
        CONNECTING_SESSION_TIMEOUT,
    );
    let establish_handle = spawn_establish_session(
        sess,
        override_dest,
        ctx,
        established_tx,
        capacity_permit,
    );

    connecting_sessions.insert(
        session_key,
        ConnectingSession {
            id: sess_id,
            delay_key,
            packets,
            establish_handle,
        },
    );
}

fn spawn_establish_session(
    sess: Session,
    override_dest: bool,
    ctx: &UdpDispatchContext,
    established_tx: &tokio::sync::mpsc::Sender<EstablishOutcome>,
    capacity_permit: tokio::sync::OwnedSemaphorePermit,
) -> JoinHandle<()> {
    let ctx = ctx.clone();
    let established_tx = established_tx.clone();
    let sess_id = sess.id;
    let session_key = (
        sess.source,
        sess.orig_destination
            .clone()
            .unwrap_or_else(|| sess.destination.clone()),
    );

    tokio::spawn(async move {
        let outcome = match establish_outbound_session(
            sess,
            override_dest,
            &ctx,
            established_tx.clone(),
        )
        .await
        {
            Some(established) => {
                EstablishOutcome::Success(established, capacity_permit)
            }
            None => EstablishOutcome::Failed(session_key, sess_id),
        };
        let _ = established_tx.send(outcome).await;
    })
}

async fn establish_outbound_session(
    mut sess: Session,
    override_dest: bool,
    ctx: &UdpDispatchContext,
    established_tx: tokio::sync::mpsc::Sender<EstablishOutcome>,
) -> Option<EstablishedSession> {
    let orig_inbound_dst = sess
        .orig_destination
        .clone()
        .unwrap_or_else(|| sess.destination.clone());
    let orig_dst_ip = orig_inbound_dst.ip();
    let is_fake_ip = orig_dst_ip.map_or(false, |ip| ctx.resolver.is_fake_ip(ip));
    let is_real_ip = match orig_dst_ip {
        Some(_) => !is_fake_ip,
        None => false,
    };
    if is_real_ip {
        sess.resolved_ip = orig_dst_ip;
    }

    let mode = decode_mode(ctx.mode.load(Ordering::Relaxed));
    let (outbound_name, rule) = match mode {
        RunMode::Global => (PROXY_GLOBAL, None),
        RunMode::Rule => ctx.router.match_route(&mut sess).await,
        RunMode::Direct => (PROXY_DIRECT, None),
    };

    if !override_dest && is_real_ip {
        sess.destination = orig_inbound_dst.clone();
    }

    let handler = match ctx.outbound_manager.get_outbound(outbound_name) {
        Some(h) => h,
        None => {
            debug!("unknown rule: {}, fallback to direct", outbound_name);
            ctx.outbound_manager.get_outbound(PROXY_DIRECT).unwrap()
        }
    };

    let effective_proto = if let Some(group) = handler.try_as_group_handler() {
        match group.get_active_proxy().await {
            Some(active) => active.proto(),
            None => handler.proto(),
        }
    } else {
        handler.proto()
    };
    if matches!(effective_proto, OutboundType::Reject) {
        trace!(
            "[UDP Short-Circuit] Drop packet immediately for sess: {}",
            sess
        );
        return None;
    }

    debug!(
        "building {} outbound datagram connecting to {}",
        sess, sess.destination
    );
    let outbound_datagram = match handler
        .connect_datagram(&sess, ctx.resolver.clone())
        .await
    {
        Ok(v) => v,
        Err(err) => {
            if is_reject_error(&err) {
                trace!(
                    "[UDP Short-Circuit] Drop packet immediately for sess: {}",
                    sess
                );
            } else {
                error!("failed to connect outbound: sess = {} ,err = {}", sess, err);
            }
            return None;
        }
    };

    // Groups return the selected transport, including nested selectors and
    // per-flow strategies. Only a physical Direct socket preserves peer sources.
    let is_direct = matches!(outbound_datagram, AnyOutboundDatagram::Direct(_));

    debug!("{} outbound datagram connected", sess);

    let tracker_info = Arc::new(TrackerInfo::new(&sess, rule));
    let established = dispatch_datagram!(outbound_datagram, |datagram| {
        spawn_udp_relay(
            datagram,
            sess,
            orig_inbound_dst,
            ctx,
            established_tx,
            tracker_info,
            (is_fake_ip, is_direct),
        )
    });
    Some(established)
}

/// Monomorphize the packet loop after selecting the transport once per session.
fn spawn_udp_relay<D: OutboundDatagram<UdpPacket>>(
    outbound_datagram: D,
    sess: Session,
    orig_inbound_dst: SocksAddr,
    ctx: &UdpDispatchContext,
    established_tx: tokio::sync::mpsc::Sender<EstablishOutcome>,
    tracker_info: Arc<TrackerInfo>,
    (is_fake_ip, is_direct): (bool, bool),
) -> EstablishedSession {
    let (close_tx, close_rx) = tokio::sync::oneshot::channel();
    ctx.manager.track(sess.id, tracker_info.clone(), close_tx);
    let track_guard = TrackGuard::new(sess.id, ctx.manager.clone());

    let (remote_sender, remote_forwarder) =
        tokio::sync::mpsc::channel::<UdpPacket>(UDP_CHANNEL_CAPACITY);

    let relay_dest = sess.destination.clone();
    let orig_inbound_dst_for_relay = orig_inbound_dst.clone();
    let relay_sess = sess.clone();
    let relay_session_key = (sess.source, orig_inbound_dst.clone());
    let relay_sess_id = sess.id;
    let reply_sender = ctx.reply_sender.clone();
    let allow_quic = ctx.allow_quic.clone();
    let reply_activity = Arc::new(UdpReplyActivity::new());
    let relay_reply_activity = reply_activity.clone();
    let tracker = TrafficTracker::new(tracker_info, ctx.manager.clone());
    let (relay_start, relay_start_rx) = tokio::sync::oneshot::channel();

    let relay_handle = tokio::spawn(async move {
        let _guard = track_guard;
        // Do not let a short-lived outbound report termination before the
        // actor has installed the corresponding session entry.
        if relay_start_rx.await.is_err() {
            return;
        }

        let mut forward_reply = |mut packet: UdpPacket| {
            tracker.push_download(packet.data.len());

            // Only allow preserving unmapped peer source addresses (for Full-Cone NAT P2P hole punching)
            // when using Direct outbound and the destination is not Fake-IP.
            // In all other cases (e.g. Fake-IP sessions, or proxy outbounds like Shadowsocks returning
            // physical server IPs), the packet's source address must always be restored to orig_inbound_dst.
            let should_rewrite_source = is_fake_ip
                || !is_direct
                || packet.src_addr == orig_inbound_dst_for_relay
                || packet.src_addr == relay_sess.destination;
            if should_rewrite_source {
                packet.src_addr = orig_inbound_dst_for_relay.clone();
            }

            packet.dst_addr = relay_sess.source.into();
            debug!("UDP NAT for packet: {:?}, session: {}", packet, relay_sess);
            if !allow_quic.load(Ordering::Relaxed) && packet.src_addr.port() == 443 {
                trace!("QUIC reply packet dropped (UDP 443) from {}", packet.src_addr);
                return true;
            }
            relay_reply_activity.record();
            match reply_sender.try_send(packet) {
                Ok(_) => {}
                Err(TrySendError::Full(_)) => {
                    debug!(
                        "[UDP NAT] Backpressure: inbound reply queue is full for sess: {}",
                        relay_sess
                    );
                }
                Err(TrySendError::Closed(_)) => {
                    debug!(
                        "[UDP NAT] reply channel closed, ending session: {}",
                        relay_sess
                    );
                    return false;
                }
            }
            true
        };

        let relay = relay_datagram(
            outbound_datagram,
            remote_forwarder,
            &relay_dest,
            |len| tracker.push_upload(len),
            &mut forward_reply,
        );
        tokio::select! {
            _ = relay => {}
            _ = close_rx => {}
        }

        let _ = established_tx
            .send(EstablishOutcome::Terminated(
                relay_session_key,
                relay_sess_id,
            ))
            .await;
    });

    EstablishedSession {
        session_key: (sess.source, orig_inbound_dst),
        sess_id: sess.id,
        dest: sess.destination,
        sender: remote_sender,
        relay_handle,
        relay_start,
        reply_activity,
    }
}

/// Drive both directions without splitting the transport. Retain each send
/// across Pending, including DNS/socket backpressure, while continuing reads.
async fn relay_datagram<D, W, R>(
    mut datagram: D,
    mut outgoing: tokio::sync::mpsc::Receiver<UdpPacket>,
    destination: &SocksAddr,
    mut on_sent: W,
    mut on_received: R,
) where
    D: OutboundDatagram<UdpPacket>,
    W: FnMut(usize),
    R: FnMut(UdpPacket) -> bool,
{
    use std::{pin::Pin, task::Poll};

    enum Event {
        Sent(std::io::Result<usize>),
        Received(UdpPacket),
        Closed,
    }

    fn poll_send<D: OutboundDatagram<UdpPacket>>(
        datagram: &mut D,
        outgoing: &mut tokio::sync::mpsc::Receiver<UdpPacket>,
        destination: &SocksAddr,
        queued: &mut Option<UdpPacket>,
        flushing: &mut Option<usize>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Event> {
        if flushing.is_none() && queued.is_none() {
            match outgoing.poll_recv(cx) {
                Poll::Ready(Some(mut packet)) => {
                    if packet.dst_addr != *destination {
                        packet.dst_addr = destination.clone();
                    }
                    *queued = Some(packet);
                }
                Poll::Ready(None) => return Poll::Ready(Event::Closed),
                Poll::Pending => return Poll::Pending,
            }
        }
        if let Some(packet) = queued.as_ref() {
            match Pin::new(&mut *datagram).poll_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => {
                    *queued = None;
                    return Poll::Ready(Event::Sent(Err(err)));
                }
                Poll::Pending => return Poll::Pending,
            }
            let len = packet.data.len();
            let packet = queued.take().unwrap();
            if let Err(err) = Pin::new(&mut *datagram).start_send(packet) {
                return Poll::Ready(Event::Sent(Err(err)));
            }
            *flushing = Some(len);
        }
        match Pin::new(datagram).poll_flush(cx) {
            Poll::Ready(result) => {
                let len = flushing.take().unwrap();
                Poll::Ready(Event::Sent(result.map(|()| len)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    let mut queued = None::<UdpPacket>;
    let mut flushing = None::<usize>;
    let mut read_first = true;
    loop {
        let event = futures::future::poll_fn(|cx| {
            // Alternate priority so either continuously ready direction cannot
            // starve the other. A Pending send never prevents polling reads.
            if !read_first {
                if let Poll::Ready(event) = poll_send(
                    &mut datagram,
                    &mut outgoing,
                    destination,
                    &mut queued,
                    &mut flushing,
                    cx,
                ) {
                    return Poll::Ready(event);
                }
            }
            match Pin::new(&mut datagram).poll_next(cx) {
                Poll::Ready(Some(packet)) => {
                    return Poll::Ready(Event::Received(packet));
                }
                Poll::Ready(None) => return Poll::Ready(Event::Closed),
                Poll::Pending => {}
            }
            if read_first {
                poll_send(
                    &mut datagram,
                    &mut outgoing,
                    destination,
                    &mut queued,
                    &mut flushing,
                    cx,
                )
            } else {
                Poll::Pending
            }
        })
        .await;
        match event {
            Event::Sent(Ok(len)) => on_sent(len),
            Event::Sent(Err(err)) => {
                warn!("failed to send packet to remote: {err:?}")
            }
            Event::Received(packet) => {
                if !on_received(packet) {
                    break;
                }
            }
            Event::Closed => break,
        }
        read_first = !read_first;
        tokio::task::consume_budget().await;
    }
}

fn decode_mode(raw: u8) -> RunMode {
    match raw {
        0 => RunMode::Global,
        1 => RunMode::Rule,
        2 => RunMode::Direct,
        _ => unreachable!("mode is only ever written from a RunMode"),
    }
}

/// `proxy/reject/mod.rs` signals a rejected connection with
/// `io::Error::other("REJECT")`. The type-based short-circuit in
/// `dispatch_datagram` catches the common cases, but a nested group can still
/// surface this here, so recognise it and stay quiet instead of logging an
/// error for traffic the config asked us to drop.
fn is_reject_error(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::Other
        && err.get_ref().is_some_and(|e| e.to_string() == "REJECT")
}

/// Hand a packet to a session's relay task without ever awaiting.
///
/// A packet is returned only when the relay has already gone away, allowing
/// the actor to remove the stale session and route that packet through a new
/// outbound association.
fn forward_to_remote(
    sender: &OutboundPacketSender,
    packet: UdpPacket,
    sess_id: u64,
) -> Option<UdpPacket> {
    match sender.try_send(packet) {
        Ok(_) => None,
        Err(TrySendError::Full(_)) => {
            debug!(
                "[UDP] outbound queue full, dropping packet for session #{}",
                sess_id
            );
            None
        }
        Err(TrySendError::Closed(packet)) => {
            debug!("[UDP] outbound relay gone, rebuilding session #{}", sess_id);
            Some(packet)
        }
    }
}

// helper function to resolve the destination address
// if the destination is an IP address, check if it's a fake IP
// or look for cached IP
// if the destination is a domain name, don't resolve
fn reverse_lookup(
    resolver: &Arc<dyn ClashResolver>,
    dst: &SocksAddr,
    force_dns_mapping: bool,
) -> Option<SocksAddr> {
    // A malformed host is client-controlled input on a hot path, so surface it
    // as a dropped packet rather than a panic that kills the relay task.
    fn to_addr(host: String, port: u16) -> Option<SocksAddr> {
        match SocksAddr::try_from((host, port)) {
            Ok(addr) => Some(addr),
            Err(err) => {
                warn!("ignoring invalid destination host: {}", err);
                None
            }
        }
    }

    let dst = match dst {
        SocksAddr::Ip(socket_addr) => {
            let ip = socket_addr.ip();
            if resolver.fake_ip_enabled() && resolver.is_fake_ip(ip) {
                trace!("looking up fake ip: {}", ip);
                let host = resolver.reverse_lookup(ip);
                match host {
                    Some(host) => to_addr(host, socket_addr.port())?,
                    None => {
                        error!("failed to reverse lookup fake ip: {}", ip);
                        return None;
                    }
                }
            } else if force_dns_mapping || !resolver.fake_ip_enabled() {
                trace!("looking up resolve cache ip: {}", ip);
                match resolver.cached_for(ip) {
                    Some(resolved) => to_addr(resolved, socket_addr.port())?,
                    _ => (*socket_addr).into(),
                }
            } else {
                (*socket_addr).into()
            }
        }
        SocksAddr::Domain(host, port) => SocksAddr::Domain(host.clone(), *port),
    };
    Some(dst)
}

#[cfg(test)]
mod tests {
    use futures::{Sink, Stream};
    use std::{io, task::{Context, Poll}};
    use super::*;

    /// Flush remains pending until the test releases a token, independently of reads.
    #[derive(Debug)]
    struct BackpressuredDatagram {
        replies: tokio::sync::mpsc::Receiver<UdpPacket>,
        permits: tokio::sync::mpsc::Receiver<()>,
        sent: tokio::sync::mpsc::Sender<UdpPacket>,
        staged: Option<UdpPacket>,
        started: tokio::sync::mpsc::Sender<()>,
        fail_first: bool,
    }

    impl Stream for BackpressuredDatagram {
        type Item = UdpPacket;
        fn poll_next(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<UdpPacket>> {
            self.replies.poll_recv(cx)
        }
    }

    impl Sink<UdpPacket> for BackpressuredDatagram {
        type Error = io::Error;
        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            assert!(
                self.staged.is_none(),
                "send restarted before flush completed"
            );
            Poll::Ready(Ok(()))
        }
        fn start_send(
            mut self: Pin<&mut Self>,
            packet: UdpPacket,
        ) -> Result<(), Self::Error> {
            assert!(self.staged.replace(packet).is_none());
            self.started.try_send(()).unwrap();
            Ok(())
        }
        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            if self.staged.is_none() {
                return Poll::Ready(Ok(()));
            }
            futures::ready!(self.permits.poll_recv(cx))
                .expect("permit channel closed");
            let packet = self.staged.take().unwrap();
            if self.fail_first {
                self.fail_first = false;
                return Poll::Ready(Err(io::Error::other(
                    "test send failure",
                )));
            }
            self.sent.try_send(packet).unwrap();
            Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.poll_flush(cx)
        }
    }

    #[tokio::test]
    async fn unsplit_relay_reads_during_backpressure_and_retains_sends() {
        check_unsplit_backpressure(false).await;
    }

    #[tokio::test]
    async fn unsplit_relay_continues_after_send_error() {
        check_unsplit_backpressure(true).await;
    }

    async fn check_unsplit_backpressure(fail_first: bool) {
        let (outgoing_tx, outgoing_rx) = tokio::sync::mpsc::channel(4);
        let (reply_tx, reply_rx) = tokio::sync::mpsc::channel(4);
        let (permit_tx, permit_rx) = tokio::sync::mpsc::channel(4);
        let (sent_tx, mut sent_rx) = tokio::sync::mpsc::channel(4);
        let (received_tx, mut received_rx) = tokio::sync::mpsc::channel(4);
        let (count_tx, mut count_rx) = tokio::sync::mpsc::channel(4);
        let (started_tx, mut started_rx) = tokio::sync::mpsc::channel(4);
        let destination: SocksAddr =
            "127.0.0.1:12345".parse::<SocketAddr>().unwrap().into();
        let expected_destination = destination.clone();
        for data in [b"first".as_slice(), b"second".as_slice()] {
            outgoing_tx
                .send(UdpPacket {
                    data: bytes::Bytes::copy_from_slice(data),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        drop(outgoing_tx);
        let relay = tokio::spawn(async move {
            relay_datagram(
                AnyOutboundDatagram::dynamic(BackpressuredDatagram {
                    replies: reply_rx,
                    permits: permit_rx,
                    sent: sent_tx,
                    staged: None,
                    started: started_tx,
                    fail_first,
                }),
                outgoing_rx,
                &destination,
                |len| count_tx.try_send(len).unwrap(),
                |packet| {
                    received_tx.try_send(packet).unwrap();
                    true
                },
            )
            .await;
        });
        tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
            .await
            .unwrap()
            .unwrap();
        // No flush tokens: replies must still progress, and upload accounting
        // must wait for actual completion rather than start_send.
        reply_tx
            .send(UdpPacket {
                data: bytes::Bytes::from_static(b"reply"),
                ..Default::default()
            })
            .await
            .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), received_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply.data.as_ref(), b"reply");
        assert!(count_rx.try_recv().is_err());
        assert!(!relay.is_finished());
        permit_tx.send(()).await.unwrap();
        permit_tx.send(()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap();
        let first = sent_rx.recv().await.unwrap();
        assert_eq!(first.dst_addr, expected_destination);
        if fail_first {
            assert_eq!(first.data.as_ref(), b"second");
            assert_eq!(count_rx.recv().await, Some(6));
        } else {
            assert_eq!(first.data.as_ref(), b"first");
            assert_eq!(sent_rx.recv().await.unwrap().data.as_ref(), b"second");
            assert_eq!(count_rx.recv().await, Some(5));
            assert_eq!(count_rx.recv().await, Some(6));
        }
        assert!(sent_rx.recv().await.is_none());
        assert!(count_rx.recv().await.is_none());
    }
    use crate::app::dispatcher::StatisticsManager;
    use crate::app::dns::MockClashResolver;
    use crate::app::outbound::manager::OutboundManager;
    use crate::app::router::Router;
    use crate::proxy::{AnyOutboundHandler, loadbalance, selector};
    use crate::proxy::mocks::MockDummyProxyProvider;
    use crate::app::remote_content_manager::ProxyManager;
    use crate::proxy::direct::Handler as DirectHandler;
    use crate::proxy::datagram::ChannelDatagram;
    use crate::session::{Network, Type};
    use bytes::Bytes;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use tokio::net::UdpSocket;

    #[test]
    fn reverse_lookup_rejects_unmapped_fake_ip() {
        let fake_ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
        let mut resolver = MockClashResolver::new();
        resolver.expect_fake_ip_enabled().return_const(true);
        resolver
            .expect_is_fake_ip()
            .returning(move |ip| ip == fake_ip);
        resolver.expect_reverse_lookup().return_const(None);
        let resolver: Arc<dyn ClashResolver> = Arc::new(resolver);

        let dst = SocksAddr::Ip(SocketAddr::new(fake_ip, 443));
        assert_eq!(reverse_lookup(&resolver, &dst, false), None);
    }

    #[tokio::test]
    async fn closed_relay_returns_packet_for_reconnect() {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        drop(receiver);

        let src = SocksAddr::Ip("127.0.0.1:12345".parse().unwrap());
        let dst = SocksAddr::Domain("example.com".into(), 443);
        let packet =
            UdpPacket::new(Bytes::from_static(b"hello"), src.clone(), dst.clone());

        let returned = forward_to_remote(&sender, packet, 42)
            .expect("closed relay must return the packet");
        assert_eq!(returned.data, Bytes::from_static(b"hello"));
        assert_eq!(returned.src_addr, src);
        assert_eq!(returned.dst_addr, dst);
    }

    #[tokio::test]
    async fn dropping_connecting_session_aborts_establish_task() {
        struct NotifyOnDrop(Option<tokio::sync::oneshot::Sender<()>>);

        impl Drop for NotifyOnDrop {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let establish_handle = tokio::spawn(async move {
            let _notify = NotifyOnDrop(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();

        let mut delay_queue = DelayQueue::new();
        let delay_key = delay_queue.insert(
            UdpQueueEvent::Connecting(
                (
                    "127.0.0.1:12345".parse().unwrap(),
                    SocksAddr::Domain("example.com".into(), 443),
                ),
                42,
            ),
            CONNECTING_SESSION_TIMEOUT,
        );
        let connecting = ConnectingSession {
            id: 42,
            delay_key,
            packets: Vec::new(),
            establish_handle,
        };

        drop(connecting);
        tokio::time::timeout(Duration::from_secs(1), dropped_rx)
            .await
            .expect("aborted establish task was not dropped")
            .unwrap();
    }

    #[tokio::test]
    async fn active_session_retains_global_capacity_permit_until_drop() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let mut delay_queue = DelayQueue::new();
        let delay_key = delay_queue.insert(
            UdpQueueEvent::SessionIdle((
                "127.0.0.1:12345".parse().unwrap(),
                SocksAddr::Domain("example.com".into(), 443),
            )),
            Duration::from_secs(60),
        );
        let relay_handle = tokio::spawn(std::future::pending::<()>());

        let session = OutboundSession {
            id: 42,
            dest: SocksAddr::Domain("example.com".into(), 443),
            sender,
            delay_key,
            idle_deadline: Instant::now() + Duration::from_secs(60),
            scheduled_deadline: Instant::now() + Duration::from_secs(60),
            last_upload: Instant::now(),
            reply_activity: Arc::new(UdpReplyActivity::new()),
            _relay_handle: relay_handle,
            _capacity_permit: permit,
            upload_count: 1,
            is_short_flow: false,
        };

        assert_eq!(semaphore.available_permits(), 0);
        drop(session);
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn active_session_defers_timer_reset_until_its_scheduled_deadline() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.acquire_owned().await.unwrap();
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let mut delay_queue = DelayQueue::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        let delay_key = delay_queue.insert_at(
            UdpQueueEvent::SessionIdle((
                "127.0.0.1:12345".parse().unwrap(),
                SocksAddr::Ip("1.1.1.1:53".parse().unwrap()),
            )),
            deadline,
        );
        let relay_handle = tokio::spawn(std::future::pending::<()>());
        let mut session = OutboundSession {
            id: 42,
            dest: SocksAddr::Ip("1.1.1.1:53".parse().unwrap()),
            sender,
            delay_key,
            idle_deadline: deadline,
            scheduled_deadline: deadline,
            last_upload: Instant::now(),
            reply_activity: Arc::new(UdpReplyActivity::new()),
            _relay_handle: relay_handle,
            _capacity_permit: permit,
            upload_count: 1,
            is_short_flow: true,
        };

        let queued_deadline = delay_queue.deadline(&session.delay_key);
        session.refresh_idle(&mut delay_queue, Duration::from_secs(60));
        assert_eq!(delay_queue.deadline(&session.delay_key), queued_deadline);
        assert!(session.idle_deadline > session.scheduled_deadline);

        session.refresh_idle(&mut delay_queue, Duration::from_secs(1));
        assert!(delay_queue.deadline(&session.delay_key) < queued_deadline);
        assert_eq!(session.idle_deadline, session.scheduled_deadline);
    }

    #[tokio::test(start_paused = true)]
    async fn reply_activity_obeys_latest_direction_and_short_flow_timeout() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.acquire_owned().await.unwrap();
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let mut delay_queue = DelayQueue::new();
        let now = Instant::now();
        let delay_key = delay_queue.insert_at(
            UdpQueueEvent::SessionIdle((
                "127.0.0.1:12345".parse().unwrap(),
                SocksAddr::Ip("1.1.1.1:53".parse().unwrap()),
            )),
            now + FAST_RESPONSE_TIMEOUT,
        );
        let mut session = OutboundSession {
            id: 42,
            dest: SocksAddr::Ip("1.1.1.1:53".parse().unwrap()),
            sender,
            delay_key,
            idle_deadline: now + SHORT_FLOW_INIT_TIMEOUT,
            scheduled_deadline: now + FAST_RESPONSE_TIMEOUT,
            last_upload: now,
            reply_activity: Arc::new(UdpReplyActivity::new()),
            _relay_handle: tokio::spawn(std::future::pending::<()>()),
            _capacity_permit: permit,
            upload_count: 1,
            is_short_flow: true,
        };
        let timeout = Duration::from_secs(60);
        assert_eq!(session.latest_idle_deadline(timeout), now + SHORT_FLOW_INIT_TIMEOUT);

        tokio::time::advance(Duration::from_secs(1)).await;
        session.reply_activity.record();
        assert_eq!(session.latest_idle_deadline(timeout), Instant::now() + FAST_RESPONSE_TIMEOUT);

        tokio::time::advance(Duration::from_secs(1)).await;
        session.refresh_idle(&mut delay_queue, SHORT_FLOW_INIT_TIMEOUT);
        assert_eq!(session.latest_idle_deadline(timeout), Instant::now() + SHORT_FLOW_INIT_TIMEOUT);

        // Once uploads promote the flow, later replies use the normal timeout.
        session.is_short_flow = false;
        tokio::time::advance(Duration::from_secs(1)).await;
        session.reply_activity.record();
        assert_eq!(session.latest_idle_deadline(timeout), Instant::now() + timeout);
    }

    #[test]
    fn test_short_flow_ports() {
        assert!(is_short_flow_port(53));
        assert!(is_short_flow_port(123));
        assert!(is_short_flow_port(5353));
        assert!(!is_short_flow_port(3478));
        assert!(!is_short_flow_port(5349));
        assert!(!is_short_flow_port(443));
        assert!(!is_short_flow_port(80));
    }

    #[derive(Debug)]
    struct MockInboundDatagram {
        rx: tokio::sync::mpsc::Receiver<UdpPacket>,
        tx: tokio::sync::mpsc::Sender<UdpPacket>,
    }

    impl futures::Stream for MockInboundDatagram {
        type Item = UdpPacket;

        fn poll_next(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            self.rx.poll_recv(cx)
        }
    }

    impl futures::Sink<UdpPacket> for MockInboundDatagram {
        type Error = std::io::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn start_send(
            self: Pin<&mut Self>,
            item: UdpPacket,
        ) -> Result<(), Self::Error> {
            self.tx
                .try_send(item)
                .map_err(|e| std::io::Error::other(e.to_string()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn test_provider(handler: AnyOutboundHandler) -> Arc<MockDummyProxyProvider> {
        let mut provider = MockDummyProxyProvider::new();
        let proxies = Arc::new(vec![handler]);
        provider.expect_proxies().returning(move || proxies.clone());
        provider.expect_touch().return_const(());
        Arc::new(provider)
    }

    async fn test_dispatcher(proto: OutboundType) -> Arc<Dispatcher> {
        let direct_handler: AnyOutboundHandler =
            Arc::new(DirectHandler::new("DIRECT"));
        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_fake_ip_enabled().returning(|| false);
        mock_resolver.expect_is_fake_ip().returning(|_| false);
        mock_resolver.expect_cached_for().returning(|_| None);
        mock_resolver
            .expect_resolve_v4()
            .returning(|_, _| Ok(Some(std::net::Ipv4Addr::LOCALHOST)));
        mock_resolver.expect_resolve().returning(|_, _| {
            Ok(Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)))
        });
        let resolver: ThreadSafeDNSResolver = Arc::new(mock_resolver);

        let handler = match proto {
            OutboundType::Selector => {
                let inner = selector::Handler::new(
                    selector::HandlerOptions {
                        name: "inner".into(),
                        udp: true,
                        ..Default::default()
                    },
                    vec![test_provider(direct_handler)],
                    None,
                ).await;
                Arc::new(selector::Handler::new(
                    selector::HandlerOptions {
                        name: "outer".into(),
                        udp: true,
                        ..Default::default()
                    },
                    vec![test_provider(Arc::new(inner))],
                    None,
                ).await) as AnyOutboundHandler
            }
            OutboundType::LoadBalance => Arc::new(loadbalance::Handler::new(
                loadbalance::HandlerOptions {
                    name: "balance".into(),
                    udp: true,
                    ..Default::default()
                },
                vec![test_provider(direct_handler)],
                ProxyManager::new(resolver.clone(), None),
            )) as AnyOutboundHandler,
            OutboundType::Direct => direct_handler,
            _ => unreachable!(),
        };
        let mut handlers = HashMap::new();
        handlers.insert("DIRECT".to_string(), handler);
        let outbound_manager = Arc::new(OutboundManager::new_for_test(handlers));

        let router = Arc::new(
            Router::new(
                vec![],
                HashMap::new(),
                resolver.clone(),
                None,
                None,
                None,
                None,
                None,
                "".to_string(),
            )
            .await
            .unwrap(),
        );

        let manager = StatisticsManager::new();
        Arc::new(Dispatcher::new(
            outbound_manager,
            router,
            resolver,
            RunMode::Direct,
            manager,
            None,
            None,
            true,
        ))
    }

    #[tokio::test]
    async fn inbound_backpressure_does_not_block_upstream_or_close() {
        check_inbound_backpressure(true).await;
    }

    #[tokio::test]
    async fn inbound_backpressure_does_not_block_expiration() {
        check_inbound_backpressure(false).await;
    }

    #[tokio::test]
    async fn downstream_only_activity_keeps_session_alive_until_idle() {
        let dispatcher = test_dispatcher(OutboundType::Direct).await;
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = SocksAddr::Ip(server.local_addr().unwrap());
        let source: SocketAddr = "127.0.0.1:54324".parse().unwrap();
        let sess = Session {
            network: Network::Udp,
            source,
            destination: destination.clone(),
            udp_timeout: Some(Duration::from_millis(500)),
            ..Default::default()
        };
        let (client_tx, inbound_rx) = tokio::sync::mpsc::channel(4);
        let (inbound_tx, mut client_rx) = tokio::sync::mpsc::channel(4);
        let _closer = dispatcher.dispatch_datagram(sess, Box::new(
            MockInboundDatagram { rx: inbound_rx, tx: inbound_tx },
        )).await;
        client_tx.send(UdpPacket::new(
            Bytes::from_static(b"request"), SocksAddr::Ip(source), destination,
        )).await.unwrap();
        let mut buf = [0u8; 64];
        let (_, outbound_addr) = tokio::time::timeout(
            Duration::from_secs(2), server.recv_from(&mut buf),
        ).await.unwrap().unwrap();
        let session_id = dispatcher.manager.active_connections_snapshot()[0].id;

        // Cross the initial idle deadline without any additional upstream packet.
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            server.send_to(b"reply", outbound_addr).await.unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
                .await.unwrap().unwrap();
            assert_eq!(reply.data.as_ref(), b"reply");
            assert_eq!(dispatcher.manager.active_connections_snapshot()[0].id, session_id);
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while dispatcher.udp_session_semaphore.available_permits()
                != MAX_GLOBAL_UDP_SESSIONS
                || !dispatcher.manager.active_connections_snapshot().is_empty()
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("downstream activity must expire after replies stop");
    }

    #[tokio::test]
    async fn direct_reply_delivery_honors_dynamic_quic_setting() {
        let dispatcher = test_dispatcher(OutboundType::Direct).await;
        dispatcher.set_quic(false);
        let (reply_sender, mut replies) = tokio::sync::mpsc::channel(4);
        let ctx = UdpDispatchContext {
            outbound_manager: dispatcher.outbound_manager.clone(),
            router: dispatcher.router.clone(),
            resolver: dispatcher.resolver.clone(),
            manager: dispatcher.manager.clone(),
            mode: dispatcher.mode.clone(),
            reply_sender,
            allow_quic: dispatcher.allow_quic.clone(),
            session_semaphore: dispatcher.udp_session_semaphore.clone(),
        };
        let sess = Session {
            network: Network::Udp,
            source: "127.0.0.1:54325".parse().unwrap(),
            destination: SocksAddr::Ip("127.0.0.1:443".parse().unwrap()),
            ..Default::default()
        };
        let tracker_info = Arc::new(TrackerInfo::new(&sess, None));
        let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(4);
        let (sent_tx, _sent_rx) = tokio::sync::mpsc::channel(4);
        let (established_tx, _established_rx) = tokio::sync::mpsc::channel(4);
        let established = spawn_udp_relay(
            ChannelDatagram::new(sent_tx, incoming_rx),
            sess.clone(),
            sess.destination.clone(),
            &ctx,
            established_tx,
            tracker_info.clone(),
            (false, false),
        );
        let _relay = AbortOnDropHandle::new(established.relay_handle);
        let _outgoing = established.sender;
        established.relay_start.send(()).unwrap();
        incoming_tx.send(UdpPacket {
            data: Bytes::from_static(b"blocked"),
            src_addr: SocksAddr::Ip("127.0.0.1:8443".parse().unwrap()),
            ..Default::default()
        }).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while tracker_info.download_total.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        assert!(replies.try_recv().is_err());
        assert!(established.reply_activity.latest().is_none());

        dispatcher.set_quic(true);
        incoming_tx.send(UdpPacket {
            data: Bytes::from_static(b"allowed"),
            src_addr: SocksAddr::Ip("127.0.0.1:8443".parse().unwrap()),
            ..Default::default()
        }).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), replies.recv())
            .await.unwrap().unwrap();
        assert_eq!(reply.data.as_ref(), b"allowed");
        assert_eq!(reply.src_addr, sess.destination);
        assert_eq!(reply.dst_addr, SocksAddr::Ip(sess.source));
        assert!(established.reply_activity.latest().is_some());
    }

    async fn check_inbound_backpressure(explicit_close: bool) {
        let dispatcher = test_dispatcher(OutboundType::Direct).await;
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = SocksAddr::Ip(server.local_addr().unwrap());
        let source: SocketAddr = "127.0.0.1:54323".parse().unwrap();
        let sess = Session {
            network: Network::Udp,
            source,
            destination: destination.clone(),
            udp_timeout: Some(Duration::from_millis(500)),
            ..Default::default()
        };
        let (client_tx, client_rx) = tokio::sync::mpsc::channel(4);
        let (_permit_tx, permit_rx) = tokio::sync::mpsc::channel(4);
        let (sent_tx, _sent_rx) = tokio::sync::mpsc::channel(4);
        let (started_tx, mut started_rx) = tokio::sync::mpsc::channel(4);
        let closer = dispatcher.dispatch_datagram(sess, Box::new(
            BackpressuredDatagram {
                replies: client_rx,
                permits: permit_rx,
                sent: sent_tx,
                staged: None,
                started: started_tx,
                fail_first: false,
            },
        )).await;
        let packet = UdpPacket::new(
            Bytes::from_static(b"request"),
            SocksAddr::Ip(source),
            destination,
        );
        client_tx.send(packet.clone()).await.unwrap();
        let mut buf = [0u8; 64];
        let (_, outbound_addr) = tokio::time::timeout(
            Duration::from_secs(2), server.recv_from(&mut buf),
        ).await.unwrap().unwrap();
        server.send_to(b"reply", outbound_addr).await.unwrap();
        // The inbound sink has accepted the reply, but its flush is blocked.
        tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
            .await.unwrap().unwrap();

        client_tx.send(packet).await.unwrap();
        let (len, _) = tokio::time::timeout(
            Duration::from_secs(2), server.recv_from(&mut buf),
        ).await.unwrap().unwrap();
        assert_eq!(&buf[..len], b"request");
        if explicit_close {
            closer.send(0).unwrap();
            tokio::time::timeout(Duration::from_secs(2), client_tx.closed())
                .await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while dispatcher.udp_session_semaphore.available_permits()
                != MAX_GLOBAL_UDP_SESSIONS
                || !dispatcher.manager.active_connections_snapshot().is_empty()
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("blocked inbound must not retain expired or closed sessions");
    }

    #[tokio::test]
    async fn test_dispatcher_full_cone_relay_preserves_peer_source_address_end_to_end() {
        check_full_cone_relay(OutboundType::Direct).await;
    }

    #[tokio::test]
    async fn nested_selector_direct_preserves_peer_source() {
        check_full_cone_relay(OutboundType::Selector).await;
    }

    #[tokio::test]
    async fn loadbalance_direct_preserves_peer_source() {
        check_full_cone_relay(OutboundType::LoadBalance).await;
    }

    async fn check_full_cone_relay(proto: OutboundType) {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_socket.local_addr().unwrap();

        let dispatcher = test_dispatcher(proto).await;

        let client_src: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let sess = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            source: client_src,
            destination: SocksAddr::Ip(server_addr),
            ..Default::default()
        };

        let (client_tx, inbound_rx) = tokio::sync::mpsc::channel(16);
        let (inbound_tx, mut client_rx) = tokio::sync::mpsc::channel(16);

        let inbound = Box::new(MockInboundDatagram {
            rx: inbound_rx,
            tx: inbound_tx,
        });

        let _close_tx = dispatcher.dispatch_datagram(sess, inbound).await;

        // 1. Client sends UDP to Server via Dispatcher
        client_tx
            .send(UdpPacket {
                data: Bytes::from_static(b"hello-server"),
                src_addr: SocksAddr::Ip(client_src),
                dst_addr: SocksAddr::Ip(server_addr),
                ..Default::default()
            })
            .await
            .unwrap();

        // 2. Server receives packet from Direct Outbound socket
        let mut buf = [0u8; 1024];
        let (n, direct_outbound_addr) =
            tokio::time::timeout(
                Duration::from_secs(2), server_socket.recv_from(&mut buf),
            ).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"hello-server");

        // 3. A third-party peer sends an unsolicited hole-punching UDP packet to Direct Outbound
        peer_socket
            .send_to(b"peer-hole-punch", direct_outbound_addr)
            .await
            .unwrap();

        // 4. Client receives packet from Dispatcher
        let peer_reply =
            tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
                .await
                .expect("timeout waiting for peer reply")
                .expect("channel closed");

        assert_eq!(peer_reply.data.as_ref(), b"peer-hole-punch");
        // CRITICAL: Full-Cone unsolicited peer packet's source address MUST be preserved
        // as the actual physical address of the peer, NOT rewritten to server_addr!
        assert_eq!(peer_reply.src_addr, SocksAddr::Ip(peer_addr));
        assert_eq!(peer_reply.dst_addr, SocksAddr::Ip(client_src));

        // 5. Server also replies normally
        server_socket
            .send_to(b"server-reply", direct_outbound_addr)
            .await
            .unwrap();

        let server_reply =
            tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
                .await
                .expect("timeout waiting for server reply")
                .expect("channel closed");

        assert_eq!(server_reply.data.as_ref(), b"server-reply");
        // Normal reply from server should have source matching server_addr
        assert_eq!(server_reply.src_addr, SocksAddr::Ip(server_addr));
        assert_eq!(server_reply.dst_addr, SocksAddr::Ip(client_src));
    }

    #[tokio::test]
    async fn test_dispatcher_fake_ip_relay_restores_fake_ip_source_address() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let fake_ip = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, 5)),
            server_addr.port(),
        );

        let direct_handler: AnyOutboundHandler =
            Arc::new(DirectHandler::new("DIRECT"));
        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_fake_ip_enabled().returning(|| true);
        mock_resolver.expect_is_fake_ip().returning(|ip| {
            ip == std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, 5))
        });
        mock_resolver
            .expect_reverse_lookup()
            .returning(|_| Some("fake.domain.com".to_string()));
        mock_resolver.expect_cached_for().returning(|_| None);
        mock_resolver
            .expect_resolve_v4()
            .returning(move |_, _| Ok(Some(std::net::Ipv4Addr::LOCALHOST)));
        mock_resolver.expect_resolve().returning(move |_, _| {
            Ok(Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)))
        });
        let resolver: ThreadSafeDNSResolver = Arc::new(mock_resolver);

        let mut handlers = HashMap::new();
        handlers.insert("DIRECT".to_string(), direct_handler);
        let outbound_manager = Arc::new(OutboundManager::new_for_test(handlers));

        let router = Arc::new(
            Router::new(
                vec![],
                HashMap::new(),
                resolver.clone(),
                None,
                None,
                None,
                None,
                None,
                "".to_string(),
            )
            .await
            .unwrap(),
        );

        let manager = StatisticsManager::new();
        let dispatcher = Arc::new(Dispatcher::new(
            outbound_manager,
            router,
            resolver,
            RunMode::Direct,
            manager,
            None,
            None,
            true,
        ));

        let client_src: SocketAddr = "127.0.0.1:54322".parse().unwrap();
        let sess = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            source: client_src,
            destination: SocksAddr::Ip(fake_ip),
            ..Default::default()
        };

        let (client_tx, inbound_rx) = tokio::sync::mpsc::channel(16);
        let (inbound_tx, mut client_rx) = tokio::sync::mpsc::channel(16);

        let inbound = Box::new(MockInboundDatagram {
            rx: inbound_rx,
            tx: inbound_tx,
        });

        let _close_tx = dispatcher.dispatch_datagram(sess, inbound).await;

        // 1. Client sends UDP to Fake-IP via Dispatcher
        client_tx
            .send(UdpPacket {
                data: Bytes::from_static(b"hello-fake-ip"),
                src_addr: SocksAddr::Ip(client_src),
                dst_addr: SocksAddr::Ip(fake_ip),
                ..Default::default()
            })
            .await
            .unwrap();

        // 2. Server receives packet from Direct Outbound socket
        let mut buf = [0u8; 1024];
        let (n, direct_outbound_addr) =
            server_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello-fake-ip");

        // 3. Server replies back with its physical server_addr
        server_socket
            .send_to(b"reply-from-real-server", direct_outbound_addr)
            .await
            .unwrap();

        // 4. Client receives reply, source address MUST be restored to fake_ip, NOT server_addr!
        let reply = tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
            .await
            .expect("timeout waiting for server reply")
            .expect("channel closed");

        assert_eq!(reply.data.as_ref(), b"reply-from-real-server");
        assert_eq!(reply.src_addr, SocksAddr::Ip(fake_ip));
        assert_eq!(reply.dst_addr, SocksAddr::Ip(client_src));
    }
}
