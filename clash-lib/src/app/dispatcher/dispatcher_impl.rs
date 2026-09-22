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
    proxy::{AnyInboundDatagram, ClientStream, OutboundType, datagram::UdpPacket},
    session::{Session, SocksAddr},
};
use futures::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;
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
const UDP_CHANNEL_CAPACITY: usize = 1024;
const MAX_PENDING_SNIFF_PACKETS: usize = 4;
const MAX_CONNECTING_PACKETS: usize = 8;
const MAX_CONNECTING_SESSIONS: usize = 256;
const MAX_GLOBAL_CONNECTING_SESSIONS: usize = 1024;
const PENDING_SNIFF_TIMEOUT: Duration = Duration::from_millis(100);
const CONNECTING_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    router: ArcRouter,
    resolver: ThreadSafeDNSResolver,
    mode: Arc<AtomicU8>,
    manager: Arc<Manager>,
    sniffer: Option<ArcSniffer>,
    tcp_buffer_size: usize,
    udp_connect_semaphore: Arc<tokio::sync::Semaphore>,
}

type SessionKey = (SocketAddr, SocksAddr);
type OutboundPacketSender = tokio::sync::mpsc::Sender<(UdpPacket, SocksAddr)>;

struct OutboundSession {
    id: u64,
    dest: SocksAddr,
    sender: OutboundPacketSender,
    delay_key: tokio_util::time::delay_queue::Key,
    _relay_handle: JoinHandle<()>,
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
}

enum EstablishOutcome {
    Success(EstablishedSession),
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
    remote_receiver_w: tokio::sync::mpsc::Sender<UdpPacket>,
    connect_semaphore: Arc<tokio::sync::Semaphore>,
}

fn make_udp_flow_session(
    sess_base: &Session,
    src_addr: SocketAddr,
    orig_inbound_dst: SocksAddr,
    dest: SocksAddr,
    mapped_domain: Option<String>,
    inbound_user: Option<String>,
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
    ) -> Self {
        Self {
            outbound_manager,
            router,
            resolver,
            mode: Arc::new(AtomicU8::new(mode as u8)),
            manager,
            sniffer,
            tcp_buffer_size: tcp_buffer_size.unwrap_or(DEFAULT_BUFFER_SIZE),
            udp_connect_semaphore: Arc::new(tokio::sync::Semaphore::new(
                MAX_GLOBAL_CONNECTING_SESSIONS,
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

    pub fn router(&self) -> &ArcRouter {
        &self.router
    }

    #[instrument(skip(self, sess, lhs), fields(trace_id = sess.id))]
    pub async fn dispatch_stream(
        &self,
        mut sess: Session,
        mut lhs: Box<dyn ClientStream>,
    ) {
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
        let (remote_receiver_w, mut remote_receiver_r) =
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
            remote_receiver_w,
            connect_semaphore: self.udp_connect_semaphore.clone(),
        };
        let sniffer = self.sniffer.clone();
        let force_dns_mapping = sniffer
            .as_ref()
            .map_or(false, |s| s.config.force_dns_mapping);

        let current_span = tracing::Span::current();

        tokio::spawn(
            async move {
                let mut sessions: HashMap<SessionKey, OutboundSession> = HashMap::new();
                let mut connecting_sessions: HashMap<SessionKey, ConnectingSession> = HashMap::new();
                let mut pending_sniff_sessions: HashMap<SessionKey, PendingSniffSession> = HashMap::new();
                let mut delay_queue: DelayQueue<UdpQueueEvent> = DelayQueue::new();
                let timeout_duration = sess
                    .udp_timeout
                    .unwrap_or_else(|| Duration::from_secs(DEFAULT_UDP_SESSION_TIMEOUT_SECS));

                loop {
                    tokio::select! {
                        // 1. Close signal from caller (explicit close or sender drop)
                        _ = &mut close_receiver => {
                            debug!("UDP close signal received for {}, closing session actor", sess);
                            break;
                        }

                        // 2. Reply packets from remote outbounds -> send to local_w
                        Some(packet) = remote_receiver_r.recv() => {
                            // Refresh session activity on downstream reply packets
                            if let Some(src_addr) = packet.dst_addr.clone().try_into_socket_addr() {
                                let session_key = (src_addr, packet.src_addr.clone());
                                if let Some(session) = sessions.get_mut(&session_key) {
                                    delay_queue.reset(&session.delay_key, timeout_duration);
                                }
                            }

                            if let Err(err) = local_w.send(packet).await {
                                error!("failed to send packet to local: {}", err);
                            }
                        }

                        // 3. Asynchronously established outbound session ready
                        Some(outcome) = session_established_rx.recv() => {
                            match outcome {
                                EstablishOutcome::Success(established) => {
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
                                        ..
                                    } = established;

                                    for packet in buffered_packets {
                                        let _ = forward_to_remote(
                                            &sender,
                                            packet,
                                            dest.clone(),
                                            sess_id,
                                        );
                                    }

                                    let delay_key = delay_queue.insert(
                                        UdpQueueEvent::SessionIdle(session_key.clone()),
                                        timeout_duration,
                                    );

                                    sessions.insert(
                                        session_key,
                                        OutboundSession {
                                            id: sess_id,
                                            dest,
                                            sender,
                                            delay_key,
                                            _relay_handle: relay_handle,
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

                        // 4. Idle timeout expiration or pending sniff timeout from DelayQueue
                        Some(expired) = delay_queue.next() => {
                            match expired.into_inner() {
                                UdpQueueEvent::SessionIdle(key) => {
                                    trace!("UDP session expired for src: {}, dst: {}", key.0, key.1);
                                    sessions.remove(&key);
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

                        // 5. Inbound packets from local_r -> route & forward to remote
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
                                delay_queue.reset(&session.delay_key, timeout_duration);
                                if let Some(returned_packet) = forward_to_remote(
                                    &session.sender,
                                    packet,
                                    session.dest.clone(),
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
    let Ok(connect_permit) = ctx.connect_semaphore.clone().try_acquire_owned()
    else {
        debug!(
            "global UDP outbound connection limit reached, dropping flow {} -> {}",
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
        connect_permit,
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
    connect_permit: tokio::sync::OwnedSemaphorePermit,
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
        let _connect_permit = connect_permit;
        let outcome = match establish_outbound_session(
            sess,
            override_dest,
            &ctx,
            established_tx.clone(),
        )
        .await
        {
            Some(established) => EstablishOutcome::Success(established),
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
    let is_real_ip = match orig_dst_ip {
        Some(ip) => !ctx.resolver.is_fake_ip(ip),
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

    debug!("{} outbound datagram connected", sess);

    let tracker_info = Arc::new(TrackerInfo::new(&sess, rule));
    let (close_tx, close_rx) = tokio::sync::oneshot::channel();
    ctx.manager.track(sess.id, tracker_info.clone(), close_tx);
    let track_guard = TrackGuard::new(sess.id, ctx.manager.clone());

    let (mut remote_w, mut remote_r) = outbound_datagram.split();
    let (remote_sender, mut remote_forwarder) =
        tokio::sync::mpsc::channel::<(UdpPacket, SocksAddr)>(UDP_CHANNEL_CAPACITY);

    let orig_inbound_dst_for_relay = orig_inbound_dst.clone();
    let relay_sess = sess.clone();
    let relay_session_key = (sess.source, orig_inbound_dst.clone());
    let relay_sess_id = sess.id;
    let remote_receiver_w_clone = ctx.remote_receiver_w.clone();
    let tracker = TrafficTracker::new(tracker_info, ctx.manager.clone());
    let (relay_start, relay_start_rx) = tokio::sync::oneshot::channel();

    let relay_handle = tokio::spawn(async move {
        let _guard = track_guard;
        // Do not let a short-lived outbound report termination before the
        // actor has installed the corresponding session entry.
        if relay_start_rx.await.is_err() {
            return;
        }

        // local -> remote
        let tracker_out = tracker.clone();
        let outgoing = async move {
            while let Some((mut packet, dest_addr)) = remote_forwarder.recv().await {
                let len = packet.data.len();
                packet.dst_addr = dest_addr;
                if let Err(err) = remote_w.send(packet).await {
                    warn!("failed to send packet to remote: {err:?}");
                } else {
                    tracker_out.push_upload(len);
                }
            }
        };

        // remote -> local
        let tracker_in = tracker;
        let incoming = async move {
            while let Some(mut packet) = remote_r.next().await {
                tracker_in.push_download(packet.data.len());

                packet.src_addr = orig_inbound_dst_for_relay.clone();
                packet.dst_addr = relay_sess.source.into();
                debug!("UDP NAT for packet: {:?}, session: {}", packet, relay_sess);
                match remote_receiver_w_clone.try_send(packet) {
                    Ok(_) => {}
                    Err(TrySendError::Full(_)) => {
                        debug!(
                            "[UDP NAT] Backpressure: remote_receiver channel is full for sess: {}",
                            relay_sess
                        );
                    }
                    Err(TrySendError::Closed(_)) => {
                        debug!(
                            "[UDP NAT] reply channel closed, ending session: {}",
                            relay_sess
                        );
                        break;
                    }
                }
            }
        };

        tokio::select! {
            _ = outgoing => {}
            _ = incoming => {}
            _ = close_rx => {}
        }

        let _ = established_tx
            .send(EstablishOutcome::Terminated(
                relay_session_key,
                relay_sess_id,
            ))
            .await;
    });

    Some(EstablishedSession {
        session_key: (sess.source, orig_inbound_dst),
        sess_id: sess.id,
        dest: sess.destination,
        sender: remote_sender,
        relay_handle,
        relay_start,
    })
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
    dest: SocksAddr,
    sess_id: u64,
) -> Option<UdpPacket> {
    match sender.try_send((packet, dest)) {
        Ok(_) => None,
        Err(TrySendError::Full(_)) => {
            debug!(
                "[UDP] outbound queue full, dropping packet for session #{}",
                sess_id
            );
            None
        }
        Err(TrySendError::Closed((packet, _))) => {
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
    use super::*;
    use crate::app::dns::MockClashResolver;
    use bytes::Bytes;
    use std::net::{IpAddr, Ipv4Addr};

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

        let returned = forward_to_remote(&sender, packet, dst.clone(), 42)
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
}
