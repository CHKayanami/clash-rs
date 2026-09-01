use crate::{
    app::{
        dns::ClashResolver,
        outbound::manager::ThreadSafeOutboundManager,
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

use super::statistics_manager::{Manager, TrackerInfo, TrafficTracker};

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
const PENDING_SNIFF_TIMEOUT: Duration = Duration::from_millis(100);

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    router: ArcRouter,
    resolver: ThreadSafeDNSResolver,
    mode: Arc<AtomicU8>,
    manager: Arc<Manager>,
    sniffer: Option<ArcSniffer>,
    tcp_buffer_size: usize,
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
}

enum EstablishOutcome {
    Success(EstablishedSession),
    Failed(SessionKey),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UdpQueueEvent {
    SessionExpired(SessionKey),
    PendingSniffExpired(SessionKey),
}

struct PendingSniffSession {
    delay_key: tokio_util::time::delay_queue::Key,
    packets: Vec<UdpPacket>,
    sess: Session,
}

#[derive(Clone)]
struct UdpDispatchContext {
    outbound_manager: ThreadSafeOutboundManager,
    router: ArcRouter,
    resolver: ThreadSafeDNSResolver,
    manager: Arc<Manager>,
    mode: Arc<AtomicU8>,
    remote_receiver_w: tokio::sync::mpsc::Sender<UdpPacket>,
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

                let manager = self.manager.clone();
                let sess_id = sess.id;
                let tracker = TrafficTracker::new(
                    tracker_info,
                    self.manager.clone(),
                );

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

                manager.untrack(sess_id);
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
        };
        let sniffer = self.sniffer.clone();
        let force_dns_mapping = sniffer.as_ref().map_or(false, |s| s.config.force_dns_mapping);

        let current_span = tracing::Span::current();

        tokio::spawn(
            async move {
                let mut sessions: HashMap<SessionKey, OutboundSession> = HashMap::new();
                let mut connecting_sessions: HashMap<SessionKey, Vec<UdpPacket>> = HashMap::new();
                let mut pending_sniff_sessions: HashMap<SessionKey, PendingSniffSession> = HashMap::new();
                let mut delay_queue: DelayQueue<UdpQueueEvent> = DelayQueue::new();
                let timeout_duration = sess
                    .udp_timeout
                    .unwrap_or_else(|| Duration::from_secs(DEFAULT_UDP_SESSION_TIMEOUT_SECS));

                loop {
                    tokio::select! {
                        biased;

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
                                    let buffered_packets = connecting_sessions.remove(&session_key).unwrap_or_default();

                                    for packet in buffered_packets {
                                        forward_to_remote(&established.sender, packet, established.dest.clone(), established.sess_id);
                                    }

                                    let delay_key = delay_queue.insert(
                                        UdpQueueEvent::SessionExpired(session_key.clone()),
                                        timeout_duration,
                                    );

                                    sessions.insert(
                                        session_key,
                                        OutboundSession {
                                            id: established.sess_id,
                                            dest: established.dest,
                                            sender: established.sender,
                                            delay_key,
                                            _relay_handle: established.relay_handle,
                                        },
                                    );
                                }
                                EstablishOutcome::Failed(session_key) => {
                                    connecting_sessions.remove(&session_key);
                                }
                            }
                        }

                        // 4. Idle timeout expiration or pending sniff timeout from DelayQueue
                        Some(expired) = delay_queue.next() => {
                            match expired.into_inner() {
                                UdpQueueEvent::SessionExpired(key) => {
                                    trace!("UDP session expired for src: {}, dst: {}", key.0, key.1);
                                    sessions.remove(&key);
                                }
                                UdpQueueEvent::PendingSniffExpired(key) => {
                                    if let Some(pending) = pending_sniff_sessions.remove(&key) {
                                        trace!(
                                            "UDP pending sniff timed out for src: {}, dst: {}, flushing buffered packets",
                                            key.0, key.1
                                        );
                                        connecting_sessions.insert(key, pending.packets);
                                        spawn_establish_session(
                                            pending.sess,
                                            false,
                                            &ctx,
                                            &session_established_tx,
                                        );
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
                                forward_to_remote(&session.sender, packet, session.dest.clone(), session.id);
                                continue;
                            }

                            // If this flow is currently establishing an outbound session, buffer the packet
                            if let Some(buf) = connecting_sessions.get_mut(&session_key) {
                                if buf.len() < MAX_CONNECTING_PACKETS {
                                    buf.push(packet);
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

                                        connecting_sessions.insert(session_key, packets);
                                        spawn_establish_session(
                                            pending.sess,
                                            false,
                                            &ctx,
                                            &session_established_tx,
                                        );
                                    }
                                    crate::app::sniffer::SniffUdpOutcome::Domain(domain, should_override) => {
                                        let mut pending = pending_sniff_sessions.remove(&session_key).unwrap();
                                        delay_queue.remove(&pending.delay_key);
                                        pending.sess.destination = SocksAddr::Domain(domain.clone().into(), orig_inbound_dst.port());
                                        pending.sess.sniffed_domain = Some(domain);

                                        let mut packets = pending.packets;
                                        packets.push(packet);

                                        connecting_sessions.insert(session_key, packets);
                                        spawn_establish_session(
                                            pending.sess,
                                            should_override,
                                            &ctx,
                                            &session_established_tx,
                                        );
                                    }
                                    _ => {
                                        // CompleteNoDomain or NotMatched
                                        let pending = pending_sniff_sessions.remove(&session_key).unwrap();
                                        delay_queue.remove(&pending.delay_key);
                                        let mut packets = pending.packets;
                                        packets.push(packet);

                                        connecting_sessions.insert(session_key, packets);
                                        spawn_establish_session(
                                            pending.sess,
                                            false,
                                            &ctx,
                                            &session_established_tx,
                                        );
                                    }
                                }
                                continue;
                            }

                            // Fresh flow (first packet):
                            // 1. DNS / Fake-IP reverse lookup to resolve destination (Fake-IP > original target)
                            let reversed_dest = reverse_lookup(&ctx.resolver, &orig_inbound_dst, force_dns_mapping);
                            let target_dest = reversed_dest.unwrap_or_else(|| orig_inbound_dst.clone());
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
                                connecting_sessions.insert(session_key, vec![packet]);
                                spawn_establish_session(
                                    flow_sess,
                                    false,
                                    &ctx,
                                    &session_established_tx,
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
                                    UdpQueueEvent::PendingSniffExpired(session_key.clone()),
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

                            connecting_sessions.insert(session_key, vec![packet]);
                            spawn_establish_session(
                                flow_sess,
                                override_dest,
                                &ctx,
                                &session_established_tx,
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

fn spawn_establish_session(
    sess: Session,
    override_dest: bool,
    ctx: &UdpDispatchContext,
    established_tx: &tokio::sync::mpsc::Sender<EstablishOutcome>,
) {
    let ctx = ctx.clone();
    let established_tx = established_tx.clone();
    let session_key = (
        sess.source,
        sess.orig_destination
            .clone()
            .unwrap_or_else(|| sess.destination.clone()),
    );

    tokio::spawn(async move {
        let outcome = match establish_outbound_session(sess, override_dest, &ctx).await {
            Some(established) => EstablishOutcome::Success(established),
            None => EstablishOutcome::Failed(session_key),
        };
        let _ = established_tx.send(outcome).await;
    });
}

async fn establish_outbound_session(
    mut sess: Session,
    override_dest: bool,
    ctx: &UdpDispatchContext,
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
                error!(
                    "failed to connect outbound: sess = {} ,err = {}",
                    sess, err
                );
            }
            return None;
        }
    };

    debug!("{} outbound datagram connected", sess);

    let tracker_info = Arc::new(TrackerInfo::new(&sess, rule));
    let (close_tx, close_rx) = tokio::sync::oneshot::channel();
    ctx.manager.track(sess.id, tracker_info.clone(), close_tx);

    let (mut remote_w, mut remote_r) = outbound_datagram.split();
    let (remote_sender, mut remote_forwarder) =
        tokio::sync::mpsc::channel::<(UdpPacket, SocksAddr)>(
            UDP_CHANNEL_CAPACITY,
        );

    let orig_inbound_dst_for_relay = orig_inbound_dst.clone();
    let relay_sess = sess.clone();
    let remote_receiver_w_clone = ctx.remote_receiver_w.clone();
    let manager = ctx.manager.clone();
    let sess_id = sess.id;
    let tracker = TrafficTracker::new(
        tracker_info,
        ctx.manager.clone(),
    );

    let relay_handle = tokio::spawn(async move {
        // local -> remote
        let tracker_out = tracker.clone();
        let outgoing = async move {
            while let Some((mut packet, dest_addr)) =
                remote_forwarder.recv().await
            {
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
                debug!(
                    "UDP NAT for packet: {:?}, session: {}",
                    packet, relay_sess
                );
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

        manager.untrack(sess_id);
    });

    Some(EstablishedSession {
        session_key: (sess.source, orig_inbound_dst),
        sess_id: sess.id,
        dest: sess.destination,
        sender: remote_sender,
        relay_handle,
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
fn forward_to_remote(
    sender: &OutboundPacketSender,
    packet: UdpPacket,
    dest: SocksAddr,
    sess_id: u64,
) {
    match sender.try_send((packet, dest)) {
        Ok(_) => {}
        Err(TrySendError::Full(_)) => {
            debug!("[UDP] outbound queue full, dropping packet for session #{}", sess_id);
        }
        Err(TrySendError::Closed(_)) => {
            debug!("[UDP] outbound relay gone, dropping packet for session #{}", sess_id);
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
