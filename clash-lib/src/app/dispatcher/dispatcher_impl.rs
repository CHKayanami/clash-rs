use crate::{
    app::{
        dispatcher::tracked::{TrackedDatagram, TrackedStream},
        dns::ClashResolver,
        outbound::manager::ThreadSafeOutboundManager,
        router::ArcRouter,
    },
    common::io::copy_bidirectional,
    config::{
        def::RunMode,
        internal::proxy::{PROXY_DIRECT, PROXY_GLOBAL},
    },
    proxy::{
        AnyInboundDatagram, ClientStream, OutboundType, datagram::UdpPacket,
        utils::ToCanonical,
    },
    session::{Session, SocksAddr},
};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    net::SocketAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc::error::TrySendError;
use tokio::{io::AsyncWriteExt, task::JoinHandle};
use tracing::{Instrument, debug, error, info, info_span, instrument, trace, warn};

use crate::app::dns::ThreadSafeDNSResolver;

use super::statistics_manager::Manager;

// SS2022 (AEAD-2022) MAX_PACKET_SIZE is 0xFFFF (65535 bytes). Using a relay
// buffer smaller than that forces the cipher to split every full packet into
// multiple smaller encrypted chunks, multiplying encrypt/decrypt overhead.
// Classic AEAD ciphers cap at 0x3FFF (16383 bytes) so they are unaffected.
const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    router: ArcRouter,
    resolver: ThreadSafeDNSResolver,
    mode: Arc<AtomicU8>,
    manager: Arc<Manager>,
    tcp_buffer_size: usize,
    // 整个代理系统运行期间，它只在 Dispatcher::new 时被初始化一次
    session_manager: Arc<TimeoutUdpSessionManager>,
    /// Hands out one id per `dispatch_datagram` call, see `OutboundHandleKey`.
    next_dispatch_id: AtomicU64,
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
        statistics_manager: Arc<Manager>,
        tcp_buffer_size: Option<usize>,
    ) -> Self {
        Self {
            outbound_manager,
            router,
            resolver,
            mode: Arc::new(AtomicU8::new(mode as u8)),
            manager: statistics_manager,
            tcp_buffer_size: tcp_buffer_size.unwrap_or(DEFAULT_BUFFER_SIZE),
            session_manager: Arc::new(TimeoutUdpSessionManager::new()),
            next_dispatch_id: AtomicU64::new(0),
        }
    }

    pub fn set_mode(&self, mode: RunMode) {
        info!("run mode switched to {}", mode);

        self.mode.store(mode as u8, Ordering::Relaxed);
    }

    pub fn get_mode(&self) -> RunMode {
        decode_mode(self.mode.load(Ordering::Relaxed))
    }

    #[instrument(skip(self, sess, lhs), fields(trace_id = sess.id))]
    pub async fn dispatch_stream(
        &self,
        mut sess: Session,
        mut lhs: Box<dyn ClientStream>,
    ) {
        let dest: SocksAddr =
            match reverse_lookup(&self.resolver, &sess.destination).await {
                Some(dest) => dest,
                None => {
                    warn!("failed to resolve destination {}", sess);
                    return;
                }
            };

        sess.destination = dest.clone();

        let mode = self.get_mode();
        let (outbound_name, rule) = match mode {
            RunMode::Global => (PROXY_GLOBAL, None),
            RunMode::Rule => self.router.match_route(&mut sess).await,
            RunMode::Direct => (PROXY_DIRECT, None),
        };

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
                let rhs = TrackedStream::new(
                    rhs,
                    self.manager.clone(),
                    sess.clone(),
                    rule,
                )
                .await;
                match copy_bidirectional(
                    lhs,
                    rhs,
                    self.tcp_buffer_size,
                    Duration::from_secs(10),
                    Duration::from_secs(10),
                )
                .instrument(info_span!(
                    "copy_bidirectional",
                    outbound_name = outbound_name,
                ))
                .await
                {
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
                            | std::io::ErrorKind::BrokenPipe => {
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
                            | std::io::ErrorKind::BrokenPipe => {
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
                                | std::io::ErrorKind::BrokenPipe => {
                                    debug!(
                                        "connection {} closed with error {}",
                                        sess, err
                                    );
                                }
                                _ => {
                                    warn!(
                                        "connection {} closed with error {}",
                                        sess, err
                                    );
                                }
                            }
                        }
                    },
                }
            }
            Err(err) => {
                warn!(
                    "failed to establish remote connection {}, error: {}",
                    sess, err
                );
                if let Err(e) = lhs.shutdown().await {
                    warn!("error closing local connection {}: {}", sess, e)
                }
            }
        }
    }

    /// Dispatch a UDP packet to outbound handler
    /// returns the close sender
    #[instrument(skip(self, sess, udp_inbound), fields(trace_id = sess.id))]
    #[must_use]
    pub async fn dispatch_datagram(
        &self,
        sess: Session,
        udp_inbound: AnyInboundDatagram,
    ) -> tokio::sync::oneshot::Sender<u8> {
        // let outbound_handle_guard = TimeoutUdpSessionManager::new();
        // 💡 改为直接借用 Dispatcher 自身的全局常驻管理器
        // 这样，即使当前单次 tproxy 会话（sess）由于客户端断开而销毁，
        // 全局的 session_manager 也绝对不会触发 Drop，里面的老连接池活得好好的！
        let outbound_handle_guard = self.session_manager.clone();
        let router = self.router.clone();
        let outbound_manager = self.outbound_manager.clone();
        let resolver = self.resolver.clone();
        let mode = self.mode.clone();
        let manager = self.manager.clone();

        #[rustfmt::skip]
        /*
         *  implement details
         *
         *  data structure:
         *    local_r, local_w: stream/sink pair
         *    remote_r, remote_w: stream/sink pair
         *    remote_receiver_r, remote_receiver_w: channel pair
         *    remote_sender, remote_forwarder: channel pair
         *
         *  data flow:
         *    => local_r => init packet => connect_datagram => remote_sender     => remote_forwarder         => remote_w
         *    => local_w                                    <= remote_receiver_r <= NAT + remote_receiver_w  <= remote_r
         *
         *  notice:
         *    the NAT is binded to the session in the dispatch_datagram function arg and the closure
         *    so we need not to add a global NAT table and do the translation
         */
        let (mut local_w, mut local_r) = udp_inbound.split();
        let (remote_receiver_w, mut remote_receiver_r) =
            tokio::sync::mpsc::channel(256);

        // Identifies this `dispatch_datagram` call. `session_manager` is shared
        // by every inbound, so without this two calls that happen to see the
        // same (outbound, client src_addr) would share one NAT entry — and the
        // older entry's relay task still holds *its* caller's `local_w`, so
        // replies would be delivered to the wrong (often already closed)
        // inbound socket. A long-lived caller such as tproxy, which serves all
        // of its clients from a single call, still reuses sockets as intended.
        let dispatch_id = self.next_dispatch_id.fetch_add(1, Ordering::Relaxed);

        let s = sess.clone();
        let ss = sess.clone();
        let t1 = tokio::spawn(async move {
            while let Some(mut packet) = local_r.next().await {
                let mut sess = sess.clone();

                // Canonicalize IPv4-mapped IPv6 addresses (e.g. SS2022 on a
                // dual-stack socket produces ::ffff:x.x.x.x); without this
                // new_udp_socket picks AF_INET6 with bind_addr 0.0.0.0 → EINVAL.
                if let SocksAddr::Ip(addr) = &mut packet.dst_addr {
                    *addr = addr.to_canonical();
                }

                // Canonicalize the source too, in place: it keys the NAT table
                // below, so a client seen as both ::ffff:x.x.x.x and x.x.x.x
                // would otherwise get two outbound sockets. It also feeds
                // sess.source — and direct/mod.rs sees a v4-mapped source as
                // is_ipv4() == false and picks bind_addr=:: while family_hint
                // picks AF_INET for the destination, so binding fails with
                // EAFNOSUPPORT (os error 97) and every reply is silently lost.
                if let SocksAddr::Ip(addr) = &mut packet.src_addr {
                    *addr = addr.to_canonical();
                }

                // Inbound UDP sources are always socket addresses; drop rather
                // than panic if an inbound ever hands us a domain.
                let Some(src_addr) = packet.src_addr.clone().try_into_socket_addr()
                else {
                    warn!(
                        "dropping inbound udp packet with non-ip source {}",
                        packet.src_addr
                    );
                    continue;
                };

                // Remember the concrete destination IP, if there was one, before
                // reverse_lookup possibly turns it into a domain.
                let orig_dst_ip = packet.dst_addr.ip();

                let dest = match reverse_lookup(&resolver, &packet.dst_addr).await {
                    Some(dest) => dest,
                    None => {
                        warn!("failed to resolve destination {}", sess);
                        continue;
                    }
                };

                sess.source = src_addr;
                sess.destination = dest.clone();
                sess.inbound_user = packet.inbound_user.clone();
                sess.resolved_ip = match &dest {
                    // Destination stayed an IP — carry it through.
                    SocksAddr::Ip(addr) => Some(addr.ip()),
                    // reverse_lookup mapped it to a domain. With fake-ip on
                    // that only happens for an actual fake address, which must
                    // not reach routing: it would make GEOIP / IP-CIDR
                    // ,no-resolve match the fake-ip range for UDP while the TCP
                    // path — which never sets resolved_ip — skips them. With
                    // fake-ip off it means a resolve-cache hit, where the
                    // original address is genuine and worth keeping so
                    // no-resolve IP rules still match.
                    SocksAddr::Domain(..) if !resolver.fake_ip_enabled() => {
                        orig_dst_ip
                    }
                    SocksAddr::Domain(..) => None,
                };

                let mode = decode_mode(mode.load(Ordering::Relaxed));

                let (outbound_name, rule) = match mode {
                    RunMode::Global => (PROXY_GLOBAL, None),
                    RunMode::Rule => router.match_route(&mut sess).await,
                    RunMode::Direct => (PROXY_DIRECT, None),
                };

                debug!("dispatching {} to {}[{}]", sess, outbound_name, mode);

                let mgr = outbound_manager.clone();
                let handler = match mgr.get_outbound(outbound_name) {
                    Some(h) => h,
                    None => {
                        debug!(
                            "unknown rule: {}, fallback to direct",
                            outbound_name
                        );
                        mgr.get_outbound(PROXY_DIRECT).unwrap()
                    }
                };

                // Key a group's NAT entry on its *current* selection, so
                // switching proxy re-keys the session instead of silently
                // reusing the socket opened through the previous one.
                let (outbound_name, effective_proto) =
                    if let Some(group) = handler.try_as_group_handler() {
                        match group.get_active_proxy().await {
                            Some(active) => {
                                (active.name().to_owned(), active.proto())
                            }
                            None => (outbound_name.to_owned(), handler.proto()),
                        }
                    } else {
                        (outbound_name.to_owned(), handler.proto())
                    };

                // Short-circuit rejected traffic before allocating a channel,
                // spawning a relay task or inserting a NAT entry. Keyed on the
                // outbound *type* rather than the name so a group that selects
                // REJECT is caught too — and so a user proxy that happens to be
                // named "reject" is not.
                if matches!(effective_proto, OutboundType::Reject) {
                    trace!(
                        "[UDP Short-Circuit] Drop packet immediately for sess: {}",
                        sess
                    );
                    continue;
                }

                match outbound_handle_guard.get_outbound_sender_mut(
                    dispatch_id,
                    &outbound_name,
                    src_addr,
                ) {
                    None => {
                        debug!("building {} outbound datagram connecting", sess);
                        let remote_receiver_w = remote_receiver_w.clone();
                        let outbound_datagram = match handler
                            .connect_datagram(&sess, resolver.clone())
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
                                        "failed to connect outbound:sess = {} ,err = {}",
                                        sess, err
                                    );
                                }
                                continue;
                            }
                        };

                        debug!("{} outbound datagram connected", sess);

                        let outbound_datagram = TrackedDatagram::new(
                            outbound_datagram,
                            manager.clone(),
                            sess.clone(),
                            rule,
                        )
                        .await;

                        let (mut remote_w, mut remote_r) = outbound_datagram.split();
                        let (remote_sender, mut remote_forwarder) =
                            tokio::sync::mpsc::channel::<(UdpPacket, SocksAddr)>(
                                256,
                            );

                        let coarse_now = outbound_handle_guard.coarse_now.clone();
                        let now = coarse_now.load(Ordering::Relaxed);
                        let last_active = Arc::new(AtomicU64::new(now));
                        let last_active_rw = last_active.clone();
                        let coarse_now_rw = coarse_now.clone();

                        // Address-substitution state, shared by the two relay
                        // directions below. A std RwLock is used here so that
                        // the incoming direction can acquire a non-blocking read
                        // lock concurrently with other readers.
                        // `has_nat` allows a lock-free fast path: if no destination
                        // substitution ever occurred, readers bypass the RwLock entirely.
                        let nat = Arc::new(RwLock::new(NatTable::default()));
                        let nat_out = nat.clone();
                        let has_nat = Arc::new(AtomicBool::new(false));
                        let has_nat_out = has_nat.clone();
                        let has_nat_in = has_nat.clone();

                        // The relay task outlives this loop iteration, so it
                        // gets its own copy of the session (once per session,
                        // not per packet).
                        let relay_sess = sess.clone();

                        // Per-session relay task. The outgoing direction
                        // rewrites dst_addr to the logical destination (from
                        // reverse_lookup) and records the original so the
                        // incoming direction can restore it as src_addr.
                        let rw_handle = tokio::spawn(async move {
                            // local -> remote
                            let outgoing = async move {
                                while let Some((mut packet, dest)) =
                                    remote_forwarder.recv().await
                                {
                                    let orig =
                                        std::mem::replace(&mut packet.dst_addr, dest);
                                    if orig != packet.dst_addr {
                                        {
                                            let mut nat = nat_out.write().unwrap();
                                            nat.remember(
                                                packet.dst_addr.clone(),
                                                orig.clone(),
                                            );
                                            nat.last_orig_addr = Some(orig);
                                        }
                                        has_nat_out.store(true, Ordering::Release);
                                    } else if has_nat_out.load(Ordering::Relaxed) {
                                        let mut nat = nat_out.write().unwrap();
                                        nat.last_orig_addr = Some(orig);
                                    }

                                    if let Err(err) = remote_w.send(packet).await {
                                        warn!(
                                            "failed to send packet to remote: \
                                             {err:?}"
                                        );
                                    }
                                }
                            };

                            // remote -> local
                            let incoming = async move {
                                while let Some(mut packet) = remote_r.next().await {
                                    last_active_rw.store(
                                        coarse_now_rw.load(Ordering::Relaxed),
                                        Ordering::Relaxed,
                                    );
                                    if has_nat_in.load(Ordering::Acquire) {
                                        let nat = nat.read().unwrap();
                                        if let Some(orig) = nat.restore(&packet.src_addr)
                                        {
                                            packet.src_addr = orig;
                                        }
                                    }
                                    packet.dst_addr = relay_sess.source.into();
                                    debug!(
                                        "UDP NAT for packet: {:?}, session: {}",
                                        packet, relay_sess
                                    );
                                    match remote_receiver_w.try_send(packet) {
                                        Ok(_) => {}
                                        Err(TrySendError::Full(_)) => {
                                            // t2 is alive, the inbound just
                                            // can't drain fast enough. Dropping
                                            // is the correct UDP response.
                                            debug!(
                                                "[UDP NAT] Backpressure: \
                                                 remote_receiver channel is full \
                                                 for sess: {}",
                                                relay_sess
                                            );
                                        }
                                        Err(TrySendError::Closed(_)) => {
                                            // Normal teardown: the inbound side
                                            // is gone (e.g. a SOCKS5 UDP
                                            // association closed and t2 was
                                            // aborted). Nothing left to relay
                                            // to, so end the session.
                                            debug!(
                                                "[UDP NAT] reply channel closed, \
                                                 ending session: {}",
                                                relay_sess
                                            );
                                            break;
                                        }
                                    }
                                }
                            };

                            // Whichever direction finishes first tears the
                            // session down. Unlike a single select! loop over
                            // both receives, an await *inside* one direction no
                            // longer stops the other from being polled — one
                            // slow outbound sink used to stall the reply path.
                            tokio::select! {
                                _ = outgoing => {}
                                _ = incoming => {}
                            }
                        });

                        outbound_handle_guard.insert(
                            dispatch_id,
                            &outbound_name,
                            src_addr,
                            rw_handle,
                            remote_sender.clone(),
                            last_active,
                        );

                        forward_to_remote(&remote_sender, packet, dest, &sess);
                    }
                    Some(sender) => {
                        debug!("reusing {} sent to remote", sess);
                        forward_to_remote(&sender, packet, dest, &sess);
                    }
                };
            }

            trace!("UDP session local -> remote finished for {}", ss);
        });

        let ss = s.clone();
        let t2 = tokio::spawn(async move {
            while let Some(packet) = remote_receiver_r.recv().await {
                match local_w.send(packet).await {
                    Ok(_) => {}
                    Err(err) => {
                        error!("failed to send packet to local: {}", err);
                    }
                }
            }
            trace!("UDP session remote -> local finished for {}", ss);
        });

        let (close_sender, close_receiver) = tokio::sync::oneshot::channel::<u8>();

        tokio::spawn(async move {
            // Either outcome means the caller is done with this session: `Ok`
            // is an explicit close, `Err` means the sender was dropped without
            // one. Both must tear the relay tasks down — returning early on
            // `Err` used to leak them until the idle sweep noticed.
            match close_receiver.await {
                Ok(_) => trace!("UDP close signal for {} received", s),
                Err(_) => {
                    debug!("UDP close sender for {} dropped, closing session", s)
                }
            }
            t1.abort();
            t2.abort();
        });

        close_sender
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
/// `t1` reads every packet for an entire inbound socket, so blocking here on a
/// full queue would stall every other client and destination sharing it.
/// Dropping instead is both cheaper and the semantics UDP already has.
fn forward_to_remote(
    sender: &OutboundPacketSender,
    packet: UdpPacket,
    dest: SocksAddr,
    sess: &Session,
) {
    match sender.try_send((packet, dest)) {
        Ok(_) => {}
        Err(TrySendError::Full(_)) => {
            debug!("[UDP] outbound queue full, dropping packet for {}", sess);
        }
        Err(TrySendError::Closed(_)) => {
            // The relay task exited between the map lookup and this send; the
            // stale entry is reclaimed by the next lookup or the idle sweep.
            debug!("[UDP] outbound relay gone, dropping packet for {}", sess);
        }
    }
}

/// Reverse map used to restore a reply's source address to whatever the client
/// originally addressed, undoing the `dst_addr` substitution done on the way
/// out.
#[derive(Default)]
struct NatTable {
    orig_map: HashMap<SocksAddr, SocksAddr>,
    /// Fallback for outbounds that don't echo `dst_addr` back as `src_addr`.
    /// Only consulted for single-destination sessions.
    last_orig_addr: Option<SocksAddr>,
}

impl NatTable {
    /// Bounds the table so a long-lived session with many destinations cannot
    /// grow it without limit.
    const MAX_ENTRIES: usize = 256;

    /// What the client originally addressed, for a reply arriving from
    /// `src_addr` — or `None` to leave the address as the outbound reported it.
    ///
    /// Three steps, most trustworthy first:
    ///
    /// 1. Exact match: the outbound echoed the `dst_addr` we sent.
    /// 2. Port match, but only if exactly one destination uses that port. UDP
    ///    replies come back from the port they were sent to, so this correctly
    ///    separates concurrent flows (say :53 and :443) that step 1 misses
    ///    because the outbound reports the real upstream IP instead — as
    ///    Shadowsocks does.
    /// 3. Most recent destination. Right for the common send/receive round
    ///    trip, and a guess otherwise; with several same-port destinations in
    ///    flight there is no information left to do better.
    fn restore(&self, src_addr: &SocksAddr) -> Option<SocksAddr> {
        if let Some(orig) = self.orig_map.get(src_addr) {
            return Some(orig.clone());
        }

        let port = src_addr.port();
        let mut matched: Option<&SocksAddr> = None;
        let mut matches = 0usize;
        for (substituted, orig) in &self.orig_map {
            if substituted.port() == port {
                matches += 1;
                matched = Some(orig);
            }
        }
        if matches == 1
            && let Some(orig) = matched
        {
            return Some(orig.clone());
        }

        if self.orig_map.is_empty() {
            // Nothing was ever substituted for this session, so the address the
            // outbound reported is the one the client expects.
            return None;
        }
        self.last_orig_addr.clone()
    }

    fn remember(&mut self, substituted: SocksAddr, orig: SocksAddr) {
        if self.orig_map.len() >= Self::MAX_ENTRIES
            && !self.orig_map.contains_key(&substituted)
            && let Some(k) = self.orig_map.keys().next().cloned()
        {
            self.orig_map.remove(&k);
        }
        self.orig_map.insert(substituted, orig);
    }
}

// helper function to resolve the destination address
// if the destination is an IP address, check if it's a fake IP
// or look for cached IP
// if the destination is a domain name, don't resolve
async fn reverse_lookup(
    resolver: &Arc<dyn ClashResolver>,
    dst: &SocksAddr,
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
            if resolver.fake_ip_enabled() {
                let ip = socket_addr.ip();
                if resolver.is_fake_ip(ip).await {
                    trace!("looking up fake ip: {}", socket_addr.ip());
                    let host = resolver.reverse_lookup(ip).await;
                    match host {
                        Some(host) => to_addr(host, socket_addr.port())?,
                        None => {
                            error!("failed to reverse lookup fake ip: {}", ip);
                            return None;
                        }
                    }
                } else {
                    (*socket_addr).into()
                }
            } else {
                trace!("looking up resolve cache ip: {}", socket_addr.ip());
                match resolver.cached_for(socket_addr.ip()).await {
                    Some(resolved) => to_addr(resolved, socket_addr.port())?,
                    _ => (*socket_addr).into(),
                }
            }
        }
        SocksAddr::Domain(host, port) => to_addr(host.to_owned(), *port)?,
    };
    Some(dst)
}

type OutboundPacketSender = tokio::sync::mpsc::Sender<(UdpPacket, SocksAddr)>;

/// Key identifying a unique UDP NAT session.
///
/// Scoped to (dispatch call, outbound, client source) — one socket per client
/// per outbound, full cone NAT. `dispatch_id` is what keeps the map safe to
/// share across inbounds: a relay task captures the `local_w` of the
/// `dispatch_datagram` call that created it, so an entry must never be handed
/// to a different call even when the outbound and client address match.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OutboundHandleKey {
    dispatch_id: u64,
    outbound_name: String,
    src_addr: SocketAddr,
}

struct OutboundHandleVal {
    /// Handles both local→remote and remote→local, owns orig_map.
    rw_handle: JoinHandle<()>,
    sender: OutboundPacketSender,
    /// Coarse-grained last-active timestamp (seconds since manager start).
    last_active: Arc<AtomicU64>,
}

impl Drop for OutboundHandleVal {
    fn drop(&mut self) {
        self.rw_handle.abort();
    }
}

const DEFAULT_UDP_SESSION_TIMEOUT_SECS: u64 = 60;
const CLEANUP_INTERVAL_SECS: u64 = 5;

struct TimeoutUdpSessionManager {
    map: Arc<DashMap<OutboundHandleKey, OutboundHandleVal>>,
    /// Coarse monotonic clock (~1 s resolution), updated by the cleaner task.
    /// Stores seconds elapsed since the manager was created.
    coarse_now: Arc<AtomicU64>,
    cleaner: Option<JoinHandle<()>>,
}

impl Drop for TimeoutUdpSessionManager {
    fn drop(&mut self) {
        trace!("dropping timeout udp session manager");
        if let Some(x) = self.cleaner.take() {
            x.abort()
        }
        // Remaining entries are dropped when the Arc<DashMap> ref count
        // reaches zero; OutboundHandleVal::drop aborts each rw_handle.
    }
}

impl TimeoutUdpSessionManager {
    fn new() -> Self {
        let map: Arc<DashMap<OutboundHandleKey, OutboundHandleVal>> =
            Arc::new(DashMap::new());
        let timeout_secs: u64 = DEFAULT_UDP_SESSION_TIMEOUT_SECS;
        let coarse_now = Arc::new(AtomicU64::new(0));

        let map_cloned = map.clone();
        let coarse_now_cloned = coarse_now.clone();

        let cleaner = tokio::spawn(async move {
            let start = Instant::now();
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            let mut tick_count: u64 = 0;

            loop {
                interval.tick().await;

                // Update coarse clock every tick (~1 s resolution)
                let elapsed = start.elapsed().as_secs();
                coarse_now_cloned
                    .store(elapsed, Ordering::Relaxed);

                tick_count += 1;

                // Run cleanup every CLEANUP_INTERVAL_SECS ticks
                if tick_count % CLEANUP_INTERVAL_SECS != 0 {
                    continue;
                }

                trace!("timeout udp session cleaner scanning");
                let now = elapsed;
                let mut alive_count: u64 = 0;
                let mut expired_count: u64 = 0;

                // DashMap::retain locks one shard at a time, so concurrent
                // lookups on other shards are never blocked.
                map_cloned.retain(|k, val| {
                    // Eagerly reclaim sessions whose task has already exited.
                    if val.rw_handle.is_finished() {
                        expired_count += 1;
                        trace!("udp session finished: {:?}", k);
                        return false;
                    }
                    let last =
                        val.last_active.load(Ordering::Relaxed);
                    let is_alive = now.saturating_sub(last) < timeout_secs;
                    if !is_alive {
                        expired_count += 1;
                        trace!("udp session expired: {:?}", k);
                        // OutboundHandleVal::drop will abort rw_handle
                    } else {
                        alive_count += 1;
                    }
                    is_alive
                });

                trace!(
                    "timeout udp session cleaner finished, alive: {}, expired: {}",
                    alive_count, expired_count
                );
            }
        });

        Self {
            map,
            coarse_now,
            cleaner: Some(cleaner),
        }
    }

    fn insert(
        &self,
        dispatch_id: u64,
        outbound_name: &str,
        src_addr: SocketAddr,
        rw_handle: JoinHandle<()>,
        sender: OutboundPacketSender,
        last_active: Arc<AtomicU64>,
    ) {
        // If an old entry exists for this key, DashMap::insert drops it,
        // which triggers OutboundHandleVal::drop → rw_handle.abort().
        self.map.insert(
            OutboundHandleKey {
                dispatch_id,
                outbound_name: outbound_name.to_string(),
                src_addr,
            },
            OutboundHandleVal {
                rw_handle,
                sender,
                last_active,
            },
        );
    }

    fn get_outbound_sender_mut(
        &self,
        dispatch_id: u64,
        outbound_name: &str,
        src_addr: SocketAddr,
    ) -> Option<OutboundPacketSender> {
        let key = OutboundHandleKey {
            dispatch_id,
            outbound_name: outbound_name.to_owned(),
            src_addr,
        };

        // Single DashMap lookup — only the target shard is locked.
        {
            if let Some(entry) = self.map.get(&key) {
                if !entry.rw_handle.is_finished() {
                    trace!(
                        "updating last access time for outbound {:?}",
                        (outbound_name, src_addr)
                    );
                    let now = self.coarse_now.load(Ordering::Relaxed);
                    entry.last_active.store(now, Ordering::Relaxed);
                    return Some(entry.sender.clone());
                }
            }
            // Ref is dropped here before the mutable remove below.
        }

        // Entry is either missing or stale (rw_handle finished).
        // remove_if atomically checks the predicate and removes.
        if self
            .map
            .remove_if(&key, |_, v| v.rw_handle.is_finished())
            .is_some()
        {
            debug!(
                "removing stale UDP session for outbound {:?}",
                (outbound_name, src_addr)
            );
        }
        None
    }
}
