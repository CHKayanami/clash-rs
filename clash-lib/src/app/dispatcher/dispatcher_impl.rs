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
    proxy::{AnyInboundDatagram, ClientStream, OutboundType, datagram::UdpPacket},
    session::{Session, SocksAddr},
};
use futures::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc::error::TrySendError;
use tokio::{io::AsyncWriteExt, task::JoinHandle};
use tokio_util::time::DelayQueue;
use tracing::{Instrument, debug, error, info, info_span, instrument, trace, warn};

use crate::app::dns::ThreadSafeDNSResolver;

use super::statistics_manager::Manager;

use crate::app::sniffer::ArcSniffer;

// SS2022 (AEAD-2022) MAX_PACKET_SIZE is 0xFFFF (65535 bytes). Using a relay
// buffer smaller than that forces the cipher to split every full packet into
// multiple smaller encrypted chunks, multiplying encrypt/decrypt overhead.
// Classic AEAD ciphers cap at 0x3FFF (16383 bytes) so they are unaffected.
const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;
const DEFAULT_UDP_SESSION_TIMEOUT_SECS: u64 = 60;
const UDP_CHANNEL_CAPACITY: usize = 1024;

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    router: ArcRouter,
    resolver: ThreadSafeDNSResolver,
    mode: Arc<AtomicU8>,
    manager: Arc<Manager>,
    tcp_buffer_size: usize,
    sniffer: Option<ArcSniffer>,
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
        sniffer: Option<ArcSniffer>,
    ) -> Self {
        Self {
            outbound_manager,
            router,
            resolver,
            mode: Arc::new(AtomicU8::new(mode as u8)),
            manager: statistics_manager,
            tcp_buffer_size: tcp_buffer_size.unwrap_or(DEFAULT_BUFFER_SIZE),
            sniffer,
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
        let force_dns_mapping = self
            .sniffer
            .as_ref()
            .map_or(false, |s| s.config.force_dns_mapping);
        let dest: SocksAddr = match reverse_lookup(
            &self.resolver,
            &sess.destination,
            force_dns_mapping,
        )
        .await
        {
            Some(dest) => dest,
            None => {
                warn!("failed to resolve destination {}", sess);
                return;
            }
        };

        sess.destination = dest.clone();
        sess.orig_destination = Some(dest.clone());

        // Perform domain sniffing if sniffer is configured
        let mut override_dest = false;
        if let Some(sniffer) = &self.sniffer {
            let (sniffed_domain, new_lhs, should_override) =
                sniffer.sniff_stream(&sess, lhs).await;
            lhs = new_lhs;
            if let Some(domain) = sniffed_domain {
                let port = sess.destination.port();
                sess.sniffed_domain = Some(domain.clone());
                sess.destination = SocksAddr::Domain(domain, port);
                override_dest = should_override;
            }
        }

        let mode = self.get_mode();
        let (outbound_name, rule) = match mode {
            RunMode::Global => (PROXY_GLOBAL, None),
            RunMode::Rule => self.router.match_route(&mut sess).await,
            RunMode::Direct => (PROXY_DIRECT, None),
        };

        // If override_destination is not requested and original destination was an IP,
        // restore original destination for outbound connection
        if !override_dest {
            if let Some(orig) = &sess.orig_destination {
                if !orig.is_domain() {
                    sess.destination = orig.clone();
                }
            }
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
        let router = self.router.clone();
        let outbound_manager = self.outbound_manager.clone();
        let resolver = self.resolver.clone();
        let mode = self.mode.clone();
        let manager = self.manager.clone();
        let sniffer = self.sniffer.clone();

        let (mut local_w, mut local_r) = udp_inbound.split();
        let (remote_receiver_w, mut remote_receiver_r) =
            tokio::sync::mpsc::channel::<UdpPacket>(UDP_CHANNEL_CAPACITY);
        let (close_sender, mut close_receiver) =
            tokio::sync::oneshot::channel::<u8>();

        let current_span = tracing::Span::current();

        tokio::spawn(
            async move {
                let mut sessions: HashMap<SocksAddr, OutboundSession> = HashMap::new();
                let mut delay_queue: DelayQueue<SocksAddr> = DelayQueue::new();
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
                            if let Err(err) = local_w.send(packet).await {
                                error!("failed to send packet to local: {}", err);
                            }
                        }

                        // 3. Idle timeout expiration from DelayQueue -> reclaim session
                        Some(expired) = delay_queue.next() => {
                            let dest = expired.into_inner();
                            trace!("UDP session expired for dest: {}", dest);
                            sessions.remove(&dest);
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

                            let mut sess = sess.clone();

                            if let SocksAddr::Ip(addr) = &mut packet.dst_addr {
                                addr.set_ip(addr.ip().to_canonical());
                            }
                            if let SocksAddr::Ip(addr) = &mut packet.src_addr {
                                addr.set_ip(addr.ip().to_canonical());
                            }

                            let Some(src_addr) = packet.src_addr.clone().try_into_socket_addr()
                            else {
                                warn!(
                                    "dropping inbound udp packet with non-ip source {}",
                                    packet.src_addr
                                );
                                continue;
                            };

                            let force_dns_mapping = sniffer
                                .as_ref()
                                .map_or(false, |s| s.config.force_dns_mapping);
                            let orig_dst_ip = packet.dst_addr.ip();
                            let orig_inbound_dst = packet.dst_addr.clone();
                            let mut dest = match reverse_lookup(&resolver, &packet.dst_addr, force_dns_mapping).await {
                                Some(dest) => dest,
                                None => {
                                    warn!("failed to resolve destination {}", sess);
                                    continue;
                                }
                            };

                            let sess_id = match sessions.get(&dest) {
                                Some(s) => s.id,
                                None => crate::session::generate_session_id(),
                            };
                            sess.id = sess_id;

                            let orig_dest = dest.clone();
                            let mut override_dest = false;
                            if let Some(ref sniffer) = sniffer {
                                if !dest.is_domain() || sniffer.should_force_sniff(&dest) {
                                    let sniffed = if let Some(dst_sock) = packet.dst_addr.clone().try_into_socket_addr() {
                                        sniffer.sniff_udp_datagram(src_addr, dst_sock, &packet.data)
                                    } else {
                                        sniffer.sniff_datagram(dest.port(), &packet.data)
                                    };
                                    if let Some((domain, should_override)) = sniffed {
                                        sess.sniffed_domain = Some(domain.clone());
                                        dest = SocksAddr::Domain(domain, dest.port());
                                        override_dest = should_override;
                                    }
                                }
                            }

                            sess.source = src_addr;
                            sess.destination = dest.clone();
                            sess.orig_destination = Some(orig_dest.clone());
                            sess.inbound_user = packet.inbound_user.clone();
                            sess.resolved_ip = match &dest {
                                SocksAddr::Ip(addr) => Some(addr.ip()),
                                SocksAddr::Domain(..) if !resolver.fake_ip_enabled() => orig_dst_ip,
                                SocksAddr::Domain(..) => None,
                            };

                            let mode = decode_mode(mode.load(Ordering::Relaxed));
                            let (outbound_name, rule) = match mode {
                                RunMode::Global => (PROXY_GLOBAL, None),
                                RunMode::Rule => router.match_route(&mut sess).await,
                                RunMode::Direct => (PROXY_DIRECT, None),
                            };

                            if !override_dest && !orig_dest.is_domain() {
                                sess.destination = orig_dest.clone();
                            }

                            let mgr = outbound_manager.clone();
                            let handler = match mgr.get_outbound(outbound_name) {
                                Some(h) => h,
                                None => {
                                    debug!("unknown rule: {}, fallback to direct", outbound_name);
                                    mgr.get_outbound(PROXY_DIRECT).unwrap()
                                }
                            };

                            let effective_proto =
                                if let Some(group) = handler.try_as_group_handler() {
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
                                continue;
                            }

                            if let Some(session) = sessions.get_mut(&dest) {
                                debug!("reusing {} sent to remote {}", sess, dest);
                                delay_queue.reset(&session.delay_key, timeout_duration);
                                forward_to_remote(&session.sender, packet, dest.clone(), &sess);
                            } else {
                                debug!("building {} outbound datagram connecting to {}", sess, dest);
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
                                                "failed to connect outbound: sess = {} ,err = {}",
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
                                        UDP_CHANNEL_CAPACITY,
                                    );

                                let orig_inbound_dst = orig_inbound_dst.clone();
                                let relay_sess = sess.clone();
                                let remote_receiver_w = remote_receiver_w.clone();

                                let relay_handle = tokio::spawn(async move {
                                    // local -> remote
                                    let outgoing = async move {
                                        while let Some((mut packet, dest_addr)) =
                                            remote_forwarder.recv().await
                                        {
                                            packet.dst_addr = dest_addr;
                                            if let Err(err) = remote_w.send(packet).await {
                                                warn!("failed to send packet to remote: {err:?}");
                                            }
                                        }
                                    };

                                    // remote -> local
                                    let incoming = async move {
                                        while let Some(mut packet) = remote_r.next().await {
                                            packet.src_addr = orig_inbound_dst.clone();
                                            packet.dst_addr = relay_sess.source.into();
                                            debug!(
                                                "UDP NAT for packet: {:?}, session: {}",
                                                packet, relay_sess
                                            );
                                            match remote_receiver_w.try_send(packet) {
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
                                    }
                                });

                                forward_to_remote(&remote_sender, packet, dest.clone(), &sess);
                                let delay_key = delay_queue.insert(dest.clone(), timeout_duration);

                                sessions.insert(
                                    dest.clone(),
                                    OutboundSession {
                                        id: sess.id,
                                        sender: remote_sender,
                                        delay_key,
                                        _relay_handle: relay_handle,
                                    },
                                );
                            }

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

type OutboundPacketSender = tokio::sync::mpsc::Sender<(UdpPacket, SocksAddr)>;

struct OutboundSession {
    id: u64,
    sender: OutboundPacketSender,
    delay_key: tokio_util::time::delay_queue::Key,
    _relay_handle: JoinHandle<()>,
}

impl Drop for OutboundSession {
    fn drop(&mut self) {
        self._relay_handle.abort();
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
            debug!("[UDP] outbound relay gone, dropping packet for {}", sess);
        }
    }
}

// helper function to resolve the destination address
// if the destination is an IP address, check if it's a fake IP
// or look for cached IP
// if the destination is a domain name, don't resolve
async fn reverse_lookup(
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
            if resolver.fake_ip_enabled() && resolver.is_fake_ip(ip).await {
                trace!("looking up fake ip: {}", ip);
                let host = resolver.reverse_lookup(ip).await;
                match host {
                    Some(host) => to_addr(host, socket_addr.port())?,
                    None => {
                        error!("failed to reverse lookup fake ip: {}", ip);
                        return None;
                    }
                }
            } else if force_dns_mapping || !resolver.fake_ip_enabled() {
                trace!("looking up resolve cache ip: {}", ip);
                match resolver.cached_for(ip).await {
                    Some(resolved) => to_addr(resolved, socket_addr.port())?,
                    _ => (*socket_addr).into(),
                }
            } else {
                (*socket_addr).into()
            }
        }
        SocksAddr::Domain(host, port) => to_addr(host.to_owned(), *port)?,
    };
    Some(dst)
}
