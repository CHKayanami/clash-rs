use super::udp::MAX_GLOBAL_UDP_SESSIONS;
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
        AnyStream, OutboundNode, OutboundType,
    },
    session::{Session, SocksAddr},
};
use std::{
    fmt::{Debug, Formatter},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::Duration,
};
use tracing::{Instrument, debug, error, info, info_span, instrument, trace, warn};

use crate::app::dns::ThreadSafeDNSResolver;

use super::statistics_manager::{Manager, TrackGuard, TrackerInfo, TrafficTracker};

use crate::app::sniffer::ArcSniffer;

// SS2022 (AEAD-2022) MAX_PACKET_SIZE is 0xFFFF (65535 bytes). Using a relay
// buffer smaller than that forces the cipher to split every full packet into
// multiple smaller encrypted chunks, multiplying encrypt/decrypt overhead.
// Classic AEAD ciphers cap at 0x3FFF (16383 bytes) so they are unaffected.
const DEFAULT_BUFFER_SIZE: usize = 16 * 1024;
pub struct Dispatcher {
    pub(super) outbound_manager: ThreadSafeOutboundManager,
    pub(super) router: ArcRouter,
    pub(super) resolver: ThreadSafeDNSResolver,
    pub(super) mode: Arc<AtomicU8>,
    pub(super) allow_quic: Arc<AtomicBool>,
    pub(super) manager: Arc<Manager>,
    pub(super) sniffer: Option<ArcSniffer>,
    pub(super) tcp_buffer_size: usize,
    pub(super) udp_session_semaphore: Arc<tokio::sync::Semaphore>,
    pub(super) udp_association_semaphore: Arc<tokio::sync::Semaphore>,
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
            udp_association_semaphore: Arc::new(tokio::sync::Semaphore::new(
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

    #[instrument(level = "info", skip(self, sess, lhs), fields(trace_id = sess.id))]
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

        if matches!(effective_outbound_type(&handler).await, OutboundType::Reject) {
            info!("[TCP Short-Circuit] Reject connection for sess: {}", sess);
            return;
        }

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
                if is_reject_error(&err) {
                    info!("[TCP Short-Circuit] Reject connection for sess: {}", sess);
                } else {
                    warn!(
                        "failed to establish remote connection for {}: {}",
                        sess, err
                    );
                }
            }
        }
    }

}

pub(super) fn decode_mode(raw: u8) -> RunMode {
    match raw {
        0 => RunMode::Global,
        1 => RunMode::Rule,
        2 => RunMode::Direct,
        _ => unreachable!("mode is only ever written from a RunMode"),
    }
}

pub(super) async fn effective_outbound_type(handler: &OutboundNode) -> OutboundType {
    if let Some(group) = handler.as_group()
        && let Some(active) = group.get_active_proxy().await
    {
        return active.proto();
    }
    handler.proto()
}

/// `proxy/reject/mod.rs` signals a rejected connection with
/// `io::Error::other("REJECT")`. Type-based short-circuits catch direct rejects,
/// but nested groups can still return this error from stream or datagram
/// connections. Keep configured rejections out of connection failure logs.
pub(super) fn is_reject_error(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::Other
        && err.get_ref().is_some_and(|e| e.to_string() == "REJECT")
}

// helper function to resolve the destination address
// if the destination is an IP address, check if it's a fake IP
// or look for cached IP
// if the destination is a domain name, don't resolve
pub(super) fn reverse_lookup(
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
