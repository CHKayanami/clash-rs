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
        AnyStream, OutboundType, RouteChange,
    },
    session::{Session, SocksAddr},
};
#[cfg(all(target_os = "linux", feature = "ebpf"))]
use crate::{
    app::router::Rule, common::domain::has_valid_domain_labels, proxy::OutboundNode,
    session::Type,
};
#[cfg(all(target_os = "linux", feature = "ebpf"))]
use arc_swap::ArcSwapOption;
use std::{
    fmt::{Debug, Formatter},
    future::Future,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};
use tracing::{Instrument, debug, error, info, info_span, trace, warn};

use crate::app::dns::ThreadSafeDNSResolver;

use super::statistics_manager::{Manager, TrackGuard, TrackerInfo, TrafficTracker};

use crate::app::sniffer::{ArcSniffer, tls::is_valid_hostname};

// SS2022 (AEAD-2022) MAX_PACKET_SIZE is 0xFFFF (65535 bytes). Using a relay
// buffer smaller than that forces the cipher to split every full packet into
// multiple smaller encrypted chunks, multiplying encrypt/decrypt overhead.
// Classic AEAD ciphers cap at 0x3FFF (16383 bytes) so they are unaffected.
const DEFAULT_BUFFER_SIZE: usize = 16 * 1024;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteOffloadAction {
    Direct,
    Proxy,
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
#[derive(Debug, Clone)]
pub struct RouteOffloadEvent {
    pub ip: IpAddr,
    pub domain: Option<Arc<str>>,
    pub outbound: Arc<str>,
    pub action: RouteOffloadAction,
    pub rule_offloadable: bool,
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub trait RouteOffloadObserver: Send + Sync {
    fn on_route(&self, event: RouteOffloadEvent);
    fn on_mode_change(&self, mode: RunMode);
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub(super) type RouteOffloadSlot = Arc<ArcSwapOption<Arc<dyn RouteOffloadObserver>>>;

pub struct Dispatcher {
    pub(super) outbound_manager: ThreadSafeOutboundManager,
    pub(super) router: ArcRouter,
    pub(super) resolver: ThreadSafeDNSResolver,
    pub(super) mode: Arc<AtomicU8>,
    pub(super) mode_changes: RouteChange,
    pub(super) allow_quic: Arc<AtomicBool>,
    pub(super) manager: Arc<Manager>,
    pub(super) sniffer: Option<ArcSniffer>,
    pub(super) tcp_buffer_size: usize,
    pub(super) udp_session_semaphore: Arc<tokio::sync::Semaphore>,
    pub(super) udp_association_semaphore: Arc<tokio::sync::Semaphore>,
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub(super) route_offload: Option<RouteOffloadSlot>,
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
            mode_changes: RouteChange::default(),
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
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            route_offload: None,
        }
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub(crate) fn with_route_offload(mut self) -> Self {
        self.route_offload = Some(Arc::new(ArcSwapOption::empty()));
        self
    }

    pub fn set_mode(&self, mode: RunMode) {
        info!("run mode switched to {}", mode);

        let prev = self.mode.swap(mode as u8, Ordering::Relaxed);
        if prev != mode as u8 {
            self.mode_changes.notify();
        }
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        if let Some(slot) = &self.route_offload
            && let Some(observer) = slot.load().as_ref()
        {
            observer.on_mode_change(mode);
        }
    }

    pub fn get_mode(&self) -> RunMode {
        decode_mode(self.mode.load(Ordering::Relaxed))
    }

    pub(crate) fn mode_changes(&self) -> RouteChange {
        self.mode_changes.clone()
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

    pub fn outbound_manager(&self) -> &ThreadSafeOutboundManager {
        &self.outbound_manager
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub(crate) fn register_route_offload_observer(
        &self,
        observer: Arc<dyn RouteOffloadObserver>,
    ) {
        let slot = self.route_offload.as_ref().expect("route offload is configured");
        observer.on_mode_change(self.get_mode());
        slot.store(Some(Arc::new(observer)));
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub(crate) fn unregister_route_offload_observer(
        &self,
        observer: &Arc<dyn RouteOffloadObserver>,
    ) {
        if let Some(slot) = &self.route_offload {
            slot.rcu(|current| match current {
                Some(existing) if Arc::ptr_eq(existing.as_ref(), observer) => None,
                _ => current.clone(),
            });
        }
    }

    pub fn dispatch_stream(
        &self, sess: Session, lhs: AnyStream,
    ) -> impl Future<Output = ()> + Send + '_ {
        let span = info_span!("dispatch_stream", trace_id = sess.id);
        self.dispatch_stream_inner(sess, lhs).instrument(span)
    }

    fn dispatch_stream_inner(
        &self, mut sess: Session, mut lhs: AnyStream,
    ) -> impl Future<Output = ()> + Send + '_ {
        async move {
            let (rhs, tracker_info, copy_span) = {
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

                sess.destination = dest;

                // Perform domain sniffing if sniffer is configured
                let mut override_dest = false;
                if let Some(sniffer) = &self.sniffer {
                    let (sniffed_domain, new_lhs, should_override) =
                        sniffer.sniff_stream(&sess, lhs).await;
                    lhs = new_lhs;
                    if let Some(domain) = sniffed_domain {
                        override_dest = apply_sniffed_domain(
                            &mut sess, domain, should_override,
                        );
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

                let handler = self.outbound_manager.get_outbound_or_direct(outbound_name);
                #[cfg(all(target_os = "linux", feature = "ebpf"))]
                let effective_proto = outbound_type_with_offload(
                    self.route_offload.as_ref(),
                    &self.router,
                    &sess,
                    if is_real_ip { orig_dest.ip() } else { None },
                    mode,
                    rule,
                    &handler,
                )
                .await;
                #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
                let effective_proto = handler.selected_outbound_type().await;

                // If override_destination is not requested and original destination was a real IP,
                // restore original destination for outbound connection
                if !override_dest && is_real_ip {
                    sess.destination = orig_dest.clone();
                }

                debug!("dispatching {} to {}[{}]", sess, outbound_name, mode);

                if matches!(effective_proto, OutboundType::Reject) {
                    info!("[TCP Short-Circuit] Reject connection for sess: {}", sess);
                    return;
                }

                let rhs = match handler
                    .connect_stream(&sess, self.resolver.clone())
                    .instrument(info_span!("connect_stream", outbound_name = outbound_name,))
                    .await
                {
                    Ok(rhs) => rhs,
                    Err(err) => {
                        if is_reject_error(&err) {
                            info!("[TCP Short-Circuit] Reject connection for sess: {}", sess);
                        } else {
                            warn!("failed to establish remote connection for {}: {}", sess, err);
                        }
                        return;
                    }
                };
                debug!("remote connection established {}", sess);
                let tracker_info = Arc::new(TrackerInfo::new(&sess, rule));
                let copy_span = info_span!("copy_bidirectional", outbound_name = outbound_name);
                (rhs, tracker_info, copy_span)
            };

            let (close_tx, close_rx) = tokio::sync::oneshot::channel();
            self.manager.track(sess.id, tracker_info.clone(), close_tx);
            let _track_guard = TrackGuard::new(sess.id, self.manager.clone());

            let tracker =
                TrafficTracker::new(tracker_info, self.manager.clone());

            let copy_fut = copy_bidirectional(
                lhs,
                rhs,
                self.tcp_buffer_size,
                tracker,
            )
            .instrument(copy_span);

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

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub(super) async fn outbound_type_with_offload(
    route_offload: Option<&RouteOffloadSlot>,
    router: &ArcRouter,
    sess: &Session,
    orig_ip: Option<IpAddr>,
    mode: RunMode,
    rule: Option<&Rule>,
    handler: &OutboundNode,
) -> OutboundType {
    let (Some(slot), Some(ip)) = (route_offload, orig_ip) else {
        return handler.selected_outbound_type().await;
    };
    if sess.typ != Type::Ebpf || mode != RunMode::Rule {
        return handler.selected_outbound_type().await;
    }
    let Some(observer) = slot.load_full() else {
        return handler.selected_outbound_type().await;
    };
    let effective_proto = handler.effective_outbound_type().await;

    // Extract routing domain before `sess.destination` is restored to `orig_dest`.
    let domain = sess.destination.domain().filter(|d| has_valid_domain_labels(d));
    let rule_offloadable = router.is_match_offloadable(sess, rule, domain.is_some());
    if domain.is_none()
        && !rule_offloadable
        && effective_proto == OutboundType::Direct
    {
        return effective_proto;
    }

    let action = if rule_offloadable && effective_proto == OutboundType::Direct {
        RouteOffloadAction::Direct
    } else {
        RouteOffloadAction::Proxy
    };
    observer.on_route(RouteOffloadEvent {
        ip: ip.to_canonical(),
        domain: domain.map(Arc::from),
        outbound: Arc::from(handler.name()),
        action,
        rule_offloadable,
    });
    effective_proto
}

/// `proxy/reject/mod.rs` signals a rejected connection with
/// `io::Error::other("REJECT")`. Type-based short-circuits catch direct rejects,
/// but nested groups can still return this error from stream or datagram
/// connections. Keep configured rejections out of connection failure logs.
pub(super) fn is_reject_error(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::Other
        && err.get_ref().is_some_and(|e| e.to_string() == "REJECT")
}

pub(super) fn apply_sniffed_domain(
    sess: &mut Session,
    domain: String,
    should_override: bool,
) -> bool {
    // Keep IP literals as sniff metadata, without changing routing or dialing.
    let valid_domain = is_valid_hostname(&domain)
        && domain.parse::<IpAddr>().is_err()
        && domain.bytes().any(|b| {
            b.is_ascii_alphabetic() || b == b'-' || b == b'_'
        });
    if valid_domain {
        sess.destination = SocksAddr::Domain(
            domain.clone().into(), sess.destination.port(),
        );
    }
    sess.sniffed_domain = Some(domain);
    valid_domain && should_override
}

#[cfg(test)]
mod sniffed_domain_tests {
    use super::*;

    #[test]
    fn test_ip_and_invalid_host_preserve_destination() {
        for host in [
            "2001:db8::1", "192.0.2.1", "2402", "bad:host", "-bad.example",
        ] {
            let mut sess = Session {
                destination: "[2001:db8::2]:80".parse().unwrap(),
                ..Default::default()
            };
            let original = sess.destination.clone();
            assert!(!apply_sniffed_domain(&mut sess, host.to_string(), true));
            assert_eq!(sess.destination, original);
            assert_eq!(sess.sniffed_domain.as_deref(), Some(host));
        }
    }

    #[test]
    fn test_domain_preserves_port_and_override_setting() {
        for should_override in [false, true] {
            let mut sess = Session {
                destination: "[2001:db8::2]:8080".parse().unwrap(),
                ..Default::default()
            };
            assert_eq!(
                apply_sniffed_domain(
                    &mut sess, "example.com".to_string(), should_override,
                ),
                should_override,
            );
            assert_eq!(sess.destination, "example.com:8080".parse().unwrap());
        }
    }
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

#[cfg(all(test, target_os = "linux", feature = "ebpf"))]
mod route_offload_tests {
    use super::*;
    use std::{collections::HashMap, env::temp_dir, net::SocketAddr, time::Duration};
    use parking_lot::Mutex;
    use tokio::{io::duplex, net::TcpListener, time::timeout};
    use crate::{
        app::{
            dns::MockClashResolver,
            outbound::manager::OutboundManager,
            router::Router,
        },
        config::internal::rule::RuleType,
        proxy::{
            OutboundNode,
            direct::Handler as DirectHandler,
            ebpf::offloader::{RoutingAction, evaluate_dns_offload},
            group::selector::{self, SelectorControl},
            mocks::MockDummyProxyProvider,
            reject::Handler as RejectHandler,
        },
        session::Network,
    };

    struct RecordingObserver {
        events: Mutex<Vec<RouteOffloadEvent>>,
        modes: Mutex<Vec<RunMode>>,
    }

    impl RecordingObserver {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                modes: Mutex::new(Vec::new()),
            }
        }
    }

    impl RouteOffloadObserver for RecordingObserver {
        fn on_route(&self, event: RouteOffloadEvent) {
            self.events.lock().push(event);
        }

        fn on_mode_change(&self, mode: RunMode) {
            self.modes.lock().push(mode);
        }
    }

    fn test_provider(nodes: Vec<OutboundNode>) -> Arc<MockDummyProxyProvider> {
        let mut provider = MockDummyProxyProvider::new();
        let proxies = Arc::new(nodes);
        provider.expect_proxies().returning(move || proxies.clone());
        provider.expect_touch().return_const(());
        provider.expect_route_changes().return_const(None);
        Arc::new(provider)
    }

    #[tokio::test]
    async fn nested_selector_expands_effective_type_and_evaluates_dns_offload() {
        let direct = OutboundNode::protocol(Arc::new(DirectHandler::new("DIRECT")));
        let reject = OutboundNode::protocol(Arc::new(RejectHandler::new("REJECT")));
        let inner = Arc::new(
            selector::Handler::new(
                selector::HandlerOptions {
                    name: "INNER".into(),
                    ..Default::default()
                },
                vec![test_provider(vec![direct.clone(), reject.clone()])],
                Some("DIRECT".to_string()),
            )
            .await,
        );
        let outer = Arc::new(
            selector::Handler::new(
                selector::HandlerOptions {
                    name: "AUTO".into(),
                    ..Default::default()
                },
                vec![test_provider(vec![OutboundNode::group(inner.clone())])],
                None,
            )
            .await,
        );

        let outer_node = OutboundNode::group(outer);
        assert_eq!(outer_node.effective_outbound_type().await, OutboundType::Direct);
        inner.select("REJECT").unwrap();
        assert_eq!(outer_node.effective_outbound_type().await, OutboundType::Reject);
        assert_eq!(outer_node.selected_outbound_type().await, OutboundType::Selector);
        inner.select("DIRECT").unwrap();

        let mut handlers = HashMap::new();
        handlers.insert("DIRECT".to_string(), direct);
        handlers.insert("REJECT".to_string(), reject);
        handlers.insert("AUTO".to_string(), outer_node);
        let outbound_manager = Arc::new(OutboundManager::new_for_test(handlers));

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_fake_ip_enabled().returning(|| false);
        mock_resolver.expect_is_fake_ip().returning(|_| false);
        mock_resolver.expect_cached_for().returning(|_| None);
        mock_resolver.expect_resolve().returning(|_, _| Ok(None));
        let resolver: ThreadSafeDNSResolver = Arc::new(mock_resolver);

        let router = Arc::new(
            Router::new(
                vec![RuleType::Domain {
                    domain: "group.example".to_string(),
                    target: "AUTO".to_string(),
                }],
                HashMap::new(),
                resolver.clone(),
                None,
                None,
                None,
                None,
                None,
                temp_dir().to_str().unwrap().to_string(),
            )
            .await
            .unwrap(),
        );

        let dispatcher = Dispatcher::new(
            outbound_manager,
            router,
            resolver,
            RunMode::Rule,
            Manager::new(),
            None,
            None,
            true,
        );

        assert!(dispatcher.route_offload.is_none());
        let mut sess = Session {
            typ: Type::Ebpf,
            destination: SocksAddr::Domain("group.example".into(), 443),
            ..Default::default()
        };
        inner.select("REJECT").unwrap();
        let (outbound, rule) = dispatcher.router.match_route(&mut sess).await;
        let handler = dispatcher.outbound_manager.get_outbound_or_direct(outbound);
        let proto = outbound_type_with_offload(
            dispatcher.route_offload.as_ref(),
            &dispatcher.router,
            &sess,
            Some("1.1.1.1".parse().unwrap()),
            RunMode::Rule,
            rule,
            &handler,
        )
        .await;
        assert_eq!(proto, OutboundType::Selector);
        inner.select("DIRECT").unwrap();

        let dispatcher = dispatcher.with_route_offload();
        let observer = Arc::new(RecordingObserver::new());
        let observer_trait: Arc<dyn RouteOffloadObserver> = observer.clone();
        dispatcher.register_route_offload_observer(observer_trait.clone());
        dispatcher.set_mode(RunMode::Global);
        dispatcher.set_mode(RunMode::Rule);
        assert_eq!(
            *observer.modes.lock(),
            vec![RunMode::Rule, RunMode::Global, RunMode::Rule]
        );
        dispatcher.unregister_route_offload_observer(&observer_trait);

        let ips = ["1.1.1.1".parse().unwrap()];
        let (action, outbound, offloadable) =
            evaluate_dns_offload(&dispatcher, "group.example", &ips).await;
        assert_eq!(action, RoutingAction::Direct);
        assert_eq!(outbound.as_ref(), "AUTO");
        assert!(offloadable);

        inner.select("REJECT").unwrap();
        let (action, _, offloadable) =
            evaluate_dns_offload(&dispatcher, "group.example", &ips).await;
        assert_eq!(action, RoutingAction::Proxy);
        assert!(offloadable);
    }

    #[tokio::test]
    async fn ebpf_tcp_dispatch_reports_on_route_decision_and_vetoes_reject() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });

        let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = closed_listener.local_addr().unwrap();
        drop(closed_listener);

        let reject_ip: IpAddr = "203.0.113.50".parse().unwrap();

        let mut handlers = HashMap::new();
        handlers.insert(
            "DIRECT".to_string(),
            OutboundNode::protocol(Arc::new(DirectHandler::new("DIRECT"))),
        );
        handlers.insert(
            "REJECT".to_string(),
            OutboundNode::protocol(Arc::new(RejectHandler::new("REJECT"))),
        );
        let outbound_manager = Arc::new(OutboundManager::new_for_test(handlers));

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_fake_ip_enabled().returning(|| false);
        mock_resolver.expect_is_fake_ip().returning(|_| false);
        mock_resolver.expect_cached_for().returning(move |ip| {
            if ip == reject_ip {
                Some("reject.example".to_string())
            } else {
                None
            }
        });
        mock_resolver.expect_resolve().returning(|_, _| Ok(None));
        let resolver: ThreadSafeDNSResolver = Arc::new(mock_resolver);

        let router = Arc::new(
            Router::new(
                vec![
                    RuleType::IpCidr {
                        ipnet: format!("{}/32", live_addr.ip()).parse().unwrap(),
                        target: "DIRECT".to_string(),
                        no_resolve: false,
                    },
                    RuleType::Match {
                        target: "REJECT".to_string(),
                    },
                ],
                HashMap::new(),
                resolver.clone(),
                None,
                None,
                None,
                None,
                None,
                temp_dir().to_str().unwrap().to_string(),
            )
            .await
            .unwrap(),
        );

        let dispatcher = Dispatcher::new(
            outbound_manager,
            router,
            resolver,
            RunMode::Rule,
            Manager::new(),
            None,
            None,
            true,
        );
        let dispatcher = dispatcher.with_route_offload();
        let observer = Arc::new(RecordingObserver::new());
        dispatcher.register_route_offload_observer(observer.clone());

        // 1. Successful DIRECT TCP connection emits Direct event.
        let (client_left, client_right) = duplex(64);
        drop(client_right);
        let sess_ok = Session {
            network: Network::Tcp,
            typ: Type::Ebpf,
            source: "127.0.0.1:40001".parse().unwrap(),
            destination: SocksAddr::Ip(live_addr),
            ..Default::default()
        };
        timeout(
            Duration::from_secs(5),
            dispatcher.dispatch_stream(sess_ok, AnyStream::Dynamic(Box::new(client_left))),
        )
        .await
        .expect("dispatch_stream should finish once both sides close");
        timeout(Duration::from_secs(5), accept_task)
            .await
            .expect("listener should accept real direct connection")
            .unwrap();

        // 2. DIRECT TCP route decision still emits Direct event even when dial fails later.
        let (fail_left, fail_right) = duplex(64);
        drop(fail_right);
        let sess_fail = Session {
            network: Network::Tcp,
            typ: Type::Ebpf,
            source: "127.0.0.1:40002".parse().unwrap(),
            destination: SocksAddr::Ip(dead_addr),
            ..Default::default()
        };
        timeout(
            Duration::from_secs(5),
            dispatcher.dispatch_stream(sess_fail, AnyStream::Dynamic(Box::new(fail_left))),
        )
        .await
        .expect("failed connect should return promptly");

        // 3. REJECT emits immediate Proxy veto with mapped domain.
        let (rej_left, rej_right) = duplex(64);
        drop(rej_right);
        let sess_rej = Session {
            network: Network::Tcp,
            typ: Type::Ebpf,
            source: "127.0.0.1:40003".parse().unwrap(),
            destination: SocksAddr::Ip(SocketAddr::new(reject_ip, 443)),
            ..Default::default()
        };
        timeout(
            Duration::from_secs(5),
            dispatcher.dispatch_stream(sess_rej, AnyStream::Dynamic(Box::new(rej_left))),
        )
        .await
        .expect("reject short-circuit should return promptly");

        let events = observer.events.lock();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].ip, live_addr.ip());
        assert_eq!(events[0].action, RouteOffloadAction::Direct);
        assert_eq!(events[1].ip, dead_addr.ip());
        assert_eq!(events[1].action, RouteOffloadAction::Direct);
        assert_eq!(events[2].ip, reject_ip);
        assert_eq!(events[2].domain.as_deref(), Some("reject.example"));
        assert_eq!(events[2].action, RouteOffloadAction::Proxy);
    }

    #[tokio::test]
    async fn unoffloadable_pure_ip_non_direct_still_emits_proxy_veto() {
        let mut handlers = HashMap::new();
        handlers.insert(
            "DIRECT".to_string(),
            OutboundNode::protocol(Arc::new(DirectHandler::new("DIRECT"))),
        );
        handlers.insert(
            "REJECT".to_string(),
            OutboundNode::protocol(Arc::new(RejectHandler::new("REJECT"))),
        );
        let outbound_manager = Arc::new(OutboundManager::new_for_test(handlers));

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_fake_ip_enabled().returning(|| false);
        mock_resolver.expect_is_fake_ip().returning(|_| false);
        mock_resolver.expect_cached_for().returning(|_| None);
        mock_resolver.expect_resolve().returning(|_, _| Ok(None));
        let resolver: ThreadSafeDNSResolver = Arc::new(mock_resolver);

        let router = Arc::new(
            Router::new(
                vec![
                    RuleType::Domain {
                        domain: "direct.example".to_string(),
                        target: "DIRECT".to_string(),
                    },
                    RuleType::DSTPort {
                        port: 8443,
                        target: "REJECT".to_string(),
                    },
                    RuleType::DSTPort {
                        port: 8444,
                        target: "DIRECT".to_string(),
                    },
                    RuleType::Match {
                        target: "REJECT".to_string(),
                    },
                ],
                HashMap::new(),
                resolver.clone(),
                None,
                None,
                None,
                None,
                None,
                temp_dir().to_str().unwrap().to_string(),
            )
            .await
            .unwrap(),
        );

        let dispatcher = Dispatcher::new(
            outbound_manager,
            router,
            resolver,
            RunMode::Rule,
            Manager::new(),
            None,
            None,
            true,
        )
        .with_route_offload();
        let observer = Arc::new(RecordingObserver::new());
        dispatcher.register_route_offload_observer(observer.clone());

        // 1. Pure-IP falling through to MATCH,REJECT with domain rules present -> veto.
        let ip_match: IpAddr = "198.51.100.11".parse().unwrap();
        let mut sess_match = Session {
            typ: Type::Ebpf,
            destination: SocksAddr::Ip(SocketAddr::new(ip_match, 443)),
            ..Default::default()
        };
        let (outbound, rule) = dispatcher.router.match_route(&mut sess_match).await;
        let handler = dispatcher.outbound_manager.get_outbound_or_direct(outbound);
        let proto = outbound_type_with_offload(
            dispatcher.route_offload.as_ref(),
            &dispatcher.router,
            &sess_match,
            Some(ip_match),
            RunMode::Rule,
            rule,
            &handler,
        )
        .await;
        assert_eq!(proto, OutboundType::Reject);

        // 2. Pure-IP hitting context-sensitive DST-PORT,8443,REJECT -> veto.
        let ip_port_rej: IpAddr = "198.51.100.12".parse().unwrap();
        let mut sess_port_rej = Session {
            typ: Type::Ebpf,
            destination: SocksAddr::Ip(SocketAddr::new(ip_port_rej, 8443)),
            ..Default::default()
        };
        let (outbound, rule) = dispatcher.router.match_route(&mut sess_port_rej).await;
        let handler = dispatcher.outbound_manager.get_outbound_or_direct(outbound);
        let proto = outbound_type_with_offload(
            dispatcher.route_offload.as_ref(),
            &dispatcher.router,
            &sess_port_rej,
            Some(ip_port_rej),
            RunMode::Rule,
            rule,
            &handler,
        )
        .await;
        assert_eq!(proto, OutboundType::Reject);

        // 3. Pure-IP hitting context-sensitive DST-PORT,8444,DIRECT -> ignored (neither offload nor veto).
        let ip_port_direct: IpAddr = "198.51.100.13".parse().unwrap();
        let mut sess_port_direct = Session {
            typ: Type::Ebpf,
            destination: SocksAddr::Ip(SocketAddr::new(ip_port_direct, 8444)),
            ..Default::default()
        };
        let (outbound, rule) = dispatcher.router.match_route(&mut sess_port_direct).await;
        let handler = dispatcher.outbound_manager.get_outbound_or_direct(outbound);
        let proto = outbound_type_with_offload(
            dispatcher.route_offload.as_ref(),
            &dispatcher.router,
            &sess_port_direct,
            Some(ip_port_direct),
            RunMode::Rule,
            rule,
            &handler,
        )
        .await;
        assert_eq!(proto, OutboundType::Direct);

        let events = observer.events.lock();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].ip, ip_match);
        assert!(events[0].domain.is_none());
        assert_eq!(events[0].action, RouteOffloadAction::Proxy);
        assert!(!events[0].rule_offloadable);
        assert_eq!(events[1].ip, ip_port_rej);
        assert!(events[1].domain.is_none());
        assert_eq!(events[1].action, RouteOffloadAction::Proxy);
        assert!(!events[1].rule_offloadable);
    }
}
