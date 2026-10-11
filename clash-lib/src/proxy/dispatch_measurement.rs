//! Opt-in internal hook for the isolated dispatch allocation test.

use std::{collections::{HashMap, HashSet}, future::Future, mem::size_of_val, sync::Arc, time::Duration};
use arc_swap::ArcSwap;
use futures::future::BoxFuture;
use crate::{
    app::{dns::{SystemResolver, ThreadSafeDNSResolver}, remote_content_manager::{ProxyManager, healthcheck::HealthCheck, providers::proxy_provider::PlainProvider}},
    config::internal::proxy::LoadBalanceStrategy,
    proxy::{
        OutboundHandler, OutboundNode, direct, socks, selector, loadbalance, reject,
        group::{GroupHandler, fallback, urltest, smart}, utils::DialerProxyConnector,
    },
    session::Session,
};

struct Measurement<S, F> { start: S, finish: F }
impl<S: Fn(), F: Fn(&str, usize, Option<usize>) -> usize> Measurement<S, F> {
    fn measure<T: Future + Send>(&self, name: &str, create: impl FnOnce() -> T, expected: usize) {
        (self.start)();
        let future = create();
        (self.finish)(name, size_of_val(&future), Some(expected));
    }

    fn measure_boxed<'a, T>(&self, name: &str, create: impl FnOnce() -> BoxFuture<'a, T>) {
        (self.start)();
        let future = create();
        assert_eq!(size_of_val(&future), 2 * size_of::<usize>());
        // Report the actual heap state as well as the pointer measured below.
        (self.finish)(name, size_of_val(future.as_ref().get_ref()), Some(1));
    }
}

/// Measure future construction and deterministic local dispatch execution.
/// Callbacks delimit allocation tracking in the caller's executable; the library
/// installs no allocator and performs no network I/O in this fixture.
pub async fn measure_dispatch_futures(start: impl Fn(), finish: impl Fn(&str, usize, Option<usize>) -> usize) {
    let measurement = Measurement { start, finish };
    let sess = Session::default();
    let resolver: ThreadSafeDNSResolver = Arc::new(SystemResolver::new(false).unwrap());
    let direct = Arc::new(direct::Handler::new("direct"));
    let protocol = OutboundNode::protocol(direct.clone());
    let socks = socks::outbound::Handler::new(socks::outbound::HandlerOptions {
        name: "socks".to_owned(), server: "127.0.0.1".to_owned(), port: 9,
        ..Default::default()
    }, None);
    let group = OutboundNode::group(Arc::new(selector::Handler::new(
        selector::HandlerOptions { name: "group".to_owned(), ..Default::default() },
        Vec::new(), None,
    ).await));
    let registry = Arc::new(ArcSwap::from_pointee(HashMap::new()));
    let dialer = DialerProxyConnector::new("direct".to_owned(), &registry);
    let excluded = HashSet::new();
    let round_robin = loadbalance::Handler::new(
        loadbalance::HandlerOptions {
            name: "round-robin".to_owned(), strategy: LoadBalanceStrategy::RoundRobin,
            ..Default::default()
        }, Vec::new(), ProxyManager::new(resolver.clone(), None),
    );

    let manager = ProxyManager::new(resolver.clone(), None);
    let fallback = fallback::Handler::new(Default::default(), Vec::new(), manager.clone());
    let urltest = urltest::Handler::new(Default::default(), 0, Vec::new(), manager.clone());
    let smart = smart::Handler::measurement_fixture(manager);
    macro_rules! measure_group {
        ($name:literal, $handler:expr) => {{
            let handler = $handler;
            measurement.measure(concat!($name, " select"), || handler.select(&sess, &excluded), 0);
            measurement.measure(concat!($name, " attempts"), || handler.attempts(&sess), 0);
            measurement.measure(concat!($name, " record_result"), || handler.record_result(&sess, "member", Duration::ZERO, true), 0);
        }};
    }
    for (name, bytes) in OutboundNode::executor_layout(group.as_group().unwrap(), &sess, resolver.clone()) {
        (measurement.start)();
        (measurement.finish)(name, bytes, Some(0));
    }
    measurement.measure("boxed retry sleep", || Box::pin(tokio::time::sleep(Duration::ZERO)), 1);
    measure_group!("Group enum", group.as_group().unwrap());
    // Measure concrete handlers as well as the unified group enum.
    if let crate::proxy::group::ProxyGroup::Selector(handler) = group.as_group().unwrap() {
        measure_group!("Selector", handler.as_ref());
    }
    measure_group!("Fallback", &fallback);
    measure_group!("URLTest", &urltest);
    measure_group!("LoadBalance", &round_robin);
    measure_group!("Smart", &smart);

    // Warm provider snapshot initialization before isolating the boxing cost.
    assert!(smart.select(&sess, &excluded).await.unwrap().is_none());
    let future = smart.select(&sess, &excluded);
    let bytes = size_of_val(&future);
    (measurement.start)();
    let result = future.await;
    let allocations = (measurement.finish)("Smart concrete selection execution", bytes, None);
    assert!(result.unwrap().is_none());
    let smart_group = OutboundNode::group(Arc::new(smart));
    let future = smart_group.as_group().unwrap().select(&sess, &excluded);
    let bytes = size_of_val(&future);
    (measurement.start)();
    let result = future.await;
    (measurement.finish)("Smart enum selection execution", bytes, Some(allocations + 1));
    assert!(result.unwrap().is_none());

    #[cfg(feature = "shadowsocks")]
    {
        use crate::proxy::transport::{Shadowtls, Transport, TransportLayer};
        let shadow = Shadowtls::new("example.test".to_owned(), "test-only".to_owned(), false);
        let (stream, _) = tokio::io::duplex(64);
        measurement.measure("ShadowTLS concrete", || shadow.proxy_stream(stream.into()), 0);
        let layer = TransportLayer::ShadowTls(shadow);
        let (stream, _) = tokio::io::duplex(64);
        measurement.measure("transport enum", || layer.wrap(stream.into()), 0);
    }

    measurement.measure("direct", || direct.connect_stream(&sess, resolver.clone()), 0);
    measurement.measure("socks", || socks.connect_stream(&sess, resolver.clone()), 0);
    let concrete = protocol.as_protocol().unwrap();
    measurement.measure("boxed protocol TCP handle", || concrete.connect_stream(&sess, resolver.clone()), 1);
    measurement.measure("boxed protocol UDP handle", || concrete.connect_datagram(&sess, resolver.clone()), 1);
    measurement.measure_boxed("Direct TCP heap state", || concrete.connect_stream(&sess, resolver.clone()));
    measurement.measure_boxed("Direct UDP heap state", || concrete.connect_datagram(&sess, resolver.clone()));
    let socks_protocol = OutboundNode::protocol(Arc::new(socks::outbound::Handler::new(
        socks::outbound::HandlerOptions { name: "boxed-socks".to_owned(), server: "127.0.0.1".to_owned(), port: 9, ..Default::default() }, None,
    )));
    let concrete = socks_protocol.as_protocol().unwrap();
    measurement.measure_boxed("SOCKS5 TCP heap state", || concrete.connect_stream(&sess, resolver.clone()));
    measurement.measure_boxed("SOCKS5 UDP heap state", || concrete.connect_datagram(&sess, resolver.clone()));
    measurement.measure("protocol enum", || protocol.connect_stream(&sess, resolver.clone()), 0);
    measurement.measure("protocol UDP enum", || protocol.connect_datagram(&sess, resolver.clone()), 0);
    measurement.measure("group enum", || group.connect_stream(&sess, resolver.clone()), 0);
    measurement.measure("group selection", || group.as_group().unwrap().select(&sess, &excluded), 0);
    measurement.measure("round robin selection", || round_robin.select(&sess, &excluded), 0);
    measurement.measure("dialer recursion boundary", || dialer.connect_stream(
        resolver.clone(), "127.0.0.1", 9, false, None,
        #[cfg(target_os = "linux")] None,
    ), 1);

    // Poll warmed, local policies and a deterministic protocol failure. Compare
    // group execution against the same protocol to isolate dispatch allocations.
    let rejected = OutboundNode::protocol(Arc::new(reject::Handler::new("REJECT")));
    let hc = HealthCheck::new(vec![], "invalid-url".to_owned(), 0, true, ProxyManager::new(resolver.clone(), None));
    let provider = Arc::new(PlainProvider::new("fixed".to_owned(), vec![rejected.clone()], hc).unwrap());
    let selected = OutboundNode::group(Arc::new(selector::Handler::new(
        selector::HandlerOptions { name: "fixed-selector".to_owned(), ..Default::default() },
        vec![provider.clone()], None,
    ).await));
    let balanced = loadbalance::Handler::new(
        loadbalance::HandlerOptions { name: "fixed-rr".to_owned(), strategy: LoadBalanceStrategy::RoundRobin, ..Default::default() },
        vec![provider], ProxyManager::new(resolver.clone(), None),
    );
    // ArcSwap initializes its thread-local read slots on the first load.
    // Warm the actual selection path before counting steady-state execution.
    let initialization = selected.as_group().unwrap().select(&sess, &excluded);
    let bytes = size_of_val(&initialization);
    (measurement.start)();
    let result = initialization.await;
    (measurement.finish)("group selection initialization", bytes, None);
    assert!(result.unwrap().is_some());
    assert!(balanced.select(&sess, &excluded).await.unwrap().is_some());
    let baseline = rejected.connect_stream(&sess, resolver.clone());
    let bytes = size_of_val(&baseline);
    (measurement.start)();
    let result = baseline.await;
    let allocations = (measurement.finish)("protocol execution", bytes, None);
    assert!(result.is_err());
    let future = selected.connect_stream(&sess, resolver.clone());
    let bytes = size_of_val(&future);
    (measurement.start)();
    let result = future.await;
    (measurement.finish)("single-group execution", bytes, Some(allocations));
    assert!(result.is_err());
    let future = balanced.select(&sess, &excluded);
    let bytes = size_of_val(&future);
    (measurement.start)();
    let result = future.await;
    (measurement.finish)("round robin execution", bytes, Some(0));
    assert!(result.unwrap().unwrap().ptr_eq(&rejected));

}
