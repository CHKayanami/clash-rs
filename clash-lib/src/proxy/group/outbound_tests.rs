use super::{GroupHandler, GroupProxyAPIResponse, UdpPolicy, selector};
use crate::{
    app::dns::ThreadSafeDNSResolver,
    proxy::{
        AnyOutboundDatagram, OutboundNode, AnyStream,
        DialWithConnector, OutboundHandler, OutboundType,
        mocks::MockDummyProxyProvider,
        utils::test_utils::noop::NoopResolver,
    },
    session::Session,
};
use std::{collections::HashSet, io, sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};

#[derive(Debug)]
pub struct Leaf {
    name: &'static str,
    fail: bool,
    calls: AtomicUsize,
}
impl DialWithConnector for Leaf {}
impl OutboundHandler for Leaf {
    fn name(&self) -> &str { self.name }
    fn proto(&self) -> OutboundType { OutboundType::Direct }
    fn support_udp(&self) -> bool { true }


    async fn connect_stream(&self, sess: &Session, _resolver: ThreadSafeDNSResolver) -> io::Result<AnyStream> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.fail { return Err(io::Error::other("test connection failure")); }
        sess.push_chain(self.name);
        let (stream, _) = tokio::io::duplex(64);
        Ok(stream.into())
    }
    async fn connect_datagram(&self, _sess: &Session, _resolver: ThreadSafeDNSResolver) -> io::Result<AnyOutboundDatagram> {
        Err(io::Error::other("not used"))
    }
}

#[derive(Debug)]
pub struct RetryGroup {
    name: &'static str,
    members: Vec<OutboundNode>,
    selections: AtomicUsize,
    results: AtomicUsize,
}
impl RetryGroup {
    pub(crate) fn new(name: &'static str, members: Vec<OutboundNode>) -> Self {
        Self { name, members, selections: AtomicUsize::new(0), results: AtomicUsize::new(0) }
    }
}

impl GroupHandler for RetryGroup {
    fn name(&self) -> &str { self.name }
    fn proto(&self) -> OutboundType { OutboundType::Smart }
    fn udp_policy(&self) -> UdpPolicy { UdpPolicy::Enabled }


    async fn select(&self, _sess: &Session, excluded: &HashSet<String>) -> io::Result<Option<OutboundNode>> {
        self.selections.fetch_add(1, Ordering::Relaxed);
        Ok(self.members.iter().find(|h| !excluded.contains(h.name())).cloned())
    }
    async fn attempts(&self, _sess: &Session) -> u32 { 2 }
    async fn record_result(&self, _sess: &Session, _proxy: &str, _elapsed: Duration, _success: bool) {
        self.results.fetch_add(1, Ordering::Relaxed);
    }
}
impl GroupProxyAPIResponse for RetryGroup {
    async fn get_proxies(&self) -> Vec<OutboundNode> { self.members.clone() }
    async fn get_active_proxy(&self) -> Option<OutboundNode> { self.members.first().cloned() }
    fn get_latency_test_url(&self) -> Option<String> { None }
}

async fn selector(name: &str, members: Vec<OutboundNode>) -> selector::Handler {
    let snapshot = Arc::new(members);
    let mut provider = MockDummyProxyProvider::new();
    provider.expect_proxies().returning(move || snapshot.clone());
    provider.expect_touch().return_const(());
    selector::Handler::new(selector::HandlerOptions {
        name: name.to_owned(), udp: true, ..Default::default()
    }, vec![Arc::new(provider)], None).await
}

#[tokio::test]
async fn nested_groups_select_once_and_preserve_chain_order() {
    let leaf = Arc::new(Leaf { name: "leaf", fail: false, calls: AtomicUsize::new(0) });
    let inner = Arc::new(RetryGroup {
        name: "inner", members: vec![OutboundNode::protocol(leaf.clone())],
        selections: AtomicUsize::new(0), results: AtomicUsize::new(0),
    });
    let outer = selector("outer", vec![OutboundNode::group(inner.clone())]).await;
    let sess = Session::default();
    OutboundNode::group(Arc::new(outer)).connect_stream(&sess, Arc::new(NoopResolver)).await.unwrap();
    assert_eq!(inner.selections.load(Ordering::Relaxed), 1);
    assert_eq!(inner.results.load(Ordering::Relaxed), 1);
    assert_eq!(leaf.calls.load(Ordering::Relaxed), 1);
    assert_eq!(sess.proxy_chain.snapshot(), vec!["leaf", "inner", "outer"]);
}

#[tokio::test]
async fn nested_retry_finishes_before_parent_reselects() {
    let bad = Arc::new(Leaf { name: "bad", fail: true, calls: AtomicUsize::new(0) });
    let good = Arc::new(Leaf { name: "good", fail: false, calls: AtomicUsize::new(0) });
    let inner = Arc::new(RetryGroup {
        name: "inner", members: vec![OutboundNode::protocol(bad.clone()), OutboundNode::protocol(good.clone())],
        selections: AtomicUsize::new(0), results: AtomicUsize::new(0),
    });
    let outer = Arc::new(RetryGroup {
        name: "outer", members: vec![OutboundNode::group(inner.clone())],
        selections: AtomicUsize::new(0), results: AtomicUsize::new(0),
    });
    let sess = Session::default();
    OutboundNode::group(outer.clone()).connect_stream(&sess, Arc::new(NoopResolver)).await.unwrap();
    assert_eq!(outer.selections.load(Ordering::Relaxed), 1);
    assert_eq!(inner.selections.load(Ordering::Relaxed), 2);
    assert_eq!(inner.results.load(Ordering::Relaxed), 2);
    assert_eq!(sess.proxy_chain.snapshot(), vec!["good", "inner", "outer"]);
}

#[tokio::test]
async fn udp_capability_preserves_group_selection_policies() {
    use super::{fallback, urltest};
    use crate::{
        app::remote_content_manager::{ProxyManager, providers::proxy_provider::ArcProxyProvider},
        proxy::{direct, reject},
    };
    let providers = |members: Vec<OutboundNode>| -> Vec<ArcProxyProvider> {
        let snapshot = Arc::new(members);
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning(move || snapshot.clone());
        vec![Arc::new(provider)]
    };
    let manager = ProxyManager::new(Arc::new(NoopResolver), None);
    let direct = OutboundNode::protocol(Arc::new(direct::Handler::new("direct")));
    let reject = OutboundNode::protocol(Arc::new(reject::Handler::new("reject")));

    for (leaf, supported) in [(direct, true), (reject, false)] {
        let nested = OutboundNode::group(Arc::new(selector("nested", vec![leaf.clone()]).await));
        let outer = OutboundNode::group(Arc::new(selector("outer", vec![nested]).await));
        assert_eq!(outer.support_udp().await, supported);
        for udp in [false, true] {
            let fallback = OutboundNode::group(Arc::new(fallback::Handler::new(
                fallback::HandlerOptions { name: "fallback".to_owned(), udp, ..Default::default() },
                providers(vec![leaf.clone()]), manager.clone(),
            )));
            let urltest = OutboundNode::group(Arc::new(urltest::Handler::new(
                urltest::HandlerOptions { name: "urltest".to_owned(), udp, ..Default::default() },
                0, providers(vec![leaf.clone()]), manager.clone(),
            )));
            assert_eq!(fallback.support_udp().await, udp || supported);
            assert_eq!(urltest.support_udp().await, udp || supported);
            let selector = OutboundNode::group(Arc::new(selector::Handler::new(
                selector::HandlerOptions { name: "selector".to_owned(), udp, ..Default::default() },
                providers(vec![leaf.clone()]), None,
            ).await));
            assert_eq!(selector.support_udp().await, udp && supported);
        }
    }
    let empty = OutboundNode::group(Arc::new(selector("empty", Vec::new()).await));
    assert!(!empty.support_udp().await);
}
