use std::{io, collections::HashMap, sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};
use arc_swap::ArcSwap;
use bytes::Bytes;
use tokio::{io::{AsyncReadExt, AsyncWriteExt, duplex}, sync::{mpsc, Notify}};
use crate::{
    app::{dns::{config::{DNSNetMode, NameServer}, query::{DnsName, IngressProfile, QType, QueryContext, build_dns_query_wire}},
        remote_content_manager::ProxyManager},
    config::internal::proxy::LoadBalanceStrategy,
    proxy::{RouteChange, AnyOutboundDatagram, OutboundNode, OutboundType,
        datagram::{ChannelDatagram, UdpPacket}, group::{selector, selector::ThreadSafeSelectorControl, fallback, urltest, loadbalance, outbound_tests::RetryGroup},
        mocks::{MockDummyOutboundHandler, MockDummyProxyProvider},
        utils::test_utils::noop::NoopResolver},
};
use super::{UdpUpstream, UpstreamEntry, UpstreamPool, UpstreamState};

struct ProviderState {
    nodes: ArcSwap<Vec<OutboundNode>>,
    changes: RouteChange,
    reads: AtomicUsize,
    touches: AtomicUsize,
}
impl ProviderState {
    fn new(nodes: Vec<OutboundNode>) -> Self {
        Self { nodes: ArcSwap::from_pointee(nodes), changes: RouteChange::default(), reads: AtomicUsize::new(0), touches: AtomicUsize::new(0) }
    }
    fn load_full(&self) -> Arc<Vec<OutboundNode>> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.nodes.load_full()
    }
    fn store(&self, nodes: Arc<Vec<OutboundNode>>) { self.nodes.store(nodes); self.changes.notify(); }
}
type Snapshot = Arc<ProviderState>;

struct Gate { started: Notify, release: Notify }

fn leaf(name: &str, marker: u8, gate: Option<Arc<Gate>>) -> (OutboundNode, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let mut handler = MockDummyOutboundHandler::new();
    handler.expect_name().return_const(name.to_owned());
    handler.expect_proto().return_const(OutboundType::Direct);
    handler.expect_support_udp().return_const(true);
    let calls = count.clone();
    let tcp_gate = gate.clone();
    handler.expect_connect_stream().returning(move |_, _| {
        calls.fetch_add(1, Ordering::Relaxed);
        let (client, mut server) = duplex(8192);
        let gate = tcp_gate.clone();
        tokio::spawn(async move {
            while let Ok(len) = server.read_u16().await {
                let mut wire = vec![0; usize::from(len)];
                server.read_exact(&mut wire).await.unwrap();
                if let Some(gate) = &gate { gate.started.notify_one(); gate.release.notified().await; }
                wire[2] |= 0x80; wire[3] = marker;
                if server.write_u16(len).await.is_err() { break; }
                if server.write_all(&wire).await.is_err() { break; }
            }
        });
        Ok(client.into())
    });
    let calls = count.clone();
    handler.expect_connect_datagram().returning(move |sess, _| {
        calls.fetch_add(1, Ordering::Relaxed);
        let target = sess.destination.clone();
        let (outgoing, mut requests) = mpsc::channel::<UdpPacket>(16);
        let (replies, incoming) = mpsc::channel(16);
        let gate = gate.clone();
        tokio::spawn(async move {
            while let Some(packet) = requests.recv().await {
                if let Some(gate) = &gate { gate.started.notify_one(); gate.release.notified().await; }
                let mut wire = packet.data.to_vec(); wire[2] |= 0x80; wire[3] = marker;
                if replies.send(UdpPacket::new(Bytes::from(wire), target.clone(), packet.src_addr)).await.is_err() { break; }
            }
        });
        Ok(AnyOutboundDatagram::dynamic(ChannelDatagram::new(outgoing, incoming)))
    });
    (OutboundNode::protocol(Arc::new(handler)), count)
}

fn provider(snapshot: &Snapshot) -> Arc<MockDummyProxyProvider> {
    let mut provider = MockDummyProxyProvider::new();
    let changes = snapshot.changes.clone();
    provider.expect_route_changes().returning(move || Some(changes.clone()));
    let touched = snapshot.clone();
    provider.expect_touch().returning(move || { touched.touches.fetch_add(1, Ordering::Relaxed); });
    let snapshot = snapshot.clone();
    provider.expect_proxies().returning(move || snapshot.load_full());
    Arc::new(provider)
}

fn pool(net: DNSNetMode, node: OutboundNode) -> Arc<UpstreamPool> {
    let entry = UpstreamEntry::from_nameserver(&NameServer {
        net, host: url::Host::Ipv4("192.0.2.53".parse().unwrap()), port: 53,
        path: None, proxy: Some("dns-group".to_owned()), interface: None,
    }, None).unwrap();
    UpstreamPool::new(HashMap::from([("dns".to_owned(), entry)]),
        Arc::new(ArcSwap::from_pointee(HashMap::from([("dns-group".to_owned(), node)]))),
        Some(Arc::new(NoopResolver)), None, None, None)
}

async fn selected(pool: &UpstreamPool, name: &str, node: Option<&OutboundNode>) {
    tokio::time::timeout(Duration::from_secs(11), async {
        loop {
            for cached in pool.selections.values() {
                if let Ok(selection) = cached.get().await
                    && let Some(current) = &selection.node
                    && current.name() == name
                    && node.is_none_or(|expected| current.ptr_eq(expected))
                { return; }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
}

async fn query(pool: &UpstreamPool) -> u8 { query_outbound(pool, None).await }

async fn query_outbound(pool: &UpstreamPool, outbound: Option<&str>) -> u8 {
    let wire = build_dns_query_wire(&DnsName::from_domain("routing.test").unwrap(), QType::A);
    let query = QueryContext::parse(Bytes::from(wire), IngressProfile::Internal).unwrap();
    pool.query("dns", &query, outbound).await.unwrap()[3]
}

#[tokio::test(start_paused = true)]
async fn selector_switch_and_same_name_update_preserve_inflight_queries() {
    tokio::time::timeout(Duration::from_secs(60), async {
        for net in [DNSNetMode::Udp, DNSNetMode::Tcp] {
            let gate = Arc::new(Gate { started: Notify::new(), release: Notify::new() });
            let (a, a_calls) = leaf("a", 1, Some(gate.clone()));
            let (b, b_calls) = leaf("b", 2, None);
            let snapshot = Arc::new(ProviderState::new(vec![a, b]));
            let group = selector::Handler::new(selector::HandlerOptions {
                name: "nested".to_owned(), udp: true, ..Default::default()
            }, vec![provider(&snapshot)], None).await;
            let control = Arc::new(group.clone()) as ThreadSafeSelectorControl;
            let outer_snapshot = Arc::new(ProviderState::new(vec![
                OutboundNode::group(Arc::new(group)),
            ]));
            let outer = selector::Handler::new(selector::HandlerOptions {
                name: "dns-group".to_owned(), udp: true, ..Default::default()
            }, vec![provider(&outer_snapshot)], None).await;
            let mut pool = pool(net, OutboundNode::group(Arc::new(outer)));
            Arc::get_mut(&mut pool).unwrap().dns_query_timeout = Duration::from_secs(30);
            let old_pool = pool.clone();
            let pending = tokio::spawn(async move { query(&old_pool).await });
            gate.started.notified().await;
            control.select("b").unwrap();
            selected(&pool, "b", None).await;
            assert_eq!(query(&pool).await, 2);
            gate.release.notify_one();
            assert_eq!(pending.await.unwrap(), 1);
            assert_eq!(a_calls.load(Ordering::Relaxed), 1);
            assert_eq!(b_calls.load(Ordering::Relaxed), 1);
            let reads = snapshot.reads.load(Ordering::Relaxed);
            let mut queries = tokio::task::JoinSet::new();
            for _ in 0..16 { let pool = pool.clone(); queries.spawn(async move { query(&pool).await }); }
            while let Some(result) = queries.join_next().await { assert_eq!(result.unwrap(), 2); }
            assert_eq!(b_calls.load(Ordering::Relaxed), 1);
            assert_eq!(snapshot.reads.load(Ordering::Relaxed), reads);
            let (replacement, calls) = leaf("b", 3, None);
            snapshot.store(Arc::new(vec![replacement.clone()]));
            selected(&pool, "b", Some(&replacement)).await;
            assert_eq!(query(&pool).await, 3);
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            pool.close().await;
        }
    }).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn load_balance_selects_per_query_and_reuses_each_leaf_pool() {
    for net in [DNSNetMode::Udp, DNSNetMode::Tcp] {
        let (a, a_calls) = leaf("a", 1, None);
        let (b, b_calls) = leaf("b", 2, None);
        let snapshot = Arc::new(ProviderState::new(vec![a, b]));
        let group = loadbalance::Handler::new(loadbalance::HandlerOptions {
            name: "dns-group".to_owned(), udp: true,
            strategy: LoadBalanceStrategy::RoundRobin, ..Default::default()
        }, vec![provider(&snapshot)], ProxyManager::new(Arc::new(NoopResolver), None));
        let pool = pool(net, OutboundNode::group(Arc::new(group)));
        let mut responses = Vec::new();
        for _ in 0..6 { responses.push(query(&pool).await); }
        assert_eq!(responses.iter().filter(|&&marker| marker == 1).count(), 3);
        assert_eq!(responses.iter().filter(|&&marker| marker == 2).count(), 3);
        assert_eq!(a_calls.load(Ordering::Relaxed), 1);
        assert_eq!(b_calls.load(Ordering::Relaxed), 1);
        assert_eq!(pool.selections.len(), 0);
        pool.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn failed_leaf_reselects_within_the_group() {
    for net in [DNSNetMode::Udp, DNSNetMode::Tcp] {
        let mut bad = MockDummyOutboundHandler::new();
        bad.expect_name().return_const("bad".to_owned());
        bad.expect_proto().return_const(OutboundType::Direct);
        bad.expect_support_udp().return_const(true);
        bad.expect_connect_datagram().returning(|_, _| {
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "test UDP dial failed"))
        });
        bad.expect_connect_stream().returning(|_, _| {
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "test TCP dial failed"))
        });
        let (good, calls) = leaf("good", 3, None);
        let group = RetryGroup::new("dns-group", vec![OutboundNode::protocol(Arc::new(bad)), good]);
        let pool = pool(net, OutboundNode::group(Arc::new(group)));
        assert_eq!(query(&pool).await, 3);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        pool.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn health_changes_publish_routes_without_another_query() {
    for net in [DNSNetMode::Udp, DNSNetMode::Tcp] {
        for use_urltest in [false, true] {
            let (a, _) = leaf("a", 1, None);
            let (b, _) = leaf("b", 2, None);
            let snapshot = Arc::new(ProviderState::new(vec![a, b]));
            let manager = ProxyManager::new(Arc::new(NoopResolver), None);
            manager.report_delay("a", true, Duration::from_millis(10)).await;
            manager.report_delay("b", true, Duration::from_millis(100)).await;
            let group = if use_urltest {
                OutboundNode::group(Arc::new(urltest::Handler::new(urltest::HandlerOptions {
                    name: "dns-group".to_owned(), udp: true, ..Default::default()
                }, 10, vec![provider(&snapshot)], manager.clone())))
            } else {
                OutboundNode::group(Arc::new(fallback::Handler::new(fallback::HandlerOptions {
                    name: "dns-group".to_owned(), udp: true, ..Default::default()
                }, vec![provider(&snapshot)], manager.clone())))
            };
            let pool = pool(net, group);
            assert_eq!(query(&pool).await, 1);
            if use_urltest {
                manager.report_delay("a", true, Duration::from_millis(200)).await;
                manager.report_delay("b", true, Duration::from_millis(20)).await;
            } else {
                manager.report_alive("a", false, None).await;
            }
            selected(&pool, "b", None).await;
            assert_eq!(query(&pool).await, 2);
            pool.close().await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn rapid_switches_coalesce_and_shutdown_drops_subscribers() {
    let (a, _) = leaf("a", 1, None);
    let (b, _) = leaf("b", 2, None);
    let snapshot = Arc::new(ProviderState::new(vec![a, b]));
    let group = selector::Handler::new(selector::HandlerOptions {
        name: "dns-group".to_owned(), udp: true, ..Default::default()
    }, vec![provider(&snapshot)], None).await;
    let control = Arc::new(group.clone()) as ThreadSafeSelectorControl;
    let pool = pool(DNSNetMode::Udp, OutboundNode::group(Arc::new(group)));
    assert_eq!(query(&pool).await, 1);
    for _ in 0..16 { control.select("b").unwrap(); control.select("a").unwrap(); }
    control.select("b").unwrap();
    selected(&pool, "b", None).await;
    assert_eq!(query(&pool).await, 2);
    assert!(snapshot.changes.subscribers() > 0);
    pool.close().await;
    tokio::time::timeout(Duration::from_secs(11), async {
        while snapshot.changes.subscribers() != 0 { tokio::time::sleep(Duration::from_millis(10)).await; }
    }).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn background_refresh_does_not_touch_idle_provider() {
    let (a, _) = leaf("a", 1, None);
    let (b, _) = leaf("b", 2, None);
    let snapshot = Arc::new(ProviderState::new(vec![a, b]));
    let group = selector::Handler::new(selector::HandlerOptions {
        name: "dns-group".to_owned(), udp: true, ..Default::default()
    }, vec![provider(&snapshot)], None).await;
    let control = Arc::new(group.clone()) as ThreadSafeSelectorControl;
    let pool = pool(DNSNetMode::Udp, OutboundNode::group(Arc::new(group)));
    assert_eq!(query(&pool).await, 1);
    let touches = snapshot.touches.load(Ordering::Relaxed);
    control.select("b").unwrap();
    selected(&pool, "b", None).await;
    assert_eq!(snapshot.touches.load(Ordering::Relaxed), touches);
    pool.close().await;
}

#[tokio::test(start_paused = true)]
async fn direct_outbounds_do_not_create_selection_workers() {
    let (node, _) = leaf("a", 1, None);
    let pool = pool(DNSNetMode::Udp, node);
    assert_eq!(query(&pool).await, 1);
    assert_eq!(pool.selections.len(), 0);
    pool.close().await;
}


#[tokio::test(start_paused = true)]
async fn switches_retire_old_slots_and_initialize_new_connections_lazily() {
    for net in [DNSNetMode::Udp, DNSNetMode::Tcp] {
        let (a, a_calls) = leaf("a", 1, None);
        let (b, b_calls) = leaf("b", 2, None);
        let snapshot = Arc::new(ProviderState::new(vec![a, b]));
        let group = selector::Handler::new(selector::HandlerOptions {
            name: "dns-group".to_owned(), udp: true, ..Default::default()
        }, vec![provider(&snapshot)], None).await;
        let control = Arc::new(group.clone()) as ThreadSafeSelectorControl;
        let pool = pool(net, OutboundNode::group(Arc::new(group)));
        assert_eq!(query(&pool).await, 1);
        control.select("b").unwrap();
        selected(&pool, "b", None).await;
        assert_eq!(b_calls.load(Ordering::Relaxed), 0);
        assert_eq!(query(&pool).await, 2);
        assert_eq!(b_calls.load(Ordering::Relaxed), 1);
        control.select("a").unwrap();
        selected(&pool, "a", None).await;
        assert_eq!(a_calls.load(Ordering::Relaxed), 1);
        assert_eq!(query(&pool).await, 1);
        assert_eq!(a_calls.load(Ordering::Relaxed), 2);
        pool.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn switching_one_group_preserves_another_groups_shared_connection() {
    for net in [DNSNetMode::Udp, DNSNetMode::Tcp] {
        let (a, a_calls) = leaf("a", 1, None);
        let (b, b_calls) = leaf("b", 2, None);
        let snapshot = Arc::new(ProviderState::new(vec![a, b]));
        let first = selector::Handler::new(selector::HandlerOptions {
            name: "dns-group".to_owned(), udp: true, ..Default::default()
        }, vec![provider(&snapshot)], None).await;
        let first_control = Arc::new(first.clone()) as ThreadSafeSelectorControl;
        let second = selector::Handler::new(selector::HandlerOptions {
            name: "other-group".to_owned(), udp: true, ..Default::default()
        }, vec![provider(&snapshot)], None).await;
        let second_control = Arc::new(second.clone()) as ThreadSafeSelectorControl;
        let pool = pool(net, OutboundNode::group(Arc::new(first)));
        let mut registry = pool.outbounds.load_full().as_ref().clone();
        registry.insert("other-group".to_owned(), OutboundNode::group(Arc::new(second)));
        pool.outbounds.store(Arc::new(registry));
        assert_eq!(query(&pool).await, 1);
        assert_eq!(query_outbound(&pool, Some("other-group")).await, 1);
        assert_eq!(a_calls.load(Ordering::Relaxed), 1);
        first_control.select("b").unwrap();
        selected(&pool, "b", None).await;
        assert_eq!(query(&pool).await, 2);
        assert_eq!(query_outbound(&pool, Some("other-group")).await, 1);
        assert_eq!(a_calls.load(Ordering::Relaxed), 1);
        second_control.select("b").unwrap();
        tokio::time::timeout(Duration::from_secs(11), async {
            loop {
                let mut ready = true;
                for cache in pool.selections.values() {
                    ready &= cache.get().await.unwrap().node.as_ref().unwrap().name() == "b";
                }
                if ready { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        assert_eq!(query_outbound(&pool, Some("other-group")).await, 2);
        assert_eq!(b_calls.load(Ordering::Relaxed), 1);
        first_control.select("a").unwrap();
        selected(&pool, "a", None).await;
        assert_eq!(query(&pool).await, 1);
        assert_eq!(a_calls.load(Ordering::Relaxed), 2);
        pool.close().await;
    }
}


#[tokio::test(start_paused = true)]
async fn external_upstream_entries_attach_to_notifications_and_reuse_connections() {
    for net in [DNSNetMode::Udp, DNSNetMode::Tcp] {
        let (a, a_calls) = leaf("a", 1, None);
        let (b, b_calls) = leaf("b", 2, None);
        let snapshot = Arc::new(ProviderState::new(vec![a, b]));
        let group = selector::Handler::new(selector::HandlerOptions {
            name: "dns-group".to_owned(), udp: true, ..Default::default()
        }, vec![provider(&snapshot)], None).await;
        let control = Arc::new(group.clone()) as ThreadSafeSelectorControl;
        let mut pool = pool(net, OutboundNode::group(Arc::new(group)));
        let entry = Arc::get_mut(&mut pool).unwrap().entries.remove("dns").unwrap();
        let wire = build_dns_query_wire(&DnsName::from_domain("routing.test").unwrap(), QType::A);
        let query = QueryContext::parse(Bytes::from(wire), IngressProfile::Internal).unwrap();
        for _ in 0..2 { assert_eq!(pool.query_entry(&entry, &query, None).await.unwrap()[3], 1); }
        assert_eq!(a_calls.load(Ordering::Relaxed), 1);
        control.select("b").unwrap();
        selected(&pool, "b", None).await;
        assert_eq!(b_calls.load(Ordering::Relaxed), 0);
        for _ in 0..2 { assert_eq!(pool.query_entry(&entry, &query, None).await.unwrap()[3], 2); }
        assert_eq!(b_calls.load(Ordering::Relaxed), 1);
        pool.close().await;
    }
}


#[tokio::test(start_paused = true)]
async fn configured_but_unused_upstreams_are_not_retained_by_selection_bindings() {
    let (a, _) = leaf("a", 1, None);
    let (b, b_calls) = leaf("b", 2, None);
    let snapshot = Arc::new(ProviderState::new(vec![a, b]));
    let group = selector::Handler::new(selector::HandlerOptions {
        name: "dns-group".to_owned(), udp: true, ..Default::default()
    }, vec![provider(&snapshot)], None).await;
    let control = Arc::new(group.clone()) as ThreadSafeSelectorControl;
    let mut pool = pool(DNSNetMode::Udp, OutboundNode::group(Arc::new(group)));
    let mut unused = pool.entries["dns"].clone();
    unused.state = Arc::new(UpstreamState::Udp(UdpUpstream::default()));
    let state = unused.state.clone();
    Arc::get_mut(&mut pool).unwrap().entries.insert("unused".to_owned(), unused);
    let references = Arc::strong_count(&state);
    assert_eq!(query(&pool).await, 1);
    assert_eq!(Arc::strong_count(&state), references);
    control.select("b").unwrap();
    selected(&pool, "b", None).await;
    assert_eq!(Arc::strong_count(&state), references);
    assert_eq!(b_calls.load(Ordering::Relaxed), 0);
    let wire = build_dns_query_wire(&DnsName::from_domain("routing.test").unwrap(), QType::A);
    let query = QueryContext::parse(Bytes::from(wire), IngressProfile::Internal).unwrap();
    assert_eq!(pool.query("unused", &query, None).await.unwrap()[3], 2);
    assert_eq!(Arc::strong_count(&state), references + 1);
    assert_eq!(b_calls.load(Ordering::Relaxed), 1);
    pool.close().await;
}
