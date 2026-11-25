//! Tracks which protocol outbounds are currently reachable from active routing
//! rules, explicit DNS upstreams, and group selections, and toggles their
//! idle-connection keep-alive policy accordingly.

use std::{
    collections::{HashMap, HashSet},
    future::{pending, poll_fn},
    sync::Arc,
    task::Poll,
    time::Duration,
};

use tokio::{
    sync::watch::Receiver,
    time::{Instant, interval, sleep_until},
};
use tokio_util::sync::{CancellationToken, ReusableBoxFuture};
use tracing::debug;

use crate::{
    app::{
        dispatcher::Dispatcher,
        dns::ThreadSafeDNSResolver,
        outbound::manager::OutboundManager,
        router::Router,
    },
    config::{def::RunMode, internal::proxy::PROXY_GLOBAL},
    proxy::{
        OutboundNode, RouteChange, group::ProxyGroup,
        utils::provider_helper::MemberUrls,
    },
};

const MODE_FALLBACK_POLL_INTERVAL: Duration = Duration::from_secs(60);
/// Coalesce bursts of healthcheck delay updates into a single reachability
/// scan while keeping manual switches responsive.
const NOTIFY_COALESCE_WINDOW: Duration = Duration::from_millis(50);

struct CachedRoots {
    direct: Vec<String>,
    global: Vec<String>,
    rule: Vec<String>,
}

impl CachedRoots {
    fn build(router: &Router, dns_outbounds: HashSet<String>) -> Self {
        let direct: Vec<String> = dns_outbounds.iter().cloned().collect();

        let mut global_set = dns_outbounds.clone();
        global_set.insert(PROXY_GLOBAL.to_owned());
        let global: Vec<String> = global_set.into_iter().collect();

        let mut rule_set = router.referenced_outbounds();
        rule_set.extend(dns_outbounds);
        let rule: Vec<String> = rule_set.into_iter().collect();

        Self {
            direct,
            global,
            rule,
        }
    }

    fn for_mode(&self, mode: RunMode) -> &[String] {
        match mode {
            RunMode::Direct => &self.direct,
            RunMode::Global => &self.global,
            RunMode::Rule => &self.rule,
        }
    }
}

struct SourceWait {
    source: RouteChange,
    wait: ReusableBoxFuture<'static, Receiver<()>>,
}

async fn wait_change(mut receiver: Receiver<()>) -> Receiver<()> {
    // SourceWait retains the sender for the entire lifetime of this future.
    receiver
        .changed()
        .await
        .expect("subscription retains its notification source");
    receiver
}

impl SourceWait {
    fn new(source: RouteChange) -> Self {
        let wait = ReusableBoxFuture::new(wait_change(source.subscribe()));
        Self { source, wait }
    }
}

fn ensure_waits(waits: &mut Vec<SourceWait>, desired: Vec<RouteChange>) {
    let mut existing: HashSet<usize> =
        waits.iter().map(|w| w.source.identity()).collect();
    for source in desired {
        if existing.insert(source.identity()) {
            waits.push(SourceWait::new(source));
        }
    }
}

fn sync_waits(waits: &mut Vec<SourceWait>, desired: Vec<RouteChange>) {
    let mut wanted = HashSet::with_capacity(desired.len());
    let mut existing: HashSet<usize> =
        waits.iter().map(|w| w.source.identity()).collect();
    for source in desired {
        let id = source.identity();
        wanted.insert(id);
        if existing.insert(id) {
            waits.push(SourceWait::new(source));
        }
    }
    waits.retain(|w| wanted.contains(&w.source.identity()));
}

/// Waits until at least one source changes and records the fired source
/// identity into `fired_sources`.
async fn wait_any_change(
    waits: &mut [SourceWait],
    fired_sources: &mut HashSet<usize>,
) {
    if waits.is_empty() {
        pending::<()>().await;
        return;
    }
    let fired_id = poll_fn(|cx| {
        for entry in waits.iter_mut() {
            if let Poll::Ready(receiver) = entry.wait.poll(cx) {
                entry.wait.set(wait_change(receiver));
                return Poll::Ready(entry.source.identity());
            }
        }
        Poll::Pending
    })
    .await;
    fired_sources.insert(fired_id);
}

/// Drains any already-pending notifications without blocking and records all
/// fired source identities into `fired_sources`.
async fn drain_ready_changes(
    waits: &mut [SourceWait],
    fired_sources: &mut HashSet<usize>,
) {
    poll_fn(|cx| {
        for entry in waits.iter_mut() {
            while let Poll::Ready(receiver) = entry.wait.poll(cx) {
                fired_sources.insert(entry.source.identity());
                entry.wait.set(wait_change(receiver));
            }
        }
        Poll::Ready(())
    })
    .await;
}

struct GroupSnapshot {
    group: ProxyGroup,
    members: Arc<Vec<OutboundNode>>,
    urls: MemberUrls,
    selected: Option<OutboundNode>,
}

#[derive(Default)]
struct IdleTrackerCache {
    registry: Arc<HashMap<String, OutboundNode>>,
    all_protocols: Vec<OutboundNode>,
    groups: HashMap<usize, GroupSnapshot>,
    source_to_groups: HashMap<usize, Vec<usize>>,
    provider_ids: HashSet<usize>,
    prev_state: HashMap<usize, bool>,
    last_mode: Option<RunMode>,
    #[cfg(test)]
    traversal_count: usize,
}

impl IdleTrackerCache {
    fn is_provider_source(&self, id: usize) -> bool {
        self.provider_ids.contains(&id)
    }

    /// Rebuilds the cached fixed-snapshot topology and updates `waits` before
    /// computing initial group selections so notifications cannot be lost
    /// across startup or provider refreshes.
    fn rebuild_topology(
        &mut self,
        outbound_manager: &OutboundManager,
        mode_changes: &RouteChange,
        waits: &mut Vec<SourceWait>,
    ) {
        outbound_manager.invalidate_stale_provider_caches();

        // Register provider and mode watchers before capturing snapshots so
        // concurrent refreshes during rebuild still mark their receivers dirty.
        let provider_sources = outbound_manager.collect_provider_route_changes();
        let mut pre_sources = provider_sources.clone();
        pre_sources.push(mode_changes.clone());
        ensure_waits(waits, pre_sources);

        let registry = outbound_manager.registry_snapshot();
        let provider_snapshots = outbound_manager.capture_provider_snapshots();

        let mut seen_protocols = HashSet::new();
        let mut all_protocols = Vec::new();
        let mut record_protocol = |node: &OutboundNode| {
            if node.as_protocol().is_some()
                && seen_protocols.insert(node.identity())
            {
                all_protocols.push(node.clone());
            }
        };

        for node in registry.values() {
            record_protocol(node);
        }
        for snapshot in provider_snapshots.values() {
            for node in snapshot.iter() {
                record_protocol(node);
            }
        }

        let mut groups = HashMap::new();
        let mut source_to_groups: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut desired_sources = Vec::new();
        let mut seen_sources = HashSet::new();
        let mut push_source = |source: RouteChange| {
            if seen_sources.insert(source.identity()) {
                desired_sources.push(source);
            }
        };

        let mut provider_ids = HashSet::with_capacity(provider_sources.len());
        for source in provider_sources {
            provider_ids.insert(source.identity());
            push_source(source);
        }
        push_source(mode_changes.clone());

        for node in registry.values() {
            let Some(group) = node.as_group() else {
                continue;
            };
            let group_id = node.identity();
            let (members, urls) =
                group.members_from_snapshots(&provider_snapshots);
            for member in members.iter() {
                record_protocol(member);
            }

            let mut group_sources = Vec::new();
            group.route_changes_from(&members, &urls, &mut group_sources);
            let mut seen_for_group = HashSet::with_capacity(group_sources.len());
            for source in group_sources {
                let src_id = source.identity();
                if seen_for_group.insert(src_id) {
                    source_to_groups.entry(src_id).or_default().push(group_id);
                }
                push_source(source);
            }

            groups.insert(
                group_id,
                GroupSnapshot {
                    group: group.clone(),
                    members,
                    urls,
                    selected: None,
                },
            );
        }

        // Subscribe to all member/group notification sources before reading
        // initial selections so updates cannot fall between inspect and watch.
        sync_waits(waits, desired_sources);

        for entry in groups.values_mut() {
            if entry.group.stable_selection() {
                entry.selected =
                    entry.group.peek_selected_from(&entry.members, &entry.urls);
            }
        }

        self.registry = registry;
        self.all_protocols = all_protocols;
        self.groups = groups;
        self.source_to_groups = source_to_groups;
        self.provider_ids = provider_ids;
    }

    fn apply_reachability(&mut self, root_targets: &[String], mode: RunMode) {
        self.last_mode = Some(mode);
        #[cfg(test)]
        {
            self.traversal_count += 1;
        }

        let mut queue: Vec<OutboundNode> = root_targets
            .iter()
            .filter_map(|name| self.registry.get(name).cloned())
            .collect();
        let mut visited = HashSet::with_capacity(queue.len());
        let mut active_protocols = HashSet::new();

        while let Some(node) = queue.pop() {
            if !visited.insert(node.identity()) {
                continue;
            }
            match &node {
                OutboundNode::Protocol(_) => {
                    active_protocols.insert(node.identity());
                    if let Some(dep) = node.dialer_dependency().or_else(|| {
                        node.support_dialer()
                            .and_then(|name| self.registry.get(name).cloned())
                    }) {
                        queue.push(dep);
                    }
                }
                OutboundNode::Group(group) => {
                    let Some(entry) = self.groups.get(&node.identity()) else {
                        continue;
                    };
                    if group.stable_selection() {
                        if let Some(selected) = entry.selected.clone() {
                            queue.push(selected);
                        }
                    } else {
                        for member in entry.members.iter() {
                            queue.push(member.clone());
                        }
                    }
                }
            }
        }

        let mut live_ids = HashSet::with_capacity(self.all_protocols.len());
        for node in &self.all_protocols {
            let id = node.identity();
            live_ids.insert(id);
            let keep = active_protocols.contains(&id);
            if self.prev_state.insert(id, keep) != Some(keep) {
                debug!(
                    outbound = %node.name(),
                    keep_idle = keep,
                    "updating outbound idle connection policy"
                );
                node.set_keep_idle(keep);
            }
        }

        self.prev_state.retain(|id, _| live_ids.contains(id));
    }

    /// Recomputes selections only for groups impacted by `fired_sources` using
    /// the cached fixed snapshots, skipping full graph traversal when neither
    /// mode nor any dirty group's effective selection changed.
    fn handle_incremental_changes(
        &mut self,
        fired_sources: &HashSet<usize>,
        root_targets: &[String],
        mode: RunMode,
    ) -> bool {
        let mut dirty_groups = HashSet::new();
        for src_id in fired_sources {
            if let Some(group_ids) = self.source_to_groups.get(src_id) {
                dirty_groups.extend(group_ids.iter().copied());
            }
        }

        let mut selection_changed = false;
        for group_id in dirty_groups {
            let Some(entry) = self.groups.get_mut(&group_id) else {
                continue;
            };
            if !entry.group.stable_selection() {
                continue;
            }
            let next = entry.group.peek_selected_from(&entry.members, &entry.urls);
            if next.as_ref().map(OutboundNode::identity)
                != entry.selected.as_ref().map(OutboundNode::identity)
            {
                entry.selected = next;
                selection_changed = true;
            }
        }

        let mode_changed = self.last_mode != Some(mode);
        if selection_changed || mode_changed {
            self.apply_reachability(root_targets, mode);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
pub(crate) async fn sync_idle_keepers(
    outbound_manager: &OutboundManager,
    root_targets: &[String],
    prev_state: &mut HashMap<usize, bool>,
) {
    let (active_ids, all_protocols) =
        outbound_manager.snapshot_idle_keep_state(root_targets);

    let mut live_ids = HashSet::with_capacity(all_protocols.len());
    for node in all_protocols {
        let id = node.identity();
        live_ids.insert(id);
        let keep = active_ids.contains(&id);
        if prev_state.insert(id, keep) != Some(keep) {
            debug!(
                outbound = %node.name(),
                keep_idle = keep,
                "updating outbound idle connection policy"
            );
            node.set_keep_idle(keep);
        }
    }

    prev_state.retain(|id, _| live_ids.contains(id));
}

pub(crate) async fn run_reference_tracker(
    outbound_manager: Arc<OutboundManager>,
    router: Arc<Router>,
    dispatcher: Arc<Dispatcher>,
    dns_resolver: ThreadSafeDNSResolver,
    cancel: CancellationToken,
) {
    let cached_roots =
        CachedRoots::build(&router, dns_resolver.referenced_outbounds());
    let mode_changes = dispatcher.mode_changes();

    let mut waits = Vec::new();
    let mut cache = IdleTrackerCache::default();
    cache.rebuild_topology(&outbound_manager, &mode_changes, &mut waits);

    let initial_mode = dispatcher.get_mode();
    cache.apply_reachability(cached_roots.for_mode(initial_mode), initial_mode);

    let mut fallback_tick = interval(MODE_FALLBACK_POLL_INTERVAL);
    fallback_tick.tick().await;
    let mut fired_sources = HashSet::new();

    loop {
        fired_sources.clear();
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = wait_any_change(&mut waits, &mut fired_sources) => {
                // Coalesce burst notifications (e.g. batch healthchecks) before
                // updating group selections or scanning the outbound graph.
                let deadline = Instant::now() + NOTIFY_COALESCE_WINDOW;
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = sleep_until(deadline) => break,
                        _ = wait_any_change(&mut waits, &mut fired_sources) => {}
                    }
                }
                drain_ready_changes(&mut waits, &mut fired_sources).await;
            }
            _ = fallback_tick.tick() => {
                drain_ready_changes(&mut waits, &mut fired_sources).await;
            }
        }

        let structure_changed = fired_sources
            .iter()
            .any(|id| cache.is_provider_source(*id));
        let mode = dispatcher.get_mode();
        let roots = cached_roots.for_mode(mode);

        if structure_changed {
            cache.rebuild_topology(&outbound_manager, &mode_changes, &mut waits);
            cache.apply_reachability(roots, mode);
        } else {
            cache.handle_incremental_changes(&fired_sources, roots, mode);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::remote_content_manager::ProxyManager,
        proxy::{
            OutboundNode, OutboundType,
            group::{
                GroupHandler,
                selector::{self, SelectorControl},
                urltest,
            },
            mocks::{MockDummyOutboundHandler, MockDummyProxyProvider},
            utils::test_utils::noop::NoopResolver,
        },
        session::Session,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    fn make_tracked_leaf(
        name: &str,
        keep_flag: Arc<AtomicBool>,
    ) -> OutboundNode {
        let mut mock = MockDummyOutboundHandler::new();
        let name_owned = name.to_owned();
        mock.expect_name().return_const(name_owned);
        mock.expect_proto().return_const(OutboundType::Hysteria2);
        mock.expect_support_udp().return_const(true);
        mock.expect_set_keep_idle().returning(move |keep| {
            keep_flag.store(keep, Ordering::SeqCst);
        });
        OutboundNode::protocol(Arc::new(mock))
    }

    #[tokio::test]
    async fn sync_idle_keepers_tracks_selector_switch() {
        let keep_a = Arc::new(AtomicBool::new(true));
        let keep_b = Arc::new(AtomicBool::new(true));
        let node_a = make_tracked_leaf("node-a", keep_a.clone());
        let node_b = make_tracked_leaf("node-b", keep_b.clone());

        let members = Arc::new(vec![node_a.clone(), node_b.clone()]);
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning(move || members.clone());

        let selector = Arc::new(
            selector::Handler::new(
                selector::HandlerOptions {
                    name: "PROXY".to_owned(),
                    ..Default::default()
                },
                vec![Arc::new(provider)],
                Some("node-a".to_owned()),
            )
            .await,
        );

        let mut handlers = HashMap::new();
        handlers.insert("node-a".to_owned(), node_a);
        handlers.insert("node-b".to_owned(), node_b);
        handlers.insert("PROXY".to_owned(), OutboundNode::group(selector.clone()));

        let manager = OutboundManager::new_for_test(handlers);
        let mut prev = HashMap::new();
        let roots = vec!["PROXY".to_owned()];

        sync_idle_keepers(&manager, &roots, &mut prev).await;
        assert!(keep_a.load(Ordering::SeqCst));
        assert!(!keep_b.load(Ordering::SeqCst));

        SelectorControl::select(selector.as_ref(), "node-b").unwrap();
        sync_idle_keepers(&manager, &roots, &mut prev).await;
        assert!(!keep_a.load(Ordering::SeqCst));
        assert!(keep_b.load(Ordering::SeqCst));

        // Direct mode (empty roots) disables keep_idle for all nodes.
        sync_idle_keepers(&manager, &[], &mut prev).await;
        assert!(!keep_a.load(Ordering::SeqCst));
        assert!(!keep_b.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn sync_idle_keepers_does_not_commit_urltest_sticky_selection() {
        let keep_a = Arc::new(AtomicBool::new(true));
        let keep_b = Arc::new(AtomicBool::new(true));
        let node_a = make_tracked_leaf("node-a", keep_a.clone());
        let node_b = make_tracked_leaf("node-b", keep_b.clone());

        let members = Arc::new(vec![node_a.clone(), node_b.clone()]);
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning(move || members.clone());
        provider.expect_touch().returning(|| {});

        let pm = ProxyManager::new(Arc::new(NoopResolver), None);
        // Only node-a has a sample so far during startup; tolerance is 50ms.
        pm.report_delay("node-a", true, Duration::from_millis(100))
            .await;

        let group = Arc::new(urltest::Handler::new(
            urltest::HandlerOptions {
                name: "AUTO".to_owned(),
                ..Default::default()
            },
            50,
            vec![Arc::new(provider)],
            pm.clone(),
        ));

        let mut handlers = HashMap::new();
        handlers.insert("node-a".to_owned(), node_a);
        handlers.insert("node-b".to_owned(), node_b);
        handlers.insert("AUTO".to_owned(), OutboundNode::group(group.clone()));

        let manager = OutboundManager::new_for_test(handlers);
        let mut prev = HashMap::new();
        let roots = vec!["AUTO".to_owned()];

        // Background tracker scan observes node-a as current leader, but MUST
        // NOT write sticky `current_fastest`.
        sync_idle_keepers(&manager, &roots, &mut prev).await;
        assert!(keep_a.load(Ordering::SeqCst));
        assert!(!keep_b.load(Ordering::SeqCst));

        // Now node-b's latency arrives: 70ms is faster than 100ms, yet within
        // the 50ms tolerance of 100ms. Because the tracker did NOT commit
        // sticky state, the first real request must pick node-b!
        pm.report_delay("node-b", true, Duration::from_millis(70))
            .await;
        let selected = group
            .select(&Session::default(), &HashSet::new())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            selected.name(),
            "node-b",
            "background idle tracking must not pollute url-test sticky selection"
        );
    }

    #[tokio::test]
    async fn cached_roots_keep_explicit_dns_outbound_in_direct_mode() {
        let keep_dns = Arc::new(AtomicBool::new(false));
        let keep_other = Arc::new(AtomicBool::new(true));
        let dns_node = make_tracked_leaf("dns-proxy", keep_dns.clone());
        let other_node = make_tracked_leaf("other-proxy", keep_other.clone());

        let mut handlers = HashMap::new();
        handlers.insert("dns-proxy".to_owned(), dns_node);
        handlers.insert("other-proxy".to_owned(), other_node);

        let manager = OutboundManager::new_for_test(handlers);
        let dns_roots: HashSet<String> = ["dns-proxy".to_owned()].into_iter().collect();
        let direct_roots: Vec<String> = dns_roots.into_iter().collect();

        let mut prev = HashMap::new();
        sync_idle_keepers(&manager, &direct_roots, &mut prev).await;
        assert!(
            keep_dns.load(Ordering::SeqCst),
            "explicit DNS outbound must stay warm even in Direct mode"
        );
        assert!(!keep_other.load(Ordering::SeqCst));
    }

    #[test]
    fn dns_configs_collect_explicit_outbounds() {
        use crate::app::dns::{
            Config as DnsConfig,
            resolver::router::config::{RouterConfig, UpstreamConfig, UpstreamType},
        };

        let mut legacy = DnsConfig::default();
        legacy.nameserver =
            DnsConfig::parse_nameserver(&["https://1.1.1.1/dns-query#proxy=DNS_PROXY".to_owned()])
                .unwrap();
        legacy.fallback =
            DnsConfig::parse_nameserver(&["tls://8.8.8.8#proxy=FALLBACK_PROXY".to_owned()])
                .unwrap();
        legacy.nameserver_policy.insert(
            "example.com".to_owned(),
            DnsConfig::parse_nameserver(&["udp://9.9.9.9#proxy=POLICY_PROXY".to_owned()]).unwrap(),
        );
        let legacy_refs = legacy.referenced_outbounds();
        assert!(legacy_refs.contains("DNS_PROXY"));
        assert!(legacy_refs.contains("FALLBACK_PROXY"));
        assert!(legacy_refs.contains("POLICY_PROXY"));

        let mut dns2 = RouterConfig::default();
        dns2.upstreams.push(UpstreamConfig {
            tag: "remote".to_owned(),
            upstream_type: UpstreamType::Remote,
            servers: DnsConfig::parse_nameserver(&[
                "https://1.1.1.1/dns-query#proxy=SERVER_PROXY".to_owned(),
            ])
            .unwrap(),
            proxy: Some("UPSTREAM_PROXY".to_owned()),
            client_subnet: None,
            inet4_range: "198.18.0.0/16".parse().unwrap(),
            inet6_range: "fc00::/18".parse().unwrap(),
            ttl: None,
        });
        let dns2_refs = dns2.referenced_outbounds();
        assert!(dns2_refs.contains("UPSTREAM_PROXY"));
        assert!(dns2_refs.contains("SERVER_PROXY"));
    }

    #[tokio::test(start_paused = true)]
    async fn tracker_reacts_to_mode_switch_and_coalesces_burst_notifications() {
        use crate::app::dispatcher::StatisticsManager;
        use std::sync::atomic::AtomicUsize;

        let keep_a = Arc::new(AtomicBool::new(true));
        let set_calls = Arc::new(AtomicUsize::new(0));
        let mut mock = MockDummyOutboundHandler::new();
        mock.expect_name().return_const("node-a".to_owned());
        mock.expect_proto().return_const(OutboundType::Hysteria2);
        mock.expect_support_udp().return_const(true);
        {
            let keep_a = keep_a.clone();
            let set_calls = set_calls.clone();
            mock.expect_set_keep_idle().returning(move |keep| {
                keep_a.store(keep, Ordering::SeqCst);
                set_calls.fetch_add(1, Ordering::SeqCst);
            });
        }
        let node_a = OutboundNode::protocol(Arc::new(mock));

        let members = Arc::new(vec![node_a.clone()]);
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning(move || members.clone());
        provider.expect_route_changes().returning(|| None);

        let global = Arc::new(
            selector::Handler::new(
                selector::HandlerOptions {
                    name: PROXY_GLOBAL.to_owned(),
                    ..Default::default()
                },
                vec![Arc::new(provider)],
                Some("node-a".to_owned()),
            )
            .await,
        );

        let mut handlers = HashMap::new();
        handlers.insert("node-a".to_owned(), node_a);
        handlers.insert(PROXY_GLOBAL.to_owned(), OutboundNode::group(global));
        let manager = Arc::new(OutboundManager::new_for_test(handlers));
        let router = Arc::new(
            Router::new(
                Vec::new(),
                HashMap::new(),
                Arc::new(NoopResolver),
                None,
                None,
                None,
                None,
                None,
                ".".to_owned(),
            )
            .await
            .unwrap(),
        );
        let dispatcher = Arc::new(Dispatcher::new(
            manager.clone(),
            router.clone(),
            Arc::new(NoopResolver),
            RunMode::Global,
            StatisticsManager::new(),
            None,
            None,
            true,
        ));
        let cancel = CancellationToken::new();
        let tracker = tokio::spawn(run_reference_tracker(
            manager,
            router,
            dispatcher.clone(),
            Arc::new(NoopResolver),
            cancel.clone(),
        ));

        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(keep_a.load(Ordering::SeqCst));

        // Switch mode to Direct: explicit mode_changes notification must update
        // keep_idle right after the 50ms coalesce window (well before 60s poll).
        dispatcher.set_mode(RunMode::Direct);
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_millis(60)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            !keep_a.load(Ordering::SeqCst),
            "mode switch must promptly disable keep_idle via explicit notification"
        );

        // Rapid flip Global -> Direct -> Global within one coalesce window
        // collapses to a single sync pass.
        let calls_before = set_calls.load(Ordering::SeqCst);
        dispatcher.set_mode(RunMode::Global);
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        dispatcher.set_mode(RunMode::Direct);
        tokio::task::yield_now().await;
        dispatcher.set_mode(RunMode::Global);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(60)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(keep_a.load(Ordering::SeqCst));
        assert_eq!(
            set_calls.load(Ordering::SeqCst) - calls_before,
            1,
            "burst notifications within the coalesce window must merge into one sync"
        );

        cancel.cancel();
        tracker.await.unwrap();
    }

    #[tokio::test]
    async fn incremental_tracker_reuses_fixed_snapshots_and_skips_unchanged_traversal() {
        use std::sync::atomic::AtomicUsize;

        let keep_a = Arc::new(AtomicBool::new(false));
        let keep_b = Arc::new(AtomicBool::new(false));
        let node_a = make_tracked_leaf("node-a", keep_a.clone());
        let node_b = make_tracked_leaf("node-b", keep_b.clone());

        let members = Arc::new(vec![node_a.clone(), node_b.clone()]);
        let proxies_reads = Arc::new(AtomicUsize::new(0));
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning({
            let members = members.clone();
            let proxies_reads = proxies_reads.clone();
            move || {
                proxies_reads.fetch_add(1, Ordering::SeqCst);
                members.clone()
            }
        });
        provider.expect_route_changes().returning(|| None);

        let pm = ProxyManager::new(Arc::new(NoopResolver), None);
        pm.report_delay("node-a", true, Duration::from_millis(20))
            .await;
        pm.report_delay("node-b", true, Duration::from_millis(100))
            .await;

        let group = Arc::new(urltest::Handler::new(
            urltest::HandlerOptions {
                name: "AUTO".to_owned(),
                ..Default::default()
            },
            0,
            vec![Arc::new(provider)],
            pm.clone(),
        ));

        let mut handlers = HashMap::new();
        handlers.insert("node-a".to_owned(), node_a.clone());
        handlers.insert("node-b".to_owned(), node_b.clone());
        handlers.insert("AUTO".to_owned(), OutboundNode::group(group));

        let manager = OutboundManager::new_for_test(handlers);
        let mode_changes = RouteChange::default();
        let mut waits = Vec::new();
        let mut cache = IdleTrackerCache::default();
        let roots = vec!["AUTO".to_owned()];

        cache.rebuild_topology(&manager, &mode_changes, &mut waits);
        cache.apply_reachability(&roots, RunMode::Rule);
        assert_eq!(cache.traversal_count, 1);
        assert!(keep_a.load(Ordering::SeqCst));
        assert!(!keep_b.load(Ordering::SeqCst));

        let reads_after_init = proxies_reads.load(Ordering::SeqCst);

        // Update delay on slower node-b without changing the winner: must not
        // re-read provider snapshots and must skip graph traversal.
        pm.report_delay("node-b", true, Duration::from_millis(80))
            .await;
        let mut fired = HashSet::new();
        drain_ready_changes(&mut waits, &mut fired).await;
        assert!(!fired.is_empty());
        let traversed =
            cache.handle_incremental_changes(&fired, &roots, RunMode::Rule);
        assert!(
            !traversed,
            "unchanged group selection must skip full reachability traversal"
        );
        assert_eq!(cache.traversal_count, 1);
        assert_eq!(
            proxies_reads.load(Ordering::SeqCst),
            reads_after_init,
            "incremental update must not re-read live provider snapshots"
        );

        // Now node-b becomes faster than node-a: incremental recomputation
        // detects the winner change without re-reading providers and updates
        // keep_idle in a single traversal.
        pm.report_delay("node-b", true, Duration::from_millis(5))
            .await;
        fired.clear();
        drain_ready_changes(&mut waits, &mut fired).await;
        let traversed =
            cache.handle_incremental_changes(&fired, &roots, RunMode::Rule);
        assert!(traversed);
        assert_eq!(cache.traversal_count, 2);
        assert_eq!(proxies_reads.load(Ordering::SeqCst), reads_after_init);
        assert!(!keep_a.load(Ordering::SeqCst));
        assert!(keep_b.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn dialer_proxy_global_node_and_group_stay_warm() {
        use crate::proxy::utils::DialerProxyConnector;
        use arc_swap::ArcSwap;

        let keep_front_leaf = Arc::new(AtomicBool::new(false));
        let keep_group_a = Arc::new(AtomicBool::new(false));
        let keep_group_b = Arc::new(AtomicBool::new(false));
        let front_leaf = make_tracked_leaf("front-leaf", keep_front_leaf.clone());
        let group_a = make_tracked_leaf("front-group-a", keep_group_a.clone());
        let group_b = make_tracked_leaf("front-group-b", keep_group_b.clone());

        let group_members = Arc::new(vec![group_a.clone(), group_b.clone()]);
        let mut group_provider = MockDummyProxyProvider::new();
        group_provider
            .expect_proxies()
            .returning(move || group_members.clone());
        group_provider.expect_route_changes().returning(|| None);

        let front_group = Arc::new(
            selector::Handler::new(
                selector::HandlerOptions {
                    name: "FRONT_GROUP".to_owned(),
                    ..Default::default()
                },
                vec![Arc::new(group_provider)],
                Some("front-group-a".to_owned()),
            )
            .await,
        );

        let registry = Arc::new(ArcSwap::from_pointee(HashMap::new()));
        let via_leaf_connector =
            DialerProxyConnector::new("front-leaf".to_owned(), &registry);
        let via_group_connector =
            DialerProxyConnector::new("FRONT_GROUP".to_owned(), &registry);
        let front_leaf_id = front_leaf.identity();

        let mut handlers = HashMap::new();
        handlers.insert("front-leaf".to_owned(), front_leaf);
        handlers.insert("front-group-a".to_owned(), group_a);
        handlers.insert("front-group-b".to_owned(), group_b);
        handlers.insert(
            "FRONT_GROUP".to_owned(),
            OutboundNode::group(front_group.clone()),
        );
        registry.store(Arc::new(handlers.clone()));

        // Verify DialerProxyConnector::outbound_dependency() resolves both a
        // global leaf and a global group when `local` is None.
        assert_eq!(
            via_leaf_connector.outbound_dependency().unwrap().identity(),
            front_leaf_id
        );
        assert_eq!(
            via_group_connector.outbound_dependency().unwrap().name(),
            "FRONT_GROUP"
        );

        // Also verify real `socks::outbound::Handler` chained via
        // DialerProxyConnector keeps both a global leaf dialer and a global
        // group dialer warm.
        use crate::proxy::{
            socks::outbound::{
                Handler as SocksHandler, HandlerOptions as SocksHandlerOptions,
            },
            utils::RemoteConnector,
        };
        let chained_leaf = OutboundNode::protocol(Arc::new(SocksHandler::new(
            SocksHandlerOptions {
                name: "chained-to-leaf".to_owned(),
                server: "127.0.0.1".to_owned(),
                port: 1080,
                ..Default::default()
            },
            Some(Arc::new(RemoteConnector::DialerProxy(via_leaf_connector))),
        )));
        let chained_group = OutboundNode::protocol(Arc::new(SocksHandler::new(
            SocksHandlerOptions {
                name: "chained-to-group".to_owned(),
                server: "127.0.0.1".to_owned(),
                port: 1081,
                ..Default::default()
            },
            Some(Arc::new(RemoteConnector::DialerProxy(via_group_connector))),
        )));
        handlers.insert("chained-to-leaf".to_owned(), chained_leaf);
        handlers.insert("chained-to-group".to_owned(), chained_group);
        registry.store(Arc::new(handlers.clone()));

        let manager = OutboundManager::new_for_test(handlers);
        let mode_changes = RouteChange::default();
        let mut waits = Vec::new();
        let mut cache = IdleTrackerCache::default();
        let roots = vec![
            "chained-to-leaf".to_owned(),
            "chained-to-group".to_owned(),
        ];

        cache.rebuild_topology(&manager, &mode_changes, &mut waits);
        cache.apply_reachability(&roots, RunMode::Rule);

        assert!(
            keep_front_leaf.load(Ordering::SeqCst),
            "global dialer-proxy leaf must stay warm when referenced by a reachable chained proxy"
        );
        assert!(
            keep_group_a.load(Ordering::SeqCst),
            "selected member of a global dialer-proxy group must stay warm"
        );
        assert!(!keep_group_b.load(Ordering::SeqCst));

        // Switching the global dialer-proxy group updates keep_idle to the new member.
        SelectorControl::select(front_group.as_ref(), "front-group-b").unwrap();
        let mut fired = HashSet::new();
        drain_ready_changes(&mut waits, &mut fired).await;
        cache.handle_incremental_changes(&fired, &roots, RunMode::Rule);
        assert!(!keep_group_a.load(Ordering::SeqCst));
        assert!(keep_group_b.load(Ordering::SeqCst));
    }
}
