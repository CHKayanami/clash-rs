//! Tracks which protocol outbounds are currently reachable from active routing
//! rules, explicit DNS upstreams, and group selections, and toggles their
//! idle-connection keep-alive policy accordingly.

use std::{
    collections::{HashMap, HashSet},
    future::{pending, poll_fn},
    mem::take,
    pin::Pin,
    sync::Arc,
    task::Poll,
    time::Duration,
};

use futures::{
    Stream, StreamExt, future::BoxFuture, stream::FuturesUnordered,
};
use tokio::{
    sync::{oneshot, watch::Receiver},
    time::{Instant, interval, sleep_until},
};
use tokio_util::sync::CancellationToken;
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
        utils::provider_helper::{MemberUrls, Providers},
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

enum WaitOutcome {
    Changed {
        id: usize,
        generation: u64,
        receiver: Receiver<()>,
        cancel: oneshot::Receiver<()>,
    },
    Cancelled,
}

async fn wait_source(
    id: usize,
    generation: u64,
    mut receiver: Receiver<()>,
    mut cancel: oneshot::Receiver<()>,
) -> WaitOutcome {
    tokio::select! {
        biased;
        _ = &mut cancel => WaitOutcome::Cancelled,
        res = receiver.changed() => match res {
            Ok(()) => WaitOutcome::Changed {
                id,
                generation,
                receiver,
                cancel,
            },
            Err(_) => WaitOutcome::Cancelled,
        },
    }
}

struct ActiveSource {
    generation: u64,
    _source: RouteChange,
    _cancel: oneshot::Sender<()>,
}

/// Ready-queue driven watcher set backed by `FuturesUnordered` so notification
/// work scales with woken sources rather than total watched sources.
#[derive(Default)]
struct SourceWaitSet {
    active: HashMap<usize, ActiveSource>,
    futures: FuturesUnordered<BoxFuture<'static, WaitOutcome>>,
    next_gen: u64,
}

impl SourceWaitSet {
    fn insert_if_missing(&mut self, source: RouteChange) {
        let id = source.identity();
        if self.active.contains_key(&id) {
            return;
        }
        let generation = self.next_gen;
        self.next_gen = self.next_gen.wrapping_add(1);
        let receiver = source.subscribe();
        let (cancel_tx, cancel_rx) = oneshot::channel();
        self.active.insert(
            id,
            ActiveSource {
                generation,
                _source: source,
                _cancel: cancel_tx,
            },
        );
        self.futures
            .push(Box::pin(wait_source(id, generation, receiver, cancel_rx)));
    }

    fn ensure(&mut self, desired: Vec<RouteChange>) {
        for source in desired {
            self.insert_if_missing(source);
        }
    }

    fn sync(&mut self, desired: Vec<RouteChange>) {
        let mut wanted = HashSet::with_capacity(desired.len());
        for source in desired {
            wanted.insert(source.identity());
            self.insert_if_missing(source);
        }
        self.active.retain(|id, _| wanted.contains(id));
    }

    /// Waits until at least one active source changes and records the fired
    /// source identity into `fired_sources`. Cancel-safe across `tokio::select!`.
    async fn wait_any(&mut self, fired_sources: &mut HashSet<usize>) {
        if self.active.is_empty() {
            while let Some(WaitOutcome::Cancelled) = self.futures.next().await {}
            pending::<()>().await;
            return;
        }
        while let Some(outcome) = self.futures.next().await {
            match outcome {
                WaitOutcome::Cancelled => {}
                WaitOutcome::Changed {
                    id,
                    generation,
                    receiver,
                    cancel,
                } => {
                    if self
                        .active
                        .get(&id)
                        .is_some_and(|entry| entry.generation == generation)
                    {
                        fired_sources.insert(id);
                        self.futures.push(Box::pin(wait_source(
                            id, generation, receiver, cancel,
                        )));
                        return;
                    }
                }
            }
        }
        pending::<()>().await;
    }

    /// Drains any already-ready notifications without blocking and records all
    /// fired source identities into `fired_sources`.
    async fn drain_ready(&mut self, fired_sources: &mut HashSet<usize>) {
        let mut rearm = Vec::new();
        poll_fn(|cx| {
            while let Poll::Ready(Some(outcome)) =
                Pin::new(&mut self.futures).poll_next(cx)
            {
                if let WaitOutcome::Changed {
                    id,
                    generation,
                    receiver,
                    cancel,
                } = outcome
                    && self
                        .active
                        .get(&id)
                        .is_some_and(|entry| entry.generation == generation)
                {
                    fired_sources.insert(id);
                    rearm.push((id, generation, receiver, cancel));
                }
            }
            Poll::Ready(())
        })
        .await;
        for (id, generation, receiver, cancel) in rearm {
            self.futures
                .push(Box::pin(wait_source(id, generation, receiver, cancel)));
        }
    }
}

struct GroupSnapshot {
    group: ProxyGroup,
    input_snapshots: Vec<Arc<Vec<OutboundNode>>>,
    members: Arc<Vec<OutboundNode>>,
    urls: MemberUrls,
    route_changes: Vec<RouteChange>,
    selected: Option<OutboundNode>,
}

#[derive(Default)]
struct IdleTrackerCache {
    registry: Arc<HashMap<String, OutboundNode>>,
    protocols: HashMap<usize, OutboundNode>,
    /// Active protocol nodes absent from the rebuilt topology (such as
    /// out-of-topology `dialer_dependency` nodes or retired provider nodes
    /// awaiting the immediately following reachability pass).
    extra_protocols: HashMap<usize, OutboundNode>,
    active_protocols: HashSet<usize>,
    pending_init: HashMap<usize, OutboundNode>,
    groups: HashMap<usize, GroupSnapshot>,
    source_to_groups: HashMap<usize, Vec<usize>>,
    provider_ids: HashSet<usize>,
    last_mode: Option<RunMode>,
    #[cfg(test)]
    traversal_count: usize,
    #[cfg(test)]
    rebuilt_group_count: usize,
}

impl IdleTrackerCache {
    fn is_provider_source(&self, id: usize) -> bool {
        self.provider_ids.contains(&id)
    }

    /// Rebuilds the cached fixed-snapshot topology and updates `waits` before
    /// computing initial group selections so notifications cannot be lost
    /// across startup or provider refreshes. Groups whose input provider
    /// snapshots did not change reuse their cached member list and watchers.
    fn rebuild_topology(
        &mut self,
        outbound_manager: &OutboundManager,
        mode_changes: &RouteChange,
        waits: &mut SourceWaitSet,
    ) {
        outbound_manager.invalidate_stale_provider_caches();

        // Register provider and mode watchers before capturing snapshots so
        // concurrent refreshes during rebuild still mark their receivers dirty.
        let provider_sources = outbound_manager.collect_provider_route_changes();
        let mut pre_sources = provider_sources.clone();
        pre_sources.push(mode_changes.clone());
        waits.ensure(pre_sources);

        let registry = outbound_manager.registry_snapshot();
        let provider_snapshots = outbound_manager.capture_provider_snapshots();

        let mut new_protocols: HashMap<usize, OutboundNode> = HashMap::new();
        let mut record_protocol = |node: &OutboundNode| {
            if node.as_protocol().is_some() {
                new_protocols
                    .entry(node.identity())
                    .or_insert_with(|| node.clone());
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

        let mut old_groups = take(&mut self.groups);
        let mut groups = HashMap::with_capacity(old_groups.len());
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
            let input_snapshots = group.input_snapshots_from(&provider_snapshots);

            let entry = match old_groups.remove(&group_id) {
                Some(mut prev)
                    if Providers::snapshots_match(
                        &prev.input_snapshots,
                        &input_snapshots,
                    ) =>
                {
                    prev.group = group.clone();
                    prev.input_snapshots = input_snapshots;
                    prev
                }
                _ => {
                    #[cfg(test)]
                    {
                        self.rebuilt_group_count += 1;
                    }
                    let (members, urls) =
                        group.members_from_input_snapshots(&input_snapshots);
                    let mut group_sources = Vec::new();
                    group.route_changes_from(&members, &urls, &mut group_sources);
                    let mut seen_for_group =
                        HashSet::with_capacity(group_sources.len());
                    group_sources.retain(|s| seen_for_group.insert(s.identity()));
                    GroupSnapshot {
                        group: group.clone(),
                        input_snapshots,
                        members,
                        urls,
                        route_changes: group_sources,
                        selected: None,
                    }
                }
            };

            for member in entry.members.iter() {
                record_protocol(member);
            }

            for source in &entry.route_changes {
                source_to_groups
                    .entry(source.identity())
                    .or_default()
                    .push(group_id);
                push_source(source.clone());
            }

            groups.insert(group_id, entry);
        }

        // Subscribe to all member/group notification sources before reading
        // initial selections so updates cannot fall between inspect and watch.
        waits.sync(desired_sources);

        for entry in groups.values_mut() {
            if entry.group.stable_selection() {
                entry.selected =
                    entry.group.peek_selected_from(&entry.members, &entry.urls);
            }
        }

        // Preserve currently active nodes that disappeared from the topology
        // (including out-of-topology `dialer_dependency` nodes and retired
        // provider nodes) in `extra_protocols` so the following
        // `apply_reachability` either keeps them active without flapping or
        // explicitly turns `keep_idle` off and drops them.
        let old_protocols = take(&mut self.protocols);
        let old_extra = take(&mut self.extra_protocols);
        let mut extra_protocols = HashMap::new();
        for &id in &self.active_protocols {
            if !new_protocols.contains_key(&id)
                && let Some(node) =
                    old_protocols.get(&id).or_else(|| old_extra.get(&id))
            {
                extra_protocols.insert(id, node.clone());
            }
        }

        // Explicitly initialize keep_idle for newly added protocol nodes while
        // preserving diff-only updates for surviving nodes.
        self.pending_init
            .retain(|id, _| new_protocols.contains_key(id));
        for (&id, node) in &new_protocols {
            if !old_protocols.contains_key(&id) && !old_extra.contains_key(&id) {
                self.pending_init.insert(id, node.clone());
            }
        }

        self.registry = registry;
        self.protocols = new_protocols;
        self.extra_protocols = extra_protocols;
        self.active_protocols.retain(|id| {
            self.protocols.contains_key(id) || self.extra_protocols.contains_key(id)
        });
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
        let mut new_active = HashSet::new();

        while let Some(node) = queue.pop() {
            if !visited.insert(node.identity()) {
                continue;
            }
            match &node {
                OutboundNode::Protocol(_) => {
                    let id = node.identity();
                    new_active.insert(id);
                    if !self.protocols.contains_key(&id)
                        && !self.extra_protocols.contains_key(&id)
                    {
                        self.extra_protocols.insert(id, node.clone());
                        self.pending_init.insert(id, node.clone());
                    }
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

        let initialized_now = if self.pending_init.is_empty() {
            None
        } else {
            let mut done = HashSet::with_capacity(self.pending_init.len());
            for (id, node) in self.pending_init.drain() {
                let keep = new_active.contains(&id);
                debug!(
                    outbound = %node.name(),
                    keep_idle = keep,
                    "updating outbound idle connection policy"
                );
                node.set_keep_idle(keep);
                done.insert(id);
            }
            Some(done)
        };

        for id in new_active.difference(&self.active_protocols) {
            if initialized_now.as_ref().is_some_and(|done| done.contains(id)) {
                continue;
            }
            if let Some(node) = self
                .protocols
                .get(id)
                .or_else(|| self.extra_protocols.get(id))
            {
                debug!(
                    outbound = %node.name(),
                    keep_idle = true,
                    "updating outbound idle connection policy"
                );
                node.set_keep_idle(true);
            }
        }

        for id in self.active_protocols.difference(&new_active) {
            if let Some(node) = self
                .protocols
                .get(id)
                .or_else(|| self.extra_protocols.get(id))
            {
                debug!(
                    outbound = %node.name(),
                    keep_idle = false,
                    "updating outbound idle connection policy"
                );
                node.set_keep_idle(false);
            }
        }

        self.active_protocols = new_active;
        self.extra_protocols
            .retain(|id, _| self.active_protocols.contains(id));
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

    let mut waits = SourceWaitSet::default();
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
            _ = waits.wait_any(&mut fired_sources) => {
                // Coalesce burst notifications (e.g. batch healthchecks) before
                // updating group selections or scanning the outbound graph.
                let deadline = Instant::now() + NOTIFY_COALESCE_WINDOW;
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = sleep_until(deadline) => break,
                        _ = waits.wait_any(&mut fired_sources) => {}
                    }
                }
                waits.drain_ready(&mut fired_sources).await;
            }
            _ = fallback_tick.tick() => {
                waits.drain_ready(&mut fired_sources).await;
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
        let mut waits = SourceWaitSet::default();
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
        waits.drain_ready(&mut fired).await;
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
        waits.drain_ready(&mut fired).await;
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
        let mut waits = SourceWaitSet::default();
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
        waits.drain_ready(&mut fired).await;
        cache.handle_incremental_changes(&fired, &roots, RunMode::Rule);
        assert!(!keep_group_a.load(Ordering::SeqCst));
        assert!(keep_group_b.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn source_wait_set_collects_batch_and_cancels_removed_sources() {
        let sources: Vec<RouteChange> = (0..32).map(|_| RouteChange::default()).collect();
        let mut waits = SourceWaitSet::default();
        waits.sync(sources.clone());

        // Arm all futures by draining once (none fired yet).
        let mut fired = HashSet::new();
        waits.drain_ready(&mut fired).await;
        assert!(fired.is_empty());

        // Fire a batch of 10 sources; wait_any + drain_ready must capture all 10.
        let expected: HashSet<usize> = sources[0..10]
            .iter()
            .map(|s| {
                s.notify();
                s.identity()
            })
            .collect();
        waits.wait_any(&mut fired).await;
        waits.drain_ready(&mut fired).await;
        assert_eq!(fired, expected);

        // Re-firing one of the previously fired sources must still wake cleanly.
        fired.clear();
        sources[3].notify();
        waits.wait_any(&mut fired).await;
        assert!(fired.contains(&sources[3].identity()));

        // Sync to keep only the second half; removed sources must not wake even
        // if notified, and surviving sources keep working without losing events.
        waits.sync(sources[16..32].to_vec());
        sources[0].notify();
        sources[20].notify();
        fired.clear();
        waits.wait_any(&mut fired).await;
        waits.drain_ready(&mut fired).await;
        assert!(!fired.contains(&sources[0].identity()));
        assert!(fired.contains(&sources[20].identity()));

        // Re-adding a previously removed source works cleanly.
        waits.sync(vec![sources[0].clone(), sources[20].clone()]);
        fired.clear();
        waits.drain_ready(&mut fired).await;
        sources[0].notify();
        waits.wait_any(&mut fired).await;
        assert!(fired.contains(&sources[0].identity()));
    }

    #[tokio::test]
    async fn rebuild_reuses_unchanged_group_snapshots_and_updates_keep_idle_by_diff() {
        use std::sync::atomic::AtomicUsize;
        use arc_swap::ArcSwap;
        use fancy_regex::Regex;
        use crate::app::remote_content_manager::providers::proxy_provider::{
            ArcProxyProvider, FilteredProxyProvider,
        };

        let make_counted_leaf = |name: &str, initial: bool| {
            let keep = Arc::new(AtomicBool::new(initial));
            let calls = Arc::new(AtomicUsize::new(0));
            let mut mock = MockDummyOutboundHandler::new();
            mock.expect_name().return_const(name.to_owned());
            mock.expect_proto().return_const(OutboundType::Hysteria2);
            mock.expect_support_udp().return_const(true);
            {
                let keep = keep.clone();
                let calls = calls.clone();
                mock.expect_set_keep_idle().returning(move |v| {
                    keep.store(v, Ordering::SeqCst);
                    calls.fetch_add(1, Ordering::SeqCst);
                });
            }
            (OutboundNode::protocol(Arc::new(mock)), keep, calls)
        };

        let (a1, keep_a1, calls_a1) = make_counted_leaf("HK-a1", true);
        let (a2, keep_a2, calls_a2) = make_counted_leaf("HK-a2", true);
        let (b1, keep_b1, calls_b1) = make_counted_leaf("US-b1", true);
        let (b2, keep_b2, calls_b2) = make_counted_leaf("US-b2", true);

        let slot_a = Arc::new(ArcSwap::from_pointee(vec![a1.clone(), a2.clone()]));
        let slot_b = Arc::new(ArcSwap::from_pointee(vec![b1.clone(), b2.clone()]));
        let changes_a = RouteChange::default();
        let changes_b = RouteChange::default();

        let mut prov_a_mock = MockDummyProxyProvider::new();
        prov_a_mock.expect_proxies().returning({
            let slot_a = slot_a.clone();
            move || slot_a.load_full()
        });
        prov_a_mock.expect_route_changes().returning({
            let changes_a = changes_a.clone();
            move || Some(changes_a.clone())
        });
        let prov_a: ArcProxyProvider = Arc::new(prov_a_mock);

        let mut prov_b_mock = MockDummyProxyProvider::new();
        prov_b_mock.expect_proxies().returning({
            let slot_b = slot_b.clone();
            move || slot_b.load_full()
        });
        prov_b_mock.expect_route_changes().returning({
            let changes_b = changes_b.clone();
            move || Some(changes_b.clone())
        });
        let prov_b: ArcProxyProvider = Arc::new(prov_b_mock);

        let filtered_a: ArcProxyProvider = Arc::new(FilteredProxyProvider::new(
            prov_a.clone(),
            Arc::new(Regex::new(r"^HK-").unwrap()),
            None,
        ));
        let filtered_b: ArcProxyProvider = Arc::new(FilteredProxyProvider::new(
            prov_b.clone(),
            Arc::new(Regex::new(r"^US-").unwrap()),
            None,
        ));

        let group_a = Arc::new(
            selector::Handler::new(
                selector::HandlerOptions {
                    name: "GROUP_A".to_owned(),
                    ..Default::default()
                },
                vec![filtered_a],
                Some("HK-a1".to_owned()),
            )
            .await,
        );
        let group_b = Arc::new(
            selector::Handler::new(
                selector::HandlerOptions {
                    name: "GROUP_B".to_owned(),
                    ..Default::default()
                },
                vec![filtered_b],
                Some("US-b1".to_owned()),
            )
            .await,
        );

        let group_a_node = OutboundNode::group(group_a.clone());
        let group_b_node = OutboundNode::group(group_b.clone());
        let group_a_id = group_a_node.identity();
        let group_b_id = group_b_node.identity();

        let mut handlers = HashMap::new();
        handlers.insert("GROUP_A".to_owned(), group_a_node);
        handlers.insert("GROUP_B".to_owned(), group_b_node);

        let mut providers_map = HashMap::new();
        providers_map.insert("prov_a".to_owned(), prov_a);
        providers_map.insert("prov_b".to_owned(), prov_b);

        let pm = ProxyManager::new(Arc::new(NoopResolver), None);
        let manager =
            OutboundManager::new_for_test_with_providers(handlers, providers_map, pm);
        let mode_changes = RouteChange::default();
        let mut waits = SourceWaitSet::default();
        let mut cache = IdleTrackerCache::default();
        let roots = vec!["GROUP_A".to_owned(), "GROUP_B".to_owned()];

        // Initial startup: every node (reachable and unreachable) is explicitly initialized once.
        cache.rebuild_topology(&manager, &mode_changes, &mut waits);
        cache.apply_reachability(&roots, RunMode::Rule);
        assert_eq!(cache.rebuilt_group_count, 2);
        assert!(keep_a1.load(Ordering::SeqCst));
        assert!(!keep_a2.load(Ordering::SeqCst));
        assert!(keep_b1.load(Ordering::SeqCst));
        assert!(!keep_b2.load(Ordering::SeqCst));
        assert_eq!(calls_a1.load(Ordering::SeqCst), 1);
        assert_eq!(calls_a2.load(Ordering::SeqCst), 1);
        assert_eq!(calls_b1.load(Ordering::SeqCst), 1);
        assert_eq!(calls_b2.load(Ordering::SeqCst), 1);

        let group_b_members_before = cache.groups[&group_b_id].members.clone();

        // Incremental switch in GROUP_A (HK-a1 -> HK-a2): diff updates ONLY a1 and a2;
        // b1 and b2 must NOT have set_keep_idle called again.
        SelectorControl::select(group_a.as_ref(), "HK-a2").unwrap();
        let mut fired = HashSet::new();
        waits.drain_ready(&mut fired).await;
        assert!(cache.handle_incremental_changes(&fired, &roots, RunMode::Rule));
        assert!(!keep_a1.load(Ordering::SeqCst));
        assert!(keep_a2.load(Ordering::SeqCst));
        assert_eq!(calls_a1.load(Ordering::SeqCst), 2);
        assert_eq!(calls_a2.load(Ordering::SeqCst), 2);
        assert_eq!(calls_b1.load(Ordering::SeqCst), 1);
        assert_eq!(calls_b2.load(Ordering::SeqCst), 1);

        // Refresh ONLY prov_a with new nodes (HK-a2 active, HK-a3 inactive);
        // prov_b is untouched.
        let (a2_new, keep_a2_new, calls_a2_new) = make_counted_leaf("HK-a2", false);
        let (a3_new, keep_a3_new, calls_a3_new) = make_counted_leaf("HK-a3", true);
        slot_a.store(Arc::new(vec![a2_new, a3_new]));
        changes_a.notify();

        cache.rebuild_topology(&manager, &mode_changes, &mut waits);
        cache.apply_reachability(&roots, RunMode::Rule);

        // Only GROUP_A was rebuilt; GROUP_B reused its exact member snapshot Arc.
        assert_eq!(cache.rebuilt_group_count, 3);
        assert!(Arc::ptr_eq(
            &group_b_members_before,
            &cache.groups[&group_b_id].members
        ));
        assert_eq!(cache.groups[&group_a_id].members.len(), 2);

        // Newly added nodes in prov_a are explicitly initialized
        // (both active & inactive).
        assert!(keep_a2_new.load(Ordering::SeqCst));
        assert!(!keep_a3_new.load(Ordering::SeqCst));
        assert_eq!(calls_a2_new.load(Ordering::SeqCst), 1);
        assert_eq!(calls_a3_new.load(Ordering::SeqCst), 1);

        // Surviving unchanged nodes in prov_b are NOT redundantly updated.
        assert_eq!(calls_b1.load(Ordering::SeqCst), 1);
        assert_eq!(calls_b2.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dialer_dependency_outside_topology_turns_keep_idle_off_after_rebuild() {
        use std::sync::atomic::AtomicUsize;

        use arc_swap::ArcSwap;

        use crate::{
            config::internal::proxy::OutboundProxyProtocol,
            proxy::utils::ProviderSnapshot,
        };

        let keep_entry = Arc::new(AtomicBool::new(false));
        let calls_entry = Arc::new(AtomicUsize::new(0));
        let mut entry_mock = MockDummyOutboundHandler::new();
        entry_mock
            .expect_name()
            .return_const("local-entry".to_owned());
        entry_mock.expect_proto().return_const(OutboundType::Hysteria2);
        entry_mock.expect_support_udp().return_const(true);
        {
            let keep_entry = keep_entry.clone();
            let calls_entry = calls_entry.clone();
            entry_mock.expect_set_keep_idle().returning(move |v| {
                keep_entry.store(v, Ordering::SeqCst);
                calls_entry.fetch_add(1, Ordering::SeqCst);
            });
        }
        let entry = OutboundNode::protocol(Arc::new(entry_mock));

        let registry_swap = Arc::new(ArcSwap::from_pointee(HashMap::new()));
        let local_snap = Arc::new(ArcSwap::from_pointee(ProviderSnapshot::new(
            vec![entry.clone()],
        )));
        let cfg: OutboundProxyProtocol = yaml_serde::from_str(
            "type: socks5\nname: exit\nserver: 127.0.0.1\nport: 1080\n\
             dialer-proxy: local-entry\n",
        )
        .unwrap();
        let exit = OutboundManager::load_provider_outbounds(
            vec![cfg],
            &registry_swap,
            Some(&local_snap),
        )
        .unwrap()
        .remove(0);
        assert!(exit.dialer_dependency().unwrap().ptr_eq(&entry));

        let plain = make_tracked_leaf("plain", Arc::new(AtomicBool::new(true)));
        let members = Arc::new(vec![exit, plain]);
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning(move || members.clone());
        provider.expect_route_changes().returning(|| None);
        let group = Arc::new(
            selector::Handler::new(
                selector::HandlerOptions {
                    name: "PROXY".to_owned(),
                    ..Default::default()
                },
                vec![Arc::new(provider)],
                Some("exit".to_owned()),
            )
            .await,
        );

        let mut handlers = HashMap::new();
        handlers.insert("PROXY".to_owned(), OutboundNode::group(group.clone()));
        let manager = OutboundManager::new_for_test(handlers);
        let mode_changes = RouteChange::default();
        let mut waits = SourceWaitSet::default();
        let mut cache = IdleTrackerCache::default();
        let roots = vec!["PROXY".to_owned()];

        // Initial pass reaches `local-entry` solely via `exit.dialer_dependency()`.
        cache.rebuild_topology(&manager, &mode_changes, &mut waits);
        cache.apply_reachability(&roots, RunMode::Rule);
        assert!(keep_entry.load(Ordering::SeqCst));
        assert_eq!(calls_entry.load(Ordering::SeqCst), 1);

        // Rebuilding topology while `local-entry` remains reachable must not flap.
        cache.rebuild_topology(&manager, &mode_changes, &mut waits);
        cache.apply_reachability(&roots, RunMode::Rule);
        assert!(keep_entry.load(Ordering::SeqCst));
        assert_eq!(calls_entry.load(Ordering::SeqCst), 1);

        // Switching away and rebuilding topology must explicitly turn
        // `keep_idle` back off and release `local-entry` from `extra_protocols`.
        SelectorControl::select(group.as_ref(), "plain").unwrap();
        cache.rebuild_topology(&manager, &mode_changes, &mut waits);
        cache.apply_reachability(&roots, RunMode::Rule);
        assert!(
            !keep_entry.load(Ordering::SeqCst),
            "out-of-topology dialer dependency must reset keep_idle to false"
        );
        assert_eq!(calls_entry.load(Ordering::SeqCst), 2);
        assert!(cache.extra_protocols.is_empty());
    }
}
