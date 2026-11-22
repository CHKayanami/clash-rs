use std::collections::{HashMap, HashSet};
use std::future::pending;
use std::net::IpAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use clash_ebpf::EbpfManager;
use futures::future::select_all;
use tokio::sync::{
    mpsc::{self, UnboundedSender, WeakUnboundedSender},
    watch,
};
use tokio::task::AbortHandle;
use tokio::time::{Instant, sleep, sleep_until};
use tracing::{debug, info, warn};

use super::utils::is_reserved_ip;
use crate::app::dispatcher::{
    Dispatcher, RouteOffloadAction, RouteOffloadEvent, RouteOffloadObserver,
};
use crate::app::dns::{ClashResolver, ThreadSafeDNSResolver};
use crate::app::remote_content_manager::providers::rule_provider::CidrTrie;
use crate::common::domain::has_valid_domain_labels;
use crate::config::def::RunMode;
use crate::proxy::{OutboundType, RouteChange};

mod state;

use state::{
    DnsObservation, Observation, OffloadDesiredState, RouteDomainObservation,
    RouteIpObservation,
};

pub type DomainKey = Arc<str>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingAction {
    Direct,
    Proxy,
}

pub fn normalize_domain(domain: &str) -> Option<DomainKey> {
    let trimmed = domain.trim().trim_end_matches('.');
    if trimmed.is_empty()
        || trimmed.parse::<IpAddr>().is_ok()
        || !has_valid_domain_labels(trimmed)
    {
        return None;
    }
    if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        Some(Arc::from(trimmed.to_ascii_lowercase()))
    } else {
        Some(Arc::from(trimmed))
    }
}

#[derive(Debug)]
enum OffloadMessage {
    Observe(Observation),
    ModeChanged(RunMode),
    GroupRouteChanged,
}

async fn wait_any_route_change(waits: &mut [(usize, watch::Receiver<()>)]) {
    let futs = waits
        .iter_mut()
        .map(|(_, rx)| Box::pin(rx.changed()));
    let _ = select_all(futs).await;
}

fn sync_route_waits(
    waits: &mut Vec<(usize, watch::Receiver<()>)>,
    changes: Vec<RouteChange>,
) {
    let wanted: HashSet<usize> = changes.iter().map(|c| c.identity()).collect();
    waits.retain(|(id, _)| wanted.contains(id));
    for change in changes {
        let id = change.identity();
        if !waits.iter().any(|(existing, _)| *existing == id) {
            waits.push((id, change.subscribe()));
        }
    }
}

fn spawn_route_change_watcher(
    dispatcher: Weak<Dispatcher>,
    weak_tx: WeakUnboundedSender<OffloadMessage>,
    mut route_waits: Vec<(usize, watch::Receiver<()>)>,
) -> AbortHandle {
    tokio::spawn(async move {
        const ROUTE_CHANGE_DEBOUNCE: Duration = Duration::from_millis(50);
        while !route_waits.is_empty() {
            wait_any_route_change(&mut route_waits).await;
            sleep(ROUTE_CHANGE_DEBOUNCE).await;
            for (_, rx) in &mut route_waits {
                let _ = rx.borrow_and_update();
            }
            let Some(disp) = dispatcher.upgrade() else {
                break;
            };
            sync_route_waits(
                &mut route_waits,
                disp.outbound_manager().collect_group_route_changes(),
            );
            let Some(tx) = weak_tx.upgrade() else {
                break;
            };
            if tx.send(OffloadMessage::GroupRouteChanged).is_err() {
                break;
            }
        }
    })
    .abort_handle()
}

pub(crate) async fn evaluate_dns_offload(
    dispatcher: &Dispatcher,
    domain: &str,
    ips: &[IpAddr],
) -> (RoutingAction, Arc<str>, bool) {
    let router = dispatcher.router();
    let (sess, outbound, rule) = router.match_domain_probe(domain, ips).await;
    let rule_offloadable = router.is_match_offloadable(&sess, rule, true);
    let handler = dispatcher
        .outbound_manager()
        .get_outbound_or_direct(outbound);
    let action = if rule_offloadable
        && handler.effective_outbound_type().await == OutboundType::Direct
    {
        RoutingAction::Direct
    } else {
        RoutingAction::Proxy
    };
    (action, Arc::from(handler.name()), rule_offloadable)
}

async fn reconcile_group_routes(
    state: &mut OffloadDesiredState,
    dispatcher: &Weak<Dispatcher>,
    direct_outbounds: &mut Option<HashSet<Arc<str>>>,
) {
    let Some(disp) = dispatcher.upgrade() else {
        return;
    };
    let current = disp.outbound_manager().direct_outbound_names().await;
    let Some(previous) = direct_outbounds.as_mut() else {
        *direct_outbounds = Some(current);
        return;
    };
    if current == *previous {
        return;
    }
    let actions = current
        .difference(previous)
        .map(|name| (name.clone(), RoutingAction::Direct))
        .chain(
            previous
                .difference(&current)
                .map(|name| (name.clone(), RoutingAction::Proxy)),
        )
        .collect::<HashMap<_, _>>();
    state.reconcile_outbounds(&actions);
    *previous = current;
}

async fn reconcile_observation(
    observation: &mut Observation,
    state: &mut OffloadDesiredState,
    affected: &mut HashSet<IpAddr>,
    dispatcher: &Weak<Dispatcher>,
    direct_outbounds: &mut Option<HashSet<Arc<str>>>,
) {
    let (Some(snapshot), Some((outbound, observed))) =
        (direct_outbounds.as_ref(), observation.route_reconcile_key())
    else {
        return;
    };
    let was_direct = snapshot.contains(outbound);
    if (observed == RoutingAction::Direct) == was_direct {
        return;
    }

    let is_direct = if let Some(disp) = dispatcher.upgrade() {
        match disp.outbound_manager().get_outbound(outbound) {
            Some(handler) => {
                handler.effective_outbound_type().await == OutboundType::Direct
            }
            None => false,
        }
    } else {
        was_direct
    };
    let is_direct = if is_direct != was_direct {
        state.recompute_ips(affected.drain());
        reconcile_group_routes(state, dispatcher, direct_outbounds).await;
        direct_outbounds.as_ref().is_some_and(|set| set.contains(outbound))
    } else {
        was_direct
    };

    let action = if is_direct {
        RoutingAction::Direct
    } else {
        RoutingAction::Proxy
    };
    observation.set_action(action);
}

async fn process_message_batch(
    state: &mut OffloadDesiredState,
    active_mode: &mut RunMode,
    dispatcher: &Weak<Dispatcher>,
    direct_outbounds: &mut Option<HashSet<Arc<str>>>,
    batch: impl IntoIterator<Item = OffloadMessage>,
) {
    let mut affected = HashSet::new();
    for msg in batch {
        match msg {
            OffloadMessage::ModeChanged(next_mode) => {
                state.recompute_ips(affected.drain());
                DirectOffloader::apply_mode_transition(state, active_mode, next_mode);
            }
            OffloadMessage::GroupRouteChanged => {
                state.recompute_ips(affected.drain());
                reconcile_group_routes(state, dispatcher, direct_outbounds).await;
            }
            OffloadMessage::Observe(mut observation) => {
                reconcile_observation(
                    &mut observation, state, &mut affected, dispatcher, direct_outbounds,
                )
                .await;
                state.observe(observation, &mut affected);
            }
        }
    }
    state.recompute_ips(affected);
}

#[derive(Clone)]
pub struct DirectOffloader {
    tx: UnboundedSender<OffloadMessage>,
    resolver: Weak<dyn ClashResolver>,
    bypass_dst_trie: Arc<CidrTrie>,
    proxy_dst_trie: Arc<CidrTrie>,
    abort_handle: Arc<AbortHandle>,
    route_watch_abort: Arc<AbortHandle>,
}

impl DirectOffloader {
    pub async fn new(
        manager: Weak<EbpfManager>,
        resolver: ThreadSafeDNSResolver,
        bypass_dst_trie: Arc<CidrTrie>,
        proxy_dst_trie: Arc<CidrTrie>,
        dispatcher: Weak<Dispatcher>,
    ) -> Self {
        let mut route_waits = Vec::new();
        let mut direct_outbounds = None;
        if let Some(disp) = dispatcher.upgrade() {
            let outbound_manager = disp.outbound_manager();
            // Subscribe before reading the initial snapshot so concurrent changes stay pending.
            sync_route_waits(&mut route_waits, outbound_manager.collect_group_route_changes());
            direct_outbounds = Some(outbound_manager.direct_outbound_names().await);
        }
        let (tx, mut rx) = mpsc::unbounded_channel::<OffloadMessage>();
        let route_watch_abort = spawn_route_change_watcher(
            dispatcher.clone(), tx.downgrade(), route_waits,
        );

        let handle = tokio::spawn(async move {
            const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(1);
            const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
            let mut state = OffloadDesiredState::new();
            let mut active_mode = RunMode::Rule;
            let mut retry_delay = INITIAL_RETRY_DELAY;
            let mut retry_at = None;
            const MAX_BATCH_OBSERVATIONS: usize = 256;
            let mut batch = Vec::with_capacity(MAX_BATCH_OBSERVATIONS);

            loop {
                if !state.dirty_ips.is_empty()
                    && retry_at.is_none_or(|deadline| Instant::now() >= deadline)
                {
                    let mut add_v4 = Vec::new();
                    let mut add_v6 = Vec::new();
                    let mut del_v4 = Vec::new();
                    let mut del_v6 = Vec::new();
                    for ip in &state.dirty_ips {
                        let desired_active =
                            active_mode != RunMode::Global && state.desired.contains(ip);
                        match (desired_active, state.applied.contains(ip), ip) {
                            (true, false, IpAddr::V4(v4)) => add_v4.push(*v4),
                            (true, false, IpAddr::V6(v6)) => add_v6.push(*v6),
                            (false, true, IpAddr::V4(v4)) => del_v4.push(*v4),
                            (false, true, IpAddr::V6(v6)) => del_v6.push(*v6),
                            _ => {}
                        }
                    }
                    let has_updates = !add_v4.is_empty()
                        || !add_v6.is_empty()
                        || !del_v4.is_empty()
                        || !del_v6.is_empty();
                    let mut flush_succeeded = !has_updates;
                    if has_updates {
                        if let Some(mgr) = manager.upgrade() {
                            match mgr
                                .update_dynamic_bypass_batch(
                                    &add_v4, &add_v6, &del_v4, &del_v6,
                                )
                                .await
                            {
                                Ok(()) => {
                                    flush_succeeded = true;
                                    if !add_v4.is_empty() || !add_v6.is_empty() {
                                        info!(
                                            "[eBPF DirectOffloader] Dynamic bypass added: IPv4={}, IPv6={}",
                                            add_v4.len(),
                                            add_v6.len()
                                        );
                                    }
                                    if !del_v4.is_empty() || !del_v6.is_empty() {
                                        info!(
                                            "[eBPF DirectOffloader] Dynamic bypass removed: IPv4={}, IPv6={}",
                                            del_v4.len(),
                                            del_v6.len()
                                        );
                                    }
                                    for ip in add_v4
                                        .into_iter()
                                        .map(IpAddr::V4)
                                        .chain(add_v6.into_iter().map(IpAddr::V6))
                                    {
                                        state.applied.insert(ip);
                                    }
                                    for ip in del_v4
                                        .into_iter()
                                        .map(IpAddr::V4)
                                        .chain(del_v6.into_iter().map(IpAddr::V6))
                                    {
                                        state.applied.remove(&ip);
                                    }
                                }
                                Err(e) => warn!(
                                    "eBPF dynamic bypass batch update failed: {e} (retrying in {retry_delay:?})"
                                ),
                            }
                        } else {
                            debug!(
                                "eBPF manager not initialized yet, deferring dynamic bypass flush (retrying in {retry_delay:?})"
                            );
                        }
                    }
                    if flush_succeeded {
                        state.dirty_ips.clear();
                        retry_at = None;
                        retry_delay = INITIAL_RETRY_DELAY;
                        if has_updates && active_mode != RunMode::Global {
                            state.reclaim_headroom();
                            if !state.dirty_ips.is_empty() {
                                // Flush cleanup immediately, even if no more events arrive.
                                continue;
                            }
                        }
                    } else {
                        retry_at = Some(Instant::now() + retry_delay);
                        retry_delay = (retry_delay * 2).min(MAX_RETRY_DELAY);
                    }
                }

                tokio::select! {
                    count = rx.recv_many(&mut batch, MAX_BATCH_OBSERVATIONS) => {
                        if count == 0 {
                            break;
                        }
                        process_message_batch(
                            &mut state,
                            &mut active_mode,
                            &dispatcher,
                            &mut direct_outbounds,
                            batch.drain(..),
                        )
                        .await;
                    },
                    _ = async {
                        if let Some(deadline) = retry_at {
                            sleep_until(deadline).await;
                        } else {
                            pending::<()>().await;
                        }
                    } => {}
                }
            }
        });
        Self {
            tx,
            resolver: Arc::downgrade(&resolver),
            bypass_dst_trie,
            proxy_dst_trie,
            abort_handle: Arc::new(handle.abort_handle()),
            route_watch_abort: Arc::new(route_watch_abort),
        }
    }

    fn apply_mode_transition(
        state: &mut OffloadDesiredState,
        active_mode: &mut RunMode,
        next_mode: RunMode,
    ) {
        if *active_mode == next_mode {
            return;
        }
        let was_global = *active_mode == RunMode::Global;
        *active_mode = next_mode;
        if next_mode == RunMode::Global {
            state.dirty_ips.extend(state.applied.iter().copied());
        } else if was_global {
            state.dirty_ips.extend(state.desired.iter().copied());
            state.dirty_ips.extend(state.applied.iter().copied());
        }
    }

    pub fn stop(&self) {
        self.route_watch_abort.abort();
        self.abort_handle.abort();
    }

    fn should_skip_ip(&self, ip: IpAddr) -> bool {
        let is_fake_ip = self
            .resolver
            .upgrade()
            .is_some_and(|resolver| resolver.is_fake_ip(ip));
        is_reserved_ip(ip)
            || is_fake_ip
            || self.bypass_dst_trie.contains(ip)
            || self.proxy_dst_trie.contains(ip)
    }

    fn build_dns_observation(
        &self,
        domain: &str,
        mut ips: Vec<IpAddr>,
        action: RoutingAction,
        outbound: Option<Arc<str>>,
        rule_offloadable: bool,
    ) -> Option<Observation> {
        let domain = normalize_domain(domain)?;
        ips.retain(|ip| !self.should_skip_ip(*ip));
        if ips.is_empty() {
            return None;
        }
        Some(Observation::Dns(DnsObservation {
            domain,
            ips,
            action,
            outbound,
            rule_offloadable,
        }))
    }

    fn build_route_observation(&self, event: RouteOffloadEvent) -> Option<Observation> {
        let ip = event.ip.to_canonical();
        if self.should_skip_ip(ip) {
            return None;
        }
        let action = match event.action {
            RouteOffloadAction::Direct => RoutingAction::Direct,
            RouteOffloadAction::Proxy => RoutingAction::Proxy,
        };
        if let Some(raw_domain) = event.domain {
            let domain = normalize_domain(&raw_domain)?;
            Some(Observation::RouteDomain(RouteDomainObservation {
                domain,
                ip,
                action,
                outbound: event.outbound,
                rule_offloadable: event.rule_offloadable,
            }))
        } else {
            Some(Observation::RouteIp(RouteIpObservation {
                ip,
                action,
                outbound: event.outbound,
                rule_offloadable: event.rule_offloadable,
            }))
        }
    }

    pub(super) fn observe_dns(
        &self,
        domain: &str,
        ips: Vec<IpAddr>,
        action: RoutingAction,
        outbound: Arc<str>,
        rule_offloadable: bool,
    ) {
        if let Some(observation) =
            self.build_dns_observation(domain, ips, action, Some(outbound), rule_offloadable)
        {
            let _ = self.tx.send(OffloadMessage::Observe(observation));
        }
    }
}

impl RouteOffloadObserver for DirectOffloader {
    fn on_route(&self, event: RouteOffloadEvent) {
        if let Some(observation) = self.build_route_observation(event) {
            let _ = self.tx.send(OffloadMessage::Observe(observation));
        }
    }

    fn on_mode_change(&self, mode: RunMode) {
        let _ = self.tx.send(OffloadMessage::ModeChanged(mode));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::{MockClashResolver, ThreadSafeDNSResolver};

    #[tokio::test]
    async fn direct_offloader_does_not_retain_resolver() {
        let resolver: ThreadSafeDNSResolver = Arc::new(MockClashResolver::new());
        let weak_resolver = Arc::downgrade(&resolver);
        let offloader = DirectOffloader::new(
            Weak::new(),
            resolver.clone(),
            Arc::new(CidrTrie::new()),
            Arc::new(CidrTrie::new()),
            Weak::new(),
        )
        .await;
        drop(resolver);
        assert!(weak_resolver.upgrade().is_none());
        drop(offloader);
        tokio::task::yield_now().await;
    }

    #[test]
    fn mode_transition_global_clears_applied_and_rule_restores() {
        let mut state = OffloadDesiredState::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let mut affected = HashSet::new();
        state.observe(
            Observation::Dns(DnsObservation {
                domain: "a.com".into(),
                ips: vec![ip],
                action: RoutingAction::Direct,
                outbound: None,
                rule_offloadable: true,
            }),
            &mut affected,
        );
        state.recompute_ips(affected);
        state.applied.insert(ip);
        state.dirty_ips.clear();

        let mut mode = RunMode::Rule;
        DirectOffloader::apply_mode_transition(&mut state, &mut mode, RunMode::Global);
        assert_eq!(mode, RunMode::Global);
        assert!(state.dirty_ips.contains(&ip));
        // Simulate kernel flush under Global mode: applied cleared, desired retained.
        state.applied.clear();
        state.dirty_ips.clear();
        assert!(state.desired.contains(&ip));

        DirectOffloader::apply_mode_transition(&mut state, &mut mode, RunMode::Rule);
        assert_eq!(mode, RunMode::Rule);
        assert!(state.dirty_ips.contains(&ip));
    }

    #[test]
    fn normalize_domain_handles_case_trailing_dot_and_ip_literals() {
        assert_eq!(
            normalize_domain("Example.COM.").as_deref(),
            Some("example.com")
        );
        assert!(normalize_domain("1.2.3.4").is_none());
        assert!(normalize_domain("   ").is_none());
    }

    #[tokio::test]
    async fn static_bypass_and_proxy_tries_skip_offload_on_both_paths() {
        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_is_fake_ip().returning(|_| false);
        let resolver: ThreadSafeDNSResolver = Arc::new(mock_resolver);

        let mut bypass_trie = CidrTrie::new();
        bypass_trie.insert("192.0.2.0/24");
        let mut proxy_trie = CidrTrie::new();
        proxy_trie.insert("198.51.100.0/24");

        let offloader = DirectOffloader::new(
            Weak::new(),
            resolver,
            Arc::new(bypass_trie),
            Arc::new(proxy_trie),
            Weak::new(),
        )
        .await;

        let bypass_ip: IpAddr = "192.0.2.10".parse().unwrap();
        let proxy_ip: IpAddr = "198.51.100.10".parse().unwrap();
        let normal_ip: IpAddr = "203.0.113.10".parse().unwrap();

        let dns_msg = offloader.build_dns_observation(
            "example.com",
            vec![bypass_ip, proxy_ip, normal_ip],
            RoutingAction::Direct,
            Some("DIRECT".into()),
            true,
        );
        match dns_msg {
            Some(Observation::Dns(obs)) => {
                assert_eq!(obs.ips, vec![normal_ip]);
                assert_eq!(obs.action, RoutingAction::Direct);
            }
            other => panic!("unexpected dns message: {other:?}"),
        }

        assert!(offloader
            .build_dns_observation(
                "proxy-only.example",
                vec![proxy_ip],
                RoutingAction::Direct,
                Some("DIRECT".into()),
                true,
            )
            .is_none());

        assert!(offloader
            .build_route_observation(RouteOffloadEvent {
                ip: bypass_ip,
                domain: Some("example.com".into()),
                outbound: "DIRECT".into(),
                action: RouteOffloadAction::Direct,
                rule_offloadable: true,
            })
            .is_none());
        assert!(offloader
            .build_route_observation(RouteOffloadEvent {
                ip: proxy_ip,
                domain: Some("example.com".into()),
                outbound: "DIRECT".into(),
                action: RouteOffloadAction::Direct,
                rule_offloadable: true,
            })
            .is_none());
        assert!(offloader
            .build_route_observation(RouteOffloadEvent {
                ip: proxy_ip,
                domain: None,
                outbound: "PROXY".into(),
                action: RouteOffloadAction::Proxy,
                rule_offloadable: true,
            })
            .is_none());
        assert!(offloader
            .build_route_observation(RouteOffloadEvent {
                ip: normal_ip,
                domain: None,
                outbound: "DIRECT".into(),
                action: RouteOffloadAction::Direct,
                rule_offloadable: true,
            })
            .is_some());

        offloader.stop();
    }

    #[tokio::test]
    async fn group_route_change_is_processed_in_queue_order_and_does_not_retain_dispatcher() {
        use crate::app::{
            dispatcher::StatisticsManager,
            outbound::manager::OutboundManager,
            router::Router,
        };
        use crate::proxy::{
            OutboundNode,
            direct::Handler as DirectHandler,
            group::selector::{self, SelectorControl},
            mocks::MockDummyProxyProvider,
            reject::Handler as RejectHandler,
        };

        use std::{env::temp_dir, sync::atomic::{AtomicUsize, Ordering}};
        use tokio::task::yield_now;
        use tokio::time::timeout;

        let direct = OutboundNode::protocol(Arc::new(DirectHandler::new("DIRECT")));
        let reject = OutboundNode::protocol(Arc::new(RejectHandler::new("REJECT")));
        let provider = |nodes: Vec<OutboundNode>, lookups: Option<Arc<AtomicUsize>>| {
            let mut provider = MockDummyProxyProvider::new();
            let proxies = Arc::new(nodes);
            provider.expect_proxies().returning(move || {
                if let Some(lookups) = &lookups {
                    lookups.fetch_add(1, Ordering::Relaxed);
                }
                proxies.clone()
            });
            provider.expect_touch().return_const(());
            provider.expect_route_changes().return_const(None);
            Arc::new(provider)
        };
        let other_lookups = Arc::new(AtomicUsize::new(0));
        let other = OutboundNode::group(Arc::new(
            selector::Handler::new(
                selector::HandlerOptions {
                    name: "OTHER".into(),
                    ..Default::default()
                },
                vec![provider(vec![reject.clone()], Some(other_lookups.clone()))],
                None,
            )
            .await,
        ));

        let group = Arc::new(
            selector::Handler::new(
                selector::HandlerOptions {
                    name: "INNER".into(),
                    ..Default::default()
                },
                vec![provider(vec![direct.clone(), reject.clone(), other.clone()], None)],
                Some("DIRECT".to_string()),
            )
            .await,
        );
        let inner = OutboundNode::group(group.clone());
        let outer = Arc::new(
            selector::Handler::new(
                selector::HandlerOptions {
                    name: "AUTO".into(),
                    ..Default::default()
                },
                vec![provider(vec![inner.clone()], None)],
                None,
            )
            .await,
        );

        let mut handlers = HashMap::new();
        handlers.insert("DIRECT".to_string(), direct);
        handlers.insert("REJECT".to_string(), reject);
        handlers.insert("OTHER".to_string(), other);
        handlers.insert("INNER".to_string(), inner);
        handlers.insert("AUTO".to_string(), OutboundNode::group(outer));
        let outbound_manager = Arc::new(OutboundManager::new_for_test(handlers));

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_is_fake_ip().returning(|_| false);
        mock_resolver.expect_resolve().returning(|_, _| Ok(None));
        let resolver: ThreadSafeDNSResolver = Arc::new(mock_resolver);

        let router = Arc::new(
            Router::new(
                vec![],
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

        let dispatcher = Arc::new(Dispatcher::new(
            outbound_manager,
            router,
            resolver.clone(),
            RunMode::Rule,
            StatisticsManager::new(),
            None,
            None,
            true,
        ));
        let weak_disp = Arc::downgrade(&dispatcher);

        // Verify queue ordering: [RouteDomain(AUTO->Direct), GroupRouteChanged] after AUTO switches to REJECT.
        let mut state = OffloadDesiredState::new();
        let mut active_mode = RunMode::Rule;
        let mut direct_outbounds = Some(dispatcher.outbound_manager().direct_outbound_names().await);
        let expected_direct: HashSet<Arc<str>> =
            HashSet::from([Arc::from("DIRECT"), Arc::from("AUTO"), Arc::from("INNER")]);
        let direct_only: HashSet<Arc<str>> = HashSet::from([Arc::from("DIRECT")]);
        assert_eq!(direct_outbounds.as_ref(), Some(&expected_direct));
        let ip: IpAddr = "203.0.113.77".parse().unwrap();

        group.select("REJECT").unwrap();
        process_message_batch(
            &mut state,
            &mut active_mode,
            &weak_disp,
            &mut direct_outbounds,
            [
                OffloadMessage::Observe(Observation::RouteDomain(RouteDomainObservation {
                    domain: "queued.example".into(),
                    ip,
                    action: RoutingAction::Direct,
                    outbound: "AUTO".into(),
                    rule_offloadable: true,
                })),
                OffloadMessage::GroupRouteChanged,
            ],
        )
        .await;
        assert!(!state.desired.contains(&ip));
        assert_eq!(direct_outbounds.as_ref(), Some(&direct_only));

        // Stale Direct observation arriving AFTER GroupRouteChanged must be downgraded to Proxy.
        let stale_direct_ip: IpAddr = "203.0.113.78".parse().unwrap();
        let lookups_before = other_lookups.load(Ordering::Relaxed);
        process_message_batch(
            &mut state,
            &mut active_mode,
            &weak_disp,
            &mut direct_outbounds,
            [OffloadMessage::Observe(Observation::Dns(DnsObservation {
                domain: "stale-direct.example".into(),
                ips: vec![stale_direct_ip],
                action: RoutingAction::Direct,
                outbound: Some("AUTO".into()),
                rule_offloadable: true,
            }))],
        )
        .await;
        assert!(!state.desired.contains(&stale_direct_ip));
        assert_eq!(other_lookups.load(Ordering::Relaxed), lookups_before);

        state.dirty_ips.clear();
        group.select("OTHER").unwrap();
        reconcile_group_routes(&mut state, &weak_disp, &mut direct_outbounds).await;
        assert_eq!(direct_outbounds.as_ref(), Some(&direct_only));
        assert!(state.dirty_ips.is_empty());

        // Verify watcher -> queue -> drop(dispatcher) does not leak strong reference.
        let offloader = DirectOffloader::new(
            Weak::new(),
            resolver,
            Arc::new(CidrTrie::new()),
            Arc::new(CidrTrie::new()),
            weak_disp.clone(),
        )
        .await;
        let (watcher_tx, mut watcher_rx) = mpsc::unbounded_channel::<OffloadMessage>();
        let mut route_waits = Vec::new();
        sync_route_waits(
            &mut route_waits,
            dispatcher.outbound_manager().collect_group_route_changes(),
        );
        let watch_abort = spawn_route_change_watcher(
            weak_disp.clone(), watcher_tx.downgrade(), route_waits,
        );
        group.select("DIRECT").unwrap();
        let msg = timeout(Duration::from_secs(2), watcher_rx.recv())
            .await
            .expect("watcher should enqueue GroupRouteChanged")
            .unwrap();
        assert!(matches!(msg, OffloadMessage::GroupRouteChanged));
        process_message_batch(
            &mut state,
            &mut active_mode,
            &weak_disp,
            &mut direct_outbounds,
            [msg],
        )
        .await;
        assert_eq!(direct_outbounds.as_ref(), Some(&expected_direct));
        assert!(state.desired.contains(&ip));
        assert!(state.desired.contains(&stale_direct_ip));

        // Stale Proxy observation arriving AFTER AUTO switched back to DIRECT is promoted to Direct.
        let stale_proxy_ip: IpAddr = "203.0.113.79".parse().unwrap();
        process_message_batch(
            &mut state,
            &mut active_mode,
            &weak_disp,
            &mut direct_outbounds,
            [OffloadMessage::Observe(Observation::Dns(DnsObservation {
                domain: "stale-proxy.example".into(),
                ips: vec![stale_proxy_ip],
                action: RoutingAction::Proxy,
                outbound: Some("AUTO".into()),
                rule_offloadable: true,
            }))],
        )
        .await;
        assert!(state.desired.contains(&stale_proxy_ip));

        // Fresh Proxy observation arriving BEFORE GroupRouteChanged (debounce window) immediately
        // refreshes outbound state and withdraws existing AUTO direct IPs.
        group.select("REJECT").unwrap();
        let fresh_proxy_ip: IpAddr = "203.0.113.80".parse().unwrap();
        process_message_batch(
            &mut state,
            &mut active_mode,
            &weak_disp,
            &mut direct_outbounds,
            [OffloadMessage::Observe(Observation::RouteDomain(
                RouteDomainObservation {
                    domain: "fresh-proxy.example".into(),
                    ip: fresh_proxy_ip,
                    action: RoutingAction::Proxy,
                    outbound: "AUTO".into(),
                    rule_offloadable: true,
                },
            ))],
        )
        .await;
        assert_eq!(direct_outbounds.as_ref(), Some(&direct_only));
        assert!(!state.desired.contains(&ip));
        assert!(!state.desired.contains(&fresh_proxy_ip));

        watch_abort.abort();
        offloader.stop();
        drop(offloader);
        drop(dispatcher);
        yield_now().await;
        assert!(weak_disp.upgrade().is_none());
    }
}
