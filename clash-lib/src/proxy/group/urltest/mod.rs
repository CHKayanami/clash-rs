use std::{
    collections::HashSet,
    io,
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;

use arc_swap::ArcSwapOption;
use parking_lot::RwLock;
use tracing::trace;

use super::{GroupHandler, UdpPolicy};
use crate::{
    app::remote_content_manager::{
        ProxyHealthHandle, ProxyManager, providers::proxy_provider::ArcProxyProvider,
    },
    proxy::{
        HandlerCommonOptions, OutboundNode, OutboundType, RouteChange,
        group::GroupProxyAPIResponse,
        utils::provider_helper::{MemberUrls, Providers},
    },
    session::Session,
};

#[derive(Default)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
}

struct StickySelection {
    name: Option<String>,
    version: u64,
}

struct CachedSelection {
    health_version: u64,
    sticky_version: u64,
    selected_index: usize,
    committed: bool,
}

struct CachedMemberSnapshot {
    /// Weak ref ensures a stale cache never pins superseded provider snapshots
    /// or retired protocol handlers.
    snapshot: Weak<Vec<OutboundNode>>,
    urls: MemberUrls,
    handles: Vec<ProxyHealthHandle>,
    /// Incremented only when one of `handles` changes its liveness or latest
    /// delay, so probes on unrelated proxies/URLs never invalidate this group.
    member_version: Arc<AtomicU64>,
    selection: ArcSwapOption<CachedSelection>,
}

impl CachedMemberSnapshot {
    fn matches(&self, proxies: &Arc<Vec<OutboundNode>>, urls: &MemberUrls) -> bool {
        self.snapshot
            .upgrade()
            .is_some_and(|snap| Arc::ptr_eq(&snap, proxies))
            && self.urls.ptr_eq(urls)
    }

    fn is_live(&self) -> bool {
        self.snapshot.strong_count() > 0
    }

    fn health_version(&self) -> u64 {
        self.member_version.load(Ordering::SeqCst)
    }
}

pub struct Handler {
    opts: HandlerOptions,
    tolerance: u16,

    providers: Providers,
    proxy_manager: ProxyManager,
    /// Name of the proxy the tolerance hysteresis is currently sticky to.
    /// Tracking a list position instead silently retargeted the selection
    /// whenever a provider refresh reordered the members.
    sticky: RwLock<StickySelection>,
    sticky_version: AtomicU64,
    cached_snapshot: ArcSwapOption<CachedMemberSnapshot>,
    selection_changes: RouteChange,
    #[cfg(test)]
    scan_count: AtomicUsize,
    #[cfg(test)]
    snapshot_builds: AtomicUsize,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UrlTest")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub(crate) fn select_cached(&self) -> Option<OutboundNode> {
        self.fastest(false, true)
    }

    /// Read-only inspection of the current effective proxy without mutating
    /// sticky tolerance state.
    pub(crate) fn peek_selected_from(
        &self,
        proxies: &Arc<Vec<OutboundNode>>,
        urls: &MemberUrls,
    ) -> Option<OutboundNode> {
        self.fastest_in(proxies, urls, false, false)
    }

    pub(crate) fn providers(&self) -> &Providers {
        &self.providers
    }

    pub(crate) fn invalidate_stale_cache(&self) {
        self.providers.invalidate_stale_cache();
        if self
            .cached_snapshot
            .load()
            .as_deref()
            .is_some_and(|cache| !cache.is_live())
        {
            self.cached_snapshot.store(None);
        }
    }

    pub(crate) fn route_changes_from(
        &self,
        proxies: &Arc<Vec<OutboundNode>>,
        urls: &MemberUrls,
        sources: &mut Vec<RouteChange>,
    ) {
        sources.push(self.selection_changes.clone());
        self.providers.route_changes(sources);
        let cache = self.get_or_build_snapshot(proxies, urls, false);
        sources.extend(
            cache
                .handles
                .iter()
                .map(|handle| handle.route_changes(true)),
        );
    }

    pub fn new(
        opts: HandlerOptions,
        tolerance: u16,
        providers: Vec<ArcProxyProvider>,
        proxy_manager: ProxyManager,
    ) -> Self {
        if let Some(url) = opts.common_opts.url.as_deref() {
            proxy_manager.register_probe_url(url);
        }
        Self {
            opts,
            tolerance,
            providers: Providers::new(providers),
            proxy_manager,
            sticky: RwLock::new(StickySelection {
                name: None,
                version: 0,
            }),
            sticky_version: AtomicU64::new(0),
            cached_snapshot: ArcSwapOption::new(None),
            selection_changes: RouteChange::default(),
            #[cfg(test)]
            scan_count: AtomicUsize::new(0),
            #[cfg(test)]
            snapshot_builds: AtomicUsize::new(0),
        }
    }

    fn get_proxies(&self, touch: bool) -> Arc<Vec<OutboundNode>> {
        self.providers.get_proxies(touch)
    }

    fn get_or_build_snapshot(
        &self,
        proxies: &Arc<Vec<OutboundNode>>,
        urls: &MemberUrls,
        allow_replace_live: bool,
    ) -> Arc<CachedMemberSnapshot> {
        if let Some(cached) = self.cached_snapshot.load_full()
            && cached.matches(proxies, urls)
        {
            return cached;
        }

        #[cfg(test)]
        self.snapshot_builds.fetch_add(1, Ordering::Relaxed);

        let fallback_url = self.opts.common_opts.url.as_deref();
        let member_version = Arc::new(AtomicU64::new(0));
        let weak_version = Arc::downgrade(&member_version);
        let handles: Vec<ProxyHealthHandle> = proxies
            .iter()
            .enumerate()
            .map(|(index, proxy)| {
                let handle = self
                    .proxy_manager
                    .health_handle_for(proxy, urls.url_at(index, fallback_url));
                handle.register_version(weak_version.clone());
                handle
            })
            .collect();
        let built = Arc::new(CachedMemberSnapshot {
            snapshot: Arc::downgrade(proxies),
            urls: urls.clone(),
            handles,
            member_version,
            selection: ArcSwapOption::new(None),
        });

        self.cached_snapshot.rcu(|current| {
            if let Some(existing) = current
                && existing.matches(proxies, urls)
            {
                return Some(existing.clone());
            }
            if !allow_replace_live
                && let Some(existing) = current
                && existing.is_live()
            {
                return Some(existing.clone());
            }
            Some(built.clone())
        });

        if let Some(current) = self.cached_snapshot.load_full()
            && current.matches(proxies, urls)
        {
            current
        } else {
            built
        }
    }

    fn evaluate_handles(
        &self,
        proxies: &[OutboundNode],
        handles: &[ProxyHealthHandle],
        current_name: Option<&str>,
    ) -> (usize, Duration) {
        #[cfg(test)]
        self.scan_count.fetch_add(1, Ordering::Relaxed);

        let mut fastest: Option<(usize, Duration)> = None;
        let mut current_index: Option<usize> = None;
        let mut current_alive = false;
        let mut current_delay = Duration::MAX;

        for (index, (proxy, handle)) in proxies.iter().zip(handles).enumerate() {
            let is_current = current_name == Some(proxy.name());
            let (alive, delay) = handle.alive_and_last_delay();
            if is_current && current_index.is_none() {
                current_index = Some(index);
                current_alive = alive;
            }
            if !alive {
                continue;
            }

            let delay = delay.unwrap_or(Duration::MAX);
            if current_index == Some(index) {
                current_delay = delay;
            }
            if match fastest {
                None => true,
                Some((_, fastest_delay)) => delay < fastest_delay,
            } {
                fastest = Some((index, delay));
            }
        }

        // Keep the historical first-proxy fallback when every candidate is
        // unavailable, while never preferring an unavailable proxy when a live
        // candidate exists (even if it has no delay sample yet).
        let (fastest_index, fastest_delay) = fastest.unwrap_or((0, Duration::MAX));
        let tolerance = Duration::from_millis(self.tolerance as u64);
        let switch_threshold = fastest_delay
            .checked_add(tolerance)
            .unwrap_or(Duration::MAX);

        let selected_index = match current_index {
            // Stick with the current pick while it is alive and within
            // tolerance of the best.
            Some(index) if current_alive && current_delay <= switch_threshold => {
                index
            }
            _ => fastest_index,
        };

        let selected_delay = if selected_index == fastest_index {
            fastest_delay
        } else {
            current_delay
        };

        (selected_index, selected_delay)
    }

    /// Pick the proxy to use.
    ///
    /// `commit` records the outcome as the new sticky choice. Read-only callers
    /// (the API, capability probes) pass `false` — previously every one of them
    /// rewrote the sticky state, so merely polling `/proxies` could change
    /// which proxy the group routed through.
    fn fastest(&self, touch: bool, commit: bool) -> Option<OutboundNode> {
        let (proxies, urls) = self.providers.get_members(touch);
        self.fastest_in(&proxies, &urls, commit, true)
    }

    fn fastest_in(
        &self,
        proxies: &Arc<Vec<OutboundNode>>,
        urls: &MemberUrls,
        commit: bool,
        allow_replace_live: bool,
    ) -> Option<OutboundNode> {
        if proxies.is_empty() {
            return None;
        }

        // O(1) lock-free fast path during stable periods.
        let sticky_version = self.sticky_version.load(Ordering::Acquire);
        if let Some(cache) = self.cached_snapshot.load().as_deref()
            && cache.matches(proxies, urls)
            && let Some(sel) = cache.selection.load().as_deref()
            && sel.health_version == cache.health_version()
            && sel.sticky_version == sticky_version
            && (!commit || sel.committed)
        {
            return Some(proxies[sel.selected_index].clone());
        }

        let cache = self.get_or_build_snapshot(proxies, urls, allow_replace_live);

        if !commit {
            let health_version = cache.health_version();
            let (current_name, sticky_version) = {
                let sticky = self.sticky.read();
                (sticky.name.clone(), sticky.version)
            };
            if let Some(sel) = cache.selection.load().as_deref()
                && sel.health_version == health_version
                && sel.sticky_version == sticky_version
            {
                return Some(proxies[sel.selected_index].clone());
            }

            let (selected_index, selected_delay) = self.evaluate_handles(
                proxies,
                &cache.handles,
                current_name.as_deref(),
            );
            let selected = &proxies[selected_index];
            let committed = current_name.as_deref() == Some(selected.name());

            let next = Arc::new(CachedSelection {
                health_version,
                sticky_version,
                selected_index,
                committed,
            });
            cache.selection.rcu(|current| {
                if let Some(existing) = current
                    && ((existing.sticky_version, existing.health_version)
                        > (sticky_version, health_version)
                        || (existing.sticky_version == sticky_version
                            && existing.health_version == health_version
                            && existing.committed))
                {
                    return Some(existing.clone());
                }
                Some(next.clone())
            });

            trace!(
                fastest = %selected.name(),
                delay = ?selected_delay,
                "`{}` fastest",
                self.name(),
            );

            return Some(selected.clone());
        }

        let mut sticky = self.sticky.write();
        let health_version = cache.health_version();
        let cached_for_version = cache.selection.load().as_deref().and_then(|sel| {
            if sel.health_version == health_version
                && sel.sticky_version == sticky.version
            {
                Some((sel.selected_index, sel.committed))
            } else {
                None
            }
        });

        if let Some((selected_index, true)) = cached_for_version {
            drop(sticky);
            return Some(proxies[selected_index].clone());
        }

        let (selected_index, evaluated_delay) = match cached_for_version {
            Some((idx, false)) => (idx, None),
            _ => {
                let (idx, delay) = self.evaluate_handles(
                    proxies,
                    &cache.handles,
                    sticky.name.as_deref(),
                );
                (idx, Some(delay))
            }
        };

        let selected = &proxies[selected_index];
        let mut selection_changed = false;
        if sticky.name.as_deref() != Some(selected.name()) {
            sticky.name = Some(selected.name().to_owned());
            sticky.version += 1;
            selection_changed = true;
        }

        let next_version = sticky.version;
        cache.selection.store(Some(Arc::new(CachedSelection {
            health_version,
            sticky_version: next_version,
            selected_index,
            committed: true,
        })));
        if selection_changed {
            self.sticky_version.store(next_version, Ordering::Release);
        }
        drop(sticky);

        if selection_changed {
            self.selection_changes.notify();
        }

        if let Some(selected_delay) = evaluated_delay {
            trace!(
                fastest = %selected.name(),
                delay = ?selected_delay,
                "`{}` fastest",
                self.name(),
            );
        }

        Some(selected.clone())
    }
}

impl GroupHandler for Handler {
    fn route_changes(&self, sources: &mut Vec<RouteChange>) {
        let (proxies, urls) = self.providers.get_members(false);
        self.route_changes_from(&proxies, &urls, sources);
    }

    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::UrlTest
    }

    fn udp_policy(&self) -> UdpPolicy {
        if self.opts.udp { UdpPolicy::Enabled } else { UdpPolicy::Selected }
    }

    async fn select(
        &self,
        sess: &Session,
        excluded: &HashSet<String>,
    ) -> io::Result<Option<OutboundNode>> {
        let _ = (sess, excluded);
        Ok(self.fastest(true, true))
    }
}

impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<OutboundNode> {
        Handler::get_proxies(self, false).to_vec()
    }

    async fn get_active_proxy(&self) -> Option<OutboundNode> {
        self.fastest(false, false)
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use crate::{
        app::remote_content_manager::ProxyManager,
        proxy::{
            OutboundNode,
            group::GroupProxyAPIResponse,
            mocks::MockDummyProxyProvider,
            utils::test_utils::noop::{NoopOutboundHandler, NoopResolver},
        },
    };

    #[tokio::test]
    async fn test_empty_provider_returns_none_active_proxy() {
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_name().return_const("provider1".to_owned());
        provider.expect_proxies().returning(|| Arc::new(Vec::new()));

        let proxy_manager = ProxyManager::new(Arc::new(NoopResolver), None);
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "test".to_owned(),
                udp: true,
                ..Default::default()
            },
            0,
            vec![Arc::new(provider)],
            proxy_manager,
        );

        assert!(handler.get_active_proxy().await.is_none());
    }

    #[tokio::test]
    async fn test_tolerance_and_liveness_select_proxy() {
        let proxies: Vec<OutboundNode> = vec![
            OutboundNode::protocol(Arc::new(NoopOutboundHandler { name: "a".into() })),
            OutboundNode::protocol(Arc::new(NoopOutboundHandler { name: "b".into() })),
        ];
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning({
            let proxies = proxies.clone();
            move || Arc::new(proxies.clone())
        });

        let proxy_manager = ProxyManager::new(Arc::new(NoopResolver), None);
        proxy_manager
            .report_delay("a", true, Duration::from_millis(100))
            .await;
        proxy_manager
            .report_delay("b", true, Duration::from_millis(50))
            .await;
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "url-test".to_owned(),
                ..Default::default()
            },
            20,
            vec![Arc::new(provider)],
            proxy_manager.clone(),
        );

        assert_eq!(handler.fastest(false, true).unwrap().name(), "b");

        proxy_manager
            .report_delay("a", true, Duration::from_millis(40))
            .await;
        assert_eq!(handler.fastest(false, true).unwrap().name(), "b");

        proxy_manager
            .report_delay("a", true, Duration::from_millis(20))
            .await;
        assert_eq!(handler.fastest(false, true).unwrap().name(), "a");

        proxy_manager
            .report_delay("a", false, Duration::from_millis(20))
            .await;
        assert_eq!(handler.fastest(false, true).unwrap().name(), "b");

        proxy_manager
            .report_delay("b", false, Duration::from_millis(50))
            .await;
        assert_eq!(handler.fastest(false, true).unwrap().name(), "a");
    }

    #[tokio::test]
    async fn same_named_nodes_and_distinct_urls_do_not_cross_contaminate_selection() {
        use crate::{
            app::remote_content_manager::{
                healthcheck::HealthCheck,
                providers::proxy_provider::PlainProvider,
            },
            proxy::{
                AnyStream,
                group::fallback,
                mocks::MockDummyOutboundHandler,
            },
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

        let make_http_node = |name: &str, ok_for_host: Option<&'static str>, delay_ms: u64| {
            let mut mock = MockDummyOutboundHandler::new();
            mock.expect_name().return_const(name.to_owned());
            mock.expect_connect_stream().returning(move |sess, _| {
                let host = sess.destination.host();
                let should_succeed = ok_for_host.is_some_and(|ok| host == ok);
                if !should_succeed {
                    return Err(std::io::Error::other("probe rejected"));
                }
                let (client, mut server) = duplex(1024);
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = server.read(&mut buf).await;
                    if delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                    let _ = server
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = server.shutdown().await;
                });
                Ok(AnyStream::new(client))
            });
            OutboundNode::protocol(Arc::new(mock))
        };

        let pm = ProxyManager::new(Arc::new(NoopResolver), None);

        // Scenario 1: Two distinct providers each contain a node named "HK-1".
        // Provider A's "HK-1" is healthy (fast); Provider B's "HK-1" fails.
        let hk_good = make_http_node("HK-1", Some("probe-a.example"), 5);
        let backup_a = make_http_node("BACKUP-A", Some("probe-a.example"), 60);
        let hk_bad = make_http_node("HK-1", None, 0);
        let backup_b = make_http_node("BACKUP-B", Some("probe-a.example"), 5);

        let url_a = "http://probe-a.example/generate_204";
        let prov_a = Arc::new(
            PlainProvider::new(
                "prov-a".to_owned(),
                vec![hk_good.clone(), backup_a.clone()],
                HealthCheck::new(
                    vec![hk_good.clone(), backup_a.clone()],
                    url_a.to_owned(),
                    0,
                    true,
                    pm.clone(),
                ),
            )
            .unwrap(),
        );
        let prov_b = Arc::new(
            PlainProvider::new(
                "prov-b".to_owned(),
                vec![hk_bad.clone(), backup_b.clone()],
                HealthCheck::new(
                    vec![hk_bad.clone(), backup_b.clone()],
                    url_a.to_owned(),
                    0,
                    true,
                    pm.clone(),
                ),
            )
            .unwrap(),
        );

        let group_a = super::Handler::new(
            super::HandlerOptions {
                name: "GROUP-A".to_owned(),
                ..Default::default()
            },
            0,
            vec![prov_a.clone()],
            pm.clone(),
        );
        let group_b = fallback::Handler::new(
            fallback::HandlerOptions {
                name: "GROUP-B".to_owned(),
                ..Default::default()
            },
            vec![prov_b.clone()],
            pm.clone(),
        );

        // Probe healthy prov_a first, then failing prov_b (same node name "HK-1").
        pm.check(&vec![hk_good.clone(), backup_a.clone()], url_a, Some(Duration::from_secs(2)))
            .await;
        pm.check(&vec![hk_bad.clone(), backup_b.clone()], url_a, Some(Duration::from_secs(2)))
            .await;

        assert_eq!(
            group_a.get_active_proxy().await.unwrap().identity(),
            hk_good.identity(),
            "failing same-named node from another provider must not mark healthy instance dead"
        );
        assert_eq!(
            group_b.get_active_proxy().await.unwrap().identity(),
            backup_b.identity(),
            "group B must fall back away from its own dead HK-1 instance"
        );

        // Scenario 2: Same node instance probed on two distinct URLs.
        // Succeeds on url_b, fails on url_fail.
        let shared = make_http_node("SHARED", Some("probe-b.example"), 5);
        let slow_other = make_http_node("OTHER", Some("probe-b.example"), 60);
        let url_b = "http://probe-b.example/generate_204";
        let url_fail = "http://probe-fail.example/generate_204";

        let prov_url_b = Arc::new(
            PlainProvider::new(
                "prov-url-b".to_owned(),
                vec![shared.clone(), slow_other.clone()],
                HealthCheck::new(
                    vec![shared.clone(), slow_other.clone()],
                    url_b.to_owned(),
                    0,
                    true,
                    pm.clone(),
                ),
            )
            .unwrap(),
        );
        let prov_url_fail = Arc::new(
            PlainProvider::new(
                "prov-url-fail".to_owned(),
                vec![shared.clone(), backup_b.clone()],
                HealthCheck::new(
                    vec![shared.clone(), backup_b.clone()],
                    url_fail.to_owned(),
                    0,
                    true,
                    pm.clone(),
                ),
            )
            .unwrap(),
        );

        let group_url_b = super::Handler::new(
            super::HandlerOptions {
                name: "GROUP-URL-B".to_owned(),
                ..Default::default()
            },
            0,
            vec![prov_url_b],
            pm.clone(),
        );
        let group_url_fail = fallback::Handler::new(
            fallback::HandlerOptions {
                name: "GROUP-URL-FAIL".to_owned(),
                ..Default::default()
            },
            vec![prov_url_fail],
            pm.clone(),
        );

        pm.check(&vec![shared.clone(), slow_other.clone()], url_b, Some(Duration::from_secs(2)))
            .await;
        pm.check(&vec![shared.clone()], url_fail, Some(Duration::from_secs(2)))
            .await;

        assert_eq!(
            group_url_b.get_active_proxy().await.unwrap().identity(),
            shared.identity(),
            "failure on another probe URL must not contaminate url_b selection"
        );
        assert_eq!(
            group_url_fail.get_active_proxy().await.unwrap().identity(),
            backup_b.identity(),
            "group probing url_fail must observe shared node as failed"
        );
    }

    #[tokio::test]
    async fn cached_selection_avoids_rescan_and_preserves_order_tolerance_and_readonly() {
        use std::sync::atomic::Ordering;
        use arc_swap::ArcSwap;
        use crate::proxy::utils::provider_helper::MemberUrls;

        let make_node = |name: &str| -> OutboundNode {
            OutboundNode::protocol(Arc::new(NoopOutboundHandler {
                name: name.to_owned(),
            }))
        };

        let a = make_node("a");
        let b = make_node("b");
        let c = make_node("c");
        let a_weak = a.downgrade();
        let slot = Arc::new(ArcSwap::from_pointee(vec![a.clone(), b.clone(), c.clone()]));

        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning({
            let slot = slot.clone();
            move || slot.load_full()
        });

        let pm = ProxyManager::new(Arc::new(NoopResolver), None);
        // Equal delay on a and b: member order must keep earlier member `a`.
        pm.report_delay("a", true, Duration::from_millis(50)).await;
        pm.report_delay("b", true, Duration::from_millis(50)).await;
        pm.report_delay("c", true, Duration::from_millis(120)).await;

        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "url-test-cache".to_owned(),
                ..Default::default()
            },
            20,
            vec![Arc::new(provider)],
            pm.clone(),
        );

        // Read-only queries scan once, reuse cache on repeat, and do NOT commit sticky state.
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");
        assert_eq!(handler.scan_count.load(Ordering::Relaxed), 1);
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");
        assert_eq!(
            handler
                .peek_selected_from(&slot.load_full(), &MemberUrls::Uniform(None))
                .unwrap()
                .name(),
            "a"
        );
        assert_eq!(handler.scan_count.load(Ordering::Relaxed), 1);
        assert!(handler.sticky.read().name.is_none());

        // Making `b` 40ms (within 20ms tolerance of 50ms) still switches to `b`
        // because read-only queries never committed `a`.
        pm.report_delay("b", true, Duration::from_millis(40)).await;
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");
        assert_eq!(handler.scan_count.load(Ordering::Relaxed), 2);
        assert!(handler.sticky.read().name.is_none());

        // Committing at the SAME health_version commits `b` without even rescanning.
        assert_eq!(handler.select_cached().unwrap().name(), "b");
        assert_eq!(handler.scan_count.load(Ordering::Relaxed), 2);
        assert_eq!(handler.sticky.read().name.as_deref(), Some("b"));

        // Repeated committed & read-only selections during stable period are O(1) (0 rescans).
        for _ in 0..8 {
            assert_eq!(handler.select_cached().unwrap().name(), "b");
            assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");
        }
        assert_eq!(handler.scan_count.load(Ordering::Relaxed), 2);

        // `a` improves to 25ms (within 20ms tolerance of b's 40ms): sticky stays on `b`.
        pm.report_delay("a", true, Duration::from_millis(25)).await;
        assert_eq!(handler.select_cached().unwrap().name(), "b");
        assert_eq!(handler.scan_count.load(Ordering::Relaxed), 3);
        assert_eq!(handler.select_cached().unwrap().name(), "b");
        assert_eq!(handler.scan_count.load(Ordering::Relaxed), 3);

        // `a` improves to 10ms (outside tolerance): switches to `a` and caches it.
        pm.report_delay("a", true, Duration::from_millis(10)).await;
        assert_eq!(handler.select_cached().unwrap().name(), "a");
        assert_eq!(handler.scan_count.load(Ordering::Relaxed), 4);
        assert_eq!(handler.select_cached().unwrap().name(), "a");
        assert_eq!(handler.scan_count.load(Ordering::Relaxed), 4);

        // Snapshot refresh must not pin superseded snapshot/handlers.
        drop((a, b, c));
        let fresh = make_node("fresh");
        slot.store(Arc::new(vec![fresh]));
        handler.invalidate_stale_cache();
        assert!(
            a_weak.upgrade().is_none(),
            "url-test snapshot cache must not pin retired handlers"
        );
        assert_eq!(handler.select_cached().unwrap().name(), "fresh");
        assert_eq!(handler.scan_count.load(Ordering::Relaxed), 5);
        assert_eq!(handler.select_cached().unwrap().name(), "fresh");
        assert_eq!(handler.scan_count.load(Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn unrelated_probes_do_not_invalidate_urltest_cache() {
        use std::sync::atomic::Ordering;
        use crate::{
            app::remote_content_manager::{
                healthcheck::HealthCheck,
                providers::proxy_provider::PlainProvider,
            },
            proxy::{AnyStream, mocks::MockDummyOutboundHandler},
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

        let make_http_node = |name: &str, delay_ms: u64| {
            let mut mock = MockDummyOutboundHandler::new();
            mock.expect_name().return_const(name.to_owned());
            mock.expect_connect_stream().returning(move |_, _| {
                let (client, mut server) = duplex(1024);
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = server.read(&mut buf).await;
                    if delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                    let _ = server
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = server.shutdown().await;
                });
                Ok(AnyStream::new(client))
            });
            OutboundNode::protocol(Arc::new(mock))
        };

        let pm = ProxyManager::new(Arc::new(NoopResolver), None);
        let a = make_http_node("a", 5);
        let b = make_http_node("b", 40);
        let other = make_http_node("other", 5);

        let url_a = "http://group-a.example/generate_204";
        let url_b = "http://group-b.example/generate_204";
        let url_adhoc = "http://adhoc.example/generate_204";

        let prov_a = Arc::new(
            PlainProvider::new(
                "prov-a".to_owned(),
                vec![a.clone(), b.clone()],
                HealthCheck::new(
                    vec![a.clone(), b.clone()],
                    url_a.to_owned(),
                    0,
                    true,
                    pm.clone(),
                ),
            )
            .unwrap(),
        );
        let group_a = super::Handler::new(
            super::HandlerOptions {
                name: "GROUP-A".to_owned(),
                ..Default::default()
            },
            0,
            vec![prov_a],
            pm.clone(),
        );

        pm.check(&vec![a.clone(), b.clone()], url_a, Some(Duration::from_secs(2)))
            .await;
        assert_eq!(group_a.select_cached().unwrap().name(), "a");
        assert_eq!(group_a.scan_count.load(Ordering::Relaxed), 1);

        // Unrelated name-based delay report, unrelated node probe on another URL,
        // and even probing `a` on a different ad-hoc URL must NOT invalidate group_a.
        pm.report_delay("unrelated", true, Duration::from_millis(10))
            .await;
        pm.check(&vec![other], url_b, Some(Duration::from_secs(2)))
            .await;
        pm.check(&vec![a.clone()], url_adhoc, Some(Duration::from_secs(2)))
            .await;

        assert_eq!(group_a.select_cached().unwrap().name(), "a");
        assert_eq!(group_a.get_active_proxy().await.unwrap().name(), "a");
        assert_eq!(
            group_a.scan_count.load(Ordering::Relaxed),
            1,
            "unrelated probes must not invalidate url-test cached selection"
        );

        // A real update on (a, url_a) MUST invalidate group_a and rescan once.
        let _ = pm
            .check(&vec![b.clone()], url_a, Some(Duration::from_secs(2)))
            .await;
        // Wait: b's delay may differ from its previous sample; force a definite
        // state transition on (a, url_a) via a failing probe or delay change.
        let mut failing = MockDummyOutboundHandler::new();
        failing.expect_name().return_const("fail-check".to_owned());
        let fail_node = OutboundNode::protocol(Arc::new(failing));
        let prov_no_url = Arc::new(
            PlainProvider::new(
                "prov-no-url".to_owned(),
                vec![fail_node.clone()],
                HealthCheck::new(
                    vec![fail_node.clone()],
                    String::new(),
                    0,
                    true,
                    pm.clone(),
                ),
            )
            .unwrap(),
        );
        let group_no_url = super::Handler::new(
            super::HandlerOptions {
                name: "GROUP-NO-URL".to_owned(),
                ..Default::default()
            },
            0,
            vec![prov_no_url],
            pm.clone(),
        );
        assert_eq!(group_no_url.select_cached().unwrap().name(), "fail-check");
        assert_eq!(group_no_url.scan_count.load(Ordering::Relaxed), 1);
        pm.report_delay("unrelated-2", true, Duration::from_millis(15))
            .await;
        assert_eq!(group_no_url.select_cached().unwrap().name(), "fail-check");
        assert_eq!(
            group_no_url.scan_count.load(Ordering::Relaxed),
            1,
            "unrelated name-based report must not invalidate no-URL url-test group"
        );
        pm.report_delay("fail-check", true, Duration::from_millis(25))
            .await;
        assert_eq!(group_no_url.select_cached().unwrap().name(), "fail-check");
        assert_eq!(group_no_url.scan_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn multi_provider_refresh_shares_snapshot_and_handles_between_tracker_and_traffic() {
        use std::{collections::HashMap, sync::atomic::Ordering};
        use arc_swap::ArcSwap;
        use fancy_regex::Regex;
        use crate::app::remote_content_manager::providers::proxy_provider::{
            ArcProxyProvider, FilteredProxyProvider, provider_identity,
        };

        let make_node = |name: &str| {
            OutboundNode::protocol(Arc::new(NoopOutboundHandler {
                name: name.to_owned(),
            }))
        };

        let slot1 = Arc::new(ArcSwap::from_pointee(vec![make_node("HK-1")]));
        let slot2 = Arc::new(ArcSwap::from_pointee(vec![make_node("US-1")]));

        let mut p1_mock = MockDummyProxyProvider::new();
        p1_mock.expect_proxies().returning({
            let slot1 = slot1.clone();
            move || slot1.load_full()
        });
        p1_mock.expect_route_changes().returning(|| None);
        let p1: ArcProxyProvider = Arc::new(p1_mock);

        let mut p2_mock = MockDummyProxyProvider::new();
        p2_mock.expect_proxies().returning({
            let slot2 = slot2.clone();
            move || slot2.load_full()
        });
        p2_mock.expect_route_changes().returning(|| None);
        let p2: ArcProxyProvider = Arc::new(p2_mock);

        let filtered_p1: ArcProxyProvider = Arc::new(FilteredProxyProvider::new(
            p1.clone(),
            Arc::new(Regex::new(r"^HK-").unwrap()),
            None,
        ));

        let pm = ProxyManager::new(Arc::new(NoopResolver), None);
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "MULTI".to_owned(),
                ..Default::default()
            },
            0,
            vec![filtered_p1, p2.clone()],
            pm.clone(),
        );

        // Simulate provider refresh + tracker running rebuild_topology BEFORE traffic.
        slot1.store(Arc::new(vec![make_node("HK-2"), make_node("SG-skip")]));
        handler.invalidate_stale_cache();

        let mut provider_snaps = HashMap::new();
        provider_snaps.insert(provider_identity(&p1), p1.proxies());
        provider_snaps.insert(provider_identity(&p2), p2.proxies());

        let inputs = handler.providers().input_snapshots_from(&provider_snaps);
        let (tracker_members, tracker_urls) =
            handler.providers().get_members_from_input_snapshots(&inputs);
        let mut sources = Vec::new();
        handler.route_changes_from(&tracker_members, &tracker_urls, &mut sources);
        let _ = handler.peek_selected_from(&tracker_members, &tracker_urls);
        assert_eq!(handler.snapshot_builds.load(Ordering::Relaxed), 1);

        // Traffic now resolves live members and calls select_cached(): must reuse
        // the exact same merged Arc and cached handles built by the tracker.
        let (traffic_members, _) = handler.providers().get_members(false);
        assert!(
            Arc::ptr_eq(&tracker_members, &traffic_members),
            "tracker and traffic must share the same merged snapshot Arc after refresh"
        );
        let _ = handler.select_cached();
        assert_eq!(handler.snapshot_builds.load(Ordering::Relaxed), 1);

        // Subsequent health updates + tracker peek_selected_from must NOT rebuild handles.
        pm.report_delay("HK-2", true, Duration::from_millis(15)).await;
        let _ = handler.peek_selected_from(&tracker_members, &tracker_urls);
        let _ = handler.select_cached();
        assert_eq!(
            handler.snapshot_builds.load(Ordering::Relaxed),
            1,
            "tracker incremental recomputation must reuse cached handles without rebuilding"
        );
    }
}
