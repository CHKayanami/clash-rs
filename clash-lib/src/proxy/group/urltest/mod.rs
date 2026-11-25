use crate::proxy::RouteChange;
use super::UdpPolicy;
use std::collections::HashSet;
use super::GroupHandler;
use std::{io, sync::Arc, time::Duration};

use tracing::trace;

use crate::{
    app::remote_content_manager::{
        ProxyManager, providers::proxy_provider::ArcProxyProvider,
    },
    proxy::{
        HandlerCommonOptions, OutboundNode, OutboundType,
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

pub struct Handler {
    opts: HandlerOptions,
    tolerance: u16,

    providers: Providers,
    proxy_manager: ProxyManager,
    /// Name of the proxy the tolerance hysteresis is currently sticky to.
    /// Tracking a list position instead silently retargeted the selection
    /// whenever a provider refresh reordered the members.
    current_fastest: parking_lot::RwLock<Option<String>>,
    selection_changes: RouteChange,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UrlTest")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub(crate) fn select_cached(&self) -> Option<OutboundNode> { self.fastest(false, true) }

    /// Read-only inspection of the current effective proxy without mutating
    /// sticky tolerance state.
    pub(crate) fn peek_selected_from(
        &self,
        proxies: &[OutboundNode],
        urls: &MemberUrls,
    ) -> Option<OutboundNode> {
        self.fastest_in(proxies, urls, false)
    }

    pub(crate) fn providers(&self) -> &Providers {
        &self.providers
    }

    pub(crate) fn route_changes_from(
        &self,
        proxies: &[OutboundNode],
        urls: &MemberUrls,
        sources: &mut Vec<RouteChange>,
    ) {
        sources.push(self.selection_changes.clone());
        self.providers.route_changes(sources);
        let fallback_url = self.opts.common_opts.url.as_deref();
        sources.extend(proxies.iter().enumerate().map(|(index, node)| {
            self.proxy_manager.route_changes_for(
                node,
                urls.url_at(index, fallback_url),
                true,
            )
        }));
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
            current_fastest: parking_lot::RwLock::new(None),
            selection_changes: RouteChange::default(),
        }
    }

    fn get_proxies(&self, touch: bool) -> Arc<Vec<OutboundNode>> {
        self.providers.get_proxies(touch)
    }

    /// Pick the proxy to use.
    ///
    /// `commit` records the outcome as the new sticky choice. Read-only callers
    /// (the API, capability probes) pass `false` — previously every one of them
    /// rewrote the sticky state, so merely polling `/proxies` could change
    /// which proxy the group routed through.
    fn fastest(
        &self,
        touch: bool,
        commit: bool,
    ) -> Option<OutboundNode> {
        let (proxies, urls) = self.providers.get_members(touch);
        self.fastest_in(&proxies, &urls, commit)
    }

    fn fastest_in(
        &self,
        proxies: &[OutboundNode],
        urls: &MemberUrls,
        commit: bool,
    ) -> Option<OutboundNode> {
        if proxies.is_empty() {
            return None;
        }

        let current_name = self.current_fastest.read().clone();
        let fallback_url = self.opts.common_opts.url.as_deref();

        let mut fastest: Option<(usize, Duration)> = None;
        let mut current_alive = false;
        let mut current_delay = Duration::MAX;
        for (index, proxy) in proxies.iter().enumerate() {
            let is_current = current_name.as_deref() == Some(proxy.name());
            let probe_url = urls.url_at(index, fallback_url);
            let (alive, delay) = self
                .proxy_manager
                .alive_and_last_delay_for(proxy, probe_url);
            if is_current {
                current_alive = alive;
            }
            if !alive {
                continue;
            }

            let delay = delay.unwrap_or(Duration::MAX);
            if is_current {
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

        let current_index = current_name
            .as_deref()
            .and_then(|name| proxies.iter().position(|p| p.name() == name));

        let selected_index = match current_index {
            // Stick with the current pick while it is alive and within
            // tolerance of the best.
            Some(index) if current_alive && current_delay <= switch_threshold => {
                index
            }
            _ => fastest_index,
        };

        let selected = &proxies[selected_index];

        if commit {
            let mut current = self.current_fastest.write();
            let next = selected.name();
            if current.as_deref() != Some(next) {
                *current = Some(next.to_owned());
                drop(current);
                self.selection_changes.notify();
            }
        }

        let selected_delay = if selected_index == fastest_index {
            fastest_delay
        } else {
            current_delay
        };

        trace!(
            fastest = %selected.name(),
            delay = ?selected_delay,
            "`{}` fastest",
            self.name(),
        );

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
}
