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
        OutboundNode, HandlerCommonOptions, OutboundType,
        group::GroupProxyAPIResponse,
        utils::provider_helper::Providers,
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
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UrlTest")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        tolerance: u16,
        providers: Vec<ArcProxyProvider>,
        proxy_manager: ProxyManager,
    ) -> Self {
        Self {
            opts,
            tolerance,
            providers: Providers::new(providers),
            proxy_manager,
            current_fastest: parking_lot::RwLock::new(None),
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
        let proxy_manager = self.proxy_manager.clone();

        let proxies = self.get_proxies(touch);
        if proxies.is_empty() {
            return None;
        }

        let current_name = self.current_fastest.read().clone();

        let mut fastest: Option<(usize, Duration)> = None;
        let mut current_alive = false;
        let mut current_delay = Duration::MAX;
        for (index, proxy) in proxies.iter().enumerate() {
            let is_current = current_name.as_deref() == Some(proxy.name());
            let (alive, delay) =
                proxy_manager.alive_and_last_delay(proxy.name());
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
            *self.current_fastest.write() = Some(selected.name().to_owned());
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
}
