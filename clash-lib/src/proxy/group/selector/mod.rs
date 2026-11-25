use crate::proxy::RouteChange;

use super::UdpPolicy;
use std::collections::HashSet;
use super::GroupHandler;
use std::{
    io,
    sync::{Arc, Weak},
};

use arc_swap::ArcSwapOption;
use tracing::warn;

use crate::{
    Error,
    app::remote_content_manager::providers::proxy_provider::ArcProxyProvider,
    proxy::{
        HandlerCommonOptions, OutboundNode, OutboundType, WeakOutboundNode,
        group::GroupProxyAPIResponse,
        utils::provider_helper::Providers,
    },
    session::Session,
};

pub trait SelectorControl {
    fn select(&self, name: &str) -> Result<(), Error>;
    #[cfg(test)]
    fn current(&self) -> String;
}

pub type ThreadSafeSelectorControl = Arc<dyn SelectorControl + Send + Sync>;

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
}

struct ActiveSelection {
    name: String,
    /// Weak references ensure a stale selector cache never pins a replaced
    /// provider snapshot or prevents retired protocol handlers from dropping.
    snapshot: Weak<Vec<OutboundNode>>,
    handler: WeakOutboundNode,
}

#[derive(Clone)]
pub struct Handler {
    opts: HandlerOptions,
    providers: Providers,
    cached_active: Arc<ArcSwapOption<ActiveSelection>>,
    changes: RouteChange,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Selector")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub(crate) fn select_cached(&self) -> Option<OutboundNode> { self.selected_proxy(false) }

    /// Read-only inspection of the currently selected proxy without rewriting
    /// the cached snapshot entry.
    pub(crate) fn peek_selected_from(
        &self,
        proxies: &[OutboundNode],
    ) -> Option<OutboundNode> {
        let cached_guard = self.cached_active.load();
        if let Some(active) = cached_guard.as_deref() {
            if let Some(proxy) = proxies.iter().find(|p| p.name() == active.name) {
                return Some(proxy.clone());
            }
        }
        proxies.first().cloned()
    }

    pub(crate) fn providers(&self) -> &Providers {
        &self.providers
    }

    pub async fn new(
        opts: HandlerOptions,
        providers: Vec<ArcProxyProvider>,
        selected: Option<String>,
    ) -> Self {
        // Resolve against every provider, the same set `selected_proxy` reads.
        // Consulting only `providers.first()` restored the wrong proxy for a
        // group backed by more than one provider.
        let providers = Providers::new(providers);
        let proxies = providers.get_proxies(false);
        let current_selected = selected
            .filter(|s| proxies.iter().any(|p| p.name() == s))
            .or_else(|| proxies.first().map(|p| p.name().to_owned()));

        let cached_active = current_selected.as_ref().and_then(|name| {
            proxies
                .iter()
                .find(|p| p.name() == name)
                .map(|p| Arc::new(ActiveSelection {
                    name: name.clone(),
                    snapshot: Arc::downgrade(&proxies),
                    handler: p.downgrade(),
                }))
        });

        Self {
            opts,
            providers,
            cached_active: Arc::new(ArcSwapOption::new(cached_active)),
            changes: RouteChange::default(),
        }
    }

    fn selected_proxy(&self, touch: bool) -> Option<OutboundNode> {
        let proxies = self.providers.get_proxies(touch);
        let cached_guard = self.cached_active.load();

        // Fast path: if the cached selection is valid and the provider snapshot
        // pointer has not changed, return the cached handler directly in O(1).
        if let Some(active) = cached_guard.as_deref()
            && active
                .snapshot
                .upgrade()
                .is_some_and(|snap| Arc::ptr_eq(&snap, &proxies))
            && let Some(handler) = active.handler.upgrade()
        {
            return Some(handler);
        }

        // Slow path: resolve selection from current proxies list (e.g. subscription refreshed)
        let found_proxy = if let Some(active) = cached_guard.as_deref() {
            if let Some(proxy) = proxies.iter().find(|p| p.name() == active.name) {
                Some(proxy.clone())
            } else {
                // The provider no longer offers it — say which one went missing
                // rather than the `<unknown>` the old lookup could only ever print.
                warn!(
                    "`{}` selected proxy `{}` not found, falling back to the first \
                     member",
                    self.name(),
                    active.name
                );
                proxies.first().cloned()
            }
        } else {
            proxies.first().cloned()
        };

        if let Some(ref proxy) = found_proxy {
            self.cached_active.store(Some(Arc::new(ActiveSelection {
                name: proxy.name().to_string(),
                snapshot: Arc::downgrade(&proxies),
                handler: proxy.downgrade(),
            })));
        }

        found_proxy
    }
}

impl SelectorControl for Handler {
    fn select(&self, name: &str) -> Result<(), Error> {
        let proxies = self.providers.get_proxies(false);
        if let Some(proxy) = proxies.iter().find(|x| x.name() == name) {
            self.cached_active.store(Some(Arc::new(ActiveSelection {
                name: name.to_owned(),
                snapshot: Arc::downgrade(&proxies),
                handler: proxy.downgrade(),
            })));
            self.changes.notify();
            Ok(())
        } else {
            Err(Error::Operation(format!("proxy {name} not found")))
        }
    }

    #[cfg(test)]
    fn current(&self) -> String {
        self.selected_proxy(false)
            .map(|p| p.name().to_owned())
            .unwrap_or_else(|| "<none>".to_owned())
    }
}

impl GroupHandler for Handler {
    fn route_changes(&self, sources: &mut Vec<RouteChange>) {
        self.providers.route_changes(sources);
        sources.push(self.changes.clone());
    }

    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Selector
    }

    fn udp_policy(&self) -> UdpPolicy {
        if self.opts.udp { UdpPolicy::Selected } else { UdpPolicy::Disabled }
    }

    async fn select(
        &self,
        sess: &Session,
        excluded: &HashSet<String>,
    ) -> io::Result<Option<OutboundNode>> {
        let _ = (sess, excluded);
        Ok(self.selected_proxy(true))
    }
}

impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<OutboundNode> {
        self.providers.get_proxies(false).to_vec()
    }

    async fn get_active_proxy(&self) -> Option<OutboundNode> {
        Handler::selected_proxy(self, false)
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
    use std::sync::Arc;

    use crate::proxy::{
        OutboundNode, group::selector::ThreadSafeSelectorControl,
        mocks::{MockDummyOutboundHandler, MockDummyProxyProvider},
    };

    #[tokio::test]
    async fn test_selector_control() {
        let mut mock_provider = MockDummyProxyProvider::new();
        mock_provider
            .expect_name()
            .return_const("provider1".to_owned());

        mock_provider.expect_proxies().returning(|| {
            let mut proxy1 = MockDummyOutboundHandler::new();
            proxy1.expect_name().return_const("provider1".to_owned());
            let mut proxy2 = MockDummyOutboundHandler::new();
            proxy2.expect_name().return_const("provider2".to_owned());
            Arc::new(vec![OutboundNode::protocol(Arc::new(proxy1)), OutboundNode::protocol(Arc::new(proxy2))])
        });

        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "test".to_owned(),
                udp: false,
                ..Default::default()
            },
            vec![Arc::new(mock_provider)],
            None,
        )
        .await;

        let selector_control =
            Arc::new(handler.clone()) as ThreadSafeSelectorControl;
        let outbound_handler = Arc::new(handler);

        assert_eq!(selector_control.current(), "provider1".to_owned());
        assert_eq!(
            outbound_handler.selected_proxy(false).unwrap().name(),
            "provider1".to_owned()
        );

        selector_control.select("provider2").unwrap();

        assert_eq!(selector_control.current(), "provider2".to_owned());
        assert_eq!(
            outbound_handler.selected_proxy(false).unwrap().name(),
            "provider2".to_owned()
        );

        let fail = selector_control.select("provider3");
        assert!(fail.is_err());
    }

    #[tokio::test]
    async fn test_selector_empty_provider() {
        let mut mock_provider = MockDummyProxyProvider::new();
        mock_provider
            .expect_name()
            .return_const("provider1".to_owned());
        mock_provider.expect_proxies().returning(|| Arc::new(Vec::new()));

        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "test-empty".to_owned(),
                udp: true,
                ..Default::default()
            },
            vec![Arc::new(mock_provider)],
            None,
        )
        .await;

        let selector_control =
            Arc::new(handler.clone()) as ThreadSafeSelectorControl;

        assert_eq!(selector_control.current(), "<none>".to_owned());
        assert!(handler.selected_proxy(false).is_none());
        assert!(selector_control.select("provider1").is_err());
    }

    #[tokio::test]
    async fn selector_weak_cache_does_not_pin_replaced_provider_snapshot() {
        use arc_swap::ArcSwap;

        let make_node = |name: &str| {
            let mut mock = MockDummyOutboundHandler::new();
            mock.expect_name().return_const(name.to_owned());
            OutboundNode::protocol(Arc::new(mock))
        };

        let old_node = make_node("hk-1");
        let old_weak = old_node.downgrade();
        let slot = Arc::new(ArcSwap::from_pointee(vec![old_node]));

        let mut p1 = MockDummyProxyProvider::new();
        p1.expect_proxies().returning({
            let slot = slot.clone();
            move || slot.load_full()
        });

        let static_node = make_node("static-1");
        let static_snap = Arc::new(vec![static_node]);
        let mut p2 = MockDummyProxyProvider::new();
        p2.expect_proxies().returning({
            let static_snap = static_snap.clone();
            move || static_snap.clone()
        });

        // Multi-provider selector (like GLOBAL) exercises both ActiveSelection
        // and Providers::cached_merged.
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "GLOBAL".to_owned(),
                ..Default::default()
            },
            vec![Arc::new(p1), Arc::new(p2)],
            Some("hk-1".to_owned()),
        )
        .await;

        assert!(old_weak.upgrade().is_some());

        // Replace provider snapshot; even without calling selected_proxy again,
        // invalidating stale merged cache must drop the old handler immediately.
        let new_node = make_node("hk-1");
        let new_id = new_node.identity();
        slot.store(Arc::new(vec![new_node]));
        handler.providers().invalidate_stale_cache();

        assert!(
            old_weak.upgrade().is_none(),
            "weak selector cache and invalidated merged cache must not pin replaced handler"
        );

        let members = handler.providers().get_proxies(false);
        let peeked = handler.peek_selected_from(&members).unwrap();
        assert_eq!(peeked.identity(), new_id);
    }
}
