use crate::proxy::RouteChange;

use super::UdpPolicy;
use std::collections::HashSet;
use super::GroupHandler;
use std::{
    io, ptr,
    sync::{Arc, Weak},
};

use arc_swap::{ArcSwapOption, Guard};
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

    fn try_commit_selection(
        &self,
        expected: &Guard<Option<Arc<ActiveSelection>>>,
        proxies: &Arc<Vec<OutboundNode>>,
        proxy: &OutboundNode,
    ) -> bool {
        let next = Arc::new(ActiveSelection {
            name: proxy.name().to_string(),
            snapshot: Arc::downgrade(proxies),
            handler: proxy.downgrade(),
        });
        let prev = self.cached_active.compare_and_swap(expected, Some(next));
        match (prev.as_deref(), expected.as_deref()) {
            (Some(a), Some(b)) => ptr::eq(a, b),
            (None, None) => true,
            _ => false,
        }
    }

    fn selected_proxy(&self, touch: bool) -> Option<OutboundNode> {
        if touch {
            self.providers.touch();
        }
        loop {
            // Read selection state BEFORE the member snapshot so a reader
            // holding an older member snapshot also holds a pre-switch guard;
            // any concurrent manual `select()` on a newer snapshot will then
            // cause our CAS to fail instead of overwriting the new selection.
            let cached_guard = self.cached_active.load();
            let proxies = self.providers.get_proxies(false);

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

            let prev_name = cached_guard.as_deref().map(|active| active.name.as_str());

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

            let Some(proxy) = found_proxy else {
                return None;
            };

            if self.try_commit_selection(&cached_guard, &proxies, &proxy) {
                if prev_name.is_some_and(|name| name != proxy.name()) {
                    self.changes.notify();
                }
                return Some(proxy);
            }
            // A concurrent writer (such as a manual `select()` call) updated
            // `cached_active` while we resolved the snapshot. Retry from the
            // top (re-reading `cached_active` before `proxies`) so stale reads
            // can never overwrite a newer selection.
        }
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stale_refresh_read_does_not_overwrite_concurrent_manual_select() {
        use arc_swap::ArcSwap;
        use tokio::sync::Barrier;
        use crate::proxy::group::selector::SelectorControl;

        let make_plain = |name: &str| {
            let mut mock = MockDummyOutboundHandler::new();
            mock.expect_name().return_const(name.to_owned());
            OutboundNode::protocol(Arc::new(mock))
        };

        let slot = Arc::new(ArcSwap::from_pointee(vec![
            make_plain("node-a"),
            make_plain("node-b"),
        ]));
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning({
            let slot = slot.clone();
            move || slot.load_full()
        });

        let handler = Arc::new(
            super::Handler::new(
                super::HandlerOptions {
                    name: "PROXY".to_owned(),
                    ..Default::default()
                },
                vec![Arc::new(provider)],
                Some("node-a".to_owned()),
            )
            .await,
        );
        assert_eq!(handler.current(), "node-a");

        // 1. Deterministic CAS test: a stale reader holding the pre-switch
        // guard cannot overwrite a manual `select("node-b")` that happened
        // during a provider refresh.
        let stale_guard = handler.cached_active.load();
        let refreshed = Arc::new(vec![make_plain("node-a"), make_plain("node-b")]);
        slot.store(refreshed.clone());
        SelectorControl::select(handler.as_ref(), "node-b").unwrap();

        assert!(
            !handler.try_commit_selection(&stale_guard, &refreshed, &refreshed[0]),
            "stale writeback must fail CAS after concurrent manual select"
        );
        assert_eq!(handler.current(), "node-b");

        // 2. Multi-threaded race test: racing `selected_proxy` across snapshot
        // refreshes against `select("node-b")` must never leave selection on "node-a".
        for _ in 0..64 {
            SelectorControl::select(handler.as_ref(), "node-a").unwrap();
            let next_snap =
                Arc::new(vec![make_plain("node-a"), make_plain("node-b")]);
            slot.store(next_snap);

            let barrier = Arc::new(Barrier::new(3));
            let h1 = handler.clone();
            let b1 = barrier.clone();
            let reader1 = tokio::spawn(async move {
                b1.wait().await;
                let _ = h1.selected_proxy(false);
            });

            let h2 = handler.clone();
            let b2 = barrier.clone();
            let reader2 = tokio::spawn(async move {
                b2.wait().await;
                let _ = h2.selected_proxy(false);
            });

            let h_sel = handler.clone();
            let b_sel = barrier.clone();
            let switcher = tokio::spawn(async move {
                b_sel.wait().await;
                SelectorControl::select(h_sel.as_ref(), "node-b").unwrap();
            });

            reader1.await.unwrap();
            reader2.await.unwrap();
            switcher.await.unwrap();

            assert_eq!(
                handler.current(),
                "node-b",
                "stale refresh reader must never revert manual selection back to node-a"
            );
        }
    }

    #[tokio::test]
    async fn stale_old_snapshot_without_new_member_cannot_overwrite_manual_select_and_fallback_notifies() {
        use std::{
            collections::HashMap,
            io,
            sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        };
        use arc_swap::ArcSwap;
        use async_trait::async_trait;
        use erased_serde::Serialize;
        use parking_lot::Mutex;
        use crate::{
            app::remote_content_manager::providers::{
                Provider, ProviderType, ProviderVehicleType,
                proxy_provider::ProxyProvider,
            },
            proxy::group::selector::SelectorControl,
        };

        struct RacingProvider {
            slot: Arc<ArcSwap<Vec<OutboundNode>>>,
            trigger_race: Arc<AtomicBool>,
            old_snap: Arc<Vec<OutboundNode>>,
            new_snap: Arc<Vec<OutboundNode>>,
            touch_calls: Arc<AtomicUsize>,
            handler_slot: Arc<Mutex<Option<Arc<super::Handler>>>>,
        }

        #[async_trait]
        impl Provider for RacingProvider {
            fn name(&self) -> &str {
                "racing-provider"
            }
            fn vehicle_type(&self) -> ProviderVehicleType {
                ProviderVehicleType::Compatible
            }
            fn typ(&self) -> ProviderType {
                ProviderType::Proxy
            }
            async fn initialize(&self) -> io::Result<()> {
                Ok(())
            }
            async fn update(&self) -> io::Result<()> {
                Ok(())
            }
            async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
                HashMap::new()
            }
        }

        #[async_trait]
        impl ProxyProvider for RacingProvider {
            fn proxies(&self) -> Arc<Vec<OutboundNode>> {
                if self.trigger_race.swap(false, Ordering::SeqCst) {
                    // Simulate provider refresh adding "node-b" + user manually
                    // switching to "node-b" AFTER `cached_active` was loaded as
                    // "node-a", while this reader still receives old `[node-a]`.
                    self.slot.store(self.new_snap.clone());
                    if let Some(h) = self.handler_slot.lock().clone() {
                        SelectorControl::select(h.as_ref(), "node-b").unwrap();
                    }
                    return self.old_snap.clone();
                }
                self.slot.load_full()
            }
            fn touch(&self) {
                self.touch_calls.fetch_add(1, Ordering::SeqCst);
            }
            async fn healthcheck(&self) {}
        }

        let make_plain = |name: &str| {
            let mut mock = MockDummyOutboundHandler::new();
            mock.expect_name().return_const(name.to_owned());
            OutboundNode::protocol(Arc::new(mock))
        };

        // Initial snapshot contains ONLY "node-a".
        let init_snap = Arc::new(vec![make_plain("node-a")]);
        // Intermediate refreshed snapshot also contains ONLY "node-a" (different Arc,
        // forcing `selected_proxy` into the slow path / CAS writeback).
        let mid_snap = Arc::new(vec![make_plain("node-a")]);
        let new_snap = Arc::new(vec![make_plain("node-a"), make_plain("node-b")]);
        let slot = Arc::new(ArcSwap::from(init_snap.clone()));
        let trigger_race = Arc::new(AtomicBool::new(false));
        let touch_calls = Arc::new(AtomicUsize::new(0));
        let handler_slot: Arc<Mutex<Option<Arc<super::Handler>>>> =
            Arc::new(Mutex::new(None));

        let provider = Arc::new(RacingProvider {
            slot: slot.clone(),
            trigger_race: trigger_race.clone(),
            old_snap: mid_snap.clone(),
            new_snap,
            touch_calls: touch_calls.clone(),
            handler_slot: handler_slot.clone(),
        });

        let handler = Arc::new(
            super::Handler::new(
                super::HandlerOptions {
                    name: "PROXY".to_owned(),
                    ..Default::default()
                },
                vec![provider],
                Some("node-a".to_owned()),
            )
            .await,
        );
        *handler_slot.lock() = Some(handler.clone());

        // Arm the exact race: `cached_active` points to `init_snap` ("node-a"),
        // `get_proxies` returns stale `mid_snap` (only [node-a], forcing slow-path
        // CAS) while a concurrent refresh adds "node-b" and `select("node-b")`
        // commits it. Because `selected_proxy` loaded `cached_active` before
        // `get_proxies`, its CAS against `init_snap` fails, retries, and returns
        // "node-b" without overwriting it.
        trigger_race.store(true, Ordering::SeqCst);
        let picked = handler.selected_proxy(true).unwrap();
        assert_eq!(
            picked.name(),
            "node-b",
            "stale snapshot missing newly added node-b must retry and observe node-b"
        );
        assert_eq!(handler.current(), "node-b");
        assert_eq!(
            touch_calls.load(Ordering::SeqCst),
            1,
            "touch() must run only once even when CAS retries"
        );

        // When a subsequent refresh removes "node-b", automatic fallback to
        // "node-a" must notify `changes` so the reference tracker updates
        // keep-idle.
        let rx = handler.changes.subscribe();
        slot.store(mid_snap.clone());
        let fallback = handler.selected_proxy(false).unwrap();
        assert_eq!(fallback.name(), "node-a");
        assert!(
            rx.has_changed().unwrap(),
            "automatic fallback to first member must notify route changes"
        );

        // Initial resolution from `None` (e.g. provider populated after empty
        // startup) must not emit an extra `changes` notification.
        handler.cached_active.store(None);
        let init_rx = handler.changes.subscribe();
        let resolved = handler.selected_proxy(false).unwrap();
        assert_eq!(resolved.name(), "node-a");
        assert!(
            !init_rx.has_changed().unwrap(),
            "initial resolution from None should not emit redundant route change"
        );

        *handler_slot.lock() = None;
    }
}
