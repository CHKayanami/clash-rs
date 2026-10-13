//! Bounded transport routes keyed by retained protocol node identity.

use std::{collections::HashMap, hash::{Hash, Hasher}, sync::{Arc, atomic::{AtomicBool, Ordering}}};
use parking_lot::Mutex;
use arc_swap::ArcSwap;
use crate::proxy::{OutboundNode, ProtocolOutbound};
#[cfg(test)]
use crate::proxy::direct::Handler;

const MAX_ROUTES: usize = 128;

/// Retain the node so a recycled allocation cannot collide with a live pool.
#[derive(Clone, Debug, Default)]
pub struct TransportKey {
    node: Option<OutboundNode>,
}

impl TransportKey {
    pub(super) fn new(handler: Option<&OutboundNode>) -> Self {
        Self { node: handler.cloned() }
    }

    pub(super) fn is_direct(&self) -> bool { self.node.is_none() }

    #[cfg(test)]
    pub(super) fn named(name: &str) -> Self {
        Self::new(Some(&OutboundNode::protocol(Arc::new(
            Handler::new(name),
        ))))
    }
}

impl PartialEq for TransportKey {
    fn eq(&self, other: &Self) -> bool {
        match (&self.node, &other.node) {
            (Some(a), Some(b)) => a.ptr_eq(b),
            (None, None) => true,
            _ => false,
        }
    }
}
impl Eq for TransportKey {}
impl Hash for TransportKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.node.as_ref().map(OutboundNode::identity).hash(state);
    }
}

struct CachedRoute<T> {
    value: Arc<T>,
    pinned: AtomicBool,
    sequence: u64,
}
struct Routes<T> {
    entries: HashMap<TransportKey, Arc<CachedRoute<T>>>,
}
#[derive(Default)]
struct RouteUpdates {
    references: HashMap<TransportKey, usize>,
    sequence: u64,
}
pub(super) struct RouteCache<T> {
    routes: ArcSwap<Routes<T>>,
    update: Mutex<RouteUpdates>,
}
impl<T> Default for RouteCache<T> {
    fn default() -> Self {
        Self { routes: ArcSwap::from_pointee(Routes {
            entries: HashMap::new(),
        }), update: Mutex::new(RouteUpdates::default()) }
    }
}
impl RouteUpdates {
    fn owns(&self, key: &TransportKey) -> bool {
        self.references.contains_key(key)
    }
    fn make<T>(&mut self, value: T, pinned: bool) -> Arc<CachedRoute<T>> {
        self.sequence = self.sequence.wrapping_add(1);
        Arc::new(CachedRoute {
            value: Arc::new(value), pinned: AtomicBool::new(pinned), sequence: self.sequence,
        })
    }
    fn make_room<T>(&self, entries: &mut HashMap<TransportKey, Arc<CachedRoute<T>>>) -> bool {
        if entries.len() < MAX_ROUTES { return true; }
        let oldest = entries.iter().filter(|(key, _)| !self.owns(key))
            .min_by_key(|(_, route)| route.sequence).map(|(key, _)| key.clone());
        if let Some(oldest) = oldest { entries.remove(&oldest); return true; }
        false
    }
}
impl<T> RouteCache<T> {
    pub(super) fn get(&self, key: &TransportKey, create: impl FnOnce() -> T) -> Arc<T> {
        if let Some(route) = self.routes.load().entries.get(key) {
            if !route.pinned.load(Ordering::Relaxed) { route.pinned.store(true, Ordering::Relaxed); }
            return route.value.clone();
        }
        let mut update = self.update.lock();
        let current = self.routes.load();
        if let Some(route) = current.entries.get(key) {
            route.pinned.store(true, Ordering::Relaxed);
            return route.value.clone();
        }
        let mut entries = current.entries.clone();
        if !update.make_room(&mut entries) { return Arc::new(create()); }
        let route = update.make(create(), true);
        let value = route.value.clone();
        entries.insert(key.clone(), route);
        self.routes.store(Arc::new(Routes { entries }));
        value
    }

    pub(super) fn get_routed(&self, key: &TransportKey, managed: bool,
        create: impl FnOnce() -> T,
    ) -> Arc<T> {
        if !managed { return self.get(key, create); }
        if let Some(route) = self.routes.load().entries.get(key) {
            return route.value.clone();
        }
        // A query may hold the previous selection after notification publication.
        // Let it finish with an uncached slot instead of resurrecting that route.
        Arc::new(create())
    }

    /// Calls from a binding are serialized and pair each acquisition with release.
    pub(super) fn rebind(&self, previous: Option<&TransportKey>, next: Option<&TransportKey>,
        create: impl FnOnce() -> T,
    ) {
        if previous == next { return; }
        let mut update = self.update.lock();
        if let Some(previous) = previous {
            // Shutdown may already have drained the table and its references.
            if let Some(count) = update.references.get_mut(previous) {
                *count -= 1;
                if *count == 0 { update.references.remove(previous); }
            }
        }
        if let Some(next) = next { *update.references.entry(next.clone()).or_default() += 1; }
        let current = self.routes.load();
        let retire = previous.filter(|key| !update.owns(key))
            .filter(|key| current.entries.get(*key)
                .is_some_and(|route| !route.pinned.load(Ordering::Relaxed)));
        let insert = next.filter(|key| !current.entries.contains_key(*key));
        if retire.is_none() && insert.is_none() { return; }
        let mut entries = current.entries.clone();
        if let Some(previous) = retire { entries.remove(previous); }
        if let Some(key) = insert {
            update.make_room(&mut entries);
            entries.insert(key.clone(), update.make(create(), false));
        }
        self.routes.store(Arc::new(Routes { entries }));
    }

    pub(super) fn take(&self) -> Vec<Arc<T>> {
        let mut update = self.update.lock();
        update.references.clear();
        let previous = self.routes.swap(Arc::new(Routes { entries: HashMap::new() }));
        previous.entries.values().map(|route| route.value.clone()).collect()
    }

    #[cfg(test)]
    pub(super) fn values(&self) -> Vec<Arc<T>> {
        self.routes.load().entries.values().map(|route| route.value.clone()).collect()
    }
    #[cfg(test)]
    pub(super) fn len(&self) -> usize { self.routes.load().entries.len() }
}

pub(super) struct ResolvedOutbound {
    pub key: TransportKey,
    pub managed: bool,
}
impl ResolvedOutbound {
    pub(super) fn new(handler: Option<OutboundNode>) -> Self {
        Self {
            key: TransportKey { node: handler }, managed: false,
        }
    }
    pub(super) fn selected(handler: &OutboundNode) -> Self {
        let mut route = Self::new(Some(handler.clone()));
        route.managed = true;
        route
    }
    pub(super) fn handler(&self) -> Option<&OutboundNode> { self.key.node.as_ref() }
    pub(super) fn name(&self) -> Option<&str> { self.handler().map(OutboundNode::name) }
    pub(super) fn protocol(handler: &ProtocolOutbound) -> Self {
        Self::new(Some(OutboundNode::Protocol(handler.clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::atomic::AtomicUsize, time::Duration};

    struct Value(Arc<AtomicUsize>);
    impl Drop for Value {
        fn drop(&mut self) { self.0.fetch_add(1, Ordering::Relaxed); }
    }

    #[tokio::test(start_paused = true)]
    async fn route_changes_preserve_query_ownership() {
        let routes = RouteCache::default();
        let dropped = Arc::new(AtomicUsize::new(0));
        let a = TransportKey::named("same-name");
        let b = TransportKey::named("same-name");
        assert_ne!(a, b);
        assert_eq!(a, a.clone());
        routes.rebind(None, Some(&a), || Value(dropped.clone()));
        let pending = routes.get_routed(&a, true, || panic!("bound route"));
        routes.rebind(Some(&a), Some(&b), || Value(dropped.clone()));
        let current = routes.get_routed(&b, true, || panic!("bound route"));
        assert_eq!(routes.len(), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        drop(pending);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        drop(routes.take());
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        drop(current);
        assert_eq!(dropped.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn warm_hits_do_not_wait_for_writer() {
        let routes = Arc::new(RouteCache::default());
        let key = TransportKey::default();
        let expected = routes.get(&key, || 1);
        let writer = routes.update.lock();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker_routes = routes.clone();
        let worker = std::thread::spawn(move || {
            sender.send(worker_routes.get(&key, || panic!("warm route must not rebuild")))
                .unwrap();
        });
        let result = receiver.recv_timeout(Duration::from_secs(1));
        drop(writer);
        worker.join().unwrap();
        assert!(Arc::ptr_eq(&expected, &result.unwrap()));
    }

    #[test]
    fn concurrent_misses_initialize_one_route() {
        let routes = Arc::new(RouteCache::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(std::sync::Barrier::new(16));
        let mut workers = Vec::new();
        for _ in 0..16 {
            let routes = routes.clone(); let calls = calls.clone(); let start = start.clone();
            workers.push(std::thread::spawn(move || {
                start.wait();
                routes.get(&TransportKey::default(), || {
                    calls.fetch_add(1, Ordering::Relaxed);
                    1
                })
            }));
        }
        let values: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(values.iter().all(|value| Arc::ptr_eq(value, &values[0])));
    }

    #[tokio::test(start_paused = true)]
    async fn stable_routes_survive_long_idle_periods() {
        let routes = RouteCache::default();
        let key = TransportKey::default();
        let expected = routes.get(&key, || 1);
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert!(Arc::ptr_eq(&expected, &routes.get(&key, || panic!("stable route"))));
    }

    #[test]
    fn shared_and_pinned_routes_survive_another_owner_switch() {
        let routes = RouteCache::default();
        let a = TransportKey::named("a");
        let b = TransportKey::named("b");
        routes.rebind(None, Some(&a), || 1);
        routes.rebind(None, Some(&a), || panic!("reuse shared slot"));
        let shared = routes.get_routed(&a, true, || panic!("shared route"));
        routes.rebind(Some(&a), Some(&b), || 2);
        assert!(Arc::ptr_eq(&shared, &routes.get_routed(&a, true, || panic!("second owner"))));
        routes.rebind(Some(&a), None, || panic!("unbind"));
        assert_eq!(routes.len(), 1);
        let pinned = routes.get(&b, || panic!("existing slot"));
        routes.rebind(Some(&b), None, || panic!("unbind"));
        assert!(Arc::ptr_eq(&pinned, &routes.get(&b, || panic!("pinned slot"))));
    }

    #[test]
    fn route_retention_is_bounded() {
        let routes = RouteCache::default();
        for index in 0..MAX_ROUTES * 2 {
            routes.get(&TransportKey::named(&format!("node-{index}")), || ());
        }
        assert_eq!(routes.len(), MAX_ROUTES);
    }
}
