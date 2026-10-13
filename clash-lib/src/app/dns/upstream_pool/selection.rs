//! Background selection for groups whose choice is independent of the request.
use std::{collections::HashSet, future::poll_fn, io, sync::Arc, task::Poll, time::Duration};
use arc_swap::ArcSwapOption;
use tokio::{spawn, sync::{Notify, watch::Receiver}, time::{Instant, sleep_until}};
use tokio_util::{sync::ReusableBoxFuture, task::AbortOnDropHandle};
use crate::proxy::{OutboundNode, RouteChange, group::UdpPolicy};
use super::{bindings::SelectionBinding, entries::UpstreamState};

const UPDATE_INTERVAL: Duration = Duration::from_secs(5);

pub(super) struct Selection {
    pub node: Option<OutboundNode>,
    pub udp_allowed: bool,
    pub error: Option<String>,
}
struct Shared {
    active: ArcSwapOption<Selection>,
    ready: Notify,
}
pub(super) struct SelectionCache {
    shared: Arc<Shared>,
    _task: AbortOnDropHandle<()>,
    binding: Arc<SelectionBinding>,
}
impl SelectionCache {
    pub(super) fn new(node: OutboundNode) -> Self {
        let shared = Arc::new(Shared {
            active: ArcSwapOption::empty(), ready: Notify::new(),
        });
        let binding = Arc::new(SelectionBinding::new());
        let worker = shared.clone();
        let routes = binding.clone();
        let task = spawn(async move { run(node, worker, routes).await });
        Self { shared, _task: AbortOnDropHandle::new(task), binding }
    }
    pub(super) fn attach(&self, state: &Arc<UpstreamState>) { self.binding.attach(state); }
    pub(super) async fn get(&self) -> io::Result<Arc<Selection>> {
        if let Some(selection) = self.shared.active.load_full() {
            if let Some(error) = &selection.error { return Err(io::Error::other(error.clone())); }
            return Ok(selection);
        }
        loop {
            let ready = self.shared.ready.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            if let Some(selection) = self.shared.active.load_full() {
                if let Some(error) = &selection.error { return Err(io::Error::other(error.clone())); }
                return Ok(selection);
            }
            ready.await;
        }
    }
}

// Each future owns its receiver so cancelled waits do not lose notifications.
// Re-arming uses the same allocation and unchanged sources retain their receiver.
struct SourceWait {
    source: RouteChange,
    wait: ReusableBoxFuture<'static, Receiver<()>>,
}
async fn wait_change(mut receiver: Receiver<()>) -> Receiver<()> {
    // SourceWait retains the sender for the entire lifetime of this future.
    receiver.changed().await.expect("subscription retains its notification source");
    receiver
}
impl SourceWait {
    fn new(source: RouteChange) -> Self {
        let wait = ReusableBoxFuture::new(wait_change(source.subscribe()));
        Self { source, wait }
    }
}
#[derive(Default)]
struct SelectionInputs {
    sources: Vec<RouteChange>,
    seen: HashSet<usize>,
    subscribed: HashSet<usize>,
    wanted: HashSet<usize>,
}
fn resolve(mut node: OutboundNode, waits: &mut Vec<SourceWait>, inputs: &mut SelectionInputs) -> Selection {
    let SelectionInputs { sources, seen, subscribed, wanted } = inputs;
    seen.clear();
    subscribed.clear();
    subscribed.extend(waits.iter().map(|wait| wait.source.identity()));
    wanted.clear();
    let mut selection = Selection { node: None, udp_allowed: true, error: None };
    loop {
        let Some(group) = node.as_group() else {
            selection.udp_allowed &= node.as_protocol().unwrap().support_udp();
            selection.node = Some(node);
            break;
        };
        if !seen.insert(group.identity()) || seen.len() > 64 {
            selection.error = Some("cyclic or too deep DNS proxy group".to_owned());
            break;
        }
        selection.udp_allowed &= !matches!(group.udp_policy(), UdpPolicy::Disabled);
        if !group.stable_selection() {
            selection.node = Some(node);
            break;
        }
        // Subscribe before selecting; changes during the computation remain pending.
        sources.clear();
        group.route_changes(sources);
        for source in sources.drain(..) {
            let identity = source.identity();
            wanted.insert(identity);
            if subscribed.insert(identity) { waits.push(SourceWait::new(source)); }
        }
        match group.select_cached() {
            Some(selected) => node = selected,
            None => { selection.error = Some(format!("no proxy available for {}", group.name())); break; }
        }
    }
    waits.retain(|wait| wanted.contains(&wait.source.identity()));
    selection
}
async fn changed(waits: &mut [SourceWait]) {
    poll_fn(|cx| {
        for source in waits.iter_mut() {
            if let Poll::Ready(receiver) = source.wait.poll(cx) {
                source.wait.set(wait_change(receiver));
                return Poll::Ready(());
            }
        }
        Poll::Pending
    }).await
}

// Consume the rest of a batch before reading current state.
async fn drain_changes(waits: &mut [SourceWait]) {
    poll_fn(|cx| {
        for source in waits.iter_mut() {
            if let Poll::Ready(receiver) = source.wait.poll(cx) {
                source.wait.set(wait_change(receiver));
            }
        }
        Poll::Ready(())
    }).await;
}

fn publish(selection: Selection, shared: &Shared, binding: &SelectionBinding) {
    let unchanged = shared.active.load().as_ref().is_some_and(|current| {
        current.udp_allowed == selection.udp_allowed && current.error == selection.error
            && match (&current.node, &selection.node) {
                (Some(a), Some(b)) => a.ptr_eq(b),
                (None, None) => true,
                _ => false,
            }
    });
    if !unchanged {
        binding.update(selection.node.as_ref());
        shared.active.store(Some(Arc::new(selection)));
        shared.ready.notify_waiters();
    }
}

async fn run(node: OutboundNode, shared: Arc<Shared>, binding: Arc<SelectionBinding>) {
    let mut waits = Vec::new();
    let mut inputs = SelectionInputs::default();
    publish(resolve(node.clone(), &mut waits, &mut inputs), &shared, &binding);
    let mut last_update = Instant::now();
    while !waits.is_empty() {
        changed(&mut waits).await;
        // A single deadline merges notifications without postponing the batch.
        let deadline = last_update + UPDATE_INTERVAL;
        if Instant::now() < deadline { sleep_until(deadline).await; }
        drain_changes(&mut waits).await;
        publish(resolve(node.clone(), &mut waits, &mut inputs), &shared, &binding);
        // Unchanged batches also count, preventing repeated state scans.
        last_update = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;
    use crate::proxy::{direct::Handler, mocks::MockDummyProxyProvider,
        group::selector::{Handler as Selector, HandlerOptions as SelectorOptions}};

    #[tokio::test]
    async fn leaf_resolution_drops_obsolete_subscriptions() {
        let source = RouteChange::default();
        let mut waits = vec![SourceWait::new(source.clone())];
        source.notify();
        let identity = waits[0].source.identity();
        // Resolving a leaf drops obsolete subscriptions.
        resolve(OutboundNode::protocol(Arc::new(Handler::new("leaf"))), &mut waits, &mut SelectionInputs::default());
        assert!(waits.is_empty());
        assert_eq!(source.subscribers(), 0);
        assert_eq!(identity, source.clone().identity());
    }

    #[tokio::test(start_paused = true)]
    async fn timer_cancellation_preserves_pending_wait() {
        let source = RouteChange::default();
        let mut waits = vec![SourceWait::new(source.clone())];
        tokio::select! {
            _ = changed(&mut waits) => panic!("source has not changed"),
            _ = sleep(Duration::from_secs(5)) => {}
        }
        source.notify();
        changed(&mut waits).await;
        source.notify();
        changed(&mut waits).await;
        assert_eq!(source.subscribers(), 1);
    }

    #[tokio::test]
    async fn unchanged_group_sources_keep_receivers_and_pending_changes() {
        let source = RouteChange::default();
        let nodes = Arc::new(vec![OutboundNode::protocol(Arc::new(Handler::new("leaf")))]);
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning(move || nodes.clone());
        let changes = source.clone();
        provider.expect_route_changes().returning(move || Some(changes.clone()));
        provider.expect_touch().never();
        let group = Selector::new(SelectorOptions {
            name: "group".to_owned(), udp: true, ..Default::default()
        }, vec![Arc::new(provider)], None).await;
        let node = OutboundNode::group(Arc::new(group));
        let mut waits = Vec::new();
        let mut inputs = SelectionInputs::default();
        resolve(node.clone(), &mut waits, &mut inputs);
        assert_eq!(source.subscribers(), 1);
        source.notify();
        resolve(node, &mut waits, &mut inputs);
        assert_eq!(source.subscribers(), 1);
        assert_eq!(waits.len(), 2);
        changed(&mut waits).await;
    }

    #[tokio::test(start_paused = true)]
    async fn notifications_from_multiple_members_are_drained_as_one_batch() {
        let sources: Vec<_> = (0..8).map(|_| RouteChange::default()).collect();
        let mut waits: Vec<_> = sources.iter().cloned().map(SourceWait::new).collect();
        for source in &sources { source.notify(); }
        changed(&mut waits).await;
        drain_changes(&mut waits).await;
        assert!(tokio::time::timeout(Duration::from_millis(1), changed(&mut waits)).await.is_err());
        sources[7].notify();
        changed(&mut waits).await;
    }

}

#[cfg(test)]
mod update_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::advance;
    use crate::proxy::{direct::Handler, mocks::MockDummyProxyProvider,
        group::selector::{Handler as Selector, HandlerOptions as SelectorOptions, SelectorControl}};

    async fn settle() { for _ in 0..8 { tokio::task::yield_now().await; } }

    #[tokio::test(start_paused = true)]
    async fn updates_batch_at_five_seconds_and_idle_notifications_refresh_immediately() {
        let nodes: Arc<Vec<OutboundNode>> = Arc::new(vec!["a", "b", "c"].into_iter().map(|name|
            OutboundNode::protocol(Arc::new(Handler::new(name))),
        ).collect());
        let reads = Arc::new(AtomicUsize::new(0));
        let mut provider = MockDummyProxyProvider::new();
        let calls = reads.clone();
        provider.expect_proxies().returning(move || {
            calls.fetch_add(1, Ordering::Relaxed);
            nodes.clone()
        });
        provider.expect_route_changes().return_const(None);
        provider.expect_touch().never();
        let group = Selector::new(SelectorOptions {
            name: "group".to_owned(), udp: true, ..Default::default()
        }, vec![Arc::new(provider)], None).await;
        let cache = SelectionCache::new(OutboundNode::group(Arc::new(group.clone())));
        let initial = cache.get().await.unwrap();
        assert_eq!(initial.node.as_ref().unwrap().name(), "a");
        group.select("b").unwrap();
        settle().await;
        advance(Duration::from_secs(2)).await;
        group.select("c").unwrap();
        let pending_reads = reads.load(Ordering::Relaxed);
        advance(Duration::from_millis(2999)).await;
        settle().await;
        assert!(Arc::ptr_eq(&initial, &cache.get().await.unwrap()));
        assert_eq!(reads.load(Ordering::Relaxed), pending_reads);
        advance(Duration::from_millis(1)).await;
        settle().await;
        assert_eq!(cache.get().await.unwrap().node.as_ref().unwrap().name(), "c");
        assert_eq!(reads.load(Ordering::Relaxed), pending_reads + 1);
        advance(Duration::from_secs(6)).await;
        settle().await;
        assert_eq!(reads.load(Ordering::Relaxed), pending_reads + 1);
        group.select("b").unwrap();
        settle().await;
        let published = cache.get().await.unwrap();
        assert_eq!(published.node.as_ref().unwrap().name(), "b");
        group.select("b").unwrap();
        let pending_reads = reads.load(Ordering::Relaxed);
        advance(Duration::from_secs(5)).await;
        settle().await;
        assert!(Arc::ptr_eq(&published, &cache.get().await.unwrap()));
        assert_eq!(reads.load(Ordering::Relaxed), pending_reads + 1);
        group.select("a").unwrap();
        let pending_reads = reads.load(Ordering::Relaxed);
        settle().await;
        advance(Duration::from_millis(4999)).await;
        settle().await;
        assert!(Arc::ptr_eq(&published, &cache.get().await.unwrap()));
        assert_eq!(reads.load(Ordering::Relaxed), pending_reads);
        advance(Duration::from_millis(1)).await;
        settle().await;
        assert_eq!(cache.get().await.unwrap().node.as_ref().unwrap().name(), "a");
    }
}
