//! One queued wake per connection, shared by socket, stream and relay readiness.
use std::{collections::VecDeque, sync::{Arc, Mutex, Weak, atomic::{AtomicBool, Ordering, fence}}, task::Waker};
use futures::task::{ArcWake, AtomicWaker};
use tokio::sync::Notify;

enum WakeTarget {
    Notify(Notify),
    Waker(AtomicWaker),
}

pub(crate) struct ReadyQueue {
    queue: Mutex<VecDeque<Arc<Ready>>>,
    target: WakeTarget,
}

pub(crate) struct Ready {
    pub id: u64,
    queued: AtomicBool,
    queue: Weak<ReadyQueue>,
}

impl Ready {
    pub fn new(id: u64, queue: Arc<ReadyQueue>) -> Arc<Self> {
        Arc::new(Self { id, queued: AtomicBool::new(false), queue: Arc::downgrade(&queue) })
    }

    pub fn begin_service(&self) {
        // Pair with the SeqCst fence in schedule() (Dekker pattern) so any
        // non-SeqCst Release/Acquire state written before schedule() cannot be
        // missed by subsequent reads after begin_service().
        self.queued.store(false, Ordering::Relaxed);
        fence(Ordering::SeqCst);
    }

    pub fn schedule(self: &Arc<Self>) {
        fence(Ordering::SeqCst);
        if !self.queued.swap(true, Ordering::AcqRel)
            && let Some(queue) = self.queue.upgrade() {
            queue.queue.lock().unwrap().push_back(self.clone());
            queue.wake();
        }
    }
}

impl ArcWake for Ready {
    fn wake_by_ref(arc_self: &Arc<Self>) { arc_self.schedule(); }
}

impl ReadyQueue {
    pub fn with_notify() -> Self {
        Self { queue: Mutex::new(VecDeque::new()), target: WakeTarget::Notify(Notify::new()) }
    }

    pub fn with_waker() -> Self {
        Self { queue: Mutex::new(VecDeque::new()), target: WakeTarget::Waker(AtomicWaker::new()) }
    }

    pub fn wake(&self) {
        match &self.target {
            WakeTarget::Notify(notify) => notify.notify_one(),
            WakeTarget::Waker(waker) => waker.wake(),
        }
    }

    pub fn register_waker(&self, waker: &Waker) {
        match &self.target {
            WakeTarget::Waker(target) => target.register(waker),
            WakeTarget::Notify(_) => unreachable!("register_waker requires waker-mode ReadyQueue"),
        }
    }

    pub async fn notified(&self) {
        match &self.target {
            WakeTarget::Notify(notify) => notify.notified().await,
            WakeTarget::Waker(_) => unreachable!("notified requires notify-mode ReadyQueue"),
        }
    }

    pub fn take_batch(&self, batch: &mut Vec<Arc<Ready>>, limit: usize) {
        let mut queue = self.queue.lock().unwrap();
        let count = limit.min(queue.len());
        batch.extend(queue.drain(..count));
    }

    #[cfg(test)]
    pub fn pop(&self) -> Option<Arc<Ready>> {
        let ready = self.queue.lock().unwrap().pop_front()?;
        ready.begin_service();
        Some(ready)
    }

    pub fn is_empty(&self) -> bool { self.queue.lock().unwrap().is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[test]
    fn wakes_are_coalesced_and_can_be_rearmed() {
        let queue = Arc::new(ReadyQueue::with_waker());
        let ready = Ready::new(1, queue.clone());
        for _ in 0..100 { ready.schedule(); }
        assert_eq!(queue.pop().unwrap().id, 1);
        assert!(queue.pop().is_none());
        ready.schedule();
        assert_eq!(queue.pop().unwrap().id, 1);
    }

    #[test]
    fn batch_keeps_waiting_wakes_coalesced_and_servicing_wakes_rearmed() {
        let queue = Arc::new(ReadyQueue::with_waker());
        let first = Ready::new(1, queue.clone());
        let second = Ready::new(2, queue.clone());
        first.schedule();
        second.schedule();
        let mut batch = Vec::new();
        queue.take_batch(&mut batch, 1);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].id, 1);
        // The first connection is already waiting for service in the batch.
        first.schedule();
        assert_eq!(queue.pop().unwrap().id, 2);
        assert!(queue.is_empty());
        batch[0].begin_service();
        first.schedule();
        assert_eq!(queue.pop().unwrap().id, 1);
        assert!(queue.is_empty());
    }

    #[test]
    fn waker_mode_notifies_only_once_while_queued_and_ignores_dropped_queue() {
        use std::{sync::atomic::AtomicUsize, task::{Context, Wake}};
        struct Counter(AtomicUsize);
        impl Wake for Counter {
            fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::Relaxed); }
        }
        let queue = Arc::new(ReadyQueue::with_waker());
        let hits = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(hits.clone());
        let cx = Context::from_waker(&waker);
        let ready = Ready::new(1, queue.clone());
        queue.register_waker(cx.waker());
        ready.schedule();
        ready.schedule();
        assert_eq!(hits.0.load(Ordering::Relaxed), 1);
        assert_eq!(queue.pop().unwrap().id, 1);
        queue.register_waker(cx.waker());
        ready.schedule();
        assert_eq!(hits.0.load(Ordering::Relaxed), 2);
        drop(queue);
        ready.schedule();
    }

    #[tokio::test]
    async fn notify_mode_wakes_and_coalesces_duplicates() {
        let queue = Arc::new(ReadyQueue::with_notify());
        let ready = Ready::new(1, queue.clone());
        ready.schedule();
        ready.schedule();
        timeout(Duration::from_secs(1), queue.notified()).await.unwrap();
        assert_eq!(queue.pop().unwrap().id, 1);
        assert!(queue.is_empty());
    }

}
