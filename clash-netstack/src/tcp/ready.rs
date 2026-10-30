//! One queued wake per connection, shared by socket, stream and relay readiness.
use std::{collections::VecDeque, sync::{Arc, Mutex, Weak, atomic::{AtomicBool, Ordering}}};
use futures::task::ArcWake;
use tokio::sync::Notify;

#[derive(Default)]
pub(crate) struct ReadyQueue {
    queue: Mutex<VecDeque<Arc<Ready>>>,
    pub notify: Notify,
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
        // Clear immediately before servicing, so a concurrent wake rearms it.
        self.queued.store(false, Ordering::Release);
    }

    pub fn schedule(self: &Arc<Self>) {
        if let Some(queue) = self.queue.upgrade()
            && !self.queued.swap(true, Ordering::AcqRel) {
            queue.queue.lock().unwrap().push_back(self.clone());
            queue.notify.notify_one();
        }
    }
}

impl ArcWake for Ready {
    fn wake_by_ref(arc_self: &Arc<Self>) { arc_self.schedule(); }
}

impl ReadyQueue {
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

    #[test]
    fn wakes_are_coalesced_and_can_be_rearmed() {
        let queue = Arc::new(ReadyQueue::default());
        let ready = Ready::new(1, queue.clone());
        for _ in 0..100 { ready.schedule(); }
        assert_eq!(queue.pop().unwrap().id, 1);
        assert!(queue.pop().is_none());
        ready.schedule();
        assert_eq!(queue.pop().unwrap().id, 1);
    }

    #[test]
    fn batch_keeps_waiting_wakes_coalesced_and_servicing_wakes_rearmed() {
        let queue = Arc::new(ReadyQueue::default());
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

}
