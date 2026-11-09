//! Readiness is coalesced per association; only the owner drains the queue.
use std::{collections::VecDeque, sync::{Arc, Weak, atomic::{AtomicBool, AtomicU64, Ordering}}};
use parking_lot::Mutex;
use futures::task::{ArcWake, AtomicWaker};

#[derive(Default)]
pub(super) struct Queue {
    ids: Mutex<VecDeque<Arc<Ready>>>,
    pub waker: AtomicWaker,
}
pub(super) struct Ready {
    pub id: u64,
    queued: AtomicBool,
    generation: AtomicU64,
    live: AtomicBool,
    queue: Weak<Queue>,
}
impl Ready {
    pub fn new(id: u64, queue: &Arc<Queue>) -> Arc<Self> {
        Arc::new(Self { id, queued: AtomicBool::new(false), generation: AtomicU64::new(0), live: AtomicBool::new(true), queue: Arc::downgrade(queue) })
    }
    pub fn generation(&self) -> u64 { self.generation.load(Ordering::Acquire) }
    pub fn schedule(self: &Arc<Self>) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        if self.live.load(Ordering::Acquire) && let Some(queue) = self.queue.upgrade()
            && !self.queued.swap(true, Ordering::AcqRel) {
            queue.ids.lock().push_back(self.clone());
            queue.waker.wake();
        }
    }
    pub fn close(&self) { self.live.store(false, Ordering::Release); }
}
impl ArcWake for Ready {
    fn wake_by_ref(this: &Arc<Self>) { this.schedule(); }
}
impl Queue {
    pub fn pop(&self) -> Option<Arc<Ready>> {
        let ready = self.ids.lock().pop_front()?;
        ready.queued.store(false, Ordering::Release);
        Some(ready)
    }
    pub fn is_empty(&self) -> bool { self.ids.lock().is_empty() }
    pub fn len(&self) -> usize { self.ids.lock().len() }
}
