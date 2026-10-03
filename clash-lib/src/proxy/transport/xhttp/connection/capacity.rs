use std::{io, sync::atomic::{AtomicBool, AtomicUsize, Ordering}};
use tokio::sync::Notify;

#[derive(Default)]
pub(super) struct Capacity {
    limit: AtomicUsize,
    active: AtomicUsize,
    closed: AtomicBool,
    changed: Notify,
}

impl Capacity {
    pub(super) fn update(&self, limit: usize) {
        if self.limit.swap(limit, Ordering::AcqRel) != limit {
            self.changed.notify_waiters();
        }
    }

    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    pub(super) fn closed(&self) -> bool { self.closed.load(Ordering::Acquire) }

    pub(super) fn reserve(&self, reserve_upload: bool) -> bool {
        if self.closed() { return false; }
        let limit = self.limit.load(Ordering::Acquire);
        // Keep an upload slot on shared H2 connections. A one-stream peer
        // uses separate physical connections for its upload and download.
        let limit = if reserve_upload && limit > 1 { limit - 1 } else { limit };
        self.active.try_update(Ordering::AcqRel, Ordering::Acquire,
            |active| (active < limit).then(|| active + 1)).is_ok()
    }

    pub(super) fn release(&self) { self.active.fetch_sub(1, Ordering::AcqRel); }

    pub(super) async fn initialized(&self) -> io::Result<()> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.closed() { return Err(io::ErrorKind::BrokenPipe.into()); }
            if self.limit.load(Ordering::Acquire) != 0 { return Ok(()); }
            changed.await;
        }
    }
}
