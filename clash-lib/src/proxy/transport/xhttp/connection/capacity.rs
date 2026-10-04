use std::{io, sync::{Arc, atomic::{AtomicUsize, Ordering}}};
use crate::proxy::transport::h2_common::ConnectionState;

#[derive(Default)]
pub(super) struct Capacity {
    state: Arc<ConnectionState>,
    active: AtomicUsize,
}

impl Capacity {
    pub(super) fn new(state: Arc<ConnectionState>) -> Self {
        Self { state, active: AtomicUsize::new(0) }
    }

    pub(super) fn update(&self, limit: usize) { self.state.update(limit); }
    pub(super) fn close(&self) { self.state.close(); }
    pub(super) fn closed(&self) -> bool { self.state.closed() }

    pub(super) fn reserve(&self, reserve_upload: bool) -> bool {
        if self.closed() { return false; }
        let limit = self.state.limit();
        // Keep an upload slot on shared H2 connections. A one-stream peer
        // uses separate physical connections for its upload and download.
        let limit = if reserve_upload && limit > 1 { limit - 1 } else { limit };
        self.active.try_update(Ordering::AcqRel, Ordering::Acquire,
            |active| (active < limit).then(|| active + 1)).is_ok()
    }

    pub(super) fn release(&self) { self.active.fetch_sub(1, Ordering::AcqRel); }

    pub(super) async fn initialized(&self) -> io::Result<()> {
        self.state.initialized().await
    }
}
