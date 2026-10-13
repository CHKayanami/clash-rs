//! Notification-owned pool slots; initialization remains query-driven.
use std::{collections::HashMap, sync::Arc};
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use crate::proxy::OutboundNode;
use super::{entries::UpstreamState, routes::TransportKey};

pub(super) struct SelectionBinding {
    states: ArcSwap<HashMap<usize, Arc<UpstreamState>>>,
    selected: Mutex<Option<TransportKey>>,
}
impl SelectionBinding {
    pub(super) fn new() -> Self {
        Self {
            states: ArcSwap::from_pointee(HashMap::new()),
            selected: Mutex::new(None),
        }
    }
    pub(super) fn attach(&self, state: &Arc<UpstreamState>) {
        let identity = Arc::as_ptr(state) as usize;
        if self.states.load().contains_key(&identity) { return; }
        let selected = self.selected.lock();
        let current = self.states.load();
        if current.contains_key(&identity) { return; }
        state.rebind(None, selected.as_ref());
        let mut states = current.as_ref().clone();
        states.insert(identity, state.clone());
        self.states.store(Arc::new(states));
    }
    pub(super) fn update(&self, node: Option<&OutboundNode>) {
        let next = node.filter(|node| node.as_protocol().is_some())
            .map(|node| TransportKey::new(Some(node)));
        let mut selected = self.selected.lock();
        if *selected == next { return; }
        for state in self.states.load().values() { state.rebind(selected.as_ref(), next.as_ref()); }
        *selected = next;
    }
}
impl Drop for SelectionBinding {
    fn drop(&mut self) {
        let selected = self.selected.get_mut().as_ref();
        for state in self.states.load().values() { state.rebind(selected, None); }
    }
}
