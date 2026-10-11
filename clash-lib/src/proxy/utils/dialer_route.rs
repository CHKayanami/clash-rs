//! A UDP association pins every named target and nested group selection.
//! Cached workers keep a weak context, so factories cannot retain route nodes.

use crate::proxy::OutboundNode;
use parking_lot::Mutex;
use std::{collections::HashMap, future::Future, io, sync::{Arc, Weak}};

#[derive(Debug, Default)]
pub(crate) struct Route {
    nodes: Mutex<HashMap<(bool, usize), OutboundNode>>,
}

pub(super) type WeakRoute = Weak<Route>;

tokio::task_local! {
    static ROUTE: Arc<Route>;
}

pub(crate) fn retain() -> Option<Arc<Route>> { ROUTE.try_with(Arc::clone).ok() }

pub(super) fn capture() -> Option<WeakRoute> {
    ROUTE.try_with(Arc::downgrade).ok()
}

pub(crate) async fn association<T>(enabled: bool, future: impl Future<Output = T>) -> T {
    if !enabled || ROUTE.try_with(|_| ()).is_ok() { return future.await; }
    ROUTE.scope(Arc::new(Route::default()), future).await
}

pub(super) async fn scoped<T>(route: Option<&WeakRoute>, future: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    if ROUTE.try_with(|_| ()).is_ok() || route.is_none() { return future.await; }
    let route = route.unwrap().upgrade().ok_or_else(|| io::Error::other("UDP dialer association released"))?;
    ROUTE.scope(route, future).await
}

impl Route {
    pub(crate) fn selected(&self, group: usize) -> Option<OutboundNode> {
        self.nodes.lock().get(&(true, group)).cloned()
    }

    pub(crate) fn remember(&self, group: usize, node: &OutboundNode) {
        self.nodes.lock().insert((true, group), node.clone());
    }

    pub(crate) fn forget(&self, group: usize) {
        self.nodes.lock().remove(&(true, group));
    }
}

pub(super) fn target(id: usize, resolve: impl FnOnce() -> io::Result<OutboundNode>) -> io::Result<OutboundNode> {
    let route = ROUTE.try_with(Arc::clone).ok();
    let Some(route) = route else { return resolve(); };
    let mut nodes = route.nodes.lock();
    if let Some(node) = nodes.get(&(false, id)) { return Ok(node.clone()); }
    let node = resolve()?;
    nodes.insert((false, id), node.clone());
    Ok(node)
}
