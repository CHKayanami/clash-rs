//! Coalesced routing invalidation; consumers only need the latest state.
use std::sync::Arc;
use tokio::sync::watch;

#[derive(Clone, Debug)]
pub struct RouteChange(Arc<watch::Sender<()>>);
impl Default for RouteChange {
    fn default() -> Self { Self(Arc::new(watch::channel(()).0)) }
}
impl RouteChange {
    pub(crate) fn identity(&self) -> usize { Arc::as_ptr(&self.0) as usize }
    pub fn notify(&self) { self.0.send_replace(()); }
    #[cfg(test)]
    pub(crate) fn subscribers(&self) -> usize { self.0.receiver_count() }
    pub fn subscribe(&self) -> watch::Receiver<()> { self.0.subscribe() }
}
