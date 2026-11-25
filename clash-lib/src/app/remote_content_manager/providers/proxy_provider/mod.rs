use crate::proxy::RouteChange;
pub mod filtered_provider;
pub mod plain_provider;
pub mod proxy_set_provider;

pub use filtered_provider::FilteredProxyProvider;
pub use plain_provider::PlainProvider;
pub use proxy_set_provider::ProxySetProvider;

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;

use crate::{
    app::remote_content_manager::providers::Provider, proxy::OutboundNode,
};

pub type ArcProxyProvider = Arc<dyn ProxyProvider + Send + Sync>;

/// Stable identity of a provider instance for matching fixed snapshot tables.
pub(crate) fn provider_identity(provider: &ArcProxyProvider) -> usize {
    Arc::as_ptr(provider) as *const () as usize
}

#[async_trait]
pub trait ProxyProvider: Provider {
    fn proxies(&self) -> Arc<Vec<OutboundNode>>;
    fn touch(&self);
    fn route_changes(&self) -> Option<RouteChange> { None }
    /// The healthcheck URL actually used to probe members of this provider,
    /// when applicable.
    fn healthcheck_url(&self) -> Option<&str> { None }
    /// Resolve this provider's member list against a pre-captured snapshot
    /// generation keyed by `provider_identity`, falling back to `proxies()`.
    fn proxies_from_snapshots(
        &self,
        snapshots: &HashMap<usize, Arc<Vec<OutboundNode>>>,
    ) -> Arc<Vec<OutboundNode>> {
        let key = self as *const Self as *const () as usize;
        snapshots
            .get(&key)
            .cloned()
            .unwrap_or_else(|| self.proxies())
    }
    /// Returns whether `snapshot` is still this provider's current live
    /// snapshot without rebuilding or populating derived caches.
    fn is_snapshot_current(&self, snapshot: &Arc<Vec<OutboundNode>>) -> bool {
        Arc::ptr_eq(snapshot, &self.proxies())
    }
    /// Drops any cached derived snapshot that still references a superseded
    /// upstream snapshot so retired handlers can drop promptly.
    fn invalidate_stale_cache(&self) {}
    /// this is a blocking call, you may want to spawn a new task to run this
    async fn healthcheck(&self);
}
