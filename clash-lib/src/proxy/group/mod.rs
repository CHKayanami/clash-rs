use crate::proxy::{OutboundNode, OutboundType};
use crate::session::Session;
use std::{collections::HashSet, fmt::Debug, future::Future, io, time::Duration};
use erased_serde::Serialize;
use std::collections::HashMap;

/// Preserve each group's existing capability semantics without async recursion.
#[derive(Debug, Clone, Copy)]
pub enum UdpPolicy {
    Enabled,
    Disabled,
    Selected,
}

mod dispatch;
pub use dispatch::{ProxyGroup, WeakProxyGroup};

pub mod fallback;
pub mod loadbalance;
pub mod selector;
pub mod smart;
pub mod urltest;

/// Selection policy only. Connection execution belongs to the outbound adapter.
pub trait GroupHandler: Send + Sync + Unpin + Debug {
    fn name(&self) -> &str;
    fn proto(&self) -> OutboundType;
    fn udp_policy(&self) -> UdpPolicy;

    fn select(
        &self,
        sess: &Session,
        excluded: &HashSet<String>,
    ) -> impl Future<Output = io::Result<Option<OutboundNode>>> + Send;

    fn attempts(&self, _sess: &Session) -> impl Future<Output = u32> + Send {
        async { 1 }
    }

    fn retry_delay(&self, _attempt: u32) -> Duration {
        Duration::ZERO
    }

    fn record_result(
        &self, _sess: &Session, _proxy: &str, _elapsed: Duration, _success: bool,
    ) -> impl Future<Output = ()> + Send {
        async {}
    }
}

/// API inspection is independent of the connection execution contract.
pub trait GroupProxyAPIResponse: Send + Sync {
    fn get_proxies(&self) -> impl Future<Output = Vec<OutboundNode>> + Send;
    /// Returns the current effective proxy for the group.
    /// e.g. for a selector, it returns the currently selected proxy, and for
    /// urltest, it returns the fastest proxy, etc.
    fn get_active_proxy(&self) -> impl Future<Output = Option<OutboundNode>> + Send;

    /// Returns the latency test URL for the group.
    fn get_latency_test_url(&self) -> Option<String>;

    /// used in the API responses.
    fn as_map(&self) -> impl Future<Output = HashMap<String, Box<dyn Serialize + Send>>> + Send {
        async move {
            let all = self.get_proxies().await;
            let mut m = HashMap::new();
            if let Some(active) = self.get_active_proxy().await {
                m.insert("now".to_owned(), Box::new(active.name().to_owned()) as _);
            }
            m.insert("icon".to_owned(), Box::new(self.icon().unwrap_or_default()) as _);
            m.insert("hidden".to_owned(), Box::new(false) as _);
            m.insert("testUrl".to_owned(), Box::new(self.get_latency_test_url().unwrap_or_default()) as _);
            m.insert("all".to_owned(), Box::new(all.iter().map(|p| p.name().to_owned()).collect::<Vec<_>>()) as _);
            m
        }
    }

    fn icon(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
pub(crate) mod outbound_tests;
