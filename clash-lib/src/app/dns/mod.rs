use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;

#[cfg(test)]
use mockall::automock;

pub mod collector;
pub mod config;
pub mod ecs;
pub mod endpoint;
mod fakeip;
pub mod filters;
pub mod framing;
pub mod query;
pub mod resolver;
pub mod response;
mod rule_dispatch;
pub mod server;
pub mod singleflight;
pub mod transport;
pub mod upstream_pool;
pub mod wire;

use crate::app::router::Router;
pub use collector::{DnsCollector, ThreadSafeDnsCollector};
pub use config::{Config, EdnsClientSubnet};

pub use filters::PendingMmdb;
pub use resolver::{EnhancedResolver, SystemResolver, new as new_resolver};
pub use rule_dispatch::{PendingOutboundManager, PendingRouter, RuleDispatch};

pub use server::DnsRunner;
#[cfg(any(feature = "tun", feature = "ebpf"))]
pub use server::exchange_with_resolver;

pub enum ResolverKind {
    Clash,
    System,
}

pub type ThreadSafeDNSResolver = Arc<dyn ClashResolver>;

#[derive(Clone)]
pub struct DnsResolutionHookWrapper(
    pub Arc<dyn Fn(&str, &[std::net::IpAddr], std::time::Duration) + Send + Sync>,
);
pub type DnsResolutionHook = Arc<dyn Fn(&str, &[std::net::IpAddr], std::time::Duration) + Send + Sync>;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait ClashResolver: Sync + Send {
    fn register_resolution_hook(&self, _hook: DnsResolutionHook) {}
    fn unregister_resolution_hook(&self, _hook: &DnsResolutionHook) {}

    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>>;
    async fn resolve_v4(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv4Addr>>;
    async fn resolve_v6(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv6Addr>>;

    fn cached_for(&self, ip: std::net::IpAddr) -> Option<String>;

    /// Used for DNS Server / TUN / eBPF: accepts raw wire-format query bytes and returns raw response bytes
    async fn exchange(&self, message: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// DNS listeners supply the peer IP; internal queries may omit it.
    async fn exchange_from(
        &self,
        message: &[u8],
        _source_ip: Option<IpAddr>,
    ) -> anyhow::Result<Vec<u8>> {
        self.exchange(message).await
    }

    /// Only used for look up fake IP
    fn reverse_lookup(&self, ip: std::net::IpAddr) -> Option<String>;
    fn is_fake_ip(&self, ip: std::net::IpAddr) -> bool;
    fn fake_ip_enabled(&self) -> bool;

    async fn after_router_inited(&self, r: Arc<Router>);

    fn ipv6(&self) -> bool;
    fn set_ipv6(&self, enable: bool);

    fn kind(&self) -> ResolverKind;

    fn list_upstreams(&self) -> Vec<DnsUpstreamInfo> {
        Vec::new()
    }

    fn search_cache_by_upstream(
        &self,
        _pattern: &str,
        _upstream: &str,
    ) -> Option<DnsCacheUpstreamStat> {
        None
    }

    fn clear_cache_by_upstream(&self, _pattern: &str, _upstream: &str) -> usize {
        0
    }

    fn search_cache(&self, _pattern: &str) -> DnsCacheReport {
        DnsCacheReport {
            upstreams: Vec::new(),
            total: 0,
        }
    }

    fn clear_cache<'a>(&self, _pattern: &str, _upstream: Option<&'a str>) -> usize {
        0
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DnsUpstreamInfo {
    pub tag: String,
    pub r#type: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DnsCacheItem {
    pub domain: String,
    pub qtype: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_stale: Option<bool>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DnsCacheUpstreamStat {
    pub name: String,
    pub count: usize,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub upstream_type: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub items: Vec<DnsCacheItem>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DnsCacheReport {
    pub upstreams: Vec<DnsCacheUpstreamStat>,
    pub total: usize,
}

/// Returns the IP address if `host` is a valid IP literal, otherwise `None`.
/// Used by resolvers to short-circuit DNS resolution for IP literals.
pub(crate) fn parse_ip_literal(host: &str) -> Option<std::net::IpAddr> {
    host.parse().ok()
}
