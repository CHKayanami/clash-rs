use async_trait::async_trait;
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

pub type DnsResolutionHook = Arc<dyn Fn(&str, &[std::net::IpAddr], std::time::Duration) + Send + Sync>;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait ClashResolver: Sync + Send {
    fn register_resolution_hook(&self, _hook: DnsResolutionHook) {}

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

    async fn cached_for(&self, ip: std::net::IpAddr) -> Option<String>;

    /// Used for DNS Server / TUN / eBPF: accepts raw wire-format query bytes and returns raw response bytes
    async fn exchange(&self, message: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// Only used for look up fake IP
    async fn reverse_lookup(&self, ip: std::net::IpAddr) -> Option<String>;
    async fn is_fake_ip(&self, ip: std::net::IpAddr) -> bool;
    fn fake_ip_enabled(&self) -> bool;

    async fn after_router_inited(&self, r: Arc<Router>);

    fn ipv6(&self) -> bool;
    fn set_ipv6(&self, enable: bool);

    fn kind(&self) -> ResolverKind;
}

/// Returns the IP address if `host` is a valid IP literal, otherwise `None`.
/// Used by resolvers to short-circuit DNS resolution for IP literals.
pub(crate) fn parse_ip_literal(host: &str) -> Option<std::net::IpAddr> {
    host.parse().ok()
}
