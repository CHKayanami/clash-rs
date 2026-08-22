use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use async_trait::async_trait;
use rand::seq::IteratorRandom;
use tracing::{debug, warn};

use crate::app::dns::{ClashResolver, ResolverKind, parse_ip_literal};
use crate::app::router::Router;
use crate::Error;

pub struct SystemResolver {
    ipv6: AtomicBool,
}

impl SystemResolver {
    pub fn new(ipv6: bool) -> anyhow::Result<Self> {
        debug!("creating system resolver with ipv6={}", ipv6);
        Ok(Self {
            ipv6: AtomicBool::new(ipv6),
        })
    }
}

#[async_trait]
impl ClashResolver for SystemResolver {
    async fn resolve(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>> {
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(Some(ip));
        }

        let response = tokio::net::lookup_host(format!("{host}:0"))
            .await?
            .filter_map(|x| {
                if self.ipv6() || x.is_ipv4() {
                    Some(x.ip())
                } else {
                    warn!(
                        "resolved v6 address {} for {} but ipv6 is disabled",
                        x.ip(),
                        host
                    );
                    None
                }
            })
            .collect::<Vec<_>>();
        Ok(response.into_iter().choose(&mut rand::rng()))
    }

    async fn resolve_v4(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
        let response = tokio::net::lookup_host(format!("{host}:0"))
            .await?
            .filter_map(|ip| match ip.ip() {
                std::net::IpAddr::V4(ip) => Some(ip),
                _ => None,
            })
            .collect::<Vec<_>>();
        Ok(response.into_iter().choose(&mut rand::rng()))
    }

    async fn resolve_v6(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<std::net::Ipv6Addr>> {
        if !self.ipv6() {
            return Err(Error::DNSError("ipv6 disabled".into()).into());
        }
        let response = tokio::net::lookup_host(format!("{host}:0"))
            .await?
            .filter_map(|x| match x.ip() {
                std::net::IpAddr::V6(ip) => Some(ip),
                _ => None,
            })
            .collect::<Vec<_>>();
        Ok(response.into_iter().choose(&mut rand::rng()))
    }

    async fn cached_for(&self, _: std::net::IpAddr) -> Option<String> {
        None
    }

    async fn exchange(
        &self,
        _: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        Err(anyhow::anyhow!("unsupported"))
    }

    fn ipv6(&self) -> bool {
        self.ipv6.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set_ipv6(&self, val: bool) {
        self.ipv6.store(val, std::sync::atomic::Ordering::Relaxed);
    }

    fn kind(&self) -> ResolverKind {
        ResolverKind::System
    }

    fn fake_ip_enabled(&self) -> bool {
        false
    }

    async fn is_fake_ip(&self, _: std::net::IpAddr) -> bool {
        false
    }

    async fn reverse_lookup(&self, _: std::net::IpAddr) -> Option<String> {
        None
    }

    async fn after_router_inited(&self, _: Arc<Router>) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_system_resolver_default_config() {
        let resolver = SystemResolver::new(false).unwrap();
        let response = resolver.resolve("127.0.0.1", false).await.unwrap();
        assert_eq!(response, Some(std::net::IpAddr::V4("127.0.0.1".parse().unwrap())));
    }
}
