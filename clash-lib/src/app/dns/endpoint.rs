//! Parse DNS upstream address strings into host/port/path/SNI.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::app::dns::ClashResolver;

mod addresses;
use addresses::AddressCache;

/// Default DoH / DoH3 request path (RFC 8484).
pub const DEFAULT_DOH_PATH: &str = "/dns-query";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsStrategy {
    #[default]
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsProtocol {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
    H3,
}

/// Parsed upstream endpoint used by the DNS transports.
#[derive(Clone)]
pub struct DnsEndpoint {
    pub host: String,
    pub port: u16,
    /// HTTP path for DoH/DoH3 (always starts with `/`).
    pub path: String,
    /// TLS/QUIC server name (SNI). Falls back to `host` when host is not an IP.
    pub sni: String,
    pub bootstrap_resolver: Option<Arc<dyn ClashResolver>>,
    pub strategy: DnsStrategy,
    addresses: Arc<AddressCache>,
}

impl DnsEndpoint {
    pub fn parse(
        address: &str,
        protocol: DnsProtocol,
        tls_server_name: Option<&str>,
        bootstrap_resolver: Option<Arc<dyn ClashResolver>>,
        strategy: DnsStrategy,
    ) -> anyhow::Result<Self> {
        let address = address.trim();
        if address.is_empty() {
            anyhow::bail!("empty DNS upstream address");
        }

        let (hostport, path_raw) = split_hostport_path(address);
        let (host, port_opt) = split_host_port(hostport)?;

        let default_port = match protocol {
            DnsProtocol::Udp | DnsProtocol::Tcp => 53,
            DnsProtocol::Tls => 853,
            DnsProtocol::Https | DnsProtocol::H3 => 443,
            DnsProtocol::Quic => 853,
        };
        let port = port_opt.unwrap_or(default_port);

        let path = match protocol {
            DnsProtocol::Https | DnsProtocol::H3 => normalize_path(path_raw),
            _ => String::new(),
        };

        let sni = if let Some(sni) =
            tls_server_name.map(str::trim).filter(|s| !s.is_empty())
        {
            sni.to_string()
        } else if host.parse::<IpAddr>().is_ok() {
            host.clone()
        } else {
            host.clone()
        };

        Ok(Self {
            host,
            port,
            path,
            sni,
            bootstrap_resolver,
            strategy,
            addresses: Arc::new(AddressCache::default()),
        })
    }

    /// Resolve host to every allowed candidate, preferred family first.
    pub async fn resolve_addrs(&self) -> anyhow::Result<Vec<SocketAddr>> {
        // IP literals bypass shared resolution state entirely.
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            return self.select_addrs(&[ip]);
        }
        let ips = self.addresses.ips(self).await?;
        self.select_addrs(&ips)
    }

    pub(crate) fn invalidate_addresses(&self) {
        self.addresses.invalidate(self);
    }

    async fn resolve_ips(&self) -> anyhow::Result<Vec<IpAddr>> {
        let ips = if let Some(ref resolver) = self.bootstrap_resolver {
            let mut resolved = Vec::new();
            if let Ok(Some(v4)) = resolver.resolve_v4(&self.host, false).await {
                resolved.push(IpAddr::V4(v4));
            }
            if let Ok(Some(v6)) = resolver.resolve_v6(&self.host, false).await {
                resolved.push(IpAddr::V6(v6));
            }
            if resolved.is_empty() {
                anyhow::bail!(
                    "bootstrap resolve '{}' returned no addresses",
                    self.host
                );
            }
            resolved
        } else {
            // Fallback to std DNS lookup for IP literals or basic system resolution
            let addrs =
                tokio::net::lookup_host(format!("{}:{}", self.host, self.port))
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!("std resolve '{}': {}", self.host, e)
                    })?;
            addrs.map(|sa| sa.ip()).collect()
        };

        Ok(ips)
    }

    fn select_addrs(&self, ips: &[IpAddr]) -> anyhow::Result<Vec<SocketAddr>> {
        let (mut v4, mut v6): (Vec<_>, Vec<_>) = ips
            .iter()
            .copied()
            .map(|ip| SocketAddr::new(ip, self.port))
            .partition(SocketAddr::is_ipv4);
        let addresses = match &self.strategy {
            DnsStrategy::PreferIpv6 => {
                v6.extend(v4);
                v6
            }
            DnsStrategy::Ipv4Only => v4,
            DnsStrategy::Ipv6Only => v6,
            DnsStrategy::PreferIpv4 | DnsStrategy::Both => {
                v4.extend(v6);
                v4
            }
        };
        if addresses.is_empty() {
            anyhow::bail!(
                "bootstrap resolve '{}' had no addresses matching strategy {:?}",
                self.host,
                self.strategy
            );
        }
        Ok(addresses)
    }
}

fn split_hostport_path(address: &str) -> (&str, &str) {
    if let Some(slash) = address.find('/') {
        (&address[..slash], &address[slash..])
    } else {
        (address, "")
    }
}

fn split_host_port(hostport: &str) -> anyhow::Result<(String, Option<u16>)> {
    if hostport.starts_with('[') {
        let close = hostport.find(']').ok_or_else(|| {
            anyhow::anyhow!("unclosed bracket in IPv6 address '{hostport}'")
        })?;
        let host = &hostport[1..close];
        let rest = &hostport[close + 1..];
        let port = if let Some(colon) = rest.strip_prefix(':') {
            Some(
                colon
                    .parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("invalid port in '{hostport}'"))?,
            )
        } else if rest.is_empty() {
            None
        } else {
            anyhow::bail!("unexpected trailing text in '{hostport}'");
        };
        return Ok((host.to_string(), port));
    }

    if let Some(colon) = hostport.rfind(':') {
        if hostport[..colon].contains(':') {
            // Bare unbracketed IPv6 without port
            return Ok((hostport.to_string(), None));
        }
        let host = &hostport[..colon];
        let port = hostport[colon + 1..]
            .parse::<u16>()
            .map_err(|_| anyhow::anyhow!("invalid port in '{hostport}'"))?;
        return Ok((host.to_string(), Some(port)));
    }

    Ok((hostport.to_string(), None))
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        DEFAULT_DOH_PATH.to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::MockClashResolver;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn cloned_endpoints_share_ips_but_apply_their_own_port_and_strategy() {
        let mut bootstrap = MockClashResolver::new();
        bootstrap
            .expect_resolve_v4()
            .times(1)
            .returning(|_, _| Ok(Some("192.0.2.1".parse().unwrap())));
        bootstrap
            .expect_resolve_v6()
            .times(1)
            .returning(|_, _| Ok(Some("2001:db8::1".parse().unwrap())));
        let endpoint = DnsEndpoint::parse(
            "dns.example:853",
            DnsProtocol::Tls,
            None,
            Some(Arc::new(bootstrap)),
            DnsStrategy::PreferIpv4,
        )
        .unwrap();
        assert_eq!(
            endpoint.resolve_addrs().await.unwrap(),
            vec![
                "192.0.2.1:853".parse::<SocketAddr>().unwrap(),
                "[2001:db8::1]:853".parse().unwrap()
            ]
        );
        let mut doh = endpoint.clone();
        doh.port = 443;
        doh.strategy = DnsStrategy::Ipv6Only;
        assert_eq!(
            doh.resolve_addrs().await.unwrap(),
            vec!["[2001:db8::1]:443".parse::<SocketAddr>().unwrap()]
        );
        let tcp = endpoint.clone();
        assert_eq!(
            tcp.resolve_addrs().await.unwrap(),
            endpoint.resolve_addrs().await.unwrap()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn bootstrap_cache_expires_and_invalidation_is_shared() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let mut bootstrap = MockClashResolver::new();
        bootstrap
            .expect_resolve_v4()
            .times(3)
            .returning(move |_, _| {
                let index = count.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(Some(std::net::Ipv4Addr::new(192, 0, 2, index as u8)))
            });
        bootstrap
            .expect_resolve_v6()
            .times(3)
            .returning(|_, _| Ok(None));
        let endpoint = DnsEndpoint::parse(
            "dns.example",
            DnsProtocol::Udp,
            None,
            Some(Arc::new(bootstrap)),
            DnsStrategy::PreferIpv4,
        )
        .unwrap();
        let cloned = endpoint.clone();
        assert_eq!(
            endpoint.resolve_addrs().await.unwrap()[0].ip().to_string(),
            "192.0.2.1"
        );
        assert_eq!(
            cloned.resolve_addrs().await.unwrap()[0].ip().to_string(),
            "192.0.2.1"
        );
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(
            cloned.resolve_addrs().await.unwrap()[0].ip().to_string(),
            "192.0.2.2"
        );
        endpoint.invalidate_addresses();
        assert_eq!(
            cloned.resolve_addrs().await.unwrap()[0].ip().to_string(),
            "192.0.2.3"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn failed_bootstrap_is_not_cached() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let mut bootstrap = MockClashResolver::new();
        bootstrap
            .expect_resolve_v4()
            .times(2)
            .returning(move |_, _| {
                if count.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(anyhow::anyhow!("temporary bootstrap failure"))
                } else {
                    Ok(Some(std::net::Ipv4Addr::LOCALHOST))
                }
            });
        bootstrap
            .expect_resolve_v6()
            .times(2)
            .returning(|_, _| Ok(None));
        let endpoint = DnsEndpoint::parse(
            "dns.example",
            DnsProtocol::Udp,
            None,
            Some(Arc::new(bootstrap)),
            DnsStrategy::PreferIpv4,
        )
        .unwrap();
        assert!(endpoint.resolve_addrs().await.is_err());
        assert_eq!(
            endpoint.resolve_addrs().await.unwrap(),
            vec!["127.0.0.1:53".parse::<SocketAddr>().unwrap()]
        );
    }
}
