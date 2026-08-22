//! Parse DNS upstream address strings into host/port/path/SNI.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::app::dns::ClashResolver;

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

        let sni = if let Some(sni) = tls_server_name.map(str::trim).filter(|s| !s.is_empty()) {
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
        })
    }

    /// Resolve host to every allowed candidate, preferred family first.
    pub async fn resolve_addrs(&self) -> anyhow::Result<Vec<SocketAddr>> {
        let ips = if let Ok(ip) = self.host.parse::<IpAddr>() {
            vec![ip]
        } else if let Some(ref resolver) = self.bootstrap_resolver {
            let mut resolved = Vec::new();
            if let Ok(Some(v4)) = resolver.resolve_v4(&self.host, false).await {
                resolved.push(IpAddr::V4(v4));
            }
            if let Ok(Some(v6)) = resolver.resolve_v6(&self.host, false).await {
                resolved.push(IpAddr::V6(v6));
            }
            if resolved.is_empty() {
                anyhow::bail!("bootstrap resolve '{}' returned no addresses", self.host);
            }
            resolved
        } else {
            // Fallback to std DNS lookup for IP literals or basic system resolution
            let addrs = tokio::net::lookup_host(format!("{}:{}", self.host, self.port))
                .await
                .map_err(|e| anyhow::anyhow!("std resolve '{}': {}", self.host, e))?;
            addrs.map(|sa| sa.ip()).collect()
        };

        let (mut v4, mut v6): (Vec<_>, Vec<_>) = ips
            .into_iter()
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
        let close = hostport
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("unclosed bracket in IPv6 address '{hostport}'"))?;
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
