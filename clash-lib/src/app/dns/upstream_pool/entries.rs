use std::sync::Arc;

use super::transports::TransportPool;
use super::udp::UdpUpstream;
use crate::app::dns::ClashResolver;
use crate::app::dns::config::{EdnsClientSubnet, NameServer};
use crate::app::dns::endpoint::{DnsEndpoint, DnsProtocol, DnsStrategy};

/// Only the connection state used by this upstream's protocol is allocated.
pub enum UpstreamState {
    Udp(UdpUpstream),
    Transport(TransportPool),
}

impl UpstreamState {
    pub(crate) async fn close(&self) {
        match self {
            Self::Udp(udp) => udp.close().await,
            Self::Transport(pool) => pool.close().await,
        }
    }
}

#[derive(Clone)]
pub struct UpstreamEntry {
    pub name: String,
    pub protocol: DnsProtocol,
    pub endpoint: DnsEndpoint,
    pub outbound: Option<String>,
    pub interface: Option<crate::app::net::OutboundInterface>,
    pub ecs: Option<EdnsClientSubnet>,
    /// Protocol-specific connection state, shared across entry clones.
    pub state: Arc<UpstreamState>,
}

impl UpstreamEntry {
    pub(super) fn udp_state(&self) -> anyhow::Result<&UdpUpstream> {
        match self.state.as_ref() {
            UpstreamState::Udp(udp) => Ok(udp),
            UpstreamState::Transport(_) => {
                anyhow::bail!("upstream '{}' is not UDP", self.name)
            }
        }
    }

    pub fn from_nameserver(
        ns: &NameServer,
        bootstrap_resolver: Option<Arc<dyn ClashResolver>>,
    ) -> anyhow::Result<Self> {
        let protocol = match ns.net {
            crate::app::dns::config::DNSNetMode::Udp => DnsProtocol::Udp,
            crate::app::dns::config::DNSNetMode::Tcp => DnsProtocol::Tcp,
            crate::app::dns::config::DNSNetMode::Tls => DnsProtocol::Tls,
            crate::app::dns::config::DNSNetMode::Https => DnsProtocol::Https,
            crate::app::dns::config::DNSNetMode::Dhcp => {
                anyhow::bail!("DHCP DNS is not supported")
            }
            crate::app::dns::config::DNSNetMode::Quic => DnsProtocol::Quic,
            crate::app::dns::config::DNSNetMode::H3 => DnsProtocol::H3,
        };

        let host = ns.host.to_string();
        let host = if host.contains(':') && !host.starts_with('[') {
            format!("[{}]", ns.host)
        } else {
            host
        };
        let address = format!("{host}{}", ns.path.as_deref().unwrap_or(""));
        let mut endpoint = DnsEndpoint::parse(
            &address,
            protocol,
            None,
            bootstrap_resolver,
            DnsStrategy::PreferIpv4,
        )?;
        if ns.port != 0 {
            endpoint.port = ns.port;
        }

        let state = Arc::new(match protocol {
            DnsProtocol::Udp => {
                UpstreamState::Udp(UdpUpstream::new(&endpoint, ns.proxy.clone()))
            }
            _ => UpstreamState::Transport(TransportPool::new(ns.proxy.clone())),
        });
        Ok(Self {
            name: ns.to_string(),
            protocol,
            endpoint,
            outbound: ns.proxy.clone(),
            interface: ns.interface.clone(),
            ecs: None,
            state,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::config::DNSNetMode;

    #[test]
    fn explicit_ports_are_preserved_for_every_protocol() {
        for protocol in [
            DNSNetMode::Udp,
            DNSNetMode::Tcp,
            DNSNetMode::Tls,
            DNSNetMode::Https,
            DNSNetMode::Quic,
            DNSNetMode::H3,
        ] {
            for port in [53, 443, 853, 5353] {
                for host in [
                    url::Host::Domain("dns.example".into()),
                    url::Host::Ipv6("::1".parse().unwrap()),
                ] {
                    let ns = NameServer {
                        net: protocol.clone(),
                        host,
                        port,
                        path: Some("/custom".into()),
                        interface: None,
                        proxy: None,
                    };
                    let entry = UpstreamEntry::from_nameserver(&ns, None).unwrap();
                    assert_eq!(entry.endpoint.port, port);
                    assert_eq!(
                        matches!(entry.state.as_ref(), UpstreamState::Udp(_)),
                        matches!(protocol, DNSNetMode::Udp)
                    );
                    let clone = entry.clone();
                    assert!(Arc::ptr_eq(&entry.state, &clone.state));
                    if matches!(protocol, DNSNetMode::Https | DNSNetMode::H3) {
                        assert_eq!(entry.endpoint.path, "/custom");
                    }
                    assert!(!entry.endpoint.host.starts_with('['));
                }
            }
        }
    }
}
