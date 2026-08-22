use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use super::transports::{PooledTransport, TransportKey};
use crate::app::dns::config::{EdnsClientSubnet, NameServer};
use crate::app::dns::endpoint::{DnsEndpoint, DnsProtocol, DnsStrategy};
use crate::app::dns::transport::{LifecycleSlot, UdpPool};
use crate::app::dns::ClashResolver;

#[derive(Default)]
pub struct UdpState {
    pub current: Option<SocketAddr>,
    pub pools: HashMap<(Option<String>, usize), (SocketAddr, Arc<UdpPool>)>,
}

impl UdpState {
    pub fn current_pool(&self, outbound: Option<&str>) -> Option<(SocketAddr, Arc<UdpPool>)> {
        let current = self.current?;
        let family = usize::from(current.is_ipv6());
        let key = (outbound.map(str::to_string), family);
        self.pools
            .get(&key)
            .filter(|(address, _)| *address == current)
            .map(|(_, pool)| (current, Arc::clone(pool)))
    }

    pub fn mark_current(&mut self, address: SocketAddr, outbound: Option<&str>) {
        let family = usize::from(address.is_ipv6());
        let key = (outbound.map(str::to_string), family);
        if self.pools
            .get(&key)
            .is_some_and(|(cached, _)| *cached == address)
        {
            self.current = Some(address);
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
    pub transports: Arc<parking_lot::Mutex<HashMap<TransportKey, Arc<LifecycleSlot<PooledTransport>>>>>,
    pub udp: Arc<parking_lot::Mutex<UdpState>>,
}

impl UpstreamEntry {
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

        let addr_str = if let Some(ref path) = ns.path {
            if ns.port != 0 && ns.port != 53 && ns.port != 443 && ns.port != 853 {
                format!("{}:{}{}", ns.host, ns.port, path)
            } else {
                format!("{}{}", ns.host, path)
            }
        } else if ns.port != 0 && ns.port != 53 && ns.port != 443 && ns.port != 853 {
            format!("{}:{}", ns.host, ns.port)
        } else {
            ns.host.to_string()
        };

        let endpoint = DnsEndpoint::parse(
            &addr_str,
            protocol,
            None,
            bootstrap_resolver,
            DnsStrategy::PreferIpv4,
        )?;

        Ok(Self {
            name: ns.to_string(),
            protocol,
            endpoint,
            outbound: ns.proxy.clone(),
            interface: ns.interface.clone(),
            ecs: None,
            transports: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            udp: Arc::new(parking_lot::Mutex::new(UdpState::default())),
        })
    }
}
