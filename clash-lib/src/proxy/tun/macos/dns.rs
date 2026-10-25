use std::{io, net::{IpAddr, Ipv4Addr, SocketAddr}};

use core_foundation::{array::CFArray, base::{CFType, TCFType},
    dictionary::CFDictionary, number::CFNumber, string::CFString};
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
use uuid::Uuid;

use crate::{config::internal::config::TunConfig, session::Network};

/// Publish only a private, session-owned service. configd removes these keys
/// when this store connection closes, including on process termination.
pub(super) struct Dns {
    _store: SCDynamicStore,
}

pub(super) fn server(cfg: &TunConfig) -> Option<Ipv4Addr> {
    if !cfg.route_all { return None; }
    // Use an address adjacent to the interface, never the TCP NAT client (.2)
    // or the interface's own address. Route it explicitly into the TUN.
    let address = (2..=4).filter_map(|offset| {
        Some(Ipv4Addr::from(u32::from(cfg.gateway.addr()).checked_add(offset)?))
    }).find(|address| *address != cfg.gateway.network()
        && *address != cfg.gateway.broadcast())?;
    if cfg.route_exclude_address.iter().any(|net| net.contains(&IpAddr::V4(address))) {
        return None;
    }
    let socket = SocketAddr::new(IpAddr::V4(address), 53);
    (cfg.dns_hijack.is_hijacked(Network::Udp, &socket)
        && (!cfg.enable_tcp || cfg.dns_hijack.is_hijacked(Network::Tcp, &socket)))
        .then_some(address)
}

impl Dns {
    pub(super) fn new(name: &str, address: Ipv4Addr, gateway: Ipv4Addr) -> io::Result<Self> {
        let store = SCDynamicStoreBuilder::new("ClashRS TUN DNS")
            .session_keys(true).build()
            .ok_or_else(|| io::Error::other("create TUN DNS dynamic store"))?;
        let service = format!("State:/Network/Service/ClashRS-{}", Uuid::new_v4());
        let strings = |values: &[&str]| {
            CFArray::from_CFTypes(&values.iter()
                .map(|value| CFString::new(value)).collect::<Vec<_>>()).as_CFType()
        };
        let dns: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[
            (CFString::new("ServerAddresses"), strings(&[&address.to_string()])),
            (CFString::new("SupplementalMatchDomains"), strings(&[""])),
            (CFString::new("SupplementalMatchOrders"),
                CFArray::from_CFTypes(&[CFNumber::from(0i32)]).as_CFType()),
            (CFString::new("InterfaceName"), CFString::new(name).as_CFType()),
        ]);
        let ipv4: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[
            (CFString::new("InterfaceName"), CFString::new(name).as_CFType()),
            (CFString::new("Addresses"), strings(&[&gateway.to_string()])),
            (CFString::new("SubnetMasks"), strings(&["255.255.255.255"])),
        ]);
        if !store.set(format!("{service}/IPv4").as_str(), ipv4.to_untyped()) {
            return Err(io::Error::other("publish TUN DNS interface"));
        }
        if !store.set(format!("{service}/DNS").as_str(), dns.to_untyped()) {
            return Err(io::Error::other("publish TUN DNS service"));
        }
        Ok(Self { _store: store })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::internal::config::DnsHijack;

    #[test]
    fn dns_requires_routing_and_matching_hijack_rules() {
        let mut cfg = TunConfig { route_all: true, dns_hijack: DnsHijack::All,
            gateway: "198.18.0.1/30".parse().unwrap(),
            ..Default::default() };
        let address = server(&cfg).unwrap();
        assert_ne!(address, cfg.gateway.addr());
        assert_ne!(address, cfg.gateway.broadcast());
        cfg.dns_hijack = DnsHijack::Rules(vec!["udp://any:53".parse().unwrap()]);
        assert_eq!(server(&cfg), None);
        cfg.enable_tcp = false;
        assert_eq!(server(&cfg), Some(address));
        cfg.route_all = false;
        assert_eq!(server(&cfg), None);
    }
}
