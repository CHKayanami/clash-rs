use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

#[derive(Default)]
pub(super) struct StaticBypass {
    pub source_ports: Vec<u16>,
    pub dest_ports: Vec<u16>,
    pub source_v4: Vec<Ipv4Net>,
    pub source_v6: Vec<Ipv6Net>,
    pub dest_v4: Vec<Ipv4Net>,
    pub dest_v6: Vec<Ipv6Net>,
}

impl StaticBypass {
    pub fn new(
        source_ports: &[u16], dest_ports: &[u16],
        source_ips: &[String], dest_ips: &[String], tproxy_port: u16,
    ) -> Result<Self, String> {
        let (source_v4, source_v6) = parse_static_bypass_nets(source_ips, "source")?;
        let (dest_v4, dest_v6) = parse_static_bypass_nets(dest_ips, "destination")?;
        Ok(Self {
            source_ports: select_static_bypass_ports(source_ports, tproxy_port),
            dest_ports: select_static_bypass_ports(dest_ports, tproxy_port),
            source_v4, source_v6, dest_v4, dest_v6,
        })
    }

    pub fn map_capacities(&self) -> Result<[(&'static str, u32); 6], String> {
        let counts = [
            ("BYPASS_SRC_PORTS", self.source_ports.len()),
            ("BYPASS_DST_PORTS", self.dest_ports.len()),
            ("BYPASS_SRC_IPS", self.source_v4.len()),
            ("BYPASS_SRC_IP6S", self.source_v6.len()),
            ("BYPASS_DST_IPS", self.dest_v4.len()),
            ("BYPASS_DST_IP6S", self.dest_v6.len()),
        ];
        let mut capacities = [("", 1); 6];
        for (slot, (name, count)) in capacities.iter_mut().zip(counts) {
            *slot = (name, map_capacity(name, count)?);
        }
        Ok(capacities)
    }
}

fn map_capacity(name: &str, count: usize) -> Result<u32, String> {
    u32::try_from(count.max(1))
        .map_err(|_| format!("static bypass map '{name}' entry count exceeds u32: {count}"))
}

fn parse_static_bypass_nets(
    entries: &[String],
    label: &str,
) -> Result<(Vec<Ipv4Net>, Vec<Ipv6Net>), String> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for entry in entries {
        if let Ok(net) = IpNet::from_str(entry) {
            match net {
                IpNet::V4(net) => v4.push(net),
                IpNet::V6(net) => v6.push(net),
            }
        } else if let Ok(ip) = IpAddr::from_str(entry) {
            match ip {
                IpAddr::V4(ip) => {
                    v4.push(Ipv4Net::new(ip, 32).map_err(|e| {
                        format!("invalid static {label} bypass IP {ip}: {e}")
                    })?)
                }
                IpAddr::V6(ip) => {
                    v6.push(Ipv6Net::new(ip, 128).map_err(|e| {
                        format!("invalid static {label} bypass IP {ip}: {e}")
                    })?)
                }
            }
        } else {
            return Err(format!("invalid static {label} bypass IP/CIDR: {entry}"));
        }
    }

    let v4 = Ipv4Net::aggregate(&v4);
    let v6 = Ipv6Net::aggregate(&v6);
    Ok((v4, v6))
}

fn select_static_bypass_ports(configured: &[u16], tproxy_port: u16) -> Vec<u16> {
    let mut seen = HashSet::new();
    std::iter::once(tproxy_port).chain(configured.iter().copied())
        .filter(|port| seen.insert(*port)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn static_bypass_exceeds_previous_limits_without_truncation() {
        let mut ips: Vec<String> = (0..5000u32)
            .map(|i| Ipv4Addr::from(0x0a00_0000 + i * 2).to_string())
            .collect();
        ips.extend((0..5000u128)
            .map(|i| Ipv6Addr::from(0x20010db8u128 << 96 | i * 2).to_string()));
        let ports: Vec<u16> = (1..=300).collect();
        let bypass = StaticBypass::new(&ports, &ports, &ips, &ips, 12345).unwrap();
        assert_eq!(bypass.map_capacities().unwrap(), [
            ("BYPASS_SRC_PORTS", 301), ("BYPASS_DST_PORTS", 301),
            ("BYPASS_SRC_IPS", 5000), ("BYPASS_SRC_IP6S", 5000),
            ("BYPASS_DST_IPS", 5000), ("BYPASS_DST_IP6S", 5000),
        ]);
        assert_eq!(bypass.source_v4.last().unwrap().addr(),
            Ipv4Addr::from(0x0a00_0000 + 4999 * 2));
        assert_eq!(bypass.dest_v6.last().unwrap().addr(),
            Ipv6Addr::from(0x20010db8u128 << 96 | 4999 * 2));
    }

    #[test]
    fn static_bypass_capacities_follow_aggregation_and_deduplication() {
        let ips = ["10.0.0.0/24", "10.0.1.1/24", "10.0.0.1",
            "2001:db8::/64", "2001:db8::1"]
            .into_iter().map(String::from).collect::<Vec<_>>();
        let bypass = StaticBypass::new(&[80, 80, 12345], &[443], &[], &ips, 12345)
            .unwrap();
        assert_eq!(bypass.source_ports, vec![12345, 80]);
        assert_eq!(bypass.map_capacities().unwrap(), [
            ("BYPASS_SRC_PORTS", 2), ("BYPASS_DST_PORTS", 2),
            ("BYPASS_SRC_IPS", 1), ("BYPASS_SRC_IP6S", 1),
            ("BYPASS_DST_IPS", 1), ("BYPASS_DST_IP6S", 1),
        ]);
        assert!(bypass.source_v4.is_empty());
        assert_eq!(bypass.dest_v4, vec!["10.0.0.0/23".parse().unwrap()]);
    }

    #[test]
    fn static_bypass_rejects_invalid_entries_and_capacity_overflow() {
        let error = StaticBypass::new(&[], &[], &[], &["invalid".into()], 12345)
            .err().unwrap();
        assert!(error.contains("destination"));
        assert_eq!(map_capacity("empty", 0).unwrap(), 1);
        assert_eq!(map_capacity("full", u32::MAX as usize).unwrap(), u32::MAX);
        if let Some(count) = (u32::MAX as usize).checked_add(1) {
            assert!(map_capacity("overflow", count).is_err());
        }
    }
}
