use std::fmt::Write;

use ipnet::IpNet;

use crate::config::internal::config::TunConfig;

// Four interval sets keep lookup independent of the number of provider CIDRs.
// Aggregate before loading: nft rejects overlapping intervals. CIDR syntax also
// handles terminal addresses (/0, 255.255.255.255 and ffff::/16) without overflow.
pub(super) fn write_sets(script: &mut String, cfg: &TunConfig, table: &str, create: bool) {
    for (name, ipv4, networks) in [
        ("route4", true, &cfg.routes),
        ("route6", false, &cfg.routes),
        ("exclude4", true, &cfg.route_exclude_address),
        ("exclude6", false, &cfg.route_exclude_address),
    ] {
        write_set(script, table, name, ipv4, networks, create);
    }
}

pub(super) fn write_set(script: &mut String, table: &str, name: &str, ipv4: bool,
    networks: &[IpNet], create: bool) {
    if create {
        let kind = if ipv4 { "ipv4_addr" } else { "ipv6_addr" };
        writeln!(script, "add set inet {table} {name} {{ type {kind}; flags interval; }}").unwrap();
    } else {
        writeln!(script, "flush set inet {table} {name}").unwrap();
    }
    let networks: Vec<_> = networks.iter().copied()
        .filter(|network| network.addr().is_ipv4() == ipv4).collect();
    let networks = IpNet::aggregate(&networks);
    // Bound each command without truncating large providers. All chunks and
    // all four sets remain part of one atomic nft transaction on stdin.
    for chunk in networks.chunks(512) {
        write!(script, "add element inet {table} {name} {{ ").unwrap();
        for (index, network) in chunk.iter().enumerate() {
            if index != 0 { script.push_str(", "); }
            write!(script, "{network}").unwrap();
        }
        script.push_str(" }\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn address_sets_load_every_chunk_of_large_providers() {
        let cfg = TunConfig { routes: (0..6000).map(|index| {
            IpNet::new(Ipv4Addr::from(0x0a000000 + index * 2).into(), 32).unwrap()
        }).collect(), ..Default::default() };
        let mut script = String::new();
        write_sets(&mut script, &cfg, "test", false);
        assert_eq!(script.matches("add element inet test route4").count(), 12);
        for network in &cfg.routes { assert!(script.contains(&network.to_string())); }
    }

    #[test]
    fn address_sets_aggregate_and_keep_terminal_addresses() {
        let cfg = TunConfig { routes: ["10.0.0.0/24", "10.0.1.0/24", "10.0.0.0/25"]
            .map(|value| value.parse().unwrap()).to_vec(),
            route_exclude_address: ["255.255.255.255/32", "ffff::/16"]
                .map(|value| value.parse().unwrap()).to_vec(), ..Default::default() };
        let mut script = String::new();
        write_sets(&mut script, &cfg, "test", true);
        assert!(script.contains("route4 { 10.0.0.0/23 }"));
        assert!(script.contains("exclude4 { 255.255.255.255/32 }"));
        assert!(script.contains("exclude6 { ffff::/16 }"));
        script.clear();
        write_sets(&mut script, &TunConfig::default(), "test", false);
        assert_eq!(script.matches("flush set").count(), 4);
        assert!(!script.contains("add element"));
    }
}
