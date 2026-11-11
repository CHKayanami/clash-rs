use std::{io, net::IpAddr};

use ipnet::IpNet;

use crate::{
    config::internal::config::{DnsHijack, DnsHijackRule, TunConfig},
    session::Network,
};
use super::scope_exclusions;

// Output packets selected by the route/mangle chain already leave through TUN
// with their original destination and use the original hijack rules. DNS DNAT
// covers selected prerouting traffic before routing to TUN; only that path
// needs the synthetic destination recognized by the UDP adapter.
pub(in crate::proxy::tun) fn hijack_config(cfg: &TunConfig, hijack: DnsHijack)
    -> DnsHijack {
    if !cfg.auto_redirect { return hijack; }
    let DnsHijack::Rules(mut rules) = hijack else { return hijack; };
    let original_count = rules.len();
    for address in [cfg.auto_redirect_dns_address.0.map(IpAddr::V4),
        cfg.auto_redirect_dns_address.1.map(IpAddr::V6)].into_iter().flatten()
    {
        for index in 0..original_count {
            let DnsHijackRule::IpNet { network, port, ipnet } = rules[index] else { continue; };
            if network == Some(Network::Tcp) || ipnet.addr().is_ipv4() != address.is_ipv4() { continue; }
            let rule = DnsHijackRule::IpNet {
                network: Some(Network::Udp), ipnet: IpNet::from(address), port,
            };
            if !rules.contains(&rule) { rules.push(rule); }
        }
    }
    DnsHijack::Rules(rules)
}

pub(super) fn write_rules(script: &mut String, cfg: &TunConfig, quoted_device: &str,
    table: &str, tcp_port: Option<u16>) -> io::Result<()> {
    if !cfg.dns_hijack.is_enabled() { return Ok(()); }
    let rules = cfg.dns_hijack.rules();
    let hook = "prerouting";
    let interface = "iifname";
    let chain = "prerouting_dns";
    script.push_str(&format!("add chain inet {table} {chain} {{ type nat hook {hook} priority dstnat - 1; policy accept; }}\n"));
    let mut add = |rule: String| {
        script.push_str(&format!("add rule inet {table} {chain} {rule}\n"));
    };
    add(format!("meta mark {} return", cfg.so_mark.unwrap_or(0x162)));
    add(format!("{interface} {quoted_device} return"));
    // Never expose the resolver on host addresses, including WAN, bridge
    // and LAN service addresses. This applies to both UDP and TCP DNS.
    add("fib daddr type local return".into());
    add("ct direction reply return".into());
    add("ct state { invalid, untracked } return".into());
    for rule in scope_exclusions(cfg, interface, false, "return")? { add(rule); }
    add("ip daddr @exclude4 return".into());
    add("ip6 daddr @exclude6 return".into());
    if !cfg.routes.is_empty() || !cfg.route_address_set.is_empty() {
        add("ip daddr != @route4 return".into());
        add("ip6 daddr != @route6 return".into());
    }
    add("ip daddr { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/3 } return".into());
    add("ip6 daddr { ::/128, ::1/128, fe80::/10, ff00::/8 } return".into());
    // Respect the routing verdict, including cached bypass decisions.
    add(format!("meta mark != {} return", super::INPUT_MARK));
    for (ipv4, address) in [(true, cfg.auto_redirect_dns_address.0.map(IpAddr::V4)),
        (false, cfg.auto_redirect_dns_address.1.map(IpAddr::V6))] {
        if !ipv4 && cfg.gateway_v6.is_none() { continue; }
        let family = if ipv4 { "ip" } else { "ip6" };
        for rule in rules.iter() {
            let (network, port, destination) = match rule {
                DnsHijackRule::Any { network, port } => (network, port, String::new()),
                DnsHijackRule::IpNet { network, port, ipnet } => {
                    if ipnet.addr().is_ipv4() != ipv4 { continue; }
                    (network, port, format!("{family} daddr {ipnet} "))
                }
            };
            let nfproto = if ipv4 { "ipv4" } else { "ipv6" };
            if *network != Some(Network::Tcp) {
                let address = address.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput,
                    format!("missing validated {nfproto} auto-redirect DNS address")))?;
                add(format!("meta nfproto {nfproto} {destination}udp dport {port} dnat {family} to {address}"));
            }
            if *network != Some(Network::Udp) {
                if let Some(tcp_port) = tcp_port {
                    add(format!("meta nfproto {nfproto} {destination}tcp dport {port} redirect to :{tcp_port}"));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "dns_tests.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "dns_linux_tests.rs"]
mod linux_tests;
