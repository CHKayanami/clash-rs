use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct EbpfLanConfig {
    /// Source ports to bypass (e.g., local sshd 22, dhcp 67/68, local web servers).
    #[serde(default = "default_bypass_src_ports", rename = "bypass-src-ports")]
    pub bypass_src_ports: Vec<u16>,

    /// Source ports to proxy (only traffic from these source ports will be proxied).
    #[serde(default, rename = "proxy-src-ports")]
    pub proxy_src_ports: Vec<u16>,

    /// Source IPs/CIDRs to bypass (e.g., specific LAN client IPs).
    #[serde(default, rename = "bypass-src-ips", alias = "bypass-clients")]
    pub bypass_src_ips: Vec<String>,

    /// Source IPs/CIDRs to proxy (e.g., specific LAN client IPs to be proxied).
    #[serde(default, rename = "proxy-src-ips", alias = "proxy-clients")]
    pub proxy_src_ips: Vec<String>,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct EbpfTargetConfig {
    /// Destination ports to bypass (e.g., direct dns 53, direct ntp 123).
    #[serde(default, rename = "bypass-dst-ports")]
    pub bypass_dst_ports: Vec<u16>,

    /// Destination ports to proxy (e.g. 80, 443; only traffic to these ports will be proxied).
    #[serde(default, rename = "proxy-dst-ports")]
    pub proxy_dst_ports: Vec<u16>,

    /// Destination IPs/CIDRs to bypass (e.g., local subnets, multicast).
    #[serde(default = "default_bypass_dst_ips", rename = "bypass-dst-ips")]
    pub bypass_dst_ips: Vec<String>,

    /// Destination IPs/CIDRs to proxy (only traffic to these destination IPs will be proxied).
    #[serde(default, rename = "proxy-dst-ips")]
    pub proxy_dst_ips: Vec<String>,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct EbpfHostConfig {
    /// Whether to proxy local machine originated traffic (default: false).
    #[serde(default, rename = "proxy-local")]
    pub proxy_local: bool,

    /// Process names (comm) to proxy for local traffic. If non-empty, only matching processes will be proxied.
    #[serde(default, rename = "proxy-processes", alias = "proxy-process")]
    pub proxy_processes: Vec<String>,

    /// Process names (comm) to bypass for local traffic. Matching processes will be bypassed directly.
    #[serde(default, rename = "bypass-processes", alias = "bypass-process")]
    pub bypass_processes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EbpfConfig {
    #[serde(default)]
    pub enable: bool,

    /// LAN interfaces to attach eBPF ingress filter.
    #[serde(default, rename = "lan-interface")]
    pub lan_interface: Vec<String>,

    /// WAN interface to attach eBPF egress filter (e.g. "auto" or interface name).
    #[serde(default, rename = "wan-interface")]
    pub wan_interface: Option<String>,

    /// TCP transparent proxy port inside daens.
    #[serde(default = "default_tproxy_port", rename = "tproxy-port")]
    pub tproxy_port: u16,

    /// UDP transparent proxy port inside daens.
    #[serde(default = "default_tproxy_port", rename = "tproxy-udp-port")]
    pub tproxy_udp_port: u16,

    /// Automatically offload DIRECT domains/IPs to eBPF map for fast path forwarding.
    #[serde(default = "default_true", rename = "auto-direct-offload")]
    pub auto_direct_offload: bool,

    /// Optional routing mark for bypass detection (e.g. from routing-mark).
    #[serde(default, rename = "routing-mark")]
    pub routing_mark: Option<u32>,

    /// LAN client configuration policies (TC Ingress on LAN interfaces).
    #[serde(default)]
    pub lan: EbpfLanConfig,

    /// Target destination configuration policies (both LAN and Host traffic).
    #[serde(default)]
    pub target: EbpfTargetConfig,

    /// Host-local traffic configuration policies (TC Egress on WAN interface & cgroups).
    #[serde(default)]
    pub host: EbpfHostConfig,
}

fn default_tproxy_port() -> u16 {
    12345
}

fn default_true() -> bool {
    true
}

fn default_bypass_src_ports() -> Vec<u16> {
    vec![22, 67, 68, 5353]
}

fn default_bypass_dst_ips() -> Vec<String> {
    vec![
        "127.0.0.0/8".to_string(),
        "169.254.0.0/16".to_string(),
        "224.0.0.0/4".to_string(),
        "::1/128".to_string(),
        "fe80::/10".to_string(),
        "ff00::/8".to_string(),
    ]
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            enable: false,
            lan_interface: Vec::new(),
            wan_interface: Some("auto".to_string()),
            tproxy_port: default_tproxy_port(),
            tproxy_udp_port: default_tproxy_port(),
            auto_direct_offload: true,
            routing_mark: None,
            lan: EbpfLanConfig {
                bypass_src_ports: default_bypass_src_ports(),
                proxy_src_ports: Vec::new(),
                bypass_src_ips: Vec::new(),
                proxy_src_ips: Vec::new(),
            },
            target: EbpfTargetConfig {
                bypass_dst_ports: Vec::new(),
                proxy_dst_ports: Vec::new(),
                bypass_dst_ips: default_bypass_dst_ips(),
                proxy_dst_ips: Vec::new(),
            },
            host: EbpfHostConfig::default(),
        }
    }
}

/// Parse, deduplicate, and aggregate a list of IP/CIDR strings.
pub fn aggregate_ip_cidrs(entries: impl IntoIterator<Item = impl AsRef<str>>) -> Vec<String> {
    use std::str::FromStr;

    let mut v4_nets = Vec::new();
    let mut v6_nets = Vec::new();

    for item in entries {
        let s = item.as_ref().trim();
        if s.is_empty() {
            continue;
        }

        if let Ok(net) = ipnet::IpNet::from_str(s) {
            match net {
                ipnet::IpNet::V4(v4) => v4_nets.push(v4),
                ipnet::IpNet::V6(v6) => v6_nets.push(v6),
            }
        } else if let Ok(ip) = std::net::IpAddr::from_str(s) {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    if let Ok(net) = ipnet::Ipv4Net::new(v4, 32) {
                        v4_nets.push(net);
                    }
                }
                std::net::IpAddr::V6(v6) => {
                    if let Ok(net) = ipnet::Ipv6Net::new(v6, 128) {
                        v6_nets.push(net);
                    }
                }
            }
        }
    }

    let agg_v4 = ipnet::Ipv4Net::aggregate(&v4_nets);
    let agg_v6 = ipnet::Ipv6Net::aggregate(&v6_nets);

    let mut result = Vec::with_capacity(agg_v4.len() + agg_v6.len());
    for n in agg_v4 {
        result.push(n.to_string());
    }
    for n in agg_v6 {
        result.push(n.to_string());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregate_ip_cidrs() {
        let inputs = vec![
            "192.168.1.0/24",
            "192.168.1.10/32",
            "10.0.0.0/24",
            "10.0.1.0/24",
            "10.0.2.0/24",
            "10.0.3.0/24",
            "::1",
            "fe80::/10",
            "fe80::1/128",
        ];

        let agg = aggregate_ip_cidrs(&inputs);
        assert!(agg.contains(&"192.168.1.0/24".to_string()));
        assert!(!agg.contains(&"192.168.1.10/32".to_string())); // subsumed
        assert!(agg.contains(&"10.0.0.0/22".to_string())); // merged 4 /24s into /22
        assert!(agg.contains(&"::1/128".to_string()));
        assert!(agg.contains(&"fe80::/10".to_string()));
        assert!(!agg.contains(&"fe80::1/128".to_string())); // subsumed
    }
}
