use serde::{Deserialize, Serialize};

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

    /// Automatically manage default route and direct offload.
    #[serde(default = "default_true", rename = "auto-route")]
    pub auto_route: bool,

    /// General bypass ports (applies to both source and dest).
    #[serde(default = "default_bypass_ports", rename = "bypass-ports")]
    pub bypass_ports: Vec<u16>,

    /// Source ports to bypass (e.g., local sshd 22, dhcp 67/68, local web servers).
    #[serde(default = "default_bypass_ports", rename = "bypass-src-ports")]
    pub bypass_src_ports: Vec<u16>,

    /// Destination ports to bypass (e.g., direct dns 53, direct ntp 123).
    #[serde(default, rename = "bypass-dst-ports")]
    pub bypass_dst_ports: Vec<u16>,

    /// General bypass IPs/CIDRs (applies to both source and dest).
    #[serde(default, rename = "bypass-ips")]
    pub bypass_ips: Vec<String>,

    /// Source IPs/CIDRs to bypass (e.g., specific LAN client IPs).
    #[serde(default, rename = "bypass-src-ips")]
    pub bypass_src_ips: Vec<String>,

    /// Destination IPs/CIDRs to bypass (e.g., local subnets, multicast).
    #[serde(default = "default_bypass_dst_ips", rename = "bypass-dst-ips")]
    pub bypass_dst_ips: Vec<String>,

    /// General proxy whitelist ports (applies to both source and dest).
    #[serde(default, rename = "proxy-ports")]
    pub proxy_ports: Vec<u16>,

    /// Source ports to proxy (only traffic with these source ports will be proxied).
    #[serde(default, rename = "proxy-src-ports")]
    pub proxy_src_ports: Vec<u16>,

    /// Destination ports to proxy (e.g. 80, 443; only traffic to these ports will be proxied).
    #[serde(default, rename = "proxy-dst-ports")]
    pub proxy_dst_ports: Vec<u16>,

    /// General proxy whitelist IPs/CIDRs (applies to both source and dest).
    #[serde(default, rename = "proxy-ips")]
    pub proxy_ips: Vec<String>,

    /// Source IPs/CIDRs to proxy (e.g. specific LAN client IPs to be proxied).
    #[serde(default, rename = "proxy-src-ips")]
    pub proxy_src_ips: Vec<String>,

    /// Destination IPs/CIDRs to proxy (only traffic to these destination IPs will be proxied).
    #[serde(default, rename = "proxy-dst-ips")]
    pub proxy_dst_ips: Vec<String>,

    /// Automatically offload DIRECT domains/IPs to eBPF map for fast path forwarding.
    #[serde(default = "default_true", rename = "auto-direct-offload")]
    pub auto_direct_offload: bool,
}

fn default_tproxy_port() -> u16 {
    12345
}

fn default_true() -> bool {
    true
}

fn default_bypass_ports() -> Vec<u16> {
    vec![22, 67, 68, 5353]
}

fn default_bypass_dst_ips() -> Vec<String> {
    vec![
        "127.0.0.0/8".to_string(),
        "169.254.0.0/16".to_string(),
        "224.0.0.0/4".to_string(),
        "::1/128".to_string(),
        "fe80::/10".to_string(),
        "fc00::/7".to_string(),
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
            auto_route: true,
            bypass_ports: default_bypass_ports(),
            bypass_src_ports: default_bypass_ports(),
            bypass_dst_ports: Vec::new(),
            bypass_ips: Vec::new(),
            bypass_src_ips: Vec::new(),
            bypass_dst_ips: default_bypass_dst_ips(),
            proxy_ports: Vec::new(),
            proxy_src_ports: Vec::new(),
            proxy_dst_ports: Vec::new(),
            proxy_ips: Vec::new(),
            proxy_src_ips: Vec::new(),
            proxy_dst_ips: Vec::new(),
            auto_direct_offload: true,
        }
    }
}
