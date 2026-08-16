use crate::{
    Error,
    app::{
        dns,
        net::Interface,
        remote_content_manager::providers::rule_provider::{
            RuleSetBehavior, RuleSetFormat,
        },
    },
    common::auth,
    config::{
        def::{self, LogLevel, RunMode},
        internal::{proxy::OutboundProxy, rule::RuleType},
    },
};
use anyhow::anyhow;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use super::{
    listener::{InboundOpts, InboundProviderDef},
    proxy::OutboundProxyProviderDef,
};

pub struct Config {
    pub general: General,
    pub dns: dns::Config,
    pub tun: TunConfig,
    pub experimental: Option<def::Experimental>,
    pub profile: Profile,
    pub sniffer: Option<crate::app::sniffer::SnifferConfig>,
    pub rules: Vec<RuleType>,
    pub rule_providers: HashMap<String, RuleProviderDef>,
    pub users: Vec<auth::User>,
    /// a list maintaining the order from the config file
    pub proxy_names: Vec<String>,
    pub proxies: HashMap<String, OutboundProxy>,
    pub proxy_groups: HashMap<String, OutboundProxy>,
    pub proxy_providers: HashMap<String, OutboundProxyProviderDef>,
    pub listeners: HashSet<InboundOpts>,
    pub inbound_providers: HashMap<String, InboundProviderDef>,
}

impl Config {
    pub fn validate(self) -> Result<Self, crate::Error> {
        for r in self.rules.iter() {
            if !self.proxies.contains_key(r.target())
                && !self.proxy_groups.contains_key(r.target())
            {
                return Err(Error::InvalidConfig(format!(
                    "proxy `{}` referenced in a rule was not found",
                    r.target()
                )));
            }
        }
        // Check for duplicate AnyTLS user passwords
        for opts in &self.listeners {
            if let crate::config::internal::listener::InboundOpts::Anytls {
                common_opts,
                users,
                ..
            } = opts
            {
                let mut seen = std::collections::HashSet::new();
                for u in users {
                    if !seen.insert(u.password.as_str()) {
                        return Err(Error::InvalidConfig(format!(
                            "anytls inbound '{}': duplicate user password",
                            common_opts.name
                        )));
                    }
                }
            }
        }
        Ok(self)
    }
}

pub struct General {
    pub authentication: Vec<String>,
    pub bind_address: BindAddress,
    pub controller: Controller,
    pub mode: RunMode,
    pub log_level: LogLevel,
    pub ipv6: bool,
    pub interface: Option<Interface>,
    pub routing_mask: Option<u32>,
    pub mmdb: Option<String>,
    pub mmdb_download_url: Option<String>,
    pub asn_mmdb: Option<String>,
    pub asn_mmdb_download_url: Option<String>,

    pub geosite: Option<String>,
    pub geosite_download_url: Option<String>,
}

pub struct Profile {
    pub store_selected: bool,
    pub store_smart_stats: bool,
    // this is read to dns config directly
    // store_fake_ip: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DnsHijackRule {
    Any {
        network: Option<crate::session::Network>,
        port: u16,
    },
    IpNet {
        network: Option<crate::session::Network>,
        ipnet: IpNet,
        port: u16,
    },
}

impl std::str::FromStr for DnsHijackRule {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (network, rest) = if let Some(stripped) = s.strip_prefix("tcp://") {
            (Some(crate::session::Network::Tcp), stripped)
        } else if let Some(stripped) = s.strip_prefix("udp://") {
            (Some(crate::session::Network::Udp), stripped)
        } else {
            (None, s)
        };

        let (host_str, port) = if let Some((h, p)) = rest.rsplit_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                (h, port)
            } else {
                (rest, 53)
            }
        } else {
            (rest, 53)
        };

        if host_str.eq_ignore_ascii_case("any")
            || host_str == "0.0.0.0"
            || host_str == "::"
        {
            Ok(DnsHijackRule::Any { network, port })
        } else if let Ok(ipnet) = host_str.parse::<IpNet>() {
            Ok(DnsHijackRule::IpNet {
                network,
                ipnet,
                port,
            })
        } else if let Ok(ip) = host_str.parse::<std::net::IpAddr>() {
            let ipnet = match ip {
                std::net::IpAddr::V4(v4) => {
                    IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap())
                }
                std::net::IpAddr::V6(v6) => {
                    IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap())
                }
            };
            Ok(DnsHijackRule::IpNet {
                network,
                ipnet,
                port,
            })
        } else {
            Err(crate::Error::InvalidConfig(format!(
                "invalid dns-hijack rule: {s}"
            )))
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum DnsHijack {
    Disabled,
    All,
    Rules(Vec<DnsHijackRule>),
}

impl Default for DnsHijack {
    fn default() -> Self {
        Self::Disabled
    }
}

impl DnsHijack {
    pub fn is_enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    pub fn is_hijacked(
        &self,
        network: crate::session::Network,
        dst: &std::net::SocketAddr,
    ) -> bool {
        match self {
            Self::Disabled => false,
            Self::All => dst.port() == 53,
            Self::Rules(rules) => rules.iter().any(|rule| match rule {
                DnsHijackRule::Any {
                    network: net,
                    port,
                } => (net.is_none() || *net == Some(network)) && dst.port() == *port,
                DnsHijackRule::IpNet {
                    network: net,
                    ipnet,
                    port,
                } => {
                    (net.is_none() || *net == Some(network))
                        && dst.port() == *port
                        && ipnet.contains(&dst.ip())
                }
            }),
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct TunConfig {
    pub enable: bool,
    pub device_id: String,
    pub stack: Option<String>,
    pub route_all: bool,
    pub routes: Vec<IpNet>,
    pub route_exclude_address: Vec<IpNet>,
    pub auto_detect_interface: bool,
    pub gateway: Ipv4Net,
    pub gateway_v6: Option<Ipv6Net>,
    pub mtu: Option<u16>,
    pub gso: Option<bool>,
    pub gso_max_size: Option<u32>,
    pub so_mark: Option<u32>,
    pub route_table: u32,
    pub iproute2_rule_index: Option<u32>,
    pub strict_route: bool,
    pub endpoint_independent_nat: bool,
    pub udp_timeout: Option<u64>,
    pub file_descriptor: Option<i32>,
    pub include_interface: Vec<String>,
    pub exclude_interface: Vec<String>,
    pub include_uid: Vec<u32>,
    pub exclude_uid: Vec<u32>,
    pub include_android_user: Vec<i32>,
    pub include_package: Vec<String>,
    pub exclude_package: Vec<String>,
    pub dns_hijack: DnsHijack,
}

#[derive(Serialize, Clone, Debug, Copy, PartialEq, Hash, Eq)]
#[serde(transparent)]
pub struct BindAddress(pub IpAddr);
impl BindAddress {
    pub fn all_v4() -> Self {
        Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    pub fn dual_stack() -> Self {
        Self(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    }

    pub fn local() -> Self {
        Self(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    pub fn is_localhost(&self) -> bool {
        match self.0 {
            IpAddr::V4(ip) => ip.is_loopback(),
            IpAddr::V6(ip) => ip.is_loopback(),
        }
    }
}
impl Default for BindAddress {
    fn default() -> Self {
        Self::all_v4()
    }
}

impl<'de> Deserialize<'de> for BindAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        match str.as_str() {
            "*" => Ok(Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
            "localhost" => Ok(Self(IpAddr::from([127, 0, 0, 1]))),
            "[::]" | "::" => Ok(Self(IpAddr::V6(Ipv6Addr::UNSPECIFIED))),
            _ => {
                if let Ok(ip) = str.parse::<IpAddr>() {
                    Ok(Self(ip))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "Invalid BindAddress value {str}"
                    )))
                }
            }
        }
    }
}

impl FromStr for BindAddress {
    type Err = anyhow::Error;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match str {
            "*" => Ok(Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
            "localhost" => Ok(Self(IpAddr::from([127, 0, 0, 1]))),
            "[::]" | "::" => Ok(Self(IpAddr::V6(Ipv6Addr::UNSPECIFIED))),
            _ => {
                if let Ok(ip) = str.parse::<IpAddr>() {
                    Ok(Self(ip))
                } else {
                    Err(anyhow!("Invalid BindAddress value {str}"))
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Controller {
    pub external_controller: Option<String>,
    pub external_controller_ipc: Option<String>,
    pub external_ui: Option<String>,
    pub external_ui_download_url: Option<String>,
    pub secret: Option<String>,
    pub cors_allow_origins: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum RuleProviderDef {
    Http(HttpRuleProvider),
    File(FileRuleProvider),
    Inline(InlineRuleProvider),
}

#[derive(Serialize, Deserialize)]
pub struct HttpRuleProvider {
    pub url: String,
    pub interval: u64,
    pub behavior: RuleSetBehavior,
    pub path: String,
    pub format: Option<RuleSetFormat>,
    #[serde(alias = "payload")]
    pub inline_rules: Option<Vec<String>>,
    pub proxy: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct FileRuleProvider {
    pub path: String,
    pub interval: Option<u64>,
    pub behavior: RuleSetBehavior,
    pub format: Option<RuleSetFormat>,
    #[serde(alias = "payload")]
    pub inline_rules: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct InlineRuleProvider {
    pub path: String,
    pub behavior: RuleSetBehavior,
    #[serde(alias = "payload")]
    pub inline_rules: Vec<String>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{
        config::{
            def,
            internal::{
                config::{DnsHijack, DnsHijackRule},
                convert::convert,
            },
            listener::InboundOpts,
        },
        session::Network,
    };

    #[test]
    fn from_def_config() {
        let cfg = r#"
        port: 9090
        mixed-port: "9091"
        "#;
        let c = cfg.parse::<def::Config>().expect("should parse");
        assert_eq!(c.port.map(|x| x.into()), Some(9090));
        assert_eq!(c.mixed_port.map(|x| x.into()), Some(9091));
        let cc = convert(c).expect("should convert");

        assert!(cc.listeners.iter().any(|listener| match listener {
            InboundOpts::Http { common_opts, .. } => common_opts.port == 9090,
            _ => false,
        }));
        assert!(cc.listeners.iter().any(|listener| match listener {
            InboundOpts::Mixed { common_opts, .. } => common_opts.port == 9091,
            _ => false,
        }));
    }

    #[test]
    fn test_dns_hijack_rules() {
        let rule_any = DnsHijackRule::from_str("any:53").unwrap();
        let rule_tcp = DnsHijackRule::from_str("tcp://8.8.8.8:53").unwrap();
        let rule_udp = DnsHijackRule::from_str("udp://1.1.1.1:53").unwrap();
        let rule_subnet = DnsHijackRule::from_str("198.18.0.0/16:53").unwrap();

        let hijack_any = DnsHijack::Rules(vec![rule_any]);
        assert!(hijack_any.is_hijacked(Network::Tcp, &"1.2.3.4:53".parse().unwrap()));
        assert!(hijack_any.is_hijacked(Network::Udp, &"1.2.3.4:53".parse().unwrap()));

        let hijack = DnsHijack::Rules(vec![rule_tcp, rule_udp, rule_subnet]);

        let addr_8888 = "8.8.8.8:53".parse().unwrap();
        let addr_1111 = "1.1.1.1:53".parse().unwrap();
        let addr_fakeip = "198.18.0.2:53".parse().unwrap();
        let addr_other = "9.9.9.9:53".parse().unwrap();

        assert!(hijack.is_hijacked(Network::Tcp, &addr_8888));
        assert!(!hijack.is_hijacked(Network::Udp, &addr_8888));

        assert!(hijack.is_hijacked(Network::Udp, &addr_1111));
        assert!(!hijack.is_hijacked(Network::Tcp, &addr_1111));

        assert!(hijack.is_hijacked(Network::Tcp, &addr_fakeip));
        assert!(hijack.is_hijacked(Network::Udp, &addr_fakeip));

        assert!(!hijack.is_hijacked(Network::Tcp, &addr_other));
        assert!(!hijack.is_hijacked(Network::Udp, &addr_other));

        let hijack_all = DnsHijack::All;
        assert!(hijack_all.is_hijacked(Network::Tcp, &addr_other));
        assert!(hijack_all.is_hijacked(Network::Udp, &addr_other));
        assert!(!hijack_all.is_hijacked(Network::Udp, &"9.9.9.9:80".parse().unwrap()));
    }
}
