use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use tracing::warn;

use crate::Error;
use crate::app::dns::config::{Config as LegacyDnsConfig, NameServer};
use crate::app::dns::query::QType;
use crate::config::def::{DNSListen, Dns2Config as DefDns2Config, Dns2StringOrList};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectCode {
    Nodata,
    Nxdomain,
    Refused,
}

impl RejectCode {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "nxdomain" => Self::Nxdomain,
            "refused" => Self::Refused,
            _ => Self::Nodata,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamType {
    Remote,
    Local,
    FakeIp,
}

#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub tag: String,
    pub upstream_type: UpstreamType,
    pub servers: Vec<NameServer>,
    pub proxy: Option<String>,
    pub client_subnet: Option<crate::app::dns::config::EdnsClientSubnet>,
    pub inet4_range: ipnet::Ipv4Net,
    pub inet6_range: ipnet::Ipv6Net,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestAction {
    Route(String),
    Reject(RejectCode),
}

#[derive(Debug, Clone)]
pub struct RequestRule {
    pub domain: Vec<String>,
    pub rule_set: Vec<String>,
    pub query_type: HashSet<QType>,
    pub source_ip_cidr: Vec<IpNet>,
    pub action: RequestAction,
    pub invert: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseAction {
    Accept,
    Reject,
    Requery(String),
}

#[derive(Debug, Clone)]
pub struct ResponseRule {
    pub from_upstream: Option<String>,
    pub domain: Vec<String>,
    pub rule_set: Vec<String>,
    pub query_type: HashSet<QType>,
    pub ip_cidr: Vec<IpNet>,
    pub action: ResponseAction,
    pub invert: bool,
}

#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub enable: bool,
    pub listen: Option<DNSListen>,
    pub ipv6: bool,
    pub use_hosts: bool,
    pub hosts_files: Vec<String>,
    pub hosts: HashMap<String, Vec<IpAddr>>,
    pub default_nameserver: Vec<NameServer>,
    pub proxy_server_nameserver: Vec<NameServer>,
    pub upstreams: Vec<UpstreamConfig>,
    pub request_rules: Vec<RequestRule>,
    pub request_fallback: RequestAction,
    pub response_rules: Vec<ResponseRule>,
    pub response_fallback: ResponseAction,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            enable: true,
            listen: None,
            ipv6: true,
            use_hosts: true,
            hosts_files: Vec::new(),
            hosts: HashMap::new(),
            default_nameserver: Vec::new(),
            proxy_server_nameserver: Vec::new(),
            upstreams: Vec::new(),
            request_rules: Vec::new(),
            request_fallback: RequestAction::Reject(RejectCode::Nodata),
            response_rules: Vec::new(),
            response_fallback: ResponseAction::Accept,
        }
    }
}

impl RouterConfig {
    pub fn from_def(def: &DefDns2Config, global_ipv6: bool) -> Result<Self, Error> {
        let mut hosts = HashMap::new();
        for (domain, value) in &def.hosts {
            let mut ips = Vec::new();
            match value {
                Dns2StringOrList::Single(s) => {
                    if let Ok(ip) = s.parse::<IpAddr>() {
                        ips.push(ip);
                    } else {
                        warn!("invalid IP address in dns2.hosts: {s}");
                    }
                }
                Dns2StringOrList::List(l) => {
                    for s in l {
                        if let Ok(ip) = s.parse::<IpAddr>() {
                            ips.push(ip);
                        } else {
                            warn!("invalid IP address in dns2.hosts: {s}");
                        }
                    }
                }
            }
            if !ips.is_empty() {
                hosts.insert(domain.to_ascii_lowercase(), ips);
            }
        }

        let default_nameserver = if !def.default_nameserver.is_empty() {
            LegacyDnsConfig::parse_nameserver(&def.default_nameserver)?
        } else {
            LegacyDnsConfig::parse_nameserver(&["114.114.114.114".to_string(), "8.8.8.8".to_string()])?
        };

        let proxy_server_nameserver = if !def.proxy_server_nameserver.is_empty() {
            LegacyDnsConfig::parse_nameserver(&def.proxy_server_nameserver)?
        } else {
            Vec::new()
        };

        let mut upstreams = Vec::new();
        for u in &def.upstreams {
            let upstream_type = match u.r#type.to_ascii_lowercase().as_str() {
                "local" => UpstreamType::Local,
                "fakeip" => UpstreamType::FakeIp,
                _ => UpstreamType::Remote,
            };

            let servers = if let Some(ref s_def) = u.servers {
                let raw_servers = s_def.as_slice();
                LegacyDnsConfig::parse_nameserver(raw_servers)?
            } else {
                Vec::new()
            };

            let inet4_range = u
                .inet4_range
                .parse::<ipnet::Ipv4Net>()
                .unwrap_or_else(|_| "198.18.0.1/16".parse().unwrap());
            let inet6_range = u
                .inet6_range
                .parse::<ipnet::Ipv6Net>()
                .unwrap_or_else(|_| "fc00::/18".parse().unwrap());

            upstreams.push(UpstreamConfig {
                tag: u.tag.clone(),
                upstream_type,
                servers,
                proxy: u.proxy.clone(),
                client_subnet: None,
                inet4_range,
                inet6_range,
                ttl: u.ttl,
            });
        }

        let mut request_rules = Vec::new();
        let mut request_fallback = RequestAction::Reject(RejectCode::Nodata);

        for r in &def.routing.request {
            if let Some(ref fb) = r.fallback {
                request_fallback = RequestAction::Route(fb.clone());
                continue;
            }

            let mut qtypes = HashSet::new();
            for qt_str in &r.query_type {
                if let Ok(qt) = QType::from_str(qt_str) {
                    qtypes.insert(qt);
                }
            }

            let mut sips = Vec::new();
            for sip_str in &r.source_ip_cidr {
                if let Ok(net) = sip_str.parse::<IpNet>() {
                    sips.push(net);
                } else if let Ok(ip) = sip_str.parse::<IpAddr>() {
                    sips.push(IpNet::from(ip));
                }
            }

            let action = if let Some(ref action_str) = r.action {
                match action_str.to_ascii_lowercase().as_str() {
                    "reject" => {
                        let code = r
                            .reject_code
                            .as_deref()
                            .map(RejectCode::parse)
                            .unwrap_or(RejectCode::Nodata);
                        RequestAction::Reject(code)
                    }
                    _ => {
                        if let Some(ref ups) = r.upstream {
                            RequestAction::Route(ups.clone())
                        } else {
                            RequestAction::Reject(RejectCode::Nodata)
                        }
                    }
                }
            } else if let Some(ref ups) = r.upstream {
                RequestAction::Route(ups.clone())
            } else {
                continue;
            };

            request_rules.push(RequestRule {
                domain: r.domain.iter().map(|d| d.to_ascii_lowercase()).collect(),
                rule_set: r.rule_set.clone(),
                query_type: qtypes,
                source_ip_cidr: sips,
                action,
                invert: r.invert,
            });
        }

        let mut response_rules = Vec::new();
        let mut response_fallback = ResponseAction::Accept;

        for r in &def.routing.response {
            if let Some(ref fb) = r.fallback {
                response_fallback = match fb.to_ascii_lowercase().as_str() {
                    "reject" => ResponseAction::Reject,
                    _ => ResponseAction::Accept,
                };
                continue;
            }

            let mut qtypes = HashSet::new();
            for qt_str in &r.query_type {
                if let Ok(qt) = QType::from_str(qt_str) {
                    qtypes.insert(qt);
                }
            }

            let mut cidrs = Vec::new();
            for ip_str in &r.ip_cidr {
                if let Ok(net) = ip_str.parse::<IpNet>() {
                    cidrs.push(net);
                } else if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    cidrs.push(IpNet::from(ip));
                }
            }

            let action = if let Some(ref action_str) = r.action {
                match action_str.to_ascii_lowercase().as_str() {
                    "reject" => ResponseAction::Reject,
                    "accept" => ResponseAction::Accept,
                    _ => {
                        if let Some(ref ups) = r.upstream {
                            ResponseAction::Requery(ups.clone())
                        } else {
                            ResponseAction::Accept
                        }
                    }
                }
            } else if let Some(ref ups) = r.upstream {
                ResponseAction::Requery(ups.clone())
            } else {
                ResponseAction::Accept
            };

            response_rules.push(ResponseRule {
                from_upstream: r.from_upstream.clone(),
                domain: r.domain.iter().map(|d| d.to_ascii_lowercase()).collect(),
                rule_set: r.rule_set.clone(),
                query_type: qtypes,
                ip_cidr: cidrs,
                action,
                invert: r.invert,
            });
        }

        Ok(Self {
            enable: def.enable,
            listen: def.listen.clone(),
            ipv6: global_ipv6 && def.ipv6,
            use_hosts: def.use_hosts,
            hosts_files: def.hosts_files.clone(),
            hosts,
            default_nameserver,
            proxy_server_nameserver,
            upstreams,
            request_rules,
            request_fallback,
            response_rules,
            response_fallback,
        })
    }
}
