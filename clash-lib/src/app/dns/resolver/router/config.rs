use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

use crate::Error;
use crate::app::dns::config::{Config as LegacyDnsConfig, EdnsClientSubnet, NameServer};
use url::Host;
use crate::app::dns::query::QType;
use crate::app::dns::fakeip::{compute_v4_range, compute_v6_range};
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
    pub client_subnet: Option<EdnsClientSubnet>,
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
    pub optimistic_cache_ttl: u32,
    pub stale_cache_retention: u32,
    pub cache_capacity: usize,
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
            optimistic_cache_ttl: 0,
            stale_cache_retention: 3600,
            cache_capacity: 4096,
        }
    }
}

impl RouterConfig {
    pub fn validate(&self) -> Result<(), Error> {
        for ns in &self.default_nameserver {
            if matches!(ns.host, Host::Domain(_)) {
                return Err(Error::InvalidConfig(format!(
                    "dns2.default-nameserver must use an IP address: {ns}",
                )));
            }
        }
        let mut tags = HashSet::new();
        let mut fakeip_tag = None;
        for upstream in &self.upstreams {
            if upstream.tag.trim().is_empty() || !tags.insert(upstream.tag.as_str()) {
                return Err(Error::InvalidConfig(format!(
                    "dns2.upstreams tag must be nonempty and unique: '{}'", upstream.tag,
                )));
            }
            if upstream.upstream_type == UpstreamType::Remote && upstream.servers.is_empty() {
                return Err(Error::InvalidConfig(format!(
                    "dns2.upstreams['{}'].server has no usable nameservers", upstream.tag,
                )));
            }
            if upstream.upstream_type != UpstreamType::FakeIp {
                continue;
            }
            if let Some(first) = fakeip_tag {
                return Err(Error::InvalidConfig(format!(
                    "dns2 allows only one fakeip upstream: '{first}' and '{}'",
                    upstream.tag,
                )));
            }
            fakeip_tag = Some(upstream.tag.as_str());
            compute_v4_range(&upstream.inet4_range).map_err(|error| {
                Error::InvalidConfig(format!(
                    "dns2.upstreams['{}'].inet4-range: {error}", upstream.tag,
                ))
            })?;
            compute_v6_range(&upstream.inet6_range).map_err(|error| {
                Error::InvalidConfig(format!(
                    "dns2.upstreams['{}'].inet6-range: {error}", upstream.tag,
                ))
            })?;
        }
        let check_tag = |tag: &str, field: &str| -> Result<(), Error> {
            if !tags.contains(tag) {
                return Err(Error::InvalidConfig(format!(
                    "{field}: unknown dns2 upstream '{tag}'",
                )));
            }
            Ok(())
        };
        for (index, rule) in self.request_rules.iter().enumerate() {
            if let RequestAction::Route(tag) = &rule.action {
                check_tag(tag, &format!("dns2.routing.request[{index}].upstream"))?;
            }
        }
        if let RequestAction::Route(tag) = &self.request_fallback {
            check_tag(tag, "dns2.routing.request.fallback")?;
        }
        for (index, rule) in self.response_rules.iter().enumerate() {
            if let Some(tag) = &rule.from_upstream {
                check_tag(tag, &format!("dns2.routing.response[{index}].from-upstream"))?;
            }
            if let ResponseAction::Requery(tag) = &rule.action {
                check_tag(tag, &format!("dns2.routing.response[{index}].upstream"))?;
            }
        }
        if let ResponseAction::Requery(tag) = &self.response_fallback {
            check_tag(tag, "dns2.routing.response.fallback")?;
        }
        Ok(())
    }

    pub fn from_def(def: &DefDns2Config, global_ipv6: bool) -> Result<Self, Error> {
        let mut hosts = HashMap::new();
        for (domain, value) in &def.hosts {
            let mut ips = Vec::new();
            match value {
                Dns2StringOrList::Single(s) => {
                    ips.push(s.parse::<IpAddr>().map_err(|e| {
                        Error::InvalidConfig(format!(
                            "invalid dns2.hosts['{domain}'] address '{s}': {e}"
                        ))
                    })?);
                }
                Dns2StringOrList::List(l) => {
                    for s in l {
                        ips.push(s.parse::<IpAddr>().map_err(|e| {
                            Error::InvalidConfig(format!(
                                "invalid dns2.hosts['{domain}'] address '{s}': {e}"
                            ))
                        })?);
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

        if default_nameserver.is_empty() {
            return Err(Error::InvalidConfig(
                "dns2.default-nameserver has no usable nameservers".into(),
            ));
        }

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
                "remote" => UpstreamType::Remote,
                _ => return Err(Error::InvalidConfig(format!(
                    "dns2.upstreams['{}'].type: unsupported type '{}'", u.tag, u.r#type,
                ))),
            };

            let servers = if let Some(ref s_def) = u.servers {
                let raw_servers = s_def.as_slice();
                LegacyDnsConfig::parse_nameserver(raw_servers)?
            } else {
                Vec::new()
            };

            let inet4_range = u.inet4_range.parse::<ipnet::Ipv4Net>().map_err(|e| {
                Error::InvalidConfig(format!(
                    "invalid dns2.upstreams['{}'].inet4-range '{}': {e}",
                    u.tag, u.inet4_range
                ))
            })?;
            let inet6_range = u.inet6_range.parse::<ipnet::Ipv6Net>().map_err(|e| {
                Error::InvalidConfig(format!(
                    "invalid dns2.upstreams['{}'].inet6-range '{}': {e}",
                    u.tag, u.inet6_range
                ))
            })?;

            let client_subnet = u.client_subnet.as_deref().map(|value| {
                let subnet = value.trim().parse::<IpNet>()
                    .or_else(|_| value.trim().parse::<IpAddr>().map(IpNet::from))
                    .map_err(|error| Error::InvalidConfig(format!(
                        "invalid dns2.upstreams['{}'].client-subnet '{value}': {error}", u.tag,
                    )))?;
                Ok::<_, Error>(match subnet {
                    IpNet::V4(ipv4) => EdnsClientSubnet { ipv4: Some(ipv4), ipv6: None },
                    IpNet::V6(ipv6) => EdnsClientSubnet { ipv4: None, ipv6: Some(ipv6) },
                })
            }).transpose()?;

            upstreams.push(UpstreamConfig {
                tag: u.tag.clone(),
                upstream_type,
                servers,
                proxy: u.proxy.clone(),
                client_subnet,
                inet4_range,
                inet6_range,
                ttl: u.ttl,
            });
        }

        let mut request_rules = Vec::new();
        let mut request_fallback = RequestAction::Reject(RejectCode::Nodata);

        for (index, r) in def.routing.request.iter().enumerate() {
            if let Some(ref fb) = r.fallback {
                request_fallback = RequestAction::Route(fb.clone());
                continue;
            }

            let mut qtypes = HashSet::new();
            for qt_str in &r.query_type {
                let qt = QType::from_str(qt_str).map_err(|e| Error::InvalidConfig(format!(
                    "invalid dns2.routing.request[{index}].query-type '{qt_str}': {e}"
                )))?;
                qtypes.insert(qt);
            }

            let mut sips = Vec::new();
            for sip_str in &r.source_ip_cidr {
                if let Ok(net) = sip_str.parse::<IpNet>() {
                    sips.push(net);
                } else if let Ok(ip) = sip_str.parse::<IpAddr>() {
                    sips.push(IpNet::from(ip));
                } else {
                    return Err(Error::InvalidConfig(format!(
                        "invalid dns2.routing.request[{index}].source-ip-cidr '{sip_str}'"
                    )));
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

        for (index, r) in def.routing.response.iter().enumerate() {
            if let Some(ref fb) = r.fallback {
                response_fallback = match fb.to_ascii_lowercase().as_str() {
                    "reject" => ResponseAction::Reject,
                    _ => ResponseAction::Accept,
                };
                continue;
            }

            let mut qtypes = HashSet::new();
            for qt_str in &r.query_type {
                let qt = QType::from_str(qt_str).map_err(|e| Error::InvalidConfig(format!(
                    "invalid dns2.routing.response[{index}].query-type '{qt_str}': {e}"
                )))?;
                qtypes.insert(qt);
            }

            let mut cidrs = Vec::new();
            for ip_str in &r.ip_cidr {
                if let Ok(net) = ip_str.parse::<IpNet>() {
                    cidrs.push(net);
                } else if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    cidrs.push(IpNet::from(ip));
                } else {
                    return Err(Error::InvalidConfig(format!(
                        "invalid dns2.routing.response[{index}].ip-cidr '{ip_str}'"
                    )));
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

        let config = Self {
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
            optimistic_cache_ttl: def.optimistic_cache_ttl,
            stale_cache_retention: def.stale_cache_retention,
            cache_capacity: def.cache_capacity.unwrap_or(4096).max(1),
        };
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod config_error_tests {
    use super::*;
    use crate::config::def::Dns2UpstreamDef;

    #[test]
    fn client_subnet_parses_both_families_and_rejects_invalid_values() {
        for value in ["192.0.2.129/25", "2001:db8::1/57", "192.0.2.1", "2001:db8::1"] {
            let mut def = DefDns2Config::default();
            def.upstreams.push(Dns2UpstreamDef {
                tag: "primary".into(), r#type: "remote".into(),
                servers: Some(Dns2StringOrList::Single("192.0.2.53".into())),
                client_subnet: Some(value.into()), ..Default::default()
            });
            let cfg = RouterConfig::from_def(&def, true).unwrap();
            let ecs = cfg.upstreams[0].client_subnet.as_ref().unwrap();
            assert_eq!(ecs.ipv4.is_some(), !value.contains(':'));
            assert_eq!(ecs.ipv6.is_some(), value.contains(':'));
        }
        for value in ["", "bad", "192.0.2.1/33", "2001:db8::1/129"] {
            let mut def = DefDns2Config::default();
            def.upstreams.push(Dns2UpstreamDef {
                tag: "primary".into(), r#type: "remote".into(), client_subnet: Some(value.into()), ..Default::default()
            });
            let error = RouterConfig::from_def(&def, true).err().unwrap().to_string();
            assert!(error.contains("dns2.upstreams['primary'].client-subnet"));
        }
    }

    #[test]
    fn invalid_dns2_upstream_range_identifies_tag_and_value() {
        let mut def = DefDns2Config::default();
        def.upstreams.push(crate::config::def::Dns2UpstreamDef {
            tag: "primary".into(), r#type: "remote".into(),
            inet4_range: "bad".into(),
            ..Default::default()
        });
        let error = RouterConfig::from_def(&def, true).err().unwrap().to_string();
        assert!(error.contains("dns2.upstreams['primary'].inet4-range"));
        assert!(error.contains("bad"));
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod validation_tests;
