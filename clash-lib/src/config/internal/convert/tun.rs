use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use crate::config::internal::tun::{AUTO_REDIRECT_INPUT_MARK, AUTO_REDIRECT_BYPASS_MARK, TunDevice, parse_device_id, validate_interface_name};

use crate::app::remote_content_manager::providers::rule_provider::RuleSetBehavior;
use crate::app::dns::{config::Config as DnsConfig, resolver::router::config::UpstreamType};
use crate::session::Network;

use crate::{
    Error,
    config::{config, def},
};

// Resolve once during conversion. Runtime DNS rules and hijack matching share
// the same addresses, so neither has to derive or guess the other's targets.
pub(super) fn configure_dns_hijack(tun: &mut config::TunConfig, dns: &DnsConfig)
    -> Result<(), Error> {
    tun.auto_redirect_dns_address = (None, None);
    if !tun.auto_redirect || !tun.dns_hijack.is_enabled() { return Ok(()); }
    let rules = tun.dns_hijack.rules();
    let mut addresses = (None, None);
    for network in [Some(IpNet::V4(tun.gateway)), tun.gateway_v6.map(IpNet::V6)]
        .into_iter().flatten()
    {
        if !rules.iter().any(|rule| match rule {
            config::DnsHijackRule::Any { network, .. } => *network != Some(Network::Tcp),
            config::DnsHijackRule::IpNet { network: protocol, ipnet, .. } => {
                *protocol != Some(Network::Tcp) && ipnet.addr().is_ipv4() == network.addr().is_ipv4()
            }
        }) { continue; }
        let next = match network {
            IpNet::V4(network) => u32::from(network.addr()).checked_add(1)
                .map(Ipv4Addr::from).filter(|address| *address != network.broadcast()).map(IpAddr::V4),
            IpNet::V6(network) => u128::from(network.addr()).checked_add(1)
                .map(Ipv6Addr::from).map(IpAddr::V6),
        };
        let address = next.filter(|address| network.contains(address)).ok_or_else(|| Error::InvalidConfig(
            format!("auto-redirect DNS hijack requires a non-broadcast next address in {network}"),
        ))?;
        let overlaps = if let Some(dns2) = &dns.dns2 {
            dns2.enable && dns2.upstreams.iter().any(|upstream| {
                upstream.upstream_type == UpstreamType::FakeIp && match address {
                    IpAddr::V4(address) => upstream.inet4_range.contains(&address),
                    IpAddr::V6(address) => upstream.inet6_range.contains(&address),
                }
            })
        } else {
            dns.enable && matches!(dns.enhance_mode, def::DNSMode::FakeIp) && match address {
                IpAddr::V4(address) => dns.fake_ip_range.contains(&address),
                IpAddr::V6(address) => dns.fake_ip_range6.contains(&address),
            }
        };
        if overlaps {
            return Err(Error::InvalidConfig(format!(
                "auto-redirect DNS address {address} overlaps a fake-ip pool; change tun.gateway/gateway-v6 or the fake-ip range",
            )));
        }
        match address {
            IpAddr::V4(address) => addresses.0 = Some(address),
            IpAddr::V6(address) => addresses.1 = Some(address),
        }
    }
    tun.auto_redirect_dns_address = addresses;
    Ok(())
}

pub(super) fn validate_address_sets(
    tun: Option<&def::TunConfig>,
    providers: Option<&HashMap<String, def::RuleProviderDef>>,
) -> Result<(), Error> {
    let Some(tun) = tun else { return Ok(()); };
    for (field, names) in [
        ("route-address-set", &tun.route_address_set),
        ("route-exclude-address-set", &tun.route_exclude_address_set),
    ] {
        for name in names {
            let provider = providers.and_then(|registry| registry.get(name))
                .ok_or_else(|| Error::InvalidConfig(format!(
                    "tun.{field}: rule-provider '{name}' does not exist",
                )))?;
            let behavior = match provider {
                def::RuleProviderDef::Http(provider) => provider.behavior,
                def::RuleProviderDef::File(provider) => provider.behavior,
                def::RuleProviderDef::Inline(provider) => provider.behavior,
            };
            if behavior != RuleSetBehavior::Ipcidr {
                return Err(Error::InvalidConfig(format!(
                    "tun.{field}: rule-provider '{name}' must use ipcidr behavior",
                )));
            }
        }
    }
    Ok(())
}

pub fn convert(
    before: Option<def::TunConfig>,
) -> Result<config::TunConfig, crate::Error> {
    match before {
        Some(t) => {
            if (!t.route_address_set.is_empty() || !t.route_exclude_address_set.is_empty())
                && !t.auto_redirect
            {
                return Err(Error::InvalidConfig(
                    "tun.route-address-set and route-exclude-address-set require auto-redirect".into(),
                ));
            }
            let device_id = if let Some(fd) = t.file_descriptor {
                if t.device_id == "utun1989" || t.device_id.is_empty() {
                    format!("fd://{fd}")
                } else { t.device_id }
            } else { t.device_id };
            let parsed_device = parse_device_id(&device_id)?;
            if t.auto_redirect {
                let TunDevice::Interface { name, .. } = &parsed_device else {
                    return Err(Error::InvalidConfig("tun.auto-redirect requires a managed TUN device".into()));
                };
                validate_interface_name(name)?;
                for name in t.include_interface.iter().flatten()
                    .chain(t.exclude_interface.iter().flatten())
                {
                    validate_interface_name(name)?;
                }
                if t.so_mark.is_some_and(|mark| matches!(mark, 0 | AUTO_REDIRECT_INPUT_MARK | AUTO_REDIRECT_BYPASS_MARK)) {
                    return Err(Error::InvalidConfig(
                        "tun.auto-redirect requires a nonzero so-mark different from 0x163 and 0x164".into(),
                    ));
                }
                if !t.route_all {
                    return Err(Error::InvalidConfig("tun.auto-redirect requires auto-route".into()));
                }
                if !cfg!(target_os = "linux") {
                    return Err(Error::InvalidConfig("tun.auto-redirect is only supported on Linux".into()));
                }
                if t.file_descriptor.is_some() {
                    return Err(Error::InvalidConfig("tun.auto-redirect requires a managed TUN device".into()));
                }
                if !t.include_android_user.as_ref().is_none_or(Vec::is_empty)
                    || !t.include_package.as_ref().is_none_or(Vec::is_empty)
                    || !t.exclude_package.as_ref().is_none_or(Vec::is_empty)
                {
                    return Err(Error::InvalidConfig("tun.auto-redirect does not support Android user or package filters".into()));
                }
            }
            let mut raw_routes = t.routes.unwrap_or_default();
            if let Some(r4) = t.inet4_route_address {
                raw_routes.extend(r4);
            }
            if let Some(r6) = t.inet6_route_address {
                raw_routes.extend(r6);
            }

            let mut raw_exclude_routes = t.route_exclude_address.unwrap_or_default();
            if let Some(er4) = t.inet4_route_exclude_address {
                raw_exclude_routes.extend(er4);
            }
            if let Some(er6) = t.inet6_route_exclude_address {
                raw_exclude_routes.extend(er6);
            }

            let device_id = if let TunDevice::FileDescriptor(fd) = parsed_device {
                format!("fd://{fd}")
            } else { device_id };

            let routes = raw_routes
                .into_iter()
                .map(|route| {
                    route.parse().map_err(|e| {
                        Error::InvalidConfig(format!("invalid tun.routes entry '{route}': {e}"))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            let route_exclude_address = raw_exclude_routes
                .into_iter()
                .map(|route| {
                    route.parse().map_err(|e| {
                        Error::InvalidConfig(format!(
                            "invalid tun.route-exclude-address entry '{route}': {e}"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok(config::TunConfig {
                enable: t.enable,
                enable_tcp: t.enable_tcp.unwrap_or(true),
                device_id,
                stack: t.stack,
                route_all: t.route_all,
                auto_redirect: t.auto_redirect,
                auto_redirect_dns_address: (None, None),
                route_address_set: t.route_address_set,
                route_exclude_address_set: t.route_exclude_address_set,
                routes,
                route_exclude_address,
                auto_detect_interface: t.auto_detect_interface.unwrap_or(false),
                gateway: t.gateway.parse().map_err(|e| {
                    Error::InvalidConfig(format!("invalid tun.gateway '{}': {e}", t.gateway))
                })?,
                gateway_v6: t
                    .gateway_v6
                    .map(|gateway| {
                        gateway.parse().map_err(|e| {
                            Error::InvalidConfig(format!(
                                "invalid tun.gateway-v6 '{gateway}': {e}"
                            ))
                        })
                    })
                    .transpose()?,
                mtu: t.mtu,
                gso: t.gso,
                so_mark: t.so_mark,
                route_table: t.route_table,
                iproute2_rule_index: t.iproute2_rule_index,
                strict_route: t.strict_route.unwrap_or(false),
                endpoint_independent_nat: t.endpoint_independent_nat.unwrap_or(false),
                udp_timeout: t.udp_timeout,
                file_descriptor: t.file_descriptor,
                include_interface: t.include_interface.unwrap_or_default(),
                exclude_interface: t.exclude_interface.unwrap_or_default(),
                include_uid: t.include_uid.unwrap_or_default(),
                exclude_uid: t.exclude_uid.unwrap_or_default(),
                include_android_user: t.include_android_user.unwrap_or_default(),
                include_package: t.include_package.unwrap_or_default(),
                exclude_package: t.exclude_package.unwrap_or_default(),
                dns_hijack: match t.dns_hijack {
                    def::DnsHijack::Switch(b) => {
                        if b {
                            config::DnsHijack::All
                        } else {
                            config::DnsHijack::Disabled
                        }
                    }
                    def::DnsHijack::List(list) => {
                        if list.is_empty() {
                            config::DnsHijack::Disabled
                        } else {
                            let rules = list
                                .into_iter()
                                .map(|rule| {
                                    rule.parse().map_err(|e| {
                                        Error::InvalidConfig(format!(
                                            "invalid tun.dns-hijack entry '{rule}': {e}"
                                        ))
                                    })
                                })
                                .collect::<Result<Vec<config::DnsHijackRule>, _>>()?;
                            config::DnsHijack::Rules(rules)
                        }
                    }
                },
                max_pooled_buffers: t.max_pooled_buffers,
            })
        }
        None => Ok(config::TunConfig::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_redirect_dns_addresses_reject_broadcast_and_fake_ip_overlap() {
        let mut cfg = config::TunConfig { auto_redirect: true, dns_hijack: config::DnsHijack::All,
            gateway: "172.18.0.1/30".parse().unwrap(),
            gateway_v6: Some("fdfe:dcba:9876::1/126".parse().unwrap()), ..Default::default() };
        let dns = DnsConfig { enable: true, enhance_mode: def::DNSMode::FakeIp,
            fake_ip_range: "198.18.0.1/16".parse().unwrap(),
            fake_ip_range6: "fc00::/18".parse().unwrap(), ..Default::default() };
        configure_dns_hijack(&mut cfg, &dns).unwrap();
        assert_eq!(cfg.auto_redirect_dns_address,
            (Some("172.18.0.2".parse().unwrap()), Some("fdfe:dcba:9876::2".parse().unwrap())));
        for gateway in ["172.18.0.2/30", "172.18.0.1/32", "255.255.255.255/32"] {
            cfg.gateway = gateway.parse().unwrap();
            assert!(configure_dns_hijack(&mut cfg, &dns).unwrap_err().to_string().contains("non-broadcast"));
        }
        cfg.gateway = "198.18.0.1/24".parse().unwrap();
        assert!(configure_dns_hijack(&mut cfg, &dns).unwrap_err().to_string().contains("overlaps a fake-ip pool"));
        cfg.gateway = "172.18.0.1/30".parse().unwrap();
        cfg.gateway_v6 = Some("fc00::1/126".parse().unwrap());
        assert!(configure_dns_hijack(&mut cfg, &dns).unwrap_err().to_string().contains("overlaps a fake-ip pool"));
        cfg.gateway_v6 = Some("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128".parse().unwrap());
        assert!(configure_dns_hijack(&mut cfg, &dns).is_err());
    }

    #[test]
    fn auto_redirect_dns_addresses_validate_dns2_fake_ip_pools() {
        let raw: def::Config = "dns2:\n  enable: true\n  upstreams:\n    - tag: fake\n      type: fakeip\n      inet4-range: 172.18.0.0/24\n".parse().unwrap();
        let dns = (&raw).try_into().unwrap();
        let mut cfg = config::TunConfig { auto_redirect: true, dns_hijack: config::DnsHijack::All,
            gateway: "172.18.0.1/30".parse().unwrap(), ..Default::default() };
        assert!(configure_dns_hijack(&mut cfg, &dns).unwrap_err().to_string().contains("overlaps a fake-ip pool"));
    }

    #[test]
    fn tun_fd_scheme_is_normalized_and_rejected_by_auto_redirect() {
        let raw = yaml_serde::from_str("enable: true\ndevice: FD://3\n").unwrap();
        assert_eq!(convert(Some(raw)).unwrap().device_id, "fd://3");
        let raw = yaml_serde::from_str(
            "enable: true\ndevice: FD://3\nauto-route: true\nauto-redirect: true\n",
        ).unwrap();
        assert!(convert(Some(raw)).unwrap_err().to_string().contains("managed TUN device"));
        let raw = yaml_serde::from_str("enable: true\nfile-descriptor: 3\n").unwrap();
        assert_eq!(convert(Some(raw)).unwrap().device_id, "fd://3");
        let raw = yaml_serde::from_str("enable: true\nfile-descriptor: -1\n").unwrap();
        assert!(convert(Some(raw)).unwrap_err().to_string().contains("nonnegative"));
        let raw = yaml_serde::from_str("enable: true\ndevice: http://tun0\n").unwrap();
        assert!(convert(Some(raw)).unwrap_err().to_string().contains("device scheme"));
    }

    #[test]
    fn auto_redirect_marks_are_validated_during_conversion() {
        for mark in [0, AUTO_REDIRECT_INPUT_MARK, AUTO_REDIRECT_BYPASS_MARK] {
            let raw = yaml_serde::from_str(&format!(
                "enable: true\nauto-route: true\nauto-redirect: true\nso-mark: {mark}\n",
            )).unwrap();
            assert!(convert(Some(raw)).unwrap_err().to_string().contains("nonzero so-mark"));
        }
    }

    #[test]
    fn address_sets_require_auto_redirect() {
        for field in ["route-address-set", "route-exclude-address-set"] {
            let raw = yaml_serde::from_str(&format!("enable: true\n{field}: [networks]\n")).unwrap();
            assert!(convert(Some(raw)).unwrap_err().to_string().contains("require auto-redirect"));
        }
    }

    #[test]
    fn address_sets_validate_provider_names_and_behavior() {
        let raw: def::TunConfig = yaml_serde::from_str(
            "enable: true\nroute-address-set: [networks]\n",
        ).unwrap();
        assert!(validate_address_sets(Some(&raw), None).unwrap_err().to_string()
            .contains("networks"));
        for (behavior, valid) in [("ipcidr", true), ("domain", false), ("classical", false)] {
            let provider = yaml_serde::from_str(&format!(
                "type: inline\nbehavior: {behavior}\npayload: []\n",
            )).unwrap();
            let registry = HashMap::from([("networks".into(), provider)]);
            assert_eq!(validate_address_sets(Some(&raw), Some(&registry)).is_ok(), valid);
        }
    }

    #[test]
    fn auto_redirect_requires_auto_route() {
        let raw = yaml_serde::from_str("enable: true\nauto-redirect: true\n").unwrap();
        assert!(convert(Some(raw)).unwrap_err().to_string().contains("requires auto-route"));
    }

    #[test]
    fn auto_redirect_defaults_off_and_validates_platform() {
        let raw = yaml_serde::from_str("enable: true\nauto-route: true\n").unwrap();
        assert!(!convert(Some(raw)).unwrap().auto_redirect);
        let raw = yaml_serde::from_str("enable: true\nauto-route: true\nauto-redirect: true\n").unwrap();
        let result = convert(Some(raw));
        if cfg!(target_os = "linux") {
            assert!(result.unwrap().auto_redirect);
        } else {
            assert!(result.unwrap_err().to_string().contains("only supported on Linux"));
        }
    }

    #[test]
    fn test_tun_enable_tcp_defaults_to_true() {
        let yaml = r#"
        enable: true
        "#;
        let def_tun: def::TunConfig = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(def_tun.enable_tcp, None);
        let cfg = convert(Some(def_tun)).unwrap();
        assert!(cfg.enable_tcp);
    }

    #[test]
    fn test_tun_enable_tcp_explicit_false() {
        let yaml = r#"
        enable: true
        enable-tcp: false
        "#;
        let def_tun: def::TunConfig = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(def_tun.enable_tcp, Some(false));
        let cfg = convert(Some(def_tun)).unwrap();
        assert!(!cfg.enable_tcp);
    }

    #[test]
    fn test_tun_tcp_alias_false() {
        let yaml = r#"
        enable: true
        tcp: false
        "#;
        let def_tun: def::TunConfig = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(def_tun.enable_tcp, Some(false));
        let cfg = convert(Some(def_tun)).unwrap();
        assert!(!cfg.enable_tcp);
    }

    #[test]
    fn invalid_tun_values_identify_field_and_value() {
        for (yaml, field, value) in [
            ("enable: true\nroutes: [bad]\n", "tun.routes", "bad"),
            (
                "enable: true\nroute-exclude-address: [bad]\n",
                "tun.route-exclude-address",
                "bad",
            ),
            ("enable: true\ngateway: bad\n", "tun.gateway", "bad"),
            ("enable: true\ngateway-v6: bad\n", "tun.gateway-v6", "bad"),
            (
                "enable: true\ndns-hijack: [bad]\n",
                "tun.dns-hijack",
                "bad",
            ),
        ] {
            let def_tun: def::TunConfig = yaml_serde::from_str(yaml).unwrap();
            let error = convert(Some(def_tun)).err().unwrap().to_string();
            assert!(error.contains(field) && error.contains(value), "{error}");
        }
    }
}
