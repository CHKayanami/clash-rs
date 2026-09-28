use crate::{
    Error,
    config::{config, def},
};

pub fn convert(
    before: Option<def::TunConfig>,
) -> Result<config::TunConfig, crate::Error> {
    match before {
        Some(t) => {
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

            let device_id = if let Some(fd) = t.file_descriptor {
                if t.device_id == "utun1989" || t.device_id.is_empty() {
                    format!("fd://{fd}")
                } else {
                    t.device_id
                }
            } else {
                t.device_id
            };

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
                gso_max_size: t.gso_max_size,
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
