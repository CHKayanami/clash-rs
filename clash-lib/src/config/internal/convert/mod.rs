use std::collections::HashMap;

use serde::{Deserialize, de::value::MapDeserializer};
use serde_yaml::Value;
use tracing::warn;

use crate::{
    Error,
    common::auth,
    config::{
        def,
        internal::{
            proxy::{OutboundProxy, PROXY_DIRECT, PROXY_REJECT},
            rule::RuleType,
        },
        proxy::{OutboundDirect, OutboundProxyProtocol, OutboundReject},
    },
};

mod general;
mod listener;
mod proxy_group;
mod rule_provider;
mod sniffer;
mod tun;

use super::{
    config::{self, Profile},
    proxy::{OutboundGroupProtocol, map_serde_error},
};

impl TryFrom<def::Config> for config::Config {
    type Error = crate::Error;

    fn try_from(value: def::Config) -> Result<Self, Self::Error> {
        convert(value)
    }
}

pub(super) fn convert(mut c: def::Config) -> Result<config::Config, crate::Error> {
    let mut proxy_names =
        vec![String::from(PROXY_DIRECT), String::from(PROXY_REJECT)];

    if c.allow_lan.unwrap_or_default() && c.bind_address.is_localhost() {
        warn!(
            "allow-lan is set to true, but bind-address is set to localhost. This \
             will not allow any connections from the local network."
        );
    }
    let ebpf_enabled = c.ebpf.as_ref().map(|e| e.enable).unwrap_or(false);
    let tun_route_all = c.tun.as_ref().map(|t| t.route_all).unwrap_or(false);

    let conf_routing_mark = c.routing_mark;
    let conf_tun_mark = c.tun.as_ref().and_then(|t| t.so_mark);
    let conf_ebpf_mark = c.ebpf.as_ref().and_then(|e| e.routing_mark);

    if let (Some(rm), Some(tsm)) = (conf_routing_mark, conf_tun_mark) {
        if rm != tsm {
            warn!(
                "routing-mark ({rm}) and tun.so-mark ({tsm}) conflict; overriding tun.so-mark with routing-mark ({rm}) to prevent routing loop"
            );
        }
    }
    if let (Some(rm), Some(erm)) = (conf_routing_mark, conf_ebpf_mark) {
        if rm != erm {
            warn!(
                "routing-mark ({rm}) and ebpf.routing-mark ({erm}) conflict; overriding ebpf.routing-mark with routing-mark ({rm}) to prevent routing loop"
            );
        }
    }
    if let (Some(tsm), Some(erm)) = (conf_tun_mark, conf_ebpf_mark) {
        if tsm != erm && conf_routing_mark.is_none() {
            warn!(
                "tun.so-mark ({tsm}) and ebpf.routing-mark ({erm}) conflict; unifying mark to tun.so-mark ({tsm}) to prevent routing loop"
            );
        }
    }

    let explicit_mark = conf_routing_mark.or(conf_tun_mark).or(conf_ebpf_mark);

    let default_mark = if ebpf_enabled {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            Some(clash_ebpf::DAE_BYPASS_MARK)
        }
        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            Some(0x2dae)
        }
    } else if tun_route_all {
        Some(0x162)
    } else {
        None
    };

    let effective_mark = explicit_mark.or(default_mark);
    c.routing_mark = effective_mark;

    if let Some(tun) = &mut c.tun {
        tun.so_mark = effective_mark;
    }
    if let Some(ebpf) = &mut c.ebpf {
        ebpf.routing_mark = effective_mark;
    }
    config::Config {
        general: general::convert(&c)?,
        dns: (&c).try_into()?,
        experimental: c.experimental.take(),
        tun: tun::convert(c.tun.take())?,
        ebpf: c.ebpf.take(),
        profile: Profile {

            store_selected: c.profile.store_selected,
            store_smart_stats: c.profile.store_smart_stats,
        },
        sniffer: sniffer::convert(c.sniffer.take()),
        rules: c
            .rule
            .take()
            .unwrap_or_default()
            .into_iter()
            .map(|x| {
                x.parse::<RuleType>()
                    .map_err(|x| Error::InvalidConfig(x.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?,
        rule_providers: rule_provider::convert(c.rule_provider.take()),
        users: c
            .authentication
            .clone()
            .into_iter()
            .map(|u| {
                let mut parts = u.splitn(2, ':');
                let username = parts.next().unwrap().to_string();
                let password = parts.next().unwrap_or("").to_string();
                auth::User::new(username, password)
            })
            .collect(),
        proxies: c.proxy.take().unwrap_or_default().into_iter().try_fold(
            HashMap::from([
                (
                    String::from(PROXY_DIRECT),
                    OutboundProxy::ProxyServer(OutboundProxyProtocol::Direct(
                        OutboundDirect {
                            name: PROXY_DIRECT.to_string(),
                        },
                    )),
                ),
                (
                    String::from(PROXY_REJECT),
                    OutboundProxy::ProxyServer(OutboundProxyProtocol::Reject(
                        OutboundReject {
                            name: PROXY_REJECT.to_string(),
                        },
                    )),
                ),
            ]),
            |mut rv, protocol| {
                let name = protocol.name().to_owned();
                if rv.contains_key(name.as_str()) {
                    return Err(Error::InvalidConfig(format!(
                        "duplicated proxy name: {name}"
                    )));
                }
                proxy_names.push(name.clone());
                rv.insert(name, OutboundProxy::ProxyServer(protocol));
                Ok(rv)
            },
        )?,
        proxy_groups: proxy_group::convert(c.proxy_group.take(), &mut proxy_names)?,
        proxy_names,
        proxy_providers: c
            .proxy_provider
            .take()
            .unwrap_or_default()
            .into_iter()
            .map(|(name, mut provider)| {
                // `name` is `#[serde(skip)]` so it defaults to ""; populate from the
                // map key.
                provider.set_name(name.clone());
                (name, provider)
            })
            .collect(),
        listeners: listener::convert(c.listeners.take(), &c)?,
        inbound_providers: c
            .inbound_provider
            .take()
            .unwrap_or_default()
            .into_iter()
            .map(|(name, mut provider)| {
                provider.set_name(name.clone());
                (name, provider)
            })
            .collect(),
    }
    .validate()
}

impl TryFrom<HashMap<String, Value>> for OutboundGroupProtocol {
    type Error = Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig(
                "missing field `name` in outbound proxy grouop".to_owned(),
            ))?
            .to_owned();
        OutboundGroupProtocol::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(map_serde_error(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mark_conflict_resolution_tun() {
        let yaml = r#"
        routing-mark: 100
        tun:
          enable: true
          so-mark: 200
        "#;
        let def_cfg: def::Config = serde_yaml::from_str(yaml).unwrap();
        let cfg = convert(def_cfg).unwrap();
        assert_eq!(cfg.tun.so_mark, Some(100));
    }

    #[test]
    fn test_mark_conflict_resolution_ebpf() {
        let yaml = r#"
        routing-mark: 100
        ebpf:
          enable: true
          routing-mark: 300
        "#;
        let def_cfg: def::Config = serde_yaml::from_str(yaml).unwrap();
        let cfg = convert(def_cfg).unwrap();
        assert_eq!(cfg.ebpf.as_ref().unwrap().routing_mark, Some(100));
    }
}
