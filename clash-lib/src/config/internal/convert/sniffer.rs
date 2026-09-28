use crate::Error;
use crate::app::sniffer::{
    PortMatcher, PortRange, SniffProtocolConfig, SnifferConfig,
};
use crate::config::def::{self, PortOrRange, SniffItemConfig};

pub fn convert(
    def: Option<def::SnifferConfig>,
) -> Result<Option<SnifferConfig>, Error> {
    let Some(def) = def else { return Ok(None) };
    let mut config = SnifferConfig {
        enable: def.enable,
        force_dns_mapping: def.force_dns_mapping.unwrap_or(false),
        parse_pure_ip: def.parse_pure_ip.unwrap_or(true),
        override_destination: def.override_destination,
        skip_domains: def.skip_domain.unwrap_or_default(),
        force_domains: def.force_domain.unwrap_or_default(),
        tls: None,
        http: None,
        quic: None,
    };

    if let Some(sniff) = def.sniff {
        if let Some(tls) = sniff.tls {
            config.tls = Some(convert_proto(
                "TLS",
                tls,
                vec![PortRange::Single(443), PortRange::Single(8443)],
            )?);
        }
        if let Some(http) = sniff.http {
            config.http = Some(convert_proto(
                "HTTP",
                http,
                vec![PortRange::Single(80), PortRange::Range(8080, 8880)],
            )?);
        }
        if let Some(quic) = sniff.quic {
            config.quic =
                Some(convert_proto("QUIC", quic, vec![PortRange::Single(443)])?);
        }
    }

    // Handle legacy `sniffing: [tls, http, quic]` if `sniff` was not explicitly specified
    if let Some(sniffing) = def.sniffing {
        for proto in sniffing {
            match proto.to_ascii_lowercase().as_str() {
                "tls" if config.tls.is_none() => {
                    config.tls = Some(SniffProtocolConfig {
                        ports: PortMatcher::new(vec![
                            PortRange::Single(443),
                            PortRange::Single(8443),
                        ]),
                        override_destination: None,
                    });
                }
                "http" if config.http.is_none() => {
                    config.http = Some(SniffProtocolConfig {
                        ports: PortMatcher::new(vec![
                            PortRange::Single(80),
                            PortRange::Range(8080, 8880),
                        ]),
                        override_destination: Some(true),
                    });
                }
                "quic" if config.quic.is_none() => {
                    config.quic = Some(SniffProtocolConfig {
                        ports: PortMatcher::new(vec![PortRange::Single(443)]),
                        override_destination: None,
                    });
                }
                "tls" | "http" | "quic" => {}
                _ => {
                    return Err(Error::InvalidConfig(format!(
                        "sniffer.sniffing: unsupported protocol '{proto}' (expected TLS, HTTP, or QUIC)"
                    )));
                }
            }
        }
    }

    // If enabled but no protocol explicitly configured, use defaults
    if config.enable
        && config.tls.is_none()
        && config.http.is_none()
        && config.quic.is_none()
    {
        let default_cfg = SnifferConfig::default();
        config.tls = default_cfg.tls;
        config.http = default_cfg.http;
        config.quic = default_cfg.quic;
    }

    Ok(Some(config))
}

fn convert_proto(
    name: &str,
    item: SniffItemConfig,
    default_ports: Vec<PortRange>,
) -> Result<SniffProtocolConfig, Error> {
    let ports = if let Some(p_list) = item.ports {
        let mut ranges = Vec::new();
        for p in p_list {
            match p {
                PortOrRange::Port(port) => ranges.push(PortRange::Single(port.0)),
                PortOrRange::Range(s) => {
                    if let Some((start_s, end_s)) = s.split_once('-') {
                        if let (Ok(start), Ok(end)) = (
                            start_s.trim().parse::<u16>(),
                            end_s.trim().parse::<u16>(),
                        ) {
                            if start <= end {
                                ranges.push(PortRange::Range(start, end));
                                continue;
                            }
                        }
                    } else if let Ok(port) = s.trim().parse::<u16>() {
                        ranges.push(PortRange::Single(port));
                        continue;
                    }
                    return Err(Error::InvalidConfig(format!(
                        "sniffer.sniff.{name}.ports: invalid port or range '{s}'"
                    )));
                }
            }
        }
        PortMatcher::new(ranges)
    } else {
        PortMatcher::new(default_ports)
    };

    Ok(SniffProtocolConfig {
        ports,
        override_destination: item.override_destination,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_sniffer_ports_and_protocols_are_rejected() {
        for yaml in [
            "enable: true\nsniff:\n  TLS:\n    ports: ['bad']\n",
            "enable: true\nsniff:\n  TLS:\n    ports: ['9000-8000']\n",
            "enable: true\nsniffing: [unknown]\n",
        ] {
            let def = yaml_serde::from_str(yaml).unwrap();
            assert!(convert(Some(def)).is_err(), "{yaml}");
        }
    }
}
