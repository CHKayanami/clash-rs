use crate::app::sniffer::{
    PortMatcher, PortRange, SniffProtocolConfig, SnifferConfig,
};
use crate::config::def::{self, PortOrRange, SniffItemConfig};

pub fn convert(def: Option<def::SnifferConfig>) -> Option<SnifferConfig> {
    let def = def?;
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
            config.tls = Some(convert_proto(tls, vec![PortRange::Single(443), PortRange::Single(8443)]));
        }
        if let Some(http) = sniff.http {
            config.http = Some(convert_proto(http, vec![
                PortRange::Single(80),
                PortRange::Range(8080, 8880),
            ]));
        }
        if let Some(quic) = sniff.quic {
            config.quic = Some(convert_proto(quic, vec![PortRange::Single(443)]));
        }
    }

    // Handle legacy `sniffing: [tls, http, quic]` if `sniff` was not explicitly specified
    if let Some(sniffing) = def.sniffing {
        for proto in sniffing {
            match proto.to_ascii_lowercase().as_str() {
                "tls" if config.tls.is_none() => {
                    config.tls = Some(SniffProtocolConfig {
                        ports: PortMatcher::new(vec![PortRange::Single(443), PortRange::Single(8443)]),
                        override_destination: None,
                    });
                }
                "http" if config.http.is_none() => {
                    config.http = Some(SniffProtocolConfig {
                        ports: PortMatcher::new(vec![PortRange::Single(80), PortRange::Range(8080, 8880)]),
                        override_destination: Some(true),
                    });
                }
                "quic" if config.quic.is_none() => {
                    config.quic = Some(SniffProtocolConfig {
                        ports: PortMatcher::new(vec![PortRange::Single(443)]),
                        override_destination: None,
                    });
                }
                _ => {}
            }
        }
    }

    // If enabled but no protocol explicitly configured, use defaults
    if config.enable && config.tls.is_none() && config.http.is_none() && config.quic.is_none() {
        let default_cfg = SnifferConfig::default();
        config.tls = default_cfg.tls;
        config.http = default_cfg.http;
        config.quic = default_cfg.quic;
    }

    Some(config)
}

fn convert_proto(item: SniffItemConfig, default_ports: Vec<PortRange>) -> SniffProtocolConfig {
    let ports = if let Some(p_list) = item.ports {
        let mut ranges = Vec::new();
        for p in p_list {
            match p {
                PortOrRange::Port(port) => ranges.push(PortRange::Single(port.0)),
                PortOrRange::Range(s) => {
                    if let Some((start_s, end_s)) = s.split_once('-') {
                        if let (Ok(start), Ok(end)) = (start_s.trim().parse::<u16>(), end_s.trim().parse::<u16>()) {
                            ranges.push(PortRange::Range(start, end));
                        }
                    } else if let Ok(port) = s.trim().parse::<u16>() {
                        ranges.push(PortRange::Single(port));
                    }
                }
            }
        }
        PortMatcher::new(ranges)
    } else {
        PortMatcher::new(default_ports)
    };

    SniffProtocolConfig {
        ports,
        override_destination: item.override_destination,
    }
}
