use crate::{
    config::internal::proxy::{Hysteria2Obfs, OutboundHysteria2},
    proxy::hysteria2::{self, Handler, HystOption, SalamanderObfs},
    session::SocksAddr,
};
use std::{
    num::{NonZeroU16, ParseIntError},
    ops::RangeInclusive,
};

#[derive(Clone)]
pub struct PortGenerator {
    // must have a default port
    pub default: u16,
    ports: Vec<u16>,
    range: Vec<RangeInclusive<u16>>,
}

impl PortGenerator {
    pub fn new(port: u16) -> Self {
        PortGenerator {
            default: port,
            ports: vec![],
            range: vec![],
        }
    }

    pub fn add_single(&mut self, port: u16) {
        self.ports.push(port);
    }

    fn add_range(&mut self, start: u16, end: u16) {
        self.range.push(start..=end);
    }

    pub fn get(&self) -> u16 {
        let len =
            1 + self.ports.len() + self.range.iter().map(|r| r.len()).sum::<usize>();
        let idx = rand::random_range(0..len);
        match idx {
            0 => self.default,
            idx if idx <= self.ports.len() => self.ports[idx - 1],
            idx => {
                let mut x = self.range.iter().cloned().flatten();
                x.nth(idx - 1 - self.ports.len()).unwrap()
            }
        }
    }

    pub fn parse_ports_str(self, ports: &str) -> Result<Self, ParseIntError> {
        if ports.is_empty() {
            return Ok(self);
        }
        ports
            .split(',')
            .map(|s| s.trim())
            .try_fold(self, |mut acc, ports| {
                let x: Result<_, ParseIntError> = ports
                    .parse::<u16>()
                    .map(|p| acc.add_single(p))
                    .or_else(|e| {
                        let mut iter = ports.split('-');
                        let start = iter.next().ok_or(e.clone())?;
                        let end = iter.next().ok_or(e)?;
                        let start = start.parse::<NonZeroU16>()?;
                        let end = end.parse::<NonZeroU16>()?;
                        acc.add_range(start.get(), end.get());
                        Ok(())
                    })
                    .map(|_| acc);
                x
            })
    }
}

impl TryFrom<OutboundHysteria2> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundHysteria2) -> Result<Self, Self::Error> {
        let addr = SocksAddr::try_from((value.server, value.port))?;

        let obfs = match (value.obfs, value.obfs_password.as_ref()) {
            (Some(obfs), Some(passwd)) => match obfs {
                Hysteria2Obfs::Salamander => {
                    Some(hysteria2::Obfs::Salamander(SalamanderObfs {
                        key: passwd.to_owned().into(),
                    }))
                }
            },
            (Some(_), None) => {
                return Err(crate::Error::InvalidConfig(
                    "hysteria2 found obfs enable, but obfs password is none"
                        .to_owned(),
                ));
            }
            _ => None,
        };

        let ports_gen = if let Some(ports) = value.ports {
            Some(
                PortGenerator::new(value.port)
                    .parse_ports_str(&ports)
                    .map_err(|e| {
                        crate::Error::InvalidConfig(format!(
                            "hysteria2 parse ports error: {e:?}, ports: {ports:?}"
                        ))
                    })?,
            )
        } else {
            None
        };
        let opts = HystOption {
            name: value.name,
            sni: value.sni.or(addr.domain().map(|s| s.to_owned())),
            addr,
            alpn: value.alpn.unwrap_or_default(),
            ca: value.ca.map(|s| s.into()),
            fingerprint: value.fingerprint,
            skip_cert_verify: value.skip_cert_verify,
            passwd: value.password,
            ports: ports_gen,
            obfs,
            up_down: value
                .up
                .zip(value.down)
                .map(|(u, d)| (u * 1_000_000, d * 1_000_000)),
            ca_str: value.ca_str,
            cwnd: value.cwnd,
            udp_mtu: value.udp_mtu,
            disable_mtu_discovery: value.disable_mtu_discovery.unwrap_or(false),
            tls_cert: value.tls_cert,
            tls_key: value.tls_key,
        };

        Ok(Handler::new(opts)?)
    }
}

impl std::str::FromStr for OutboundHysteria2 {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = url::Url::parse(s).map_err(|e| {
            crate::Error::InvalidConfig(format!("invalid hysteria2 URL: {e}"))
        })?;

        if url.scheme() != "hysteria2" && url.scheme() != "hy2" {
            return Err(crate::Error::InvalidConfig(format!(
                "invalid scheme for hysteria2: {}",
                url.scheme()
            )));
        }

        let password = if let Some(p) = url.password() {
            p.to_string()
        } else if !url.username().is_empty() {
            url.username().to_string()
        } else {
            return Err(crate::Error::InvalidConfig(
                "hysteria2 URL missing password".to_string(),
            ));
        };

        let server = url
            .host_str()
            .ok_or_else(|| {
                crate::Error::InvalidConfig("hysteria2 URL missing host".to_string())
            })?
            .to_string();

        let port = url.port().unwrap_or(443);
        let name = url
            .fragment()
            .filter(|f| !f.is_empty())
            .unwrap_or("hysteria2")
            .to_string();

        let mut outbound = OutboundHysteria2 {
            name,
            server,
            port,
            password,
            ..Default::default()
        };

        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "alpn" => {
                    outbound.alpn =
                        Some(v.split(',').map(|s| s.trim().to_string()).collect());
                }
                "insecure" | "allowInsecure" | "skip-cert-verify" => {
                    outbound.skip_cert_verify =
                        v == "1" || v.eq_ignore_ascii_case("true");
                }
                "pinSHA256" | "fingerprint" => {
                    outbound.fingerprint = Some(v.to_string());
                }
                "sni" | "peer" => {
                    outbound.sni = Some(v.to_string());
                }
                "obfs" => {
                    if v.eq_ignore_ascii_case("salamander") {
                        outbound.obfs = Some(Hysteria2Obfs::Salamander);
                    }
                }
                "obfs-password" | "obfs_password" => {
                    outbound.obfs_password = Some(v.to_string());
                }
                "ports" => {
                    outbound.ports = Some(v.to_string());
                }
                "up" | "up_mbps" => {
                    outbound.up = v.parse().ok();
                }
                "down" | "down_mbps" => {
                    outbound.down = v.parse().ok();
                }
                _ => {}
            }
        }

        Ok(outbound)
    }
}

impl TryFrom<&str> for OutboundHysteria2 {
    type Error = crate::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Handler {
    #[allow(dead_code)]
    pub fn try_from_url(url: &str) -> Result<Self, crate::Error> {
        let outbound: OutboundHysteria2 = url.parse()?;
        Self::try_from(outbound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::OutboundHandler;

    #[test]
    fn test_port_gen() {
        let p = PortGenerator::new(1000).parse_ports_str("").unwrap();
        let p = p.parse_ports_str("1001,1002,1003, 5000-5001").unwrap();

        for _ in 0..100 {
            println!("{}", p.get());
        }
    }

    #[test]
    fn test_hysteria2_url_parse() {
        crate::tests::initialize();
        let url_str = "hysteria2://51e322ae-88ad-42c6-960a-0309448b88e2@example.com:60747?alpn=h3&insecure=1&allowInsecure=1&pinSHA256=A400A045BC82C4EDCB82D2DA0508EDC3351A5C4EFCB71DAA72C2A877D1B92C7C";
        let outbound: OutboundHysteria2 =
            url_str.parse().expect("failed to parse hysteria2 url");
        assert_eq!(outbound.server, "example.com");
        assert_eq!(outbound.port, 60747);
        assert_eq!(outbound.password, "51e322ae-88ad-42c6-960a-0309448b88e2");
        assert_eq!(outbound.alpn.as_deref(), Some(&["h3".to_string()][..]));
        assert!(outbound.skip_cert_verify);
        assert_eq!(
            outbound.fingerprint.as_deref(),
            Some("A400A045BC82C4EDCB82D2DA0508EDC3351A5C4EFCB71DAA72C2A877D1B92C7C")
        );

        let handler = Handler::try_from(outbound)
            .expect("failed to build handler from outbound");
        assert_eq!(handler.name(), "hysteria2");
    }
}
