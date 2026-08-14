pub mod http;
pub mod quic;
pub mod stream;
pub mod tls;

use std::sync::Arc;
use std::time::Duration;
use bytes::Bytes;
use tokio::io::AsyncReadExt;
use tracing::{debug, trace};

use crate::proxy::ClientStream;
use crate::session::{Session, SocksAddr};

pub use stream::PrefixedStream;

const DEFAULT_SNIFF_TIMEOUT: Duration = Duration::from_millis(200);
const MAX_SNIFF_BUFFER_SIZE: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortRange {
    Single(u16),
    Range(u16, u16),
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        match self {
            PortRange::Single(p) => *p == port,
            PortRange::Range(start, end) => port >= *start && port <= *end,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PortMatcher {
    ranges: Vec<PortRange>,
}

impl PortMatcher {
    pub fn new(ranges: Vec<PortRange>) -> Self {
        Self { ranges }
    }

    pub fn contains(&self, port: u16) -> bool {
        if self.ranges.is_empty() {
            return true;
        }
        self.ranges.iter().any(|r| r.contains(port))
    }
}

#[derive(Debug, Clone)]
pub struct SniffProtocolConfig {
    pub ports: PortMatcher,
    pub override_destination: Option<bool>,
}

impl Default for SniffProtocolConfig {
    fn default() -> Self {
        Self {
            ports: PortMatcher::default(),
            override_destination: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SnifferConfig {
    pub enable: bool,
    pub force_dns_mapping: bool,
    pub parse_pure_ip: bool,
    pub override_destination: bool,
    pub tls: Option<SniffProtocolConfig>,
    pub http: Option<SniffProtocolConfig>,
    pub quic: Option<SniffProtocolConfig>,
    pub skip_domains: Vec<String>,
    pub force_domains: Vec<String>,
}

impl Default for SnifferConfig {
    fn default() -> Self {
        Self {
            enable: false,
            force_dns_mapping: false,
            parse_pure_ip: true,
            override_destination: false,
            tls: Some(SniffProtocolConfig {
                ports: PortMatcher::new(vec![PortRange::Single(443), PortRange::Single(8443)]),
                override_destination: None,
            }),
            http: Some(SniffProtocolConfig {
                ports: PortMatcher::new(vec![
                    PortRange::Single(80),
                    PortRange::Range(8080, 8880),
                ]),
                override_destination: Some(true),
            }),
            quic: Some(SniffProtocolConfig {
                ports: PortMatcher::new(vec![PortRange::Single(443)]),
                override_destination: None,
            }),
            skip_domains: Vec::new(),
            force_domains: Vec::new(),
        }
    }
}

pub struct Sniffer {
    pub config: SnifferConfig,
}

pub type ArcSniffer = Arc<Sniffer>;

impl Sniffer {
    pub fn new(config: SnifferConfig) -> Self {
        Self { config }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enable
    }

    pub fn force_dns_mapping(&self) -> bool {
        self.config.force_dns_mapping
    }

    pub fn parse_pure_ip(&self) -> bool {
        self.config.parse_pure_ip
    }

    pub fn should_force_sniff(&self, dest: &SocksAddr) -> bool {
        if let Some(domain) = dest.domain() {
            self.matches_domain_list(domain, &self.config.force_domains)
        } else {
            false
        }
    }

    pub fn is_domain_skipped(&self, domain: &str) -> bool {
        self.matches_domain_list(domain, &self.config.skip_domains)
    }

    fn matches_domain_list(&self, domain: &str, list: &[String]) -> bool {
        let domain_lower = domain.to_ascii_lowercase();
        for pattern in list {
            let pattern_lower = pattern.to_ascii_lowercase();
            let p = pattern_lower.as_str();

            if p.starts_with("+.") {
                let suffix = &p[2..];
                if domain_lower == suffix || domain_lower.ends_with(&format!(".{suffix}")) {
                    return true;
                }
            } else if p.starts_with('.') {
                let suffix = &p[1..];
                if domain_lower == suffix || domain_lower.ends_with(&format!(".{suffix}")) {
                    return true;
                }
            } else if p.starts_with('*') && p.ends_with('*') && p.len() > 2 {
                let keyword = &p[1..p.len() - 1];
                if domain_lower.contains(keyword) {
                    return true;
                }
            } else if domain_lower == p || domain_lower.ends_with(&format!(".{p}")) {
                return true;
            }
        }
        false
    }

    /// Sniff a TCP client stream.
    /// Returns: `(Option<sniffed_domain>, Box<dyn ClientStream>, override_destination)`
    pub async fn sniff_stream(
        &self,
        sess: &Session,
        mut stream: Box<dyn ClientStream>,
    ) -> (Option<String>, Box<dyn ClientStream>, bool) {
        if !self.config.enable {
            return (None, stream, false);
        }

        let port = sess.destination.port();
        let is_ip = !sess.destination.is_domain();
        let force = self.should_force_sniff(&sess.destination);

        if is_ip && !self.config.parse_pure_ip && !force {
            return (None, stream, false);
        }

        if !is_ip && !force {
            return (None, stream, false);
        }

        let tls_enabled = self.config.tls.as_ref().map_or(false, |cfg| cfg.ports.contains(port));
        let http_enabled = self.config.http.as_ref().map_or(false, |cfg| cfg.ports.contains(port));

        if !tls_enabled && !http_enabled {
            return (None, stream, false);
        }

        // Attempt to read initial bytes with timeout
        let mut buf = vec![0u8; MAX_SNIFF_BUFFER_SIZE];
        let read_res = tokio::time::timeout(DEFAULT_SNIFF_TIMEOUT, stream.read(&mut buf)).await;

        let n = match read_res {
            Ok(Ok(n)) if n > 0 => n,
            Ok(Ok(_)) => {
                // EOF
                return (None, stream, false);
            }
            Ok(Err(e)) => {
                trace!("sniff stream read error for {}: {}", sess, e);
                return (None, stream, false);
            }
            Err(_) => {
                // Timeout: Server-First protocol or slow client, proceed transparently
                trace!("sniff stream timeout for {}", sess);
                return (None, stream, false);
            }
        };

        buf.truncate(n);
        let prefix_bytes = Bytes::from(buf);

        // 1. Try TLS SNI
        if tls_enabled {
            if let Some(domain) = tls::parse_tls_sni(&prefix_bytes) {
                if !self.is_domain_skipped(&domain) {
                    debug!("sniffed TLS SNI domain `{}` for {}", domain, sess);
                    let override_dest = self.config.tls.as_ref()
                        .and_then(|c| c.override_destination)
                        .unwrap_or(self.config.override_destination);
                    let wrapped = Box::new(PrefixedStream::new(prefix_bytes, stream));
                    return (Some(domain), wrapped, override_dest);
                }
            }
        }

        // 2. Try HTTP Host
        if http_enabled {
            if let Some(domain) = http::parse_http_host(&prefix_bytes) {
                if !self.is_domain_skipped(&domain) {
                    debug!("sniffed HTTP Host domain `{}` for {}", domain, sess);
                    let override_dest = self.config.http.as_ref()
                        .and_then(|c| c.override_destination)
                        .unwrap_or(self.config.override_destination);
                    let wrapped = Box::new(PrefixedStream::new(prefix_bytes, stream));
                    return (Some(domain), wrapped, override_dest);
                }
            }
        }

        let wrapped = Box::new(PrefixedStream::new(prefix_bytes, stream));
        (None, wrapped, false)
    }

    /// Sniff a UDP packet (QUIC).
    /// Returns: `Option<(sniffed_domain, override_destination)>`
    pub fn sniff_datagram(
        &self,
        dest_port: u16,
        data: &[u8],
    ) -> Option<(String, bool)> {
        if !self.config.enable {
            return None;
        }

        let quic_cfg = self.config.quic.as_ref()?;
        if !quic_cfg.ports.contains(dest_port) {
            return None;
        }

        if let Some(domain) = quic::parse_quic_sni(data) {
            if !self.is_domain_skipped(&domain) {
                debug!("sniffed QUIC SNI domain `{}` on port {}", domain, dest_port);
                let override_dest = quic_cfg.override_destination.unwrap_or(self.config.override_destination);
                return Some((domain, override_dest));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests;

