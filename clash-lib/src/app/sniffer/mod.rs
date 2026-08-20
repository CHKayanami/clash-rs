pub mod http;
pub mod quic;
pub mod stream;
pub mod tls;

use bytes::BytesMut;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tracing::{debug, trace};

use crate::proxy::ClientStream;
use crate::session::{Session, SocksAddr};

pub use stream::PrefixedStream;

const DEFAULT_SNIFF_TIMEOUT: Duration = Duration::from_millis(200);
const MAX_SNIFF_BUFFER_SIZE: usize = 4096;
const SNIFF_FAILURE_THRESHOLD: u8 = 3;
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(600);

/// TCP sniffing negative cache for suppressing sniffing on non-HTTP/TLS destinations.
#[derive(Debug, Clone, Default)]
pub struct TcpSniffNegCache {
    entries: HashMap<SocketAddr, (u8, Instant)>,
}

impl TcpSniffNegCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn should_skip(&self, addr: &SocketAddr, now: Instant) -> bool {
        if let Some(&(failures, expires_at)) = self.entries.get(addr) {
            if now < expires_at && failures >= SNIFF_FAILURE_THRESHOLD {
                return true;
            }
        }
        false
    }

    pub fn note_failure(&mut self, addr: SocketAddr, now: Instant) {
        if self.entries.len() > 4096 {
            self.prune(now);
        }
        let entry = self.entries.entry(addr).or_insert((0, now));
        if now >= entry.1 {
            entry.0 = 0;
        }
        entry.0 = entry.0.saturating_add(1).min(SNIFF_FAILURE_THRESHOLD);
        entry.1 = now + NEGATIVE_CACHE_TTL;
    }

    pub fn note_success(&mut self, addr: &SocketAddr) {
        self.entries.remove(addr);
    }

    pub fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, (_, expires_at)| now < *expires_at);
    }
}

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
                ports: PortMatcher::new(vec![
                    PortRange::Single(443),
                    PortRange::Single(8443),
                ]),
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
    pub tcp_neg_cache: Mutex<TcpSniffNegCache>,
    pub quic_pool: quic::PacketSnifferPool,
}

pub type ArcSniffer = Arc<Sniffer>;

impl Sniffer {
    pub fn new(config: SnifferConfig) -> Self {
        Self {
            config,
            tcp_neg_cache: Mutex::new(TcpSniffNegCache::new()),
            quic_pool: quic::PacketSnifferPool::new(),
        }
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
                if domain_lower == suffix
                    || domain_lower.ends_with(&format!(".{suffix}"))
                {
                    return true;
                }
            } else if p.starts_with('.') {
                let suffix = &p[1..];
                if domain_lower == suffix
                    || domain_lower.ends_with(&format!(".{suffix}"))
                {
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

        let tls_enabled = self
            .config
            .tls
            .as_ref()
            .map_or(false, |cfg| cfg.ports.contains(port));
        let http_enabled = self
            .config
            .http
            .as_ref()
            .map_or(false, |cfg| cfg.ports.contains(port));

        if !tls_enabled && !http_enabled {
            return (None, stream, false);
        }

        let now = Instant::now();
        let ip_target = match sess.destination {
            SocksAddr::Ip(addr) => Some(addr),
            _ => None,
        };

        if let Some(addr) = ip_target {
            if !force && self.tcp_neg_cache.lock().should_skip(&addr, now) {
                trace!("skip sniffing for {} by negative cache", addr);
                return (None, stream, false);
            }
        }

        // Bounded prefetch with smart length requirement
        let mut buf = BytesMut::with_capacity(MAX_SNIFF_BUFFER_SIZE);
        let deadline = tokio::time::Instant::now() + DEFAULT_SNIFF_TIMEOUT;

        loop {
            let required = sniff_required_len(&buf);
            if required <= buf.len() || buf.len() >= MAX_SNIFF_BUFFER_SIZE {
                break;
            }

            let mut chunk = [0u8; 512];
            let want = (required - buf.len()).min(chunk.len());
            match tokio::time::timeout_at(deadline, stream.read(&mut chunk[..want]))
                .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                Ok(Err(e)) => {
                    trace!("sniff stream read error for {}: {}", sess, e);
                    break;
                }
                Err(_) => {
                    trace!("sniff stream timeout for {}", sess);
                    break;
                }
            }
        }

        let prefix_bytes = buf.freeze();

        // 1. Try TLS SNI
        if tls_enabled {
            if let Some(domain) = tls::parse_tls_sni(&prefix_bytes) {
                if !self.is_domain_skipped(&domain) {
                    debug!("sniffed TLS SNI domain `{}` for {}", domain, sess);
                    if let Some(addr) = ip_target {
                        self.tcp_neg_cache.lock().note_success(&addr);
                    }
                    let override_dest = self
                        .config
                        .tls
                        .as_ref()
                        .and_then(|c| c.override_destination)
                        .unwrap_or(self.config.override_destination);
                    let wrapped =
                        Box::new(PrefixedStream::new(prefix_bytes, stream));
                    return (Some(domain), wrapped, override_dest);
                }
            }
        }

        // 2. Try HTTP Host
        if http_enabled {
            if let Some(domain) = http::parse_http_host(&prefix_bytes) {
                if !self.is_domain_skipped(&domain) {
                    debug!("sniffed HTTP Host domain `{}` for {}", domain, sess);
                    if let Some(addr) = ip_target {
                        self.tcp_neg_cache.lock().note_success(&addr);
                    }
                    let override_dest = self
                        .config
                        .http
                        .as_ref()
                        .and_then(|c| c.override_destination)
                        .unwrap_or(self.config.override_destination);
                    let wrapped =
                        Box::new(PrefixedStream::new(prefix_bytes, stream));
                    return (Some(domain), wrapped, override_dest);
                }
            }
        }

        // Sniffing yielded no usable domain: record failure in negative cache if target is an IP
        if let Some(addr) = ip_target {
            self.tcp_neg_cache.lock().note_failure(addr, now);
        }

        let wrapped = Box::new(PrefixedStream::new(prefix_bytes, stream));
        (None, wrapped, false)
    }

    /// Sniff a UDP packet (QUIC) with flow session and DCID negative cache.
    /// Returns: `Option<(sniffed_domain, override_destination)>`
    pub fn sniff_udp_datagram(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        data: &[u8],
    ) -> Option<(String, bool)> {
        if !self.config.enable {
            return None;
        }

        let quic_cfg = self.config.quic.as_ref()?;
        if !quic_cfg.ports.contains(dst.port()) {
            return None;
        }

        let outcome = self.quic_pool.feed_quic_datagram(src, dst, data);
        if let quic::QuicSniffOutcome::Domain(domain) = outcome {
            if !self.is_domain_skipped(&domain) {
                debug!(
                    "sniffed QUIC SNI domain `{}` for {} -> {}",
                    domain, src, dst
                );
                let override_dest = quic_cfg
                    .override_destination
                    .unwrap_or(self.config.override_destination);
                return Some((domain, override_dest));
            }
        }

        None
    }

    /// Sniff a single UDP packet (QUIC).
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
                let override_dest = quic_cfg
                    .override_destination
                    .unwrap_or(self.config.override_destination);
                return Some((domain, override_dest));
            }
        }

        None
    }
}

/// Calculate the prefix length needed to make a bounded sniffing decision.
fn sniff_required_len(data: &[u8]) -> usize {
    if data.is_empty() {
        return 1;
    }
    if data[0] == 0x16 {
        // TLS Record
        if data.len() < 5 {
            return 5;
        }
        let record_end = 5 + u16::from_be_bytes([data[3], data[4]]) as usize;
        if record_end > MAX_SNIFF_BUFFER_SIZE {
            return MAX_SNIFF_BUFFER_SIZE;
        }
        if data.len() < 9 {
            return record_end;
        }
        if data[5] != 0x01 {
            return record_end;
        }
        let hello_len = ((data[6] as usize) << 16)
            | ((data[7] as usize) << 8)
            | (data[8] as usize);
        let hello_end = 9 + hello_len;
        return record_end.max(hello_end).min(MAX_SNIFF_BUFFER_SIZE);
    }
    if is_http_request_prefix(data) {
        return if data.windows(4).any(|w| w == b"\r\n\r\n") {
            data.len()
        } else {
            MAX_SNIFF_BUFFER_SIZE
        };
    }
    // If the data starts with standard ASCII characters, allow reading up to MAX_SNIFF_BUFFER_SIZE
    if data.iter().all(|b| {
        b.is_ascii_graphic()
            || *b == b'\r'
            || *b == b'\n'
            || *b == b'\t'
            || *b == b' '
    }) {
        return MAX_SNIFF_BUFFER_SIZE;
    }
    // Unknown non-HTTP/TLS binary protocol: 5 bytes is enough to classify
    5
}

fn is_http_request_prefix(data: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"CONNECT ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"TRACE ",
        b"PATCH ",
        b"PRI * HTTP/2.0",
    ];
    METHODS
        .iter()
        .any(|m| m.starts_with(data) || data.starts_with(m))
}

#[cfg(test)]
mod tests;
