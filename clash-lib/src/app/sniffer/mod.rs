mod domain_matcher;
mod prefetch;
pub mod http;
pub mod quic;
pub mod stream;
pub mod tls;

use dashmap::DashMap;
use parking_lot::Mutex;
use std::{future::Future, io, net::SocketAddr, pin::Pin, task::Poll};
use std::sync::Arc;
use std::time::{Duration, Instant};
use futures::future::poll_fn;
use tokio::{io::{AsyncRead, ReadBuf}, task::coop::{has_budget_remaining, unconstrained}, time::Sleep};
use tracing::{debug, trace};

use crate::common::io::SlideBuffer;
use crate::proxy::AnyStream;
use crate::session::{Session, SocksAddr};

pub use stream::PrefixedStream;

use domain_matcher::DomainMatcher;
use prefetch::Prefetch;
pub(crate) use domain_matcher::validate_domain_patterns;

// Reuse one timer across prefetch reads, retaining Timeout's read-first and
// cooperative-budget behavior without allocating a pinned timer on the heap.
fn read_until_deadline<'a, S: AsyncRead + Unpin + Send>(
    stream: &'a mut S, buffer: &'a mut [u8], mut timer: Pin<&'a mut Sleep>,
) -> impl Future<Output = Option<io::Result<usize>>> + Send + 'a {
    poll_fn(move |cx| {
        let had_budget = has_budget_remaining();
        let mut read = ReadBuf::new(buffer);
        if let Poll::Ready(result) = Pin::new(&mut *stream).poll_read(cx, &mut read) {
            return Poll::Ready(Some(result.map(|()| read.filled().len())));
        }
        let timeout = if had_budget && !has_budget_remaining() {
            // A read that exhausted its budget must not starve the deadline.
            Pin::new(&mut unconstrained(timer.as_mut())).poll(cx)
        } else {
            timer.as_mut().poll(cx)
        };
        timeout.map(|()| None)
    })
}

const DEFAULT_SNIFF_TIMEOUT: Duration = Duration::from_millis(200);
const MAX_SNIFF_BUFFER_SIZE: usize = 4096;
const SNIFF_FAILURE_THRESHOLD: u8 = 3;
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(600);
const MAX_NEG_CACHE_ENTRIES: usize = 4096;
const TARGET_NEG_CACHE_ENTRIES: usize = 3072;

/// TCP sniffing negative cache for suppressing sniffing on non-HTTP/TLS destinations.
#[derive(Default)]
pub struct TcpSniffNegCache {
    entries: DashMap<SocketAddr, (u8, Instant)>,
    eviction_lock: Mutex<()>,
}

impl TcpSniffNegCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn should_skip(&self, addr: &SocketAddr, now: Instant) -> bool {
        if let Some(entry) = self.entries.get(addr) {
            let (failures, expires_at) = *entry.value();
            if now < expires_at && failures >= SNIFF_FAILURE_THRESHOLD {
                return true;
            }
        }
        false
    }

    pub fn note_failure(&self, addr: SocketAddr, now: Instant) {
        // Fast path: if the key already exists, update in-place without triggering eviction.
        if let Some(mut entry) = self.entries.get_mut(&addr) {
            let (failures, expires_at) = entry.value_mut();
            if now >= *expires_at {
                *failures = 0;
            }
            *failures = failures.saturating_add(1).min(SNIFF_FAILURE_THRESHOLD);
            *expires_at = now + NEGATIVE_CACHE_TTL;
            return;
        }

        // Slow path: inserting a new key.
        // Synchronize under eviction_lock to ensure atomic capacity check and insertion under concurrency.
        let _guard = self.eviction_lock.lock();

        // Double check if another thread inserted it while waiting for the lock
        if let Some(mut entry) = self.entries.get_mut(&addr) {
            let (failures, expires_at) = entry.value_mut();
            if now >= *expires_at {
                *failures = 0;
            }
            *failures = failures.saturating_add(1).min(SNIFF_FAILURE_THRESHOLD);
            *expires_at = now + NEGATIVE_CACHE_TTL;
            return;
        }

        if self.entries.len() >= MAX_NEG_CACHE_ENTRIES {
            self.prune(now);
            if self.entries.len() >= MAX_NEG_CACHE_ENTRIES {
                let to_evict =
                    (self.entries.len() + 1).saturating_sub(TARGET_NEG_CACHE_ENTRIES);
                let mut evicted = 0;
                self.entries.retain(|_, _| {
                    if evicted < to_evict {
                        evicted += 1;
                        false
                    } else {
                        true
                    }
                });
            }
        }
        self.entries.insert(addr, (1, now + NEGATIVE_CACHE_TTL));
    }

    pub fn note_success(&self, addr: &SocketAddr) {
        self.entries.remove(addr);
    }

    pub fn prune(&self, now: Instant) {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffUdpOutcome {
    NotMatched,
    Incomplete,
    CompleteNoDomain,
    Domain(String, bool),
}

pub struct Sniffer {
    pub config: SnifferConfig,
    skip_domains: DomainMatcher,
    force_domains: DomainMatcher,
    pub tcp_neg_cache: TcpSniffNegCache,
    pub quic_pool: quic::PacketSnifferPool,
}

pub type ArcSniffer = Arc<Sniffer>;

impl Sniffer {
    pub fn new(config: SnifferConfig) -> Self {
        Self {
            skip_domains: DomainMatcher::new(&config.skip_domains),
            force_domains: DomainMatcher::new(&config.force_domains),
            config,
            tcp_neg_cache: TcpSniffNegCache::new(),
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
            self.force_domains.matches(domain)
        } else {
            false
        }
    }

    pub fn is_domain_skipped(&self, domain: &str) -> bool {
        self.skip_domains.matches(domain)
    }

    /// Sniff a TCP client stream.
    /// Returns: `(Option<sniffed_domain>, AnyStream, override_destination)`
    pub fn sniff_stream<'a>(
        &'a self,
        sess: &'a Session,
        mut stream: AnyStream,
    ) -> impl Future<Output = (Option<String>, AnyStream, bool)> + Send + 'a {
        async move {
            if !self.config.enable {
                return (None, stream, false);
            }

            let port = sess.destination.port();
            let orig_dest = sess.orig_destination.as_ref().unwrap_or(&sess.destination);
            // If sess.destination is already a domain (from reverse lookup or domain inbound),
            // it is not treated as a pure IP. Reverse lookup takes precedence over sniffing
            // unless explicitly forced via force_domains.
            let is_pure_ip = !sess.destination.is_domain();
            let force = self.should_force_sniff(&sess.destination)
                || self.should_force_sniff(orig_dest);

            if is_pure_ip {
                if !self.config.parse_pure_ip && !force {
                    return (None, stream, false);
                }
            } else if !force {
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
            let ip_target = match orig_dest {
                SocksAddr::Ip(addr) => Some(*addr),
                _ => match sess.destination {
                    SocksAddr::Ip(addr) => Some(addr),
                    _ => None,
                },
            };

            if let Some(addr) = ip_target {
                if !force && self.tcp_neg_cache.should_skip(&addr, now) {
                    trace!("skip sniffing for {} by negative cache", addr);
                    return (None, stream, false);
                }
            }

            // Bounded prefetch with smart length requirement
            let mut buf = SlideBuffer::new(MAX_SNIFF_BUFFER_SIZE);
            let deadline = tokio::time::Instant::now() + DEFAULT_SNIFF_TIMEOUT;
            let timer = tokio::time::sleep_until(deadline);
            tokio::pin!(timer);

            let mut prefetch = Prefetch::new(tls_enabled, http_enabled);
            loop {
                let required = prefetch.required_len(buf.as_slice());
                if required <= buf.len() || buf.len() >= MAX_SNIFF_BUFFER_SIZE {
                    break;
                }

                let want = (required - buf.len()).min(buf.remaining_capacity());
                let write_slice = &mut buf.write_slice()[..want];
                match read_until_deadline(&mut stream, write_slice, timer.as_mut()).await
                {
                    Some(Ok(0)) => break,
                    Some(Ok(n)) => buf.advance_write(n),
                    Some(Err(e)) => {
                        trace!("sniff stream read error for {}: {}", sess, e);
                        break;
                    }
                    None => {
                        trace!("sniff stream timeout for {}", sess);
                        break;
                    }
                }
            }

            let mut recognized = false;
            // 1. Try TLS SNI
            if tls_enabled {
                if let Some(domain) = tls::parse_tls_sni(buf.as_slice()) {
                    recognized = true;
                    if !self.is_domain_skipped(&domain) {
                        debug!("sniffed TLS SNI domain `{}` for {}", domain, sess);
                        if let Some(addr) = ip_target {
                            self.tcp_neg_cache.note_success(&addr);
                        }
                        let override_dest = self
                            .config
                            .tls
                            .as_ref()
                            .and_then(|c| c.override_destination)
                            .unwrap_or(self.config.override_destination);
                        let wrapped = AnyStream::new(PrefixedStream::new(buf, stream));
                        return (Some(domain), wrapped, override_dest);
                    }
                }
            }

            // 2. Try HTTP Host
            if http_enabled {
                if let Some(domain) = http::parse_http_host(buf.as_slice()) {
                    recognized = true;
                    if !self.is_domain_skipped(&domain) {
                        debug!("sniffed HTTP Host domain `{}` for {}", domain, sess);
                        if let Some(addr) = ip_target {
                            self.tcp_neg_cache.note_success(&addr);
                        }
                        let override_dest = self
                            .config
                            .http
                            .as_ref()
                            .and_then(|c| c.override_destination)
                            .unwrap_or(self.config.override_destination);
                        let wrapped = AnyStream::new(PrefixedStream::new(buf, stream));
                        return (Some(domain), wrapped, override_dest);
                    }
                }
            }

            // A skipped domain still proves that this target supports sniffing.
            if let Some(addr) = ip_target {
                if recognized {
                    self.tcp_neg_cache.note_success(&addr);
                } else {
                    self.tcp_neg_cache.note_failure(addr, now);
                }
            }

            if buf.is_empty() {
                return (None, stream, false);
            }
            let wrapped = AnyStream::new(PrefixedStream::new(buf, stream));
            (None, wrapped, false)
        }
    }

    /// Sniff a UDP packet (QUIC) with flow session and DCID negative cache, returning full outcome.
    pub fn sniff_udp_datagram_full(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        data: &[u8],
    ) -> SniffUdpOutcome {
        if !self.config.enable {
            return SniffUdpOutcome::NotMatched;
        }

        let quic_cfg = match self.config.quic.as_ref() {
            Some(cfg) => cfg,
            None => return SniffUdpOutcome::NotMatched,
        };
        if !quic_cfg.ports.contains(dst.port()) {
            return SniffUdpOutcome::NotMatched;
        }

        let outcome = self.quic_pool.feed_quic_datagram(src, dst, data);
        match outcome {
            quic::QuicSniffOutcome::Domain(domain) => {
                if !self.is_domain_skipped(&domain) {
                    debug!(
                        "sniffed QUIC SNI domain `{}` for {} -> {}",
                        domain, src, dst
                    );
                    let override_dest = quic_cfg
                        .override_destination
                        .unwrap_or(self.config.override_destination);
                    SniffUdpOutcome::Domain(domain, override_dest)
                } else {
                    SniffUdpOutcome::CompleteNoDomain
                }
            }
            quic::QuicSniffOutcome::Incomplete => SniffUdpOutcome::Incomplete,
            quic::QuicSniffOutcome::CompleteNoDomain => SniffUdpOutcome::CompleteNoDomain,
            quic::QuicSniffOutcome::NotQuic => SniffUdpOutcome::NotMatched,
        }
    }

    /// Sniff a UDP packet (QUIC) with flow session and DCID negative cache.
    /// Returns: `Option<(sniffed_domain, override_destination)>`
    pub fn sniff_udp_datagram(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        data: &[u8],
    ) -> Option<(String, bool)> {
        match self.sniff_udp_datagram_full(src, dst, data) {
            SniffUdpOutcome::Domain(domain, override_dest) => Some((domain, override_dest)),
            _ => None,
        }
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

#[cfg(test)]
mod tests;
