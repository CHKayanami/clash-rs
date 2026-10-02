use arc_swap::ArcSwapOption;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use enum_dispatch::enum_dispatch;
use tracing::debug;

use crate::app::dns::fakeip::FakeDns;
use crate::app::dns::query::{DnsName, QType, QueryContext, build_dns_query_wire};
use crate::app::dns::resolver::enhanced::{
    CacheLookup, DnsCache, ReverseLookupCache,
};
use crate::app::dns::response::{
    RenderedResponse, ResponseMetadata, ResponseTemplate, build_dns_ip_response, build_dns_nodata, build_dns_nxdomain,
};
use crate::app::dns::singleflight::{
    FlightKey, FlightLeader, FlightRole, Singleflight,
};
use crate::app::dns::upstream_pool::UpstreamPool;

use crate::app::dns::{DnsResolutionHookWrapper, ThreadSafeDnsCollector};

use super::config::UpstreamType;

const STALE_RESPONSE_TTL: u32 = 60;
const ZERO_NEGATIVE_CACHE_TTL: u32 = 5;
const MAX_NEGATIVE_CACHE_TTL: u32 = 1800;

#[derive(Clone, Copy, Debug)]
pub struct DnsCachePolicy {
    pub optimistic_cache_ttl: u32,
    pub stale_cache_retention: Duration,
}

impl Default for DnsCachePolicy {
    fn default() -> Self {
        Self {
            optimistic_cache_ttl: 0,
            stale_cache_retention: Duration::from_secs(3600),
        }
    }
}

impl DnsCachePolicy {
    pub fn new(optimistic_cache_ttl: u32, stale_cache_retention_secs: u32) -> Self {
        Self {
            optimistic_cache_ttl,
            stale_cache_retention: Duration::from_secs(
                stale_cache_retention_secs as u64,
            ),
        }
    }

    fn effective_ttl(&self, override_ttl: Option<u32>, metadata: &ResponseMetadata) -> u32 {
        let Some(ttl) = metadata.cache_ttl else { return 0; };
        if override_ttl == Some(0) { return 0; }
        if metadata.negative {
            // Briefly retain zero-TTL negatives to absorb repeated queries.
            return if ttl == 0 { ZERO_NEGATIVE_CACHE_TTL } else { ttl.min(MAX_NEGATIVE_CACHE_TTL) };
        }
        override_ttl.unwrap_or_else(|| ttl.max(self.optimistic_cache_ttl))
    }
}

#[derive(Clone)]
pub struct DnsResolvedNotifier {
    reverse_lookup_cache: ReverseLookupCache,
    resolution_hook: Arc<ArcSwapOption<DnsResolutionHookWrapper>>,
    collector: Option<ThreadSafeDnsCollector>,
}

impl DnsResolvedNotifier {
    pub fn new(
        reverse_lookup_cache: ReverseLookupCache,
        resolution_hook: Arc<ArcSwapOption<DnsResolutionHookWrapper>>,
        collector: Option<ThreadSafeDnsCollector>,
    ) -> Self {
        Self {
            reverse_lookup_cache,
            resolution_hook,
            collector,
        }
    }

    pub fn on_fresh_response(&self, qname: &str, ips: &[IpAddr], effective_ttl: u32) {

        // 1. 保存反向 IP 缓存（供后续连接管理反查域名）
        if effective_ttl > 0 {
            for ip in ips {
                if !ip.is_unspecified() {
                    self.reverse_lookup_cache.insert(*ip, qname, effective_ttl);
                }
            }
        }

        // 2. 触发 Resolution Hook (例如 eBPF offload)
        if let Some(hook) = self.resolution_hook.load().as_ref()
            && !ips.is_empty()
        {
            (hook.0)(qname, ips, Duration::from_secs(effective_ttl as u64));
        }

        // 3. 记录 DNS 统计
        if let Some(collector) = &self.collector {
            collector.record(qname, false);
        }
    }
}

pub struct RefreshTicket {
    transport: CachedTransport,
    leader: FlightLeader,
    raw_query: Vec<u8>,
    query: QueryContext,
}

impl RefreshTicket {
    pub fn tag(&self) -> &str {
        self.transport.tag()
    }

    pub fn query(&self) -> &QueryContext {
        &self.query
    }

    pub async fn run(self) -> anyhow::Result<ExchangeResult> {
        self.transport
            .fetch_and_cache(&self.raw_query, &self.query, Some(self.leader))
            .await
    }
}

pub struct ExchangeResult {
    pub wire: Vec<u8>,
    pub is_fresh: bool,
    pub refresh_ticket: Option<RefreshTicket>,
    pub answer_ips: Arc<[IpAddr]>,
    pub ttl: u32,
}

impl ExchangeResult {
    fn fresh(wire: Vec<u8>, answer_ips: Arc<[IpAddr]>, ttl: u32) -> Self {
        Self {
            wire,
            is_fresh: true,
            refresh_ticket: None,
            answer_ips,
            ttl,
        }
    }

    fn synthetic(wire: Vec<u8>, answer_ips: Arc<[IpAddr]>, ttl: u32) -> Self {
        Self { wire, answer_ips, ttl, is_fresh: false, refresh_ticket: None }
    }

    fn coalesced(template: &ResponseTemplate, query: &QueryContext) -> anyhow::Result<Self> {
        let rendered = template.render_with_ips(query)?;
        // UDP truncation makes the rendered packet uncacheable even when the
        // complete published template has a cache TTL.
        let ttl = if rendered.wire[2] & 2 != 0 { 0 } else { template.cache_ttl().unwrap_or(0) };
        Ok(Self { wire: rendered.wire, answer_ips: rendered.answer_ips,
            is_fresh: false, refresh_ticket: None, ttl })
    }

    fn cached_with_ttl(template: &ResponseTemplate, query: &QueryContext, ttl: u32, refresh_ticket: Option<RefreshTicket>) -> anyhow::Result<Self> {
        let rendered = template.render_cached(query, ttl)?;
        Ok(Self { wire: rendered.wire, is_fresh: false, refresh_ticket,
            answer_ips: rendered.answer_ips, ttl })
    }
}

impl From<ExchangeResult> for RenderedResponse {
    fn from(result: ExchangeResult) -> Self {
        Self { wire: result.wire, answer_ips: result.answer_ips }
    }
}

#[allow(async_fn_in_trait)]
#[enum_dispatch]
pub trait DnsTransport: Send + Sync {
    fn tag(&self) -> &str;
    fn upstream_type(&self) -> UpstreamType;

    fn is_fake_ip(&self) -> bool {
        self.upstream_type() == UpstreamType::FakeIp
    }

    async fn exchange(
        &self,
        raw_query: &[u8],
        query: &QueryContext,
    ) -> anyhow::Result<ExchangeResult>;
    async fn resolve_ip(
        &self,
        host: &str,
        ipv6: bool,
    ) -> anyhow::Result<Vec<IpAddr>>;
}

#[allow(async_fn_in_trait)]
#[enum_dispatch]
pub trait TransportEndpoint: Send + Sync + 'static {
    async fn fetch(
        &self,
        raw_query: &[u8],
        domain: &str,
        qtype: QType,
    ) -> anyhow::Result<Vec<u8>>;
}

#[derive(Clone)]
pub struct RemoteEndpoint {
    tag: String,
    upstream_keys: Vec<String>,
    pool: Arc<UpstreamPool>,
}

impl RemoteEndpoint {
    pub fn new(
        tag: String,
        upstream_keys: Vec<String>,
        pool: Arc<UpstreamPool>,
    ) -> Self {
        Self {
            tag,
            upstream_keys,
            pool,
        }
    }
}

impl TransportEndpoint for RemoteEndpoint {
    async fn fetch(
        &self,
        raw_query: &[u8],
        domain: &str,
        _qtype: QType,
    ) -> anyhow::Result<Vec<u8>> {
        if self.upstream_keys.is_empty() {
            anyhow::bail!("upstream '{}' has no servers configured", self.tag);
        }

        let budget = self.pool.dns_query_timeout + self.pool.dns_dial_timeout;
        let deadline = tokio::time::Instant::now() + budget;
        tokio::time::timeout_at(deadline, async {
            let mut last_err = None;
            for (index, key) in self.upstream_keys.iter().enumerate() {
                let remaining =
                    deadline.saturating_duration_since(tokio::time::Instant::now());
                let servers_left = (self.upstream_keys.len() - index) as u32;
                let attempt = tokio::time::timeout(
                    remaining / servers_left,
                    self.pool.query(key, raw_query),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(anyhow::anyhow!(
                        "DNS server '{key}' failover attempt timed out"
                    ))
                });
                match attempt {
                    Ok(resp) => return Ok(resp),
                    Err(err) => {
                        debug!(
                            upstream = %self.tag,
                            server = %key,
                            domain,
                            "upstream query failed: {err}"
                        );
                        last_err = Some(err);
                    }
                }
            }

            Err(last_err.unwrap_or_else(|| {
                anyhow::anyhow!("all servers in '{}' failed", self.tag)
            }))
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("DNS upstream '{}' failover budget exhausted", self.tag)
        })?
    }
}

#[derive(Clone)]
pub struct LocalEndpoint {
    tag: String,
}

impl LocalEndpoint {
    pub fn new(tag: String) -> Self {
        Self { tag }
    }
}

impl TransportEndpoint for LocalEndpoint {
    async fn fetch(
        &self,
        raw_query: &[u8],
        domain: &str,
        qtype: QType,
    ) -> anyhow::Result<Vec<u8>> {
        if qtype != QType::A && qtype != QType::AAAA {
            return Ok(build_dns_nodata(raw_query));
        }

        let addrs = match tokio::net::lookup_host(format!("{domain}:0")).await {
            Ok(iter) => iter.map(|s| s.ip()).collect::<Vec<_>>(),
            Err(err) => {
                debug!(upstream = %self.tag, domain, "local dns lookup failed: {err}");
                return Ok(build_dns_nxdomain(raw_query));
            }
        };

        let matching: Vec<IpAddr> = addrs
            .into_iter()
            .filter(|ip| match qtype {
                QType::A => ip.is_ipv4(),
                QType::AAAA => ip.is_ipv6(),
                _ => false,
            })
            .collect();

        if matching.is_empty() {
            Ok(build_dns_nodata(raw_query))
        } else if let Some(resp) = build_dns_ip_response(raw_query, &matching, 60) {
            Ok(resp)
        } else {
            Ok(build_dns_nodata(raw_query))
        }
    }
}

#[derive(Clone)]
#[enum_dispatch(TransportEndpoint)]
pub enum Endpoint {
    Remote(RemoteEndpoint),
    Local(LocalEndpoint),
}

#[derive(Clone)]
pub struct CachedTransport {
    tag: Arc<str>,
    upstream_type: UpstreamType,
    override_ttl: Option<u32>,
    endpoint: Endpoint,
    cache: DnsCache,
    singleflight: Singleflight,
    policy: DnsCachePolicy,
}

impl CachedTransport {
    pub fn new(
        tag: String,
        upstream_type: UpstreamType,
        override_ttl: Option<u32>,
        endpoint: Endpoint,
        cache: DnsCache,
        policy: DnsCachePolicy,
    ) -> Self {
        Self {
            tag: Arc::from(tag),
            upstream_type,
            override_ttl,
            endpoint,
            cache,
            singleflight: Singleflight::new(),
            policy,
        }
    }

    pub async fn fetch_and_cache(
        &self,
        raw_query: &[u8],
        query: &QueryContext,
        mut leader: Option<FlightLeader>,
    ) -> anyhow::Result<ExchangeResult> {
        let result = self.fetch_response(raw_query, query, leader.as_mut()).await;
        if let Err(error) = &result
            && let Some(leader) = leader.as_mut()
        {
            leader.publish_error(Arc::from(format!("{error:#}")));
        }
        result
    }

    async fn fetch_response(
        &self,
        raw_query: &[u8],
        query: &QueryContext,
        leader: Option<&mut FlightLeader>,
    ) -> anyhow::Result<ExchangeResult> {
        let domain = query.qdomain().unwrap_or_default();
        let qtype = query.qtype().unwrap_or(QType::A);
        let mut wire = self.endpoint.fetch(raw_query, domain, qtype).await?;
        let (template, negative, ttl) = ResponseTemplate::validate_with_ttl(query, &mut wire,
            |metadata| self.policy.effective_ttl(self.override_ttl, metadata))?;
        let is_acme = qtype == QType::TXT && domain.starts_with("_acme-challenge.");
        let answer_ips = template.answer_ips();
        let is_unspecified = !answer_ips.is_empty()
            && answer_ips.iter().all(|ip| ip.is_unspecified());
        let template = Arc::new(template);
        if !is_acme && !is_unspecified && ttl > 0 {
            let retention = if negative {
                Duration::ZERO
            } else {
                self.policy.stale_cache_retention
            };
            self.cache.insert_scoped(&self.tag, query, Arc::clone(&template), ttl, retention);
        }
        if let Some(leader) = leader {
            leader.publish(template);
        }
        Ok(ExchangeResult::fresh(wire, answer_ips, ttl))
    }

    pub fn new_remote(
        tag: String,
        override_ttl: Option<u32>,
        upstream_keys: Vec<String>,
        pool: Arc<UpstreamPool>,
        cache: DnsCache,
        policy: DnsCachePolicy,
    ) -> Self {
        let endpoint =
            Endpoint::Remote(RemoteEndpoint::new(tag.clone(), upstream_keys, pool));
        Self::new(
            tag,
            UpstreamType::Remote,
            override_ttl,
            endpoint,
            cache,
            policy,
        )
    }

    pub fn new_local(
        tag: String,
        override_ttl: Option<u32>,
        cache: DnsCache,
        policy: DnsCachePolicy,
    ) -> Self {
        let endpoint = Endpoint::Local(LocalEndpoint::new(tag.clone()));
        Self::new(
            tag,
            UpstreamType::Local,
            override_ttl,
            endpoint,
            cache,
            policy,
        )
    }
}

impl DnsTransport for CachedTransport {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn upstream_type(&self) -> UpstreamType {
        self.upstream_type
    }

    async fn exchange(
        &self,
        raw_query: &[u8],
        query: &QueryContext,
    ) -> anyhow::Result<ExchangeResult> {
        let domain = query.qdomain().unwrap_or_default();
        let qtype = query.qtype().unwrap_or(QType::A);

        // 1. 检查专属 LRU 缓存 (以 tag 隔离作用域，共享全局容量上限)
        let now = Instant::now();
        match self.cache.lookup_scoped(&self.tag, query, now) {
            CacheLookup::Hit(template, remaining_ttl) => {
                debug!(
                    upstream = %self.tag,
                    domain,
                    ?qtype,
                    remaining_ttl,
                    "cache hit"
                );
                return ExchangeResult::cached_with_ttl(&template, query, remaining_ttl, None);
            }
            CacheLookup::Stale(template) => {
                debug!(
                    upstream = %self.tag,
                    domain,
                    ?qtype,
                    "stale cache hit, serving stale"
                );
                let mut refresh_ticket = None;
                let flight_key = FlightKey::Refresh(query.canonical_wire_arc());
                if let FlightRole::Leader(leader) =
                    self.singleflight.acquire(flight_key)
                {
                    refresh_ticket = Some(RefreshTicket {
                        transport: self.clone(),
                        leader,
                        raw_query: raw_query.to_vec(),
                        query: query.clone(),
                    });
                }

                return ExchangeResult::cached_with_ttl(&template, query, STALE_RESPONSE_TTL, refresh_ticket);
            }
            CacheLookup::Miss => {}
        }

        // 2. 并发抑制 (Singleflight)
        let flight_key = FlightKey::Query(query.canonical_wire_arc());
        // A cancelled leader permits one coalesced retry. Endpoint failures are
        // published to all waiters instead of making each waiter query upstream.
        for _ in 0..2 {
            match self.singleflight.acquire(flight_key.clone()) {
                FlightRole::Ready(template) => {
                    return ExchangeResult::coalesced(&template, query);
                }
                FlightRole::Failed(error) => anyhow::bail!("{error}"),
                FlightRole::Waiter(waiter) => {
                    match waiter.receive_result().await {
                        Some(Ok(template)) => {
                            return ExchangeResult::coalesced(&template, query);
                        }
                        Some(Err(error)) => anyhow::bail!("{error}"),
                        None => continue,
                    }
                }
                FlightRole::Leader(leader) => {
                    return self.fetch_and_cache(raw_query, query, Some(leader)).await;
                }
                FlightRole::Rejected => anyhow::bail!("DNS singleflight capacity exhausted"),
            }
        }
        anyhow::bail!("DNS singleflight leader repeatedly cancelled")
    }

    async fn resolve_ip(
        &self,
        host: &str,
        ipv6: bool,
    ) -> anyhow::Result<Vec<IpAddr>> {
        let qtype = if ipv6 { QType::AAAA } else { QType::A };
        let name = DnsName::from_domain(host)
            .ok_or_else(|| anyhow::anyhow!("invalid domain: {host}"))?;
        let query_wire = build_dns_query_wire(&name, qtype);
        let query = QueryContext::parse(&query_wire)
            .map_err(|e| anyhow::anyhow!("failed to parse built query: {e}"))?;
        let resp = self.exchange(&query_wire, &query).await?;
        Ok(resp.answer_ips.to_vec())
    }
}

pub type RemoteTransport = CachedTransport;
pub type LocalTransport = CachedTransport;

#[derive(Clone)]
pub struct FakeIpTransport {
    tag: String,
    fake_dns: Arc<FakeDns>,
    ttl: u32,
}

impl FakeIpTransport {
    pub fn new(tag: String, fake_dns: Arc<FakeDns>, ttl: u32) -> Self {
        Self { tag, fake_dns, ttl }
    }

    pub fn fake_dns(&self) -> &Arc<FakeDns> {
        &self.fake_dns
    }
}

impl DnsTransport for FakeIpTransport {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn upstream_type(&self) -> UpstreamType {
        UpstreamType::FakeIp
    }

    async fn exchange(
        &self,
        raw_query: &[u8],
        query: &QueryContext,
    ) -> anyhow::Result<ExchangeResult> {
        let domain = query.qdomain().unwrap_or_default();
        if domain.is_empty() {
            return Ok(ExchangeResult::synthetic(build_dns_nodata(raw_query), Arc::from([]), 0));
        }
        let qtype = query.qtype().unwrap_or(QType::A);
        let ip = match qtype {
            QType::A => {
                let ip = self.fake_dns.lookup(domain);
                debug!(upstream = %self.tag, domain, ?qtype, fake_ip = %ip, "assigned fake-ip");
                Some(ip)
            }
            QType::AAAA => {
                let ip = self.fake_dns.lookupv6(domain);
                debug!(upstream = %self.tag, domain, ?qtype, fake_ip = %ip, "assigned fake-ip");
                Some(ip)
            }
            _ => None,
        };
        if let Some(ip) = ip {
            let wire = build_dns_ip_response(raw_query, &[ip], self.ttl)
                .ok_or_else(|| anyhow::anyhow!("failed to construct fakeip response"))?;
            Ok(ExchangeResult::synthetic(wire, Arc::from([ip]), self.ttl))
        } else {
            Ok(ExchangeResult::synthetic(build_dns_nodata(raw_query), Arc::from([]), 0))
        }
    }

    async fn resolve_ip(
        &self,
        host: &str,
        ipv6: bool,
    ) -> anyhow::Result<Vec<IpAddr>> {
        if host.is_empty() {
            return Ok(vec![]);
        }
        if ipv6 {
            Ok(vec![self.fake_dns.lookupv6(host)])
        } else {
            Ok(vec![self.fake_dns.lookup(host)])
        }
    }
}

#[derive(Clone)]
#[enum_dispatch(DnsTransport)]
pub enum Transport {
    Cached(CachedTransport),
    FakeIp(FakeIpTransport),
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
