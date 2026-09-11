use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use enum_dispatch::enum_dispatch;
use tracing::debug;

use crate::app::dns::fakeip::FakeDns;
use crate::app::dns::query::{DnsName, QType, QueryContext, build_dns_query_wire};
use crate::app::dns::resolver::enhanced::{
    CacheLookup, DnsCache, ReverseLookupCache, SERVE_STALE_WIRE_TTL,
};
use crate::app::dns::response::{
    ResponseTemplate, build_dns_ip_response, build_dns_nodata, build_dns_nxdomain,
};
use crate::app::dns::singleflight::{FlightKey, FlightRole, Singleflight};
use crate::app::dns::upstream_pool::UpstreamPool;
use crate::app::dns::wire::{
    extract_ips_from_dns_response, extract_min_ttl_from_dns_response,
    rewrite_dns_response_ttl,
};
use crate::app::dns::{DnsResolutionHook, ThreadSafeDnsCollector};

use super::config::UpstreamType;

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
            stale_cache_retention: Duration::from_secs(stale_cache_retention_secs as u64),
        }
    }

    pub fn calculate_effective_ttl(&self, override_ttl: Option<u32>, raw_resp: &[u8]) -> u32 {
        if let Some(ttl) = override_ttl {
            ttl
        } else {
            let min_ttl = extract_min_ttl_from_dns_response(raw_resp).unwrap_or(60);
            if self.optimistic_cache_ttl > 0 {
                min_ttl.max(self.optimistic_cache_ttl)
            } else {
                min_ttl
            }
        }
    }
}

#[derive(Clone)]
pub struct DnsResolvedNotifier {
    reverse_lookup_cache: ReverseLookupCache,
    resolution_hook: Arc<OnceLock<DnsResolutionHook>>,
    collector: Option<ThreadSafeDnsCollector>,
}

impl DnsResolvedNotifier {
    pub fn new(
        reverse_lookup_cache: ReverseLookupCache,
        resolution_hook: Arc<OnceLock<DnsResolutionHook>>,
        collector: Option<ThreadSafeDnsCollector>,
    ) -> Self {
        Self {
            reverse_lookup_cache,
            resolution_hook,
            collector,
        }
    }

    pub fn on_fresh_response(&self, qname: &str, resp: &[u8], effective_ttl: u32) {
        let ips = extract_ips_from_dns_response(resp);

        // 1. 保存反向 IP 缓存（供后续连接管理反查域名）
        if effective_ttl > 0 {
            for ip in &ips {
                if !ip.is_unspecified() {
                    self.reverse_lookup_cache.insert(*ip, qname, effective_ttl);
                }
            }
        }

        // 2. 触发 Resolution Hook (例如 eBPF offload)
        if let Some(hook) = self.resolution_hook.get() {
            if !ips.is_empty() {
                hook(qname, &ips, Duration::from_secs(effective_ttl as u64));
            }
        }

        // 3. 记录 DNS 统计
        if let Some(collector) = &self.collector {
            collector.record(qname, false);
        }
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
    ) -> anyhow::Result<Vec<u8>>;
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

        let mut last_err = None;
        for key in &self.upstream_keys {
            match self.pool.query(key, raw_query).await {
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
    notifier: Option<DnsResolvedNotifier>,
    policy: DnsCachePolicy,
}

impl CachedTransport {
    pub fn new(
        tag: String,
        upstream_type: UpstreamType,
        override_ttl: Option<u32>,
        endpoint: Endpoint,
        cache: DnsCache,
        notifier: Option<DnsResolvedNotifier>,
        policy: DnsCachePolicy,
    ) -> Self {
        Self {
            tag: Arc::from(tag),
            upstream_type,
            override_ttl,
            endpoint,
            cache,
            singleflight: Singleflight::new(),
            notifier,
            policy,
        }
    }

    pub fn new_remote(
        tag: String,
        override_ttl: Option<u32>,
        upstream_keys: Vec<String>,
        pool: Arc<UpstreamPool>,
        cache: DnsCache,
        notifier: Option<DnsResolvedNotifier>,
        policy: DnsCachePolicy,
    ) -> Self {
        let endpoint =
            Endpoint::Remote(RemoteEndpoint::new(tag.clone(), upstream_keys, pool));
        Self::new(tag, UpstreamType::Remote, override_ttl, endpoint, cache, notifier, policy)
    }

    pub fn new_local(
        tag: String,
        override_ttl: Option<u32>,
        cache: DnsCache,
        notifier: Option<DnsResolvedNotifier>,
        policy: DnsCachePolicy,
    ) -> Self {
        let endpoint = Endpoint::Local(LocalEndpoint::new(tag.clone()));
        Self::new(tag, UpstreamType::Local, override_ttl, endpoint, cache, notifier, policy)
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
    ) -> anyhow::Result<Vec<u8>> {
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
                if let Ok(mut rendered) = template.render(query) {
                    let effective_ttl = self.override_ttl.unwrap_or(remaining_ttl);
                    rewrite_dns_response_ttl(rendered.as_mut_slice(), effective_ttl);
                    return Ok(rendered);
                }
            }
            CacheLookup::Stale(template) => {
                debug!(
                    upstream = %self.tag,
                    domain,
                    ?qtype,
                    "stale cache hit, serving stale and refreshing asynchronously"
                );
                let flight_key = FlightKey::Refresh(query.canonical_wire_arc());
                if let FlightRole::Leader(mut leader) =
                    self.singleflight.acquire(flight_key)
                {
                    let this = self.clone();
                    let raw_query_vec = raw_query.to_vec();
                    let domain_string = domain.to_string();
                    let query_clone = query.clone();

                    tokio::spawn(async move {
                        if let Ok(fresh_resp) = this
                            .endpoint
                            .fetch(&raw_query_vec, &domain_string, qtype)
                            .await
                        {
                            let effective_ttl = this.policy.calculate_effective_ttl(this.override_ttl, &fresh_resp);
                            let ips = extract_ips_from_dns_response(&fresh_resp);
                            let is_acme = query_clone.qtype() == Some(QType::TXT)
                                && domain_string.starts_with("_acme-challenge.");
                            let is_unspecified = !ips.is_empty() && ips.iter().all(|ip| ip.is_unspecified());

                            if let Ok(fresh_tmpl) =
                                ResponseTemplate::validate(&query_clone, &fresh_resp)
                            {
                                let arc_template = Arc::new(fresh_tmpl);
                                leader.publish(Arc::clone(&arc_template));
                                if !is_acme && !is_unspecified && effective_ttl > 0 {
                                    this.cache.insert_scoped(
                                        &this.tag,
                                        &query_clone,
                                        arc_template,
                                        effective_ttl,
                                        this.policy.stale_cache_retention,
                                    );
                                }
                            }
                            if let Some(notifier) = &this.notifier {
                                notifier
                                    .on_fresh_response(&domain_string, &fresh_resp, effective_ttl);
                            }
                        }
                    });
                }

                if let Ok(mut rendered) = template.render(query) {
                    let effective_ttl = self.override_ttl.unwrap_or(SERVE_STALE_WIRE_TTL);
                    rewrite_dns_response_ttl(
                        rendered.as_mut_slice(),
                        effective_ttl,
                    );
                    return Ok(rendered);
                }
            }
            CacheLookup::Miss => {}
        }

        // 2. 并发抑制 (Singleflight)
        let flight_key = FlightKey::Query(query.canonical_wire_arc());
        match self.singleflight.acquire(flight_key) {
            FlightRole::Ready(template) => {
                let mut rendered = template.render(query)?;
                if let Some(ttl) = self.override_ttl {
                    rewrite_dns_response_ttl(rendered.as_mut_slice(), ttl);
                }
                Ok(rendered)
            }
            FlightRole::Waiter(waiter) => {
                if let Some(template) = waiter.receive().await {
                    let mut rendered = template.render(query)?;
                    if let Some(ttl) = self.override_ttl {
                        rewrite_dns_response_ttl(rendered.as_mut_slice(), ttl);
                    }
                    Ok(rendered)
                } else {
                    let mut resp = self.endpoint.fetch(raw_query, domain, qtype).await?;
                    let effective_ttl = self.policy.calculate_effective_ttl(self.override_ttl, &resp);
                    if self.override_ttl.is_some() || self.policy.optimistic_cache_ttl > 0 {
                        rewrite_dns_response_ttl(resp.as_mut_slice(), effective_ttl);
                    }
                    if let Some(notifier) = &self.notifier {
                        notifier.on_fresh_response(domain, &resp, effective_ttl);
                    }
                    Ok(resp)
                }
            }
            FlightRole::Leader(mut leader) => {
                let mut resp = self.endpoint.fetch(raw_query, domain, qtype).await?;
                let effective_ttl = self.policy.calculate_effective_ttl(self.override_ttl, &resp);
                let ips = extract_ips_from_dns_response(&resp);
                let is_acme = query.qtype() == Some(QType::TXT)
                    && domain.starts_with("_acme-challenge.");
                let is_unspecified = !ips.is_empty() && ips.iter().all(|ip| ip.is_unspecified());

                if let Ok(template) = ResponseTemplate::validate(query, &resp) {
                    let arc_template = Arc::new(template);
                    leader.publish(Arc::clone(&arc_template));
                    if !is_acme && !is_unspecified && effective_ttl > 0 {
                        self.cache.insert_scoped(
                            &self.tag,
                            query,
                            arc_template,
                            effective_ttl,
                            self.policy.stale_cache_retention,
                        );
                    }
                }
                if self.override_ttl.is_some() || self.policy.optimistic_cache_ttl > 0 {
                    rewrite_dns_response_ttl(resp.as_mut_slice(), effective_ttl);
                }
                if let Some(notifier) = &self.notifier {
                    notifier.on_fresh_response(domain, &resp, effective_ttl);
                }
                Ok(resp)
            }
            FlightRole::Rejected => {
                let mut resp = self.endpoint.fetch(raw_query, domain, qtype).await?;
                let effective_ttl = self.policy.calculate_effective_ttl(self.override_ttl, &resp);
                if self.override_ttl.is_some() || self.policy.optimistic_cache_ttl > 0 {
                    rewrite_dns_response_ttl(resp.as_mut_slice(), effective_ttl);
                }
                if let Some(notifier) = &self.notifier {
                    notifier.on_fresh_response(domain, &resp, effective_ttl);
                }
                Ok(resp)
            }
        }
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
        let ips = extract_ips_from_dns_response(&resp);
        Ok(ips)
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
    ) -> anyhow::Result<Vec<u8>> {
        let domain = query.qdomain().unwrap_or_default();
        let qtype = query.qtype().unwrap_or(QType::A);
        match qtype {
            QType::A => {
                let ip = self.fake_dns.lookup(domain);
                debug!(upstream = %self.tag, domain, ?qtype, fake_ip = %ip, "assigned fake-ip");
                build_dns_ip_response(raw_query, &[ip], self.ttl).ok_or_else(|| {
                    anyhow::anyhow!("failed to construct fakeip A response")
                })
            }
            QType::AAAA => {
                let ip = self.fake_dns.lookupv6(domain);
                debug!(upstream = %self.tag, domain, ?qtype, fake_ip = %ip, "assigned fake-ip");
                build_dns_ip_response(raw_query, &[ip], self.ttl).ok_or_else(|| {
                    anyhow::anyhow!("failed to construct fakeip AAAA response")
                })
            }
            _ => Ok(build_dns_nodata(raw_query)),
        }
    }

    async fn resolve_ip(
        &self,
        host: &str,
        ipv6: bool,
    ) -> anyhow::Result<Vec<IpAddr>> {
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
