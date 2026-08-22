mod cache;
mod policy;
#[cfg(test)]
mod tests;

pub use cache::{CacheLookup, DnsCache, SERVE_STALE_WIRE_TTL};
pub use policy::NameServerPolicyContainer;

use std::collections::HashMap;
use std::net::{self, IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use async_trait::async_trait;
use rand::seq::IteratorRandom;
use tracing::{debug, instrument, trace};

use crate::app::dns::config::{Config, NameServer};
use crate::app::dns::fakeip::{self, FileStore, InMemStore, ThreadSafeFakeDns};
use crate::app::dns::filters::{BlackDomainFilter, DomainFilter, FallbackFilter, PendingMmdb};
use crate::app::dns::query::{DnsName, QType, QueryContext, build_dns_query_wire};
use crate::app::dns::response::{
    ResponseTemplate, build_dns_ip_response, build_dns_nxdomain,
};
use crate::app::dns::singleflight::{FlightKey, FlightRole, Singleflight};
use crate::app::dns::upstream_pool::{UpstreamEntry, UpstreamPool};
use crate::app::dns::wire::{
    extract_ips_from_dns_response, extract_min_ttl_from_dns_response, rewrite_dns_response_ttl,
};
use crate::app::dns::{
    ClashResolver, DnsResolutionHook, ResolverKind, RuleDispatch, ThreadSafeDnsCollector,
    parse_ip_literal,
};
use crate::app::profile::ThreadSafeCacheFile;
use crate::app::router::Router;
use crate::common::trie;
use crate::config::def::DNSMode;
use crate::proxy::utils::OutboundHandlerRegistry;
use crate::Error;

#[derive(Clone)]
pub struct EnhancedResolver {
    inner: Arc<EnhancedResolverInner>,
}

impl std::ops::Deref for EnhancedResolver {
    type Target = EnhancedResolverInner;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct EnhancedResolverInner {
    ipv6: AtomicBool,
    hosts: Option<trie::StringTrie<net::IpAddr>>,
    pool: Arc<UpstreamPool>,
    main_upstreams: Vec<String>,

    fallback_upstreams: Option<Vec<String>>,
    fallback_filter: Option<FallbackFilter>,

    lru_cache: Option<DnsCache>,
    policy: Option<NameServerPolicyContainer>,

    proxy_upstreams: Option<Vec<String>>,
    proxy_server_domains: Option<trie::StringTrie<bool>>,

    fake_dns: Option<ThreadSafeFakeDns>,
    fake_ip_ttl: u32,

    reverse_lookup_cache: Option<moka::future::Cache<net::IpAddr, String>>,
    black_domain_filter: Option<BlackDomainFilter>,
    collector: Option<ThreadSafeDnsCollector>,

    singleflight: Singleflight,
    optimistic_cache_ttl: u32,
    stale_cache_retention: Duration,
    fixed_domain_ttl: Option<trie::StringTrie<u32>>,
    resolution_hook: OnceLock<DnsResolutionHook>,
}

impl EnhancedResolver {
    pub async fn new(
        cfg: Config,
        store: ThreadSafeCacheFile,
        mmdb: Option<PendingMmdb>,
        outbounds: OutboundHandlerRegistry,
        rule_dispatch: Option<Arc<RuleDispatch>>,
        collector: Option<ThreadSafeDnsCollector>,
    ) -> Self {
        let mut entries = HashMap::new();

        let register_upstream = |ns: &NameServer, entries: &mut HashMap<String, UpstreamEntry>| -> Option<String> {
            let key = ns.to_string();
            if !entries.contains_key(&key) {
                if let Ok(mut entry) = UpstreamEntry::from_nameserver(ns, None) {
                    entry.ecs = cfg.edns_client_subnet.clone();
                    entries.insert(key.clone(), entry);
                }
            }
            if entries.contains_key(&key) {
                Some(key)
            } else {
                None
            }
        };

        // 1. Default / Bootstrap resolver
        let mut default_entries = HashMap::new();
        let mut default_upstreams = Vec::new();
        for ns in &cfg.default_nameserver {
            if let Some(key) = register_upstream(ns, &mut default_entries) {
                if !default_upstreams.contains(&key) {
                    default_upstreams.push(key);
                }
            }
        }
        let bootstrap_resolver: Option<Arc<dyn ClashResolver>> = if !default_upstreams.is_empty() {
            let default_pool = UpstreamPool::new(
                default_entries,
                outbounds.clone(),
                None,
                cfg.fw_mark,
                None,
                None,
            );
            Some(Arc::new(BootstrapResolver {
                pool: default_pool,
                upstreams: default_upstreams,
            }))
        } else {
            None
        };

        // 2. Main nameservers
        let mut main_upstreams = Vec::new();
        for ns in &cfg.nameserver {
            if let Some(key) = register_upstream(ns, &mut entries) {
                if !main_upstreams.contains(&key) {
                    main_upstreams.push(key);
                }
            }
        }

        // 3. Fallback nameservers
        let mut fallback_upstreams = Vec::new();
        for ns in &cfg.fallback {
            if let Some(key) = register_upstream(ns, &mut entries) {
                if !fallback_upstreams.contains(&key) {
                    fallback_upstreams.push(key);
                }
            }
        }

        // 4. Policy nameservers
        let mut policy_container = NameServerPolicyContainer::new();
        for (domain, nss) in &cfg.nameserver_policy {
            let mut policy_ups = Vec::new();
            for ns in nss {
                if let Some(key) = register_upstream(ns, &mut entries) {
                    if !policy_ups.contains(&key) {
                        policy_ups.push(key);
                    }
                }
            }
            if !policy_ups.is_empty() {
                policy_container.insert(domain, policy_ups);
            }
        }

        // 5. Proxy server nameservers
        let mut proxy_upstreams = Vec::new();
        if let Some(ref p_ns) = cfg.proxy_server_nameserver {
            for ns in p_ns {
                if let Some(key) = register_upstream(ns, &mut entries) {
                    if !proxy_upstreams.contains(&key) {
                        proxy_upstreams.push(key);
                    }
                }
            }
        }

        let proxy_server_domains = {
            let plain_outbounds = outbounds.read();
            let mut domains = trie::StringTrie::new();
            let mut has_domain = false;
            for x in plain_outbounds.values() {
                if let Some(s) = x.server_name() {
                    domains.insert(s, Arc::new(true));
                    debug!("added proxy server domain: {}", s);
                    has_domain = true;
                }
            }
            if has_domain && !proxy_upstreams.is_empty() {
                Some(domains)
            } else {
                None
            }
        };

        let pool = UpstreamPool::new(
            entries,
            outbounds.clone(),
            bootstrap_resolver,
            cfg.fw_mark,
            None,
            rule_dispatch,
        );

        let fake_dns = match cfg.enhance_mode {
            DNSMode::FakeIp => Some(Arc::new(
                fakeip::FakeDns::new(fakeip::Opts {
                    ipnet: cfg.fake_ip_range,
                    ipnet6: cfg.fake_ip_range6,
                    domain_filter: if cfg.fake_ip_filter.is_empty() {
                        None
                    } else {
                        Some(DomainFilter::new(cfg.fake_ip_filter))
                    },
                    filter_mode: cfg.fake_ip_filter_mode,
                    store: if cfg.store_fake_ip {
                        Box::new(FileStore::new(store))
                    } else {
                        Box::new(InMemStore::new(1000))
                    },
                })
                .expect("failed to create fake ip"),
            )),
            _ => None,
        };

        let fallback_filter = {
            let filter = FallbackFilter::new(
                &cfg.fallback_filter.domain,
                &cfg.fallback_filter.ip_cidr,
                cfg.fallback_filter.geo_ip,
                &cfg.fallback_filter.geo_ip_code,
                mmdb,
            );
            if filter.is_empty() {
                None
            } else {
                Some(filter)
            }
        };

        let black_domain_filter = if !cfg.black_filter.is_empty() {
            Some(BlackDomainFilter::new(cfg.black_filter))
        } else {
            None
        };

        let reverse_lookup_cache = match cfg.enhance_mode {
            DNSMode::RedirHost => Some(
                moka::future::Cache::builder()
                    .max_capacity(4096)
                    .time_to_idle(Duration::from_secs(300))
                    .build(),
            ),
            _ => None,
        };

        let fixed_domain_ttl = if !cfg.fixed_domain_ttl.is_empty() {
            let mut trie = trie::StringTrie::new();
            for (domain, ttl) in cfg.fixed_domain_ttl {
                trie.insert(&domain, Arc::new(ttl));
            }
            Some(trie)
        } else {
            None
        };

        let inner = Arc::new(EnhancedResolverInner {
            ipv6: AtomicBool::new(cfg.ipv6),
            hosts: cfg.hosts,
            pool,
            main_upstreams,
            fallback_upstreams: if fallback_upstreams.is_empty() {
                None
            } else {
                Some(fallback_upstreams)
            },
            fallback_filter,
            lru_cache: Some(DnsCache::new(4096)),
            policy: if policy_container.is_empty() {
                None
            } else {
                Some(policy_container)
            },
            proxy_upstreams: if proxy_upstreams.is_empty() {
                None
            } else {
                Some(proxy_upstreams)
            },
            proxy_server_domains,
            fake_dns,
            fake_ip_ttl: cfg.fake_ip_ttl,
            reverse_lookup_cache,
            black_domain_filter,
            collector,
            singleflight: Singleflight::new(),
            optimistic_cache_ttl: cfg.optimistic_cache_ttl,
            stale_cache_retention: Duration::from_secs(cfg.stale_cache_retention as u64),
            fixed_domain_ttl,
            resolution_hook: OnceLock::new(),
        });

        Self { inner }
    }

    fn is_blacklisted(&self, host: &str) -> bool {
        if let Some(bdf) = &self.black_domain_filter {
            bdf.apply(host)
        } else {
            false
        }
    }

    fn match_fixed_domain_ttl(&self, domain: &str) -> Option<u32> {
        self.fixed_domain_ttl
            .as_ref()?
            .search(domain)?
            .get_data()
            .copied()
    }

    async fn batch_exchange(&self, upstreams: &[String], raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        if upstreams.is_empty() {
            anyhow::bail!("no upstreams configured");
        }

        let queries = upstreams
            .iter()
            .map(|name| Box::pin(self.pool.query(name, raw_query)));
        let (resp, _) = futures::future::select_ok(queries).await?;
        Ok(resp)
    }

    async fn fallback_exchange(&self, query: &QueryContext, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let Some(ref fallback_upstreams) = self.fallback_upstreams else {
            return self.batch_exchange(&self.main_upstreams, raw_query).await;
        };

        let filter = self.fallback_filter.as_ref();
        let main_fut = self.batch_exchange(&self.main_upstreams, raw_query);
        let fallback_fut = self.batch_exchange(fallback_upstreams, raw_query);

        let (main_res, fallback_res) = tokio::join!(main_fut, fallback_fut);

        if let Ok(main_bytes) = main_res {
            if let Some(filter) = filter {
                let ips = extract_ips_from_dns_response(&main_bytes);
                let qname = query.qdomain().unwrap_or_default();
                if filter.match_domain(qname) || ips.iter().any(|ip| filter.match_ip(ip)) {
                    if let Ok(fallback_bytes) = fallback_res {
                        return Ok(fallback_bytes);
                    }
                }
            }
            return Ok(main_bytes);
        }

        fallback_res
    }

    async fn lookup_ip(
        &self,
        host: &str,
        is_v6: bool,
    ) -> anyhow::Result<Vec<net::IpAddr>> {
        let qtype = if is_v6 { QType::AAAA } else { QType::A };
        let name = DnsName::from_domain(host)
            .ok_or_else(|| anyhow!("invalid domain name: {host}"))?;

        let query = build_dns_query_wire(&name, qtype);
        let response = self.exchange(&query).await?;
        let ips = extract_ips_from_dns_response(&response);
        if ips.is_empty() {
            return Err(anyhow!("no record for hostname: {}", host));
        }
        Ok(ips)
    }

    async fn exchange_no_cache(&self, query: &QueryContext, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let qname = query.qdomain().unwrap_or_default();

        if let (Some(proxy_upstreams), Some(proxy_domains)) =
            (&self.proxy_upstreams, &self.proxy_server_domains)
            && proxy_domains.search(qname).is_some()
        {
            debug!(
                domain = %qname,
                "using proxy-server-nameserver for proxy server domain"
            );
            return self.batch_exchange(proxy_upstreams, raw_query).await;
        }

        if let Some(policy) = &self.policy {
            if let Some(upstreams) = policy.match_policy(qname) {
                debug!(domain = %qname, ?upstreams, "DNS matched nameserver policy");
                return self.batch_exchange(upstreams, raw_query).await;
            }
        }

        trace!(domain = %qname, "DNS proceeding to main/fallback upstreams");
        self.fallback_exchange(query, raw_query).await
    }

    async fn process_fresh_response(
        &self,
        query: &QueryContext,
        host: &str,
        raw_resp: &[u8],
        template_to_publish: Option<Arc<ResponseTemplate>>,
    ) {
        let ips = extract_ips_from_dns_response(raw_resp);
        let fixed_ttl = self.match_fixed_domain_ttl(host);
        let mut ttl = fixed_ttl
            .or_else(|| extract_min_ttl_from_dns_response(raw_resp))
            .unwrap_or(60);

        if fixed_ttl.is_none() && self.optimistic_cache_ttl > 0 {
            ttl = ttl.max(self.optimistic_cache_ttl);
        }

        debug!(
            domain = %host,
            ?ips,
            ttl,
            "DNS resolved response received"
        );

        // 1. Cache insertion (with ACME challenge, 0.0.0.0 pollution filtering, and fixed_ttl=0 never-cache)
        if let (Some(template), Some(lru)) = (template_to_publish, &self.lru_cache) {
            let is_acme = query.qtype() == Some(QType::TXT) && host.starts_with("_acme-challenge.");
            let is_unspecified = !ips.is_empty() && ips.iter().all(|ip| ip.is_unspecified());
            let never_cache = fixed_ttl == Some(0) || ttl == 0;

            if !is_acme && !is_unspecified && !never_cache {
                lru.insert(query, template, ttl, self.stale_cache_retention);
            }
        }

        // 2. Save reverse lookup cache (for RedirHost mode)
        if let Some(cache) = &self.reverse_lookup_cache {
            for ip in &ips {
                cache.insert(*ip, host.to_string()).await;
            }
        }

        // 3. Trigger DNS resolution hook (e.g. for eBPF offloading)
        if let Some(hook) = self.resolution_hook.get() {
            if !ips.is_empty() {
                hook(host, &ips, Duration::from_secs(ttl as u64));
            }
        }

        // 4. Record DNS statistics
        if let Some(collector) = &self.collector {
            collector.record(host, false);
        }
    }
}

#[async_trait]
impl ClashResolver for EnhancedResolver {
    fn register_resolution_hook(&self, hook: DnsResolutionHook) {
        let _ = self.resolution_hook.set(hook);
    }

    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<net::IpAddr>> {
        debug!(domain = %host, enhanced, "DNS resolve requested");
        if self.is_blacklisted(host) {
            debug!("dns resolve domain in blacklist: {}", host);
            return Ok(None);
        }

        if let Some(ip) = parse_ip_literal(host) {
            return Ok(Some(ip));
        }

        if let Some(hosts) = &self.hosts {
            if let Some(h) = hosts.search(host).and_then(|h| h.get_data()) {
                debug!(domain = %host, ip = ?h, "DNS matched hosts file");
                return Ok(Some(*h));
            }
        }

        if enhanced && let Some(fake_dns) = &self.fake_dns {
            if !fake_dns.should_skip(host) {
                let ip = fake_dns.lookup(host).await;
                debug!(domain = %host, ?ip, "DNS Fake-IP assigned");
                if let Some(collector) = &self.collector {
                    collector.record(host, true);
                }
                return Ok(Some(ip));
            }
        }

        let is_v6 = self.ipv6();
        let ips = self.lookup_ip(host, is_v6).await?;
        if let Some(collector) = &self.collector {
            collector.record(host, false);
        }
        let chosen = ips.into_iter().choose(&mut rand::rng());
        debug!(domain = %host, ?chosen, "DNS resolve completed");
        Ok(chosen)
    }

    async fn resolve_v4(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<net::Ipv4Addr>> {
        if self.is_blacklisted(host) {
            debug!("dns resolve_v4 domain in blacklist: {}", host);
            return Ok(None);
        }

        if let Some(ip) = parse_ip_literal(host) {
            match ip {
                net::IpAddr::V4(v4) => return Ok(Some(v4)),
                _ => return Ok(None),
            }
        }

        if let Some(hosts) = &self.hosts {
            if let Some(h) = hosts.search(host).and_then(|h| h.get_data()) {
                match h {
                    net::IpAddr::V4(v4) => return Ok(Some(*v4)),
                    _ => return Ok(None),
                }
            }
        }

        if enhanced && let Some(fake_dns) = &self.fake_dns {
            if !fake_dns.should_skip(host) {
                if let net::IpAddr::V4(ip) = fake_dns.lookup(host).await {
                    if let Some(collector) = &self.collector {
                        collector.record(host, true);
                    }
                    return Ok(Some(ip));
                }
            }
        }

        let ips = self.lookup_ip(host, false).await?;
        let v4s: Vec<Ipv4Addr> = ips
            .into_iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
            .collect();
        match v4s.into_iter().choose(&mut rand::rng()) {
            Some(v4) => {
                if let Some(collector) = &self.collector {
                    collector.record(host, false);
                }
                Ok(Some(v4))
            }
            None => Ok(None),
        }
    }

    async fn resolve_v6(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<net::Ipv6Addr>> {
        if self.is_blacklisted(host) {
            debug!("dns resolve_v6 domain in blacklist: {}", host);
            return Ok(None);
        }

        if !self.ipv6() {
            return Err(Error::DNSError("ipv6 disabled".into()).into());
        }

        if let Some(ip) = parse_ip_literal(host) {
            match ip {
                net::IpAddr::V6(v6) => return Ok(Some(v6)),
                _ => return Ok(None),
            }
        }

        if let Some(hosts) = &self.hosts {
            if let Some(h) = hosts.search(host).and_then(|h| h.get_data()) {
                match h {
                    net::IpAddr::V6(v6) => return Ok(Some(*v6)),
                    _ => return Ok(None),
                }
            }
        }

        if enhanced && let Some(fake_dns) = &self.fake_dns {
            if !fake_dns.should_skip(host) {
                if let net::IpAddr::V6(ip) = fake_dns.lookupv6(host).await {
                    if let Some(collector) = &self.collector {
                        collector.record(host, true);
                    }
                    return Ok(Some(ip));
                }
            }
        }

        let ips = self.lookup_ip(host, true).await?;
        let v6s: Vec<Ipv6Addr> = ips
            .into_iter()
            .filter_map(|ip| match ip {
                IpAddr::V6(v6) => Some(v6),
                _ => None,
            })
            .collect();
        match v6s.into_iter().choose(&mut rand::rng()) {
            Some(v6) => {
                if let Some(collector) = &self.collector {
                    collector.record(host, false);
                }
                Ok(Some(v6))
            }
            None => Ok(None),
        }
    }

    async fn cached_for(&self, ip: net::IpAddr) -> Option<String> {
        if let Some(cache) = &self.reverse_lookup_cache {
            cache.get(&ip).await
        } else {
            None
        }
    }

    #[instrument(skip_all, level = "trace")]
    async fn exchange(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let query = QueryContext::parse(raw_query)
            .map_err(|e| anyhow!("invalid DNS query: {e:?}"))?;

        let host = query.qdomain().unwrap_or_default();

        let qtype = query.qtype().unwrap_or(QType::A);
        debug!(domain = %host, ?qtype, "DNS exchange query received");

        if self.is_blacklisted(host) {
            debug!("dns query domain in blacklist: {}", host);
            return Ok(build_dns_nxdomain(raw_query));
        }

        // AAAA asked for while IPv6 is globally disabled: answer NODATA (NoError + zero answers)
        if qtype == QType::AAAA && !self.ipv6() {
            debug!(domain = %host, "AAAA query while IPv6 disabled, returning NODATA");
            return Ok(crate::app::dns::response::build_dns_nodata(raw_query));
        }

        // 1. Hosts match (takes precedence over Fake-IP when record type matches)
        if let Some(hosts) = &self.hosts {
            if let Some(host_ip) = hosts.search(host).and_then(|h| h.get_data()) {
                let matches = match (qtype, host_ip) {
                    (QType::A, net::IpAddr::V4(_)) | (QType::AAAA, net::IpAddr::V6(_)) => true,
                    _ => false,
                };
                if matches {
                    debug!(domain = %host, ip = ?host_ip, "DNS exchange matched hosts");
                    if let Some(resp) = build_dns_ip_response(raw_query, &[*host_ip], 60) {
                        return Ok(resp);
                    }
                }
                // When the host entry is for the other family or query is non-A/AAAA (e.g. HTTPS/TXT),
                // fall through to normal resolution rather than returning NODATA.
            }
        }

        // 2. Fake-IP match
        if let Some(fake_dns) = &self.fake_dns {
            if !fake_dns.should_skip(host) {
                if qtype == QType::A {
                    let fake_ip = fake_dns.lookup(host).await;
                    debug!(domain = %host, ?fake_ip, "DNS exchange assigned Fake-IP (A)");
                    if let Some(resp) = build_dns_ip_response(raw_query, &[fake_ip], self.fake_ip_ttl) {
                        return Ok(resp);
                    }
                } else if qtype == QType::AAAA && self.ipv6() {
                    let fake_ip = fake_dns.lookupv6(host).await;
                    debug!(domain = %host, ?fake_ip, "DNS exchange assigned Fake-IP (AAAA)");
                    if let Some(resp) = build_dns_ip_response(raw_query, &[fake_ip], self.fake_ip_ttl) {
                        return Ok(resp);
                    }
                }
            }
        }

        // 3. Cache lookup
        if let Some(lru) = &self.lru_cache {
            match lru.lookup(&query, Instant::now()) {
                CacheLookup::Hit(template, remaining_ttl) => {
                    debug!(domain = %host, ?qtype, remaining_ttl, "DNS exchange cache hit");
                    if let Ok(mut rendered) = template.render(&query) {
                        rewrite_dns_response_ttl(&mut rendered, remaining_ttl);
                        return Ok(rendered);
                    }
                }
                CacheLookup::Stale(template) => {
                    debug!(domain = %host, ?qtype, "DNS exchange cache stale, initiating background refresh");
                    let raw_key = query.canonical_wire_arc();
                    if let FlightRole::Leader(mut leader) = self.singleflight.acquire(FlightKey::Refresh(raw_key)) {
                        let query_clone = query.clone();
                        let raw_clone = raw_query.to_vec();
                        let host_clone = host.to_string();
                        let this = self.clone();

                        tokio::spawn(async move {
                            if let Ok(fresh_resp) = this.exchange_no_cache(&query_clone, &raw_clone).await {
                                let fresh_template = ResponseTemplate::validate(&query_clone, &fresh_resp)
                                    .ok()
                                    .map(Arc::new);
                                if let Some(ref tmpl) = fresh_template {
                                    leader.publish(Arc::clone(tmpl));
                                }
                                this.process_fresh_response(
                                    &query_clone,
                                    &host_clone,
                                    &fresh_resp,
                                    fresh_template,
                                )
                                .await;
                            }
                        });
                    }

                    if let Ok(mut rendered) = template.render(&query) {
                        rewrite_dns_response_ttl(&mut rendered, SERVE_STALE_WIRE_TTL);
                        return Ok(rendered);
                    }
                }
                CacheLookup::Miss => {}
            }
        }

        // Singleflight execution
        let flight_key = FlightKey::Query(query.canonical_wire_arc());
        let (raw_resp, template_to_publish) = match self.singleflight.acquire(flight_key) {
            FlightRole::Ready(template) => {
                let rendered = template.render(&query)?;
                return Ok(rendered);
            }
            FlightRole::Waiter(waiter) => {
                if let Some(template) = waiter.receive().await {
                    let rendered = template.render(&query)?;
                    return Ok(rendered);
                }
                // Retry as leader if waiter didn't get response
                let resp = self.exchange_no_cache(&query, raw_query).await?;
                (resp, None)
            }
            FlightRole::Leader(mut leader) => {
                let resp = self.exchange_no_cache(&query, raw_query).await?;
                if let Ok(template) = ResponseTemplate::validate(&query, &resp) {
                    let arc_template = Arc::new(template);
                    leader.publish(Arc::clone(&arc_template));
                    (resp, Some(arc_template))
                } else {
                    (resp, None)
                }
            }
            FlightRole::Rejected => {
                let resp = self.exchange_no_cache(&query, raw_query).await?;
                (resp, None)
            }
        };

        self.process_fresh_response(&query, host, &raw_resp, template_to_publish).await;

        Ok(raw_resp)
    }

    async fn reverse_lookup(&self, ip: net::IpAddr) -> Option<String> {
        if let Some(fake_dns) = &self.fake_dns {
            if let Some(host) = fake_dns.reverse_lookup(ip).await {
                return Some(host);
            }
        }
        self.cached_for(ip).await
    }

    async fn is_fake_ip(&self, ip: net::IpAddr) -> bool {
        if let Some(fake_dns) = &self.fake_dns {
            fake_dns.is_fake_ip(ip).await
        } else {
            false
        }
    }

    fn fake_ip_enabled(&self) -> bool {
        self.fake_dns.is_some()
    }

    async fn after_router_inited(&self, r: Arc<Router>) {
        let rp_map = r.get_rule_providers();
        if let Some(policy) = &self.policy {
            policy.add_rule_set(&r);
        }
        if let Some(fake_dns) = &self.fake_dns {
            fake_dns.add_rule_set(&rp_map).await;
        }
        if let Some(black_filter) = &self.black_domain_filter {
            black_filter.add_rule_set(&rp_map);
        }
        if let Some(fallback_filter) = &self.fallback_filter {
            fallback_filter.add_rule_set(&rp_map);
        }
    }

    fn ipv6(&self) -> bool {
        self.ipv6.load(Relaxed)
    }

    fn set_ipv6(&self, enable: bool) {
        self.ipv6.store(enable, Relaxed);
    }

    fn kind(&self) -> ResolverKind {
        ResolverKind::Clash
    }
}

pub struct BootstrapResolver {
    pool: Arc<UpstreamPool>,
    upstreams: Vec<String>,
}

#[async_trait]
impl ClashResolver for BootstrapResolver {
    async fn resolve(
        &self,
        host: &str,
        _enhanced: bool,
    ) -> anyhow::Result<Option<net::IpAddr>> {
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(Some(ip));
        }
        if let Some(v4) = self.resolve_v4(host, false).await? {
            return Ok(Some(net::IpAddr::V4(v4)));
        }
        if let Some(v6) = self.resolve_v6(host, false).await? {
            return Ok(Some(net::IpAddr::V6(v6)));
        }
        Ok(None)
    }

    async fn resolve_v4(
        &self,
        host: &str,
        _enhanced: bool,
    ) -> anyhow::Result<Option<net::Ipv4Addr>> {
        if let Some(ip) = parse_ip_literal(host) {
            match ip {
                net::IpAddr::V4(v4) => return Ok(Some(v4)),
                _ => return Ok(None),
            }
        }
        let name = DnsName::from_domain(host)
            .ok_or_else(|| anyhow!("invalid domain name: {host}"))?;
        let query = build_dns_query_wire(&name, QType::A);
        let queries = self
            .upstreams
            .iter()
            .map(|ns| Box::pin(self.pool.query(ns, &query)));
        let (resp, _) = futures::future::select_ok(queries).await?;
        let ips = extract_ips_from_dns_response(&resp);
        for ip in ips {
            if let net::IpAddr::V4(v4) = ip {
                return Ok(Some(v4));
            }
        }
        Ok(None)
    }

    async fn resolve_v6(
        &self,
        host: &str,
        _enhanced: bool,
    ) -> anyhow::Result<Option<net::Ipv6Addr>> {
        if let Some(ip) = parse_ip_literal(host) {
            match ip {
                net::IpAddr::V6(v6) => return Ok(Some(v6)),
                _ => return Ok(None),
            }
        }
        let name = DnsName::from_domain(host)
            .ok_or_else(|| anyhow!("invalid domain name: {host}"))?;
        let query = build_dns_query_wire(&name, QType::AAAA);
        let queries = self
            .upstreams
            .iter()
            .map(|ns| Box::pin(self.pool.query(ns, &query)));
        let (resp, _) = futures::future::select_ok(queries).await?;
        let ips = extract_ips_from_dns_response(&resp);
        for ip in ips {
            if let net::IpAddr::V6(v6) = ip {
                return Ok(Some(v6));
            }
        }
        Ok(None)
    }

    async fn cached_for(&self, _ip: net::IpAddr) -> Option<String> {
        None
    }

    async fn exchange(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        let queries = self
            .upstreams
            .iter()
            .map(|ns| Box::pin(self.pool.query(ns, message)));
        let (resp, _) = futures::future::select_ok(queries).await?;
        Ok(resp)
    }

    async fn reverse_lookup(&self, _ip: net::IpAddr) -> Option<String> {
        None
    }

    async fn is_fake_ip(&self, _ip: net::IpAddr) -> bool {
        false
    }

    fn fake_ip_enabled(&self) -> bool {
        false
    }

    async fn after_router_inited(&self, _r: Arc<Router>) {}

    fn ipv6(&self) -> bool {
        true
    }

    fn set_ipv6(&self, _enable: bool) {}

    fn kind(&self) -> ResolverKind {
        ResolverKind::Clash
    }
}

