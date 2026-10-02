pub mod config;
pub mod hosts;
pub mod matcher;
pub mod routing;
pub mod transport;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod regression_tests;

use std::collections::HashMap;
use std::net;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use arc_swap::ArcSwapOption;

use anyhow::anyhow;
use async_trait::async_trait;
use tracing::{debug, info, warn};

use std::time::Instant;

use crate::Error;
use crate::app::dns::config::{EdnsClientSubnet, NameServer};
use crate::app::dns::fakeip::{FakeDns, Opts as FakeDnsOpts};
use crate::app::dns::query::{DnsName, QType, QueryContext};
use crate::app::dns::resolver::enhanced::{
    BootstrapResolver, DnsCache, DnsCacheEntryDetail, ReverseLookupCache,
};
use crate::app::dns::response::{
    RenderedResponse, build_dns_nodata, build_dns_nxdomain, build_dns_refused,
};
use crate::app::dns::upstream_pool::{UpstreamEntry, UpstreamPool};

use crate::app::dns::{
    ClashResolver, DnsCacheItem, DnsCacheReport, DnsCacheUpstreamStat, DnsResolutionHook,
    DnsResolutionHookWrapper, DnsUpstreamInfo, ResolverKind, ThreadSafeDnsCollector,
    parse_ip_literal,
};
use crate::app::profile::ThreadSafeCacheFile;
use crate::app::router::Router;
use crate::common::trie::StringTrie;
use crate::config::def::FakeIpFilterMode;
use crate::proxy::utils::OutboundHandlerRegistry;

use self::config::{
    RejectCode, RequestAction, ResponseAction, RouterConfig, UpstreamType,
};
use self::hosts::HostsSnapshot;
use self::routing::DnsRouter;
use self::transport::{
    CachedTransport, DnsCachePolicy, DnsResolvedNotifier, DnsTransport, ExchangeResult,
    FakeIpTransport, Transport,
};

pub struct RouterResolver {
    cfg: RouterConfig,
    transports: HashMap<String, Transport>,
    fake_dns: Option<Arc<FakeDns>>,
    hosts: HostsSnapshot,
    router: Arc<DnsRouter>,
    reverse_lookup_cache: ReverseLookupCache,
    #[allow(dead_code)]
    cache: DnsCache,
    ipv6: AtomicBool,
    resolution_hook: Arc<ArcSwapOption<DnsResolutionHookWrapper>>,
    proxy_server_domains: Option<StringTrie<bool>>,
    proxy_server_transports: Vec<Transport>,
    notifier: DnsResolvedNotifier,
    real_transport: Option<Transport>,
}

impl RouterResolver {
    pub async fn new(
        cfg: RouterConfig,
        fw_mark: Option<u32>,
        store: Option<ThreadSafeCacheFile>,
        outbounds: OutboundHandlerRegistry,
        collector: Option<ThreadSafeDnsCollector>,
    ) -> Result<Self, Error> {
        cfg.validate()?;
        let mut entries = HashMap::new();

        let make_key = |ns: &NameServer, proxy: Option<&str>, ecs: Option<&EdnsClientSubnet>| -> String {
            let effective_proxy = ns.proxy.as_deref().or(proxy);
            let mut key = format!("{}#proxy={:?}", ns, effective_proxy);
            if let Some(ecs) = ecs {
                key.push_str(&format!("#ecs={:?},{:?}", ecs.ipv4, ecs.ipv6));
            }
            key
        };

        let register_ns = |ns: &NameServer,
                           entries: &mut HashMap<String, UpstreamEntry>,
                           proxy: Option<&str>,
                           ecs: Option<&EdnsClientSubnet>|
         -> Option<String> {
            let key = make_key(ns, proxy, ecs);
            if !entries.contains_key(&key) {
                if let Ok(mut entry) = UpstreamEntry::from_nameserver(ns, None) {
                    let effective_proxy = ns.proxy.as_deref().or(proxy);
                    entry.ecs = ecs.cloned();
                    if let Some(p) = effective_proxy {
                        entry.outbound = Some(p.to_string());
                    }
                    entries.insert(key.clone(), entry);
                }
            }
            if entries.contains_key(&key) {
                Some(key)
            } else {
                None
            }
        };

        // 1. Default / Bootstrap nameserver
        let mut default_entries = HashMap::new();
        let mut default_upstreams = Vec::new();
        for ns in &cfg.default_nameserver {
            if let Some(key) = register_ns(ns, &mut default_entries, None, None) {
                if !default_upstreams.contains(&key) {
                    default_upstreams.push(key);
                }
            }
        }

        let bootstrap_resolver: Option<Arc<dyn ClashResolver>> =
            if !default_upstreams.is_empty() {
                let default_pool = UpstreamPool::new(
                    default_entries,
                    outbounds.clone(),
                    None,
                    fw_mark,
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

        let capacity = cfg.cache_capacity.max(1);
        let reverse_lookup_cache = ReverseLookupCache::new(capacity);
        let resolution_hook = Arc::new(ArcSwapOption::new(None));
        let notifier = DnsResolvedNotifier::new(
            reverse_lookup_cache.clone(),
            Arc::clone(&resolution_hook),
            collector.clone(),
        );
        let cache = DnsCache::new(capacity);
        let cache_policy = DnsCachePolicy::new(cfg.optimistic_cache_ttl, cfg.stale_cache_retention);
        let router = Arc::new(DnsRouter::new(&cfg));

        let mut transports: HashMap<String, Transport> = HashMap::new();
        let mut fake_dns: Option<Arc<FakeDns>> = None;

        for u in &cfg.upstreams {
            match u.upstream_type {
                UpstreamType::Remote => {
                    for ns in &u.servers {
                        let _ = register_ns(ns, &mut entries, u.proxy.as_deref(), u.client_subnet.as_ref());
                    }
                    // RemoteTransport 会在 pool 初始化后绑定
                }
                UpstreamType::Local => {
                    transports.insert(
                        u.tag.clone(),
                        Transport::Cached(CachedTransport::new_local(
                            u.tag.clone(),
                            u.ttl,
                            cache.clone(),
                            cache_policy,
                        )),
                    );
                }
                UpstreamType::FakeIp => {
                    let fake = Arc::new(
                        FakeDns::new(FakeDnsOpts {
                            ipnet: u.inet4_range,
                            ipnet6: u.inet6_range,
                            domain_filter: None,
                            filter_mode: FakeIpFilterMode::Blacklist,
                            cache_file: store.clone(),
                            store: None,
                        })?,
                    );
                    fake_dns = Some(fake.clone());
                    transports.insert(
                        u.tag.clone(),
                        Transport::FakeIp(FakeIpTransport::new(
                            u.tag.clone(),
                            fake,
                            u.ttl.unwrap_or(1),
                        )),
                    );
                }
            }
        }

        let mut proxy_keys = Vec::new();
        for ns in &cfg.proxy_server_nameserver {
            if let Some(key) = register_ns(ns, &mut entries, None, None) {
                if !proxy_keys.contains(&key) {
                    proxy_keys.push(key);
                }
            }
        }
        let mut real_keys = Vec::new();
        for ns in &cfg.default_nameserver {
            if let Some(key) = register_ns(ns, &mut entries, None, None) {
                if !real_keys.contains(&key) {
                    real_keys.push(key);
                }
            }
        }

        let pool = UpstreamPool::new(
            entries,
            outbounds.clone(),
            bootstrap_resolver,
            fw_mark,
            None,
            None,
        );

        // 为 Remote Upstreams 构建 RemoteTransport
        for u in &cfg.upstreams {
            if u.upstream_type == UpstreamType::Remote {
                let mut keys = Vec::new();
                for ns in &u.servers {
                    let key = make_key(ns, u.proxy.as_deref(), u.client_subnet.as_ref());
                    if pool.entries.contains_key(&key) && !keys.contains(&key) {
                        keys.push(key);
                    }
                }
                transports.insert(
                    u.tag.clone(),
                    Transport::Cached(CachedTransport::new_remote(
                        u.tag.clone(),
                        u.ttl,
                        keys,
                        pool.clone(),
                        cache.clone(),
                        cache_policy,
                    )),
                );
            }
        }

        // 3. 处理 proxy_server_nameserver
        let mut proxy_server_transports = Vec::new();
        if !cfg.proxy_server_nameserver.is_empty() {
            let keys = proxy_keys;
            if !keys.is_empty() {
                proxy_server_transports.push(Transport::Cached(
                    CachedTransport::new_remote(
                        "__proxy_server_dns".to_string(),
                        None,
                        keys,
                        pool.clone(),
                        cache.clone(),
                        cache_policy,
                    ),
                ));
            }
        }

        let proxy_server_domains = {
            let plain_outbounds = outbounds.read();
            let mut domains = StringTrie::new();
            let mut has_domain = false;
            for x in plain_outbounds.values() {
                if let Some(s) = x.server_name() {
                    domains.insert(s, Arc::new(true));
                    has_domain = true;
                }
            }
            if has_domain && !proxy_server_transports.is_empty() {
                Some(domains)
            } else {
                None
            }
        };

        // Real connection addresses use the first non-Fake-IP upstream,
        // falling back to bootstrap nameservers when none is configured.
        let real_transport = cfg.upstreams.iter()
            .find(|u| u.upstream_type != UpstreamType::FakeIp)
            .and_then(|u| transports.get(&u.tag))
            .cloned()
            .or_else(|| {
                (!real_keys.is_empty()).then(|| {
                    Transport::Cached(CachedTransport::new_remote(
                        "__real_dns".to_string(),
                        None,
                        real_keys,
                        pool.clone(),
                        cache.clone(),
                        cache_policy,
                    ))
                })
            });

        // 4. 初始化 Hosts 快照与路由引擎
        let hosts = HostsSnapshot::new(&cfg.hosts, &cfg.hosts_files);

        info!(
            "RouterResolver initialized with {} upstreams",
            transports.len()
        );

        Ok(Self {
            ipv6: AtomicBool::new(cfg.ipv6),
            cfg,
            transports,
            fake_dns,
            hosts,
            router,
            reverse_lookup_cache,
            cache,
            resolution_hook,
            proxy_server_domains,
            proxy_server_transports,
            notifier,
            real_transport,
        })
    }
}

impl RouterResolver {
    fn select_transport(&self, tag: &str, enhanced: bool) -> anyhow::Result<&Transport> {
        let transport = self.transports.get(tag)
            .ok_or_else(|| anyhow!("upstream '{tag}' not found"))?;
        if !enhanced && transport.is_fake_ip() {
            self.real_transport.as_ref()
                .ok_or_else(|| anyhow!("no real DNS upstream configured"))
        } else {
            Ok(transport)
        }
    }

    fn schedule_refresh(&self, result: &mut ExchangeResult) {
        if let Some(ticket) = result.refresh_ticket.take() {
            let router = Arc::clone(&self.router);
            let notifier = self.notifier.clone();
            tokio::spawn(async move {
                let tag = ticket.tag().to_string();
                let qname = ticket.query().qdomain().unwrap_or_default().to_string();
                let qtype = ticket.query().qtype().unwrap_or(QType::A);
                if let Ok(result) = ticket.run().await {
                    if router.route_response(&tag, &qname, qtype, &result.answer_ips) == &ResponseAction::Accept {
                        notifier.on_fresh_response(&qname, &result.answer_ips, result.ttl);
                    }
                }
            });
        }
    }

    async fn exchange_query(
        &self,
        query: &QueryContext,
        source_ip: Option<net::IpAddr>,
        enhanced: bool,
    ) -> anyhow::Result<RenderedResponse> {
        let message = query.wire();

        let qname = query.qdomain().unwrap_or_default();
        let qtype = query.qtype().unwrap_or(QType::A);

        debug!(domain = qname, ?qtype, "DNS query received");

        // AAAA asked for while IPv6 is globally disabled: answer NODATA (NoError + zero answers)
        if qtype == QType::AAAA && !self.ipv6() {
            debug!(domain = qname, "AAAA query while IPv6 disabled, returning NODATA");
            return Ok(RenderedResponse::empty(build_dns_nodata(message)));
        }

        // Empty domain / DNS root ('.') has no A or AAAA records.
        // Return NODATA immediately without allocating Fake-IP or querying upstream.
        if qname.is_empty() && (qtype == QType::A || qtype == QType::AAAA) {
            debug!(domain = qname, ?qtype, "DNS root/empty domain A/AAAA query, returning NODATA");
            return Ok(RenderedResponse::empty(build_dns_nodata(message)));
        }

        // 1. 优先匹配 Hosts 静态映射（最快路径：纯内存直出，零网络与零开销）
        if self.cfg.use_hosts {
            if let Some(resp) =
                self.hosts.make_response(query, self.ipv6())
            {
                debug!(domain = qname, ?qtype, "matched hosts snapshot");
                return Ok(resp);
            }
        }

        // 2. 检查节点域名直连解析通道 (proxy-server-nameserver)
        if let (Some(domains), false) = (
            &self.proxy_server_domains,
            self.proxy_server_transports.is_empty(),
        ) {
            if domains.search(qname).is_some() {
                debug!(
                    domain = qname,
                    ?qtype,
                    "using proxy-server-nameserver for proxy node domain"
                );
                for transport in &self.proxy_server_transports {
                    if let Ok(mut res) = transport.exchange(query).await {
                        if let Some(ticket) = res.refresh_ticket.take() {
                            let notifier = self.notifier.clone();
                            tokio::spawn(async move {
                                let qname = ticket.query().qdomain().unwrap_or_default().to_string();
                                if let Ok(result) = ticket.run().await {
                                    notifier.on_fresh_response(&qname, &result.answer_ips, result.ttl);
                                }
                            });
                        }
                        if res.is_fresh {
                            self.notifier
                                .on_fresh_response(qname, &res.answer_ips, res.ttl);
                        }
                        return Ok(res.into());
                    }
                }
            }
        }

        // 3. 执行 Request 路由
        let request_decision = self.router.route_request(qname, qtype, source_ip);

        let initial_tag = match request_decision {
            RequestAction::Reject(code) => {
                debug!(domain = qname, ?qtype, ?code, "request rejected by rule");
                let resp = match code {
                    RejectCode::Nodata => build_dns_nodata(message),
                    RejectCode::Nxdomain => build_dns_nxdomain(message),
                    RejectCode::Refused => build_dns_refused(message),
                };
                return Ok(RenderedResponse::empty(resp));
            }
            RequestAction::Route(tag) => tag.clone(),
        };

        let transport = self.select_transport(&initial_tag, enhanced)?;
        let initial_tag = transport.tag().to_string();

        debug!(
            domain = qname,
            ?qtype,
            upstream = %initial_tag,
            upstream_type = ?transport.upstream_type(),
            "dispatching query to upstream"
        );

        // 4. 执行初次上游查询（若为 RemoteTransport，其内部自治命中 Cache / Singleflight 并发收敛）
        let mut exchange_res = transport.exchange(query).await?;
        let current_tag = initial_tag;

        // Fake-IP 上游自动跳过后续缓存刷新与 Response 防污染检查，直接返回
        if transport.is_fake_ip() {
            return Ok(exchange_res.into());
        }

        // 如果底层命中了 Stale 缓存且作为 Leader 获得了刷新凭证，由顶层调度异步刷新！
        self.schedule_refresh(&mut exchange_res);

        let answer_ips = &exchange_res.answer_ips;

        // 5. 执行 Response 路由检查 (精准 match-response，防污染重查，限制最多重查 1 次)
        let resp_decision =
            self.router
                .route_response(&current_tag, qname, qtype, answer_ips);

        match resp_decision {
            ResponseAction::Accept => {}
            ResponseAction::Reject => {
                debug!(domain = qname, from = %current_tag, ?answer_ips, "response rejected by rule");
                return Ok(RenderedResponse::empty(build_dns_nodata(message)));
            }
            ResponseAction::Requery(next_tag) => {
                if next_tag != &current_tag {
                    if let Ok(next_transport) = self.select_transport(next_tag, enhanced) {
                        if next_transport.tag() != current_tag {
                            debug!(
                                domain = qname,
                                from = %current_tag,
                                target = %next_tag,
                                polluted_ips = ?answer_ips,
                                "re-querying DNS upstream due to response rule"
                            );
                            match next_transport.exchange(query).await {
                                Ok(new_res) => {
                                    debug!(
                                        domain = qname,
                                        target = %next_tag,
                                        "DNS requery succeeded"
                                    );
                                    exchange_res = new_res;
                                    self.schedule_refresh(&mut exchange_res);
                                }
                                Err(err) => {
                                    warn!(
                                        domain = qname,
                                        target = %next_tag,
                                        "DNS requery failed: {err}"
                                    );
                                    return Ok(RenderedResponse::empty(build_dns_nodata(message)));
                                }
                            }
                        }
                    } else {
                        warn!(target = %next_tag, "target upstream for requery not found");
                        return Ok(RenderedResponse::empty(build_dns_nodata(message)));
                    }
                }
            }
        }

        // 6. 确认为刷新缓存的结果时才下发反向缓存与直连 (Fresh Result)
        if exchange_res.is_fresh && !exchange_res.answer_ips.is_empty() {
            self.notifier.on_fresh_response(qname, &exchange_res.answer_ips, exchange_res.ttl);
        }

        Ok(exchange_res.into())
    }
}

#[async_trait]
impl ClashResolver for RouterResolver {
    fn register_resolution_hook(&self, hook: DnsResolutionHook) {
        self.resolution_hook
            .store(Some(Arc::new(DnsResolutionHookWrapper(hook))));
    }

    fn unregister_resolution_hook(&self, hook: &DnsResolutionHook) {
        self.resolution_hook.rcu(|current| match current {
            Some(wrapper) if Arc::ptr_eq(&wrapper.0, hook) => None,
            _ => current.clone(),
        });
    }

    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<net::IpAddr>> {
        if host.is_empty() {
            return Ok(None);
        }
        if let Some(v4) = self.resolve_v4(host, enhanced).await? {
            return Ok(Some(net::IpAddr::V4(v4)));
        }
        if self.ipv6() {
            if let Some(v6) = self.resolve_v6(host, enhanced).await? {
                return Ok(Some(net::IpAddr::V6(v6)));
            }
        }
        Ok(None)
    }

    async fn resolve_v4(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<net::Ipv4Addr>> {
        if host.is_empty() {
            return Ok(None);
        }
        if let Some(ip) = parse_ip_literal(host) {
            if let net::IpAddr::V4(v4) = ip {
                return Ok(Some(v4));
            }
            return Ok(None);
        }

        let name = DnsName::from_domain(host)
            .ok_or_else(|| anyhow!("invalid domain name: {host}"))?;
        let query = QueryContext::new(name, QType::A);
        let resp = self.exchange_query(&query, None, enhanced).await?;
        for ip in resp.answer_ips.iter().copied() {
            if let net::IpAddr::V4(v4) = ip {
                return Ok(Some(v4));
            }
        }
        Ok(None)
    }

    async fn resolve_v6(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<net::Ipv6Addr>> {
        if host.is_empty() {
            return Ok(None);
        }
        if !self.ipv6() {
            return Ok(None);
        }

        if let Some(ip) = parse_ip_literal(host) {
            if let net::IpAddr::V6(v6) = ip {
                return Ok(Some(v6));
            }
            return Ok(None);
        }

        let name = DnsName::from_domain(host)
            .ok_or_else(|| anyhow!("invalid domain name: {host}"))?;
        let query = QueryContext::new(name, QType::AAAA);
        let resp = self.exchange_query(&query, None, enhanced).await?;
        for ip in resp.answer_ips.iter().copied() {
            if let net::IpAddr::V6(v6) = ip {
                return Ok(Some(v6));
            }
        }
        Ok(None)
    }

    fn cached_for(&self, ip: net::IpAddr) -> Option<String> {
        self.reverse_lookup_cache.lookup(&ip)
    }

    async fn exchange(
        &self,
        query: &QueryContext,
        source_ip: Option<net::IpAddr>,
    ) -> anyhow::Result<Vec<u8>> {
        self.exchange_query(query, source_ip, true).await.map(|response| response.wire)
    }

    fn reverse_lookup(&self, ip: net::IpAddr) -> Option<String> {
        if let Some(fake) = &self.fake_dns {
            if fake.is_fake_ip(ip) {
                return fake.reverse_lookup(ip);
            }
        }
        self.reverse_lookup_cache.lookup(&ip)
    }

    fn is_fake_ip(&self, ip: net::IpAddr) -> bool {
        if let Some(fake) = &self.fake_dns {
            fake.is_fake_ip(ip)
        } else {
            false
        }
    }

    fn fake_ip_enabled(&self) -> bool {
        self.fake_dns.is_some()
    }

    async fn after_router_inited(&self, r: Arc<Router>) {
        let providers = r.get_rule_providers();
        self.router.bind_rule_providers(&providers);
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

    fn list_upstreams(&self) -> Vec<DnsUpstreamInfo> {
        let mut list = Vec::new();
        for u in &self.cfg.upstreams {
            let type_str = match u.upstream_type {
                UpstreamType::FakeIp => "fakeip",
                UpstreamType::Remote => "remote",
                UpstreamType::Local => "local",
            };
            list.push(DnsUpstreamInfo {
                tag: u.tag.clone(),
                r#type: type_str.to_string(),
            });
        }
        list
    }

    fn search_cache_by_upstream(
        &self,
        pattern: &str,
        upstream: &str,
    ) -> Option<DnsCacheUpstreamStat> {
        const MAX_RETURN_ITEMS: usize = 50;
        let now = Instant::now();
        if let Some(u) = self.cfg.upstreams.iter().find(|u| u.tag == upstream) {
            if u.upstream_type == UpstreamType::FakeIp {
                let (total_count, fake_items) = if let Some(fake) = &self.fake_dns {
                    fake.search_cache_limited(pattern, MAX_RETURN_ITEMS)
                } else {
                    (0, Vec::new())
                };
                let items: Vec<DnsCacheItem> = fake_items
                    .into_iter()
                    .map(|(ip, host)| {
                        let qtype = if ip.is_ipv6() { "AAAA" } else { "A" };
                        DnsCacheItem {
                            domain: host,
                            qtype: qtype.to_string(),
                            ip: Some(ip.to_string()),
                            ttl: u.ttl,
                            is_stale: Some(false),
                        }
                    })
                    .collect();
                Some(DnsCacheUpstreamStat {
                    name: u.tag.clone(),
                    count: total_count,
                    upstream_type: Some("fakeip".to_string()),
                    items,
                })
            } else {
                let (total_count, cache_entries) =
                    self.cache
                        .search_scoped_limited(pattern, Some(&u.tag), MAX_RETURN_ITEMS, now);
                let items: Vec<DnsCacheItem> = cache_entries
                    .into_iter()
                    .map(|e| DnsCacheItem {
                        domain: e.domain,
                        qtype: e.qtype,
                        ip: None,
                        ttl: Some(e.ttl),
                        is_stale: Some(e.is_stale),
                    })
                    .collect();
                let type_name = match u.upstream_type {
                    UpstreamType::Remote => "remote",
                    UpstreamType::Local => "local",
                    _ => "unknown",
                };
                Some(DnsCacheUpstreamStat {
                    name: u.tag.clone(),
                    count: total_count,
                    upstream_type: Some(type_name.to_string()),
                    items,
                })
            }
        } else if upstream == "fakeip" && self.fake_dns.is_some() {
            let (total_count, fake_items) = self
                .fake_dns
                .as_ref()
                .unwrap()
                .search_cache_limited(pattern, MAX_RETURN_ITEMS);
            let items: Vec<DnsCacheItem> = fake_items
                .into_iter()
                .map(|(ip, host)| {
                    let qtype = if ip.is_ipv6() { "AAAA" } else { "A" };
                    DnsCacheItem {
                        domain: host,
                        qtype: qtype.to_string(),
                        ip: Some(ip.to_string()),
                        ttl: None,
                        is_stale: Some(false),
                    }
                })
                .collect();
            Some(DnsCacheUpstreamStat {
                name: "fakeip".to_string(),
                count: total_count,
                upstream_type: Some("fakeip".to_string()),
                items,
            })
        } else {
            let (total_count, cache_entries) =
                self.cache
                    .search_scoped_limited(pattern, Some(upstream), MAX_RETURN_ITEMS, now);
            if total_count > 0 {
                let items: Vec<DnsCacheItem> = cache_entries
                    .into_iter()
                    .map(|e| DnsCacheItem {
                        domain: e.domain,
                        qtype: e.qtype,
                        ip: None,
                        ttl: Some(e.ttl),
                        is_stale: Some(e.is_stale),
                    })
                    .collect();
                Some(DnsCacheUpstreamStat {
                    name: upstream.to_string(),
                    count: total_count,
                    upstream_type: Some("extra".to_string()),
                    items,
                })
            } else {
                None
            }
        }
    }

    fn clear_cache_by_upstream(&self, pattern: &str, upstream: &str) -> usize {
        let is_fakeip = match self.cfg.upstreams.iter().find(|u| u.tag == upstream) {
            Some(u) => u.upstream_type == UpstreamType::FakeIp,
            None => upstream == "fakeip",
        };

        if is_fakeip {
            if let Some(fake) = &self.fake_dns {
                fake.delete_cache(pattern)
            } else {
                0
            }
        } else {
            let deleted = self.cache.delete_scoped(pattern, Some(upstream));
            if deleted > 0 {
                self.reverse_lookup_cache.invalidate_matching(pattern);
            }
            deleted
        }
    }

    fn search_cache(&self, pattern: &str) -> DnsCacheReport {
        const MAX_RETURN_ITEMS: usize = 50;
        let mut groups = self.cache.search_grouped_limited(pattern, MAX_RETURN_ITEMS, Instant::now());
        let items = |entries: Vec<DnsCacheEntryDetail>| {
            entries.into_iter().map(|entry| DnsCacheItem {
                domain: entry.domain,
                qtype: entry.qtype,
                ip: None,
                ttl: Some(entry.ttl),
                is_stale: Some(entry.is_stale),
            }).collect()
        };
        let mut upstreams = Vec::new();
        for upstream in &self.cfg.upstreams {
            if upstream.upstream_type == UpstreamType::FakeIp {
                if let Some(stat) = self.search_cache_by_upstream(pattern, &upstream.tag) {
                    upstreams.push(stat);
                }
                continue;
            }
            let (count, entries) = groups.remove(upstream.tag.as_str()).unwrap_or_default();
            upstreams.push(DnsCacheUpstreamStat {
                name: upstream.tag.clone(),
                count,
                upstream_type: Some(match upstream.upstream_type {
                    UpstreamType::Local => "local",
                    _ => "remote",
                }.to_string()),
                items: items(entries),
            });
        }
        for (scope, (count, entries)) in groups {
            if scope.is_empty() { continue; }
            upstreams.push(DnsCacheUpstreamStat {
                name: scope.to_string(),
                count,
                upstream_type: Some("extra".to_string()),
                items: items(entries),
            });
        }
        let total = upstreams.iter().map(|upstream| upstream.count).sum();
        DnsCacheReport { upstreams, total }
    }

    fn clear_cache(&self, pattern: &str, upstream: Option<&str>) -> usize {
        match upstream {
            Some(u) => self.clear_cache_by_upstream(pattern, u),
            None => {
                let mut deleted = 0;
                if let Some(fake) = &self.fake_dns {
                    deleted += fake.delete_cache(pattern);
                }
                let regular_deleted = self.cache.delete_scoped(pattern, None);
                if regular_deleted > 0 {
                    self.reverse_lookup_cache.invalidate_matching(pattern);
                }
                deleted += regular_deleted;
                deleted
            }
        }
    }
}
