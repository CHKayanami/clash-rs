pub mod config;
pub mod hosts;
pub mod matcher;
pub mod routing;
pub mod transport;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::net;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};

use anyhow::anyhow;
use async_trait::async_trait;
use tracing::{debug, info, warn};

use crate::app::dns::config::NameServer;
use crate::app::dns::fakeip::{FakeDns, Opts as FakeDnsOpts};
use crate::app::dns::query::{DnsName, QType, QueryContext, build_dns_query_wire};
use crate::app::dns::resolver::enhanced::{
    BootstrapResolver, DnsCache, ReverseLookupCache,
};
use crate::app::dns::response::{
    build_dns_nodata, build_dns_nxdomain, build_dns_refused,
};
use crate::app::dns::upstream_pool::{UpstreamEntry, UpstreamPool};
use crate::app::dns::wire::extract_ips_from_dns_response;
use crate::app::dns::{
    ClashResolver, DnsResolutionHook, ResolverKind, ThreadSafeDnsCollector,
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
    CachedTransport, DnsCachePolicy, DnsResolvedNotifier, DnsTransport, FakeIpTransport, Transport,
};

pub struct RouterResolver {
    cfg: RouterConfig,
    transports: HashMap<String, Transport>,
    fake_dns: Option<Arc<FakeDns>>,
    hosts: HostsSnapshot,
    router: DnsRouter,
    reverse_lookup_cache: ReverseLookupCache,
    #[allow(dead_code)]
    cache: DnsCache,
    ipv6: AtomicBool,
    resolution_hook: Arc<OnceLock<DnsResolutionHook>>,
    proxy_server_domains: Option<StringTrie<bool>>,
    proxy_server_transports: Vec<Transport>,
}

impl RouterResolver {
    pub async fn new(
        cfg: RouterConfig,
        fw_mark: Option<u32>,
        store: Option<ThreadSafeCacheFile>,
        outbounds: OutboundHandlerRegistry,
        collector: Option<ThreadSafeDnsCollector>,
    ) -> Self {
        let mut entries = HashMap::new();

        let make_key = |ns: &NameServer, proxy: Option<&str>| -> String {
            let effective_proxy = ns.proxy.as_deref().or(proxy);
            format!("{}#proxy={:?}", ns, effective_proxy)
        };

        let register_ns = |ns: &NameServer,
                           entries: &mut HashMap<String, UpstreamEntry>,
                           proxy: Option<&str>|
         -> Option<String> {
            let key = make_key(ns, proxy);
            if !entries.contains_key(&key) {
                if let Ok(mut entry) = UpstreamEntry::from_nameserver(ns, None) {
                    let effective_proxy = ns.proxy.as_deref().or(proxy);
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
            if let Some(key) = register_ns(ns, &mut default_entries, None) {
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
        let resolution_hook = Arc::new(OnceLock::new());
        let notifier = DnsResolvedNotifier::new(
            reverse_lookup_cache.clone(),
            Arc::clone(&resolution_hook),
            collector.clone(),
        );
        let cache = DnsCache::new(capacity);
        let cache_policy = DnsCachePolicy::new(cfg.optimistic_cache_ttl, cfg.stale_cache_retention);

        let mut transports: HashMap<String, Transport> = HashMap::new();
        let mut fake_dns: Option<Arc<FakeDns>> = None;

        for u in &cfg.upstreams {
            match u.upstream_type {
                UpstreamType::Remote => {
                    let mut keys = Vec::new();
                    for ns in &u.servers {
                        if let Some(key) =
                            register_ns(ns, &mut entries, u.proxy.as_deref())
                        {
                            if !keys.contains(&key) {
                                keys.push(key);
                            }
                        }
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
                            Some(notifier.clone()),
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
                        })
                        .expect("failed to initialize fakeip in router resolver"),
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
                    let key = make_key(ns, u.proxy.as_deref());
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
                        Some(notifier.clone()),
                        cache_policy,
                    )),
                );
            }
        }

        // 3. 处理 proxy_server_nameserver
        let mut proxy_server_transports = Vec::new();
        if !cfg.proxy_server_nameserver.is_empty() {
            let mut keys = Vec::new();
            for ns in &cfg.proxy_server_nameserver {
                let key = make_key(ns, None);
                if pool.entries.contains_key(&key) && !keys.contains(&key) {
                    keys.push(key);
                }
            }
            if !keys.is_empty() {
                proxy_server_transports.push(Transport::Cached(
                    CachedTransport::new_remote(
                        "__proxy_server_dns".to_string(),
                        None,
                        keys,
                        pool.clone(),
                        cache.clone(),
                        Some(notifier.clone()),
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

        // 4. 初始化 Hosts 快照与路由引擎
        let hosts = HostsSnapshot::new(&cfg.hosts, &cfg.hosts_files);
        let router = DnsRouter::new(&cfg);

        info!(
            "RouterResolver initialized with {} upstreams",
            transports.len()
        );

        Self {
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
        }
    }
}

#[async_trait]
impl ClashResolver for RouterResolver {
    fn register_resolution_hook(&self, hook: DnsResolutionHook) {
        let _ = self.resolution_hook.set(hook);
    }

    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<net::IpAddr>> {
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
        _enhanced: bool,
    ) -> anyhow::Result<Option<net::Ipv4Addr>> {
        if let Some(ip) = parse_ip_literal(host) {
            if let net::IpAddr::V4(v4) = ip {
                return Ok(Some(v4));
            }
            return Ok(None);
        }

        let name = DnsName::from_domain(host)
            .ok_or_else(|| anyhow!("invalid domain name: {host}"))?;
        let query = build_dns_query_wire(&name, QType::A);
        let resp = self.exchange(&query).await?;
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
        let query = build_dns_query_wire(&name, QType::AAAA);
        let resp = self.exchange(&query).await?;
        let ips = extract_ips_from_dns_response(&resp);
        for ip in ips {
            if let net::IpAddr::V6(v6) = ip {
                return Ok(Some(v6));
            }
        }
        Ok(None)
    }

    fn cached_for(&self, ip: net::IpAddr) -> Option<String> {
        self.reverse_lookup_cache.lookup(&ip)
    }

    async fn exchange(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        let query = match QueryContext::parse(message) {
            Ok(q) => q,
            Err(_) => return Ok(build_dns_refused(message)),
        };

        let qname = query.qdomain().unwrap_or_default();
        let qtype = query.qtype().unwrap_or(QType::A);

        debug!(domain = qname, ?qtype, "DNS query received");

        // 1. 优先匹配 Hosts 静态映射（最快路径：纯内存直出，零网络与零开销）
        if self.cfg.use_hosts {
            if let Some(resp) =
                self.hosts.make_response(message, qname, qtype, self.ipv6())
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
                    if let Ok(resp) = transport.exchange(message, &query).await {
                        return Ok(resp);
                    }
                }
            }
        }

        // 3. 执行 Request 路由
        let request_decision = self.router.route_request(qname, qtype, None);

        let initial_tag = match request_decision {
            RequestAction::Reject(code) => {
                debug!(domain = qname, ?qtype, ?code, "request rejected by rule");
                let resp = match code {
                    RejectCode::Nodata => build_dns_nodata(message),
                    RejectCode::Nxdomain => build_dns_nxdomain(message),
                    RejectCode::Refused => build_dns_refused(message),
                };
                return Ok(resp);
            }
            RequestAction::Route(tag) => tag.clone(),
        };

        let transport = self
            .transports
            .get(&initial_tag)
            .ok_or_else(|| anyhow!("upstream '{}' not found", initial_tag))?;

        debug!(
            domain = qname,
            ?qtype,
            upstream = %initial_tag,
            upstream_type = ?transport.upstream_type(),
            "dispatching query to upstream"
        );

        // 4. 执行初次上游查询（若为 RemoteTransport，其内部自治命中 Cache / Singleflight 并发收敛）
        let mut current_resp = transport.exchange(message, &query).await?;
        let current_tag = initial_tag;

        // Fake-IP 上游自动跳过 Response 阶段的防污染与规则检查
        if transport.is_fake_ip() {
            return Ok(current_resp);
        }

        // 若为非 IP 类请求（TXT/MX/HTTPS 等）或上游返回 NODATA/NXDOMAIN，无 IP 供防污染校验，直接放行
        let answer_ips = extract_ips_from_dns_response(&current_resp);
        if answer_ips.is_empty() {
            return Ok(current_resp);
        }

        // 5. 执行 Response 路由检查 (精准 match-response，防污染重查，限制最多重查 1 次)
        let resp_decision =
            self.router
                .route_response(&current_tag, qname, qtype, &answer_ips);

        match resp_decision {
            ResponseAction::Accept => {}
            ResponseAction::Reject => {
                debug!(domain = qname, from = %current_tag, ?answer_ips, "response rejected by rule");
                return Ok(build_dns_nodata(message));
            }
            ResponseAction::Requery(next_tag) => {
                if next_tag != &current_tag {
                    if let Some(next_transport) = self.transports.get(next_tag) {
                        debug!(
                            domain = qname,
                            from = %current_tag,
                            target = %next_tag,
                            polluted_ips = ?answer_ips,
                            "re-querying DNS upstream due to response rule"
                        );
                        match next_transport.exchange(message, &query).await {
                            Ok(new_resp) => {
                                debug!(
                                    domain = qname,
                                    target = %next_tag,
                                    "DNS requery succeeded"
                                );
                                current_resp = new_resp;
                            }
                            Err(err) => {
                                warn!(
                                    domain = qname,
                                    target = %next_tag,
                                    "DNS requery failed: {err}"
                                );
                            }
                        }
                    } else {
                        warn!(target = %next_tag, "target upstream for requery not found");
                    }
                }
            }
        }

        Ok(current_resp)
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
}
