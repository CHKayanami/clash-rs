mod policy;
#[cfg(test)]
mod tests;

pub use policy::NameServerPolicyContainer;

use crate::{
    Error,
    app::{
        dns::helper::build_dns_response_message, profile::ThreadSafeCacheFile,
        router::Router,
    },
    common::trie,
    config::def::DNSMode,
    dns::{
        ClashResolver, Config, ResolverKind, RuleDispatch, ThreadSafeDNSClient,
        ThreadSafeDnsCollector,
        fakeip::{self, FileStore, InMemStore, ThreadSafeFakeDns},
        filters::{BlackDomainFilter, DomainFilter, FallbackFilter, PendingMmdb},
        helper::make_clients,
        parse_ip_literal,
    },
};
use anyhow::anyhow;
use async_trait::async_trait;
use futures::{FutureExt, TryFutureExt};
use hickory_proto::{
    op::{self, Message, Query, ResponseCode},
    rr::{
        self, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use rand::seq::IndexedRandom;

use std::{
    net,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};

use tracing::{debug, error, instrument, trace, warn};

pub struct EnhancedResolver {
    ipv6: AtomicBool,
    hosts: Option<trie::StringTrie<net::IpAddr>>,
    main: Vec<ThreadSafeDNSClient>,

    fallback: Option<Vec<ThreadSafeDNSClient>>,
    fallback_filter: Option<FallbackFilter>,

    lru_cache: Option<hickory_resolver::ResponseCache>,
    policy: Option<NameServerPolicyContainer>,

    proxy_resolver: Option<Vec<ThreadSafeDNSClient>>,
    proxy_server_domains: Option<trie::StringTrie<bool>>,

    fake_dns: Option<ThreadSafeFakeDns>,

    reverse_lookup_cache: Option<moka::future::Cache<net::IpAddr, String>>,
    black_domain_filter: Option<BlackDomainFilter>,
    collector: Option<ThreadSafeDnsCollector>,
}

impl EnhancedResolver {
    /// For testing purpose
    #[cfg(test)]
    pub async fn new_default() -> Self {
        use std::net::Ipv4Addr;

        use crate::app::dns::config::NameServer;
        use crate::app::dns::dns_client::DNSNetMode;

        EnhancedResolver {
            ipv6: AtomicBool::new(false),
            hosts: None,
            main: make_clients(
                vec![NameServer {
                    net: DNSNetMode::Udp,
                    host: url::Host::Ipv4(Ipv4Addr::from_octets([8, 8, 8, 8])),
                    port: 53,
                    interface: None,
                    proxy: None,
                }],
                None,
                Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
                None,
                None,
                None,
            )
            .await,
            fallback: None,
            fallback_filter: None,
            lru_cache: None,
            policy: None,

            proxy_resolver: None,
            proxy_server_domains: None,

            fake_dns: None,

            reverse_lookup_cache: None,
            black_domain_filter: None,
            collector: None,
        }
    }

    pub async fn new(
        cfg: Config,
        store: ThreadSafeCacheFile,
        mmdb: Option<PendingMmdb>,
        outbounds: crate::proxy::utils::OutboundHandlerRegistry,
        rule_dispatch: Option<Arc<RuleDispatch>>,
        collector: Option<ThreadSafeDnsCollector>,
    ) -> Self {
        let edns_client_subnet = cfg.edns_client_subnet.clone();

        let default_resolver = Arc::new(EnhancedResolver {
            ipv6: AtomicBool::new(false),
            hosts: None,
            main: make_clients(
                cfg.default_nameserver.clone(),
                None,
                Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
                edns_client_subnet.clone(),
                cfg.fw_mark,
                // default-nameserver is the bootstrap path used to resolve
                // DoH/DoT hostnames — it MUST NOT go through the rule engine.
                None,
            )
            .await,
            fallback: None,
            fallback_filter: None,
            lru_cache: None,
            policy: None,

            proxy_resolver: None,
            proxy_server_domains: None,

            fake_dns: None,

            reverse_lookup_cache: None,
            black_domain_filter: None,
            collector: None,
        });

        let proxy_resolver = if let Some(proxy_resolver) = cfg.proxy_server_nameserver {
            let clients = make_clients(
                proxy_resolver,
                Some(default_resolver.clone()),
                Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
                edns_client_subnet.clone(),
                cfg.fw_mark,
                // proxy-server-nameserver resolves the proxies themselves;
                // routing it through rules would create a bootstrap cycle.
                None,
            )
            .await;
            if clients.is_empty() {
                warn!(
                    "no usable proxy-server-nameserver clients were \
                         initialized; proxy server domain resolution will fall \
                         back to the main nameservers"
                );
                None
            } else {
                Some(clients)
            }
        } else {
            None
        };

        // Build proxy server domains trie for proxy-server-nameserver resolution.
        // This happens before the OutboundManager is fully initialized, so we can
        // only extract domains from plain outbounds.
        let proxy_server_domains = {
            let plain_outbounds = outbounds.read();
            plain_outbounds
                .values()
                .filter_map(|x| x.server_name().map(|s| s.to_owned()))
                .collect::<Vec<String>>()
        };

        let proxy_server_domains_trie =
            if proxy_resolver.is_some() && !proxy_server_domains.is_empty() {
                let mut domains = trie::StringTrie::new();
                for server in &proxy_server_domains {
                    domains.insert(server, Arc::new(true));
                    debug!("added proxy server domain: {}", server);
                }
                Some(domains)
            } else {
                None
            };

        Self {
            ipv6: AtomicBool::new(cfg.ipv6),
            main: make_clients(
                cfg.nameserver.clone(),
                Some(default_resolver.clone()),
                outbounds.clone(),
                edns_client_subnet.clone(),
                cfg.fw_mark,
                rule_dispatch.clone(),
            )
            .await,
            hosts: cfg.hosts,
            fallback: if !cfg.fallback.is_empty() {
                Some(
                    make_clients(
                        cfg.fallback.clone(),
                        Some(default_resolver.clone()),
                        outbounds.clone(),
                        edns_client_subnet.clone(),
                        cfg.fw_mark,
                        rule_dispatch.clone(),
                    )
                    .await,
                )
            } else {
                None
            },
            fallback_filter: {
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
            },
            lru_cache: Some(hickory_resolver::ResponseCache::new(
                4096,
                hickory_resolver::TtlConfig::default(),
            )),
            policy: if !cfg.nameserver_policy.is_empty() {
                let mut container = NameServerPolicyContainer::new();
                for (domain, ns) in &cfg.nameserver_policy {
                    let clients = make_clients(
                        ns.clone(),
                        Some(default_resolver.clone()),
                        outbounds.clone(),
                        edns_client_subnet.clone(),
                        cfg.fw_mark,
                        rule_dispatch.clone(),
                    )
                    .await;
                    container.insert(domain, clients);
                }
                if container.is_empty() {
                    None
                } else {
                    Some(container)
                }
            } else {
                None
            },
            fake_dns: match cfg.enhance_mode {
                DNSMode::FakeIp => Some(Arc::new(
                    fakeip::FakeDns::new(fakeip::Opts {
                        ipnet: cfg.fake_ip_range,
                        ipnet6: cfg.fake_ip_range6,
                        domain_filter: if !cfg.fake_ip_filter.is_empty() {
                            Some(DomainFilter::new(&cfg.fake_ip_filter))
                        } else {
                            None
                        },
                        store: if cfg.store_fake_ip {
                            Box::new(FileStore::new(store))
                        } else {
                            Box::new(InMemStore::new(1000))
                        },
                    })
                    .unwrap(),
                )),
                _ => None,
            },

            proxy_resolver,
            proxy_server_domains: proxy_server_domains_trie,

            reverse_lookup_cache: Some(
                moka::future::Cache::builder()
                    .max_capacity(4096)
                    .time_to_live(Duration::from_secs(3)) /* should be shorter than TTL so
                                                          * client won't be connecting to a
                                                          * different server after the ip is
                                                          * reverse mapped to hostname and
                                                          * being resolved again */
                    .build(),
            ),
            black_domain_filter: if !cfg.black_filter.is_empty() {
                Some(BlackDomainFilter::new(&cfg.black_filter))
            } else {
                None
            },
            collector,
        }
    }

    #[instrument(skip(message), level = "trace")]
    pub async fn batch_exchange(
        clients: &Vec<ThreadSafeDNSClient>,
        message: &op::Message,
    ) -> anyhow::Result<op::Message> {
        if clients.is_empty() {
            return Err(Error::DNSError("no DNS clients available for query".into()).into());
        }
        let mut queries = Vec::new();
        let domain = EnhancedResolver::domain_name_of_message(message).unwrap_or_default();
        for c in clients {
            let domain = domain.clone();
            queries.push(
                async move {
                    c.exchange(message)
                        .inspect_err(move |x| {
                            error!(
                                client = c.id(),
                                domain = %domain,
                                err = ?x,
                                "resolve error");
                        })
                        .await
                }
                .boxed(),
            )
        }

        let timeout = tokio::time::sleep(Duration::from_secs(5));

        tokio::select! {
            result = futures::future::select_ok(queries) => match result {
                Ok(r) => Ok(r.0),
                Err(e) => Err(e),
            },
            _ = timeout => Err(Error::DNSError("DNS query timeout".into()).into())
        }
    }

    /// guaranteed to return at least 1 IP address when Ok
    async fn lookup_ip(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> anyhow::Result<Vec<net::IpAddr>> {
        let mut m = Message::query();
        let mut q = Query::new();
        let name = rr::Name::from_str_relaxed(host)
            .map_err(|_x| anyhow!("invalid domain: {}", host))?
            .append_domain(&rr::Name::root())?; // makes it FQDN
        q.set_name(name);
        q.set_query_type(record_type);
        m.add_query(q);
        m.metadata.recursion_desired = true;

        let result = self.exchange(&m).await?;
        let ip_list = EnhancedResolver::ip_list_of_message(&result);
        if ip_list.is_empty() {
            return Err(anyhow!("no record for hostname: {}", host));
        }
        Ok(ip_list)
    }

    #[instrument(skip_all, level = "trace")]
    async fn exchange(&self, message: &op::Message) -> anyhow::Result<op::Message> {
        let q = message
            .queries
            .first()
            .ok_or_else(|| anyhow!("invalid query"))?;

        trace!(q = q.to_string(), "start");

        let host = q.name().to_ascii().trim_end_matches('.').to_owned();
        if self.is_blacklisted(&host) {
            debug!("dns query domain in blacklist: {}", host);
            let mut res = build_dns_response_message(message, true, false);
            res.metadata.response_code = ResponseCode::NXDomain;
            return Ok(res);
        }

        // Cache hit — return early
        if let Some(lru) = &self.lru_cache
            && let Some(Ok(cached)) = lru
                .get(q, Instant::now())
                .map(|c| c.inspect_err(|x| warn!("failed to get cached message: {}", x)))
        {
            trace!(
                q = q.to_string(),
                "cache hit for DNS query, returning cached response",
            );
            let mut reply = build_dns_response_message(message, true, false);
            reply.add_answers(cached.answers.iter().cloned());
            let ip_list = EnhancedResolver::ip_list_of_message(&reply);
            if !ip_list.is_empty() {
                if let Some(collector) = &self.collector {
                    collector.record(&host, false);
                }
            }
            return Ok(reply);
        }

        trace!(q = q.to_string(), "querying resolver");
        let res = self.exchange_no_cache(message).await.map(|mut r| {
            if let Some(edns) = r.edns.as_mut() {
                // Remove only padding options, keep everything else
                edns.options_mut().remove(rr::rdata::opt::EdnsCode::Padding);
            }
            r
        });
        trace!(q = q.to_string(), "query completed");
        if let Ok(ref msg) = res {
            let ip_list = EnhancedResolver::ip_list_of_message(msg);
            if !ip_list.is_empty() {
                if let Some(collector) = &self.collector {
                    collector.record(&host, false);
                }
            }
        }
        res
    }

    async fn exchange_no_cache(&self, message: &op::Message) -> anyhow::Result<op::Message> {
        let q = message.queries.first().unwrap();

        let query = async move {
            if let (Some(proxy_resolver), Some(proxy_domains)) =
                (&self.proxy_resolver, &self.proxy_server_domains)
                && let Some(domain) = EnhancedResolver::domain_name_of_message(message)
                && proxy_domains.search(&domain).is_some()
            {
                debug!(
                    "using proxy-server-nameserver for proxy server domain: {}",
                    domain
                );
                return EnhancedResolver::batch_exchange(proxy_resolver, message).await;
            }


            if EnhancedResolver::is_ip_request(q) {
                return self.ip_exchange(message).await;
            }

            if let Some(matched) = self.match_policy(message) {
                return EnhancedResolver::batch_exchange(matched, message).await;
            }

            EnhancedResolver::batch_exchange(&self.main, message).await
        };

        let rv = query.await;

        if let Ok(msg) = &rv
            && let Some(lru) = &self.lru_cache
            && !(q.query_type() == rr::RecordType::TXT
                && q.name().to_ascii().starts_with("_acme-challenge."))
            && !matches!(
                msg.metadata.response_code,
                op::ResponseCode::NXDomain | op::ResponseCode::ServFail
            )
            && {
                let ips = EnhancedResolver::ip_list_of_message(msg);
                ips.is_empty() || ips.iter().any(|ip| !ip.is_unspecified())
            }
        {
            lru.insert(q.clone(), Ok(msg.clone()), Instant::now());
        }

        rv
    }

    /// `nameserver-policy` stands on its own: it must not be gated on
    /// `fallback` / `fallback-filter.domain` also being configured, otherwise a
    /// config that only sets `nameserver-policy` builds the trie and then never
    /// consults it.
    fn match_policy(&self, m: &op::Message) -> Option<&Vec<ThreadSafeDNSClient>> {
        if let Some(policy) = &self.policy
            && let Some(domain) = EnhancedResolver::domain_name_of_message(m)
        {
            return policy.search(&domain);
        }
        None
    }

    #[instrument(skip_all, level = "trace")]
    async fn ip_exchange(&self, message: &op::Message) -> anyhow::Result<op::Message> {
        if let Some(matched) = self.match_policy(message) {
            return EnhancedResolver::batch_exchange(matched, message).await;
        }

        if self.should_only_query_fallback(message) {
            return EnhancedResolver::batch_exchange(
                self.fallback.as_ref().unwrap(),
                message,
            )
            .await;
        }

        let main_query = EnhancedResolver::batch_exchange(&self.main, message);

        if self.fallback.is_none() {
            return main_query.await;
        }

        let fallback_query =
            EnhancedResolver::batch_exchange(self.fallback.as_ref().unwrap(), message);

        if let Ok(main_result) = main_query.await {
            let ip_list = EnhancedResolver::ip_list_of_message(&main_result);
            if !ip_list.is_empty() && !self.should_ip_fallback(&ip_list[0]) {
                return Ok(main_result);
            }
        }

        fallback_query.await
    }

    fn should_only_query_fallback(&self, message: &op::Message) -> bool {
        if self.fallback.is_some()
            && let Some(filter) = &self.fallback_filter
            && let Some(domain) = EnhancedResolver::domain_name_of_message(message)
        {
            return filter.match_domain(&domain);
        }
        false
    }

    fn should_ip_fallback(&self, ip: &net::IpAddr) -> bool {
        if let Some(filter) = &self.fallback_filter {
            return filter.match_ip(ip);
        }
        false
    }

    // helpers
    fn is_blacklisted(&self, host: &str) -> bool {
        if let Some(black_filter) = &self.black_domain_filter {
            black_filter.apply(host)
        } else {
            false
        }
    }
    fn is_ip_request(q: &op::Query) -> bool {
        q.query_class() == rr::DNSClass::IN
            && (q.query_type() == rr::RecordType::A
                || q.query_type() == rr::RecordType::AAAA)
    }

    fn domain_name_of_message(m: &op::Message) -> Option<String> {
        m.queries
            .first()
            .map(|x| x.name().to_ascii().trim_end_matches('.').to_owned())
    }

    pub(crate) fn ip_list_of_message(m: &op::Message) -> Vec<net::IpAddr> {
        m.answers
            .iter()
            .filter(|r| {
                r.record_type() == rr::RecordType::A || r.record_type() == rr::RecordType::AAAA
            })
            .map(|r| match &r.data {
                rr::RData::A(v4) => net::IpAddr::V4(**v4),
                rr::RData::AAAA(v6) => net::IpAddr::V6(**v6),
                _ => unreachable!("should be only A/AAAA"),
            })
            .collect()
    }

    async fn save_reverse_lookup(&self, ip: net::IpAddr, domain: String) {
        if let Some(cache) = &self.reverse_lookup_cache {
            trace!("reverse lookup cache insert: {} -> {}", ip, domain);
            cache.insert(ip, domain).await;
        }
    }
}

#[async_trait]
impl ClashResolver for EnhancedResolver {
    #[instrument(skip(self), level = "trace")]
    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<net::IpAddr>> {
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(Some(ip));
        }

        match self.ipv6.load(Relaxed) {
            true => {
                let fut1 = self
                    .resolve_v6(host, enhanced)
                    .map(|x| x.map(|v6| v6.map(net::IpAddr::from)));
                let fut2 = self
                    .resolve_v4(host, enhanced)
                    .map(|x| x.map(|v4| v4.map(net::IpAddr::from)));

                let futs = vec![fut1.boxed(), fut2.boxed()];
                let r = futures::future::select_ok(futs).await?;
                if r.0.is_some() {
                    return Ok(r.0);
                }
                let r = futures::future::select_all(r.1).await;
                r.0
            }
            false => self
                .resolve_v4(host, enhanced)
                .await
                .map(|ip| ip.map(net::IpAddr::from)),
        }
    }

    /// 终极整合版：直接接收 DNS 请求报文，内部完成策略路由与响应体组装，返回完整的 DNS 响应报文
    #[instrument(skip(self), level = "trace")]
    async fn exchange_all(&self, req: &op::Message) -> anyhow::Result<Message> {
        // 1. 基础校验：如果没有 Query 记录，直接返回格式错误的 DNS 报文
        let query = req
            .queries
            .first()
            .ok_or_else(|| anyhow::anyhow!("malformed DNS query: zero queries"))?;

        let qtype = query.query_type();
        let name = query.name().clone();
        let host = query.name().to_ascii().trim_end_matches('.').to_owned();

        if self.is_blacklisted(&host) {
            debug!("dns query domain in blacklist: {}", host);
            let mut res = build_dns_response_message(req, true, false);
            res.metadata.response_code = ResponseCode::NXDomain;
            return Ok(res);
        }

        let mut current_ttl = 60; // 默认 TTL
        // 2. 预先构建基础响应报文（带上 Transaction ID 并在头部标记为 Response）
        let mut res = build_dns_response_message(req, true, false);

        // 3. AAAA asked for while IPv6 is globally disabled. Answer NODATA
        //    (NoError + zero answers), not NXDomain: NXDomain asserts that the
        //    *name* does not exist, which makes stub resolvers cache the
        //    negative result for every record type on that name — including A.
        //    `watfaq_dns`'s own handler gets this right, but the TUN hijack
        //    path (`proxy/tun/datagram.rs`) calls `exchange_with_resolver`
        //    directly and reaches this branch.
        if qtype == RecordType::AAAA && !self.ipv6.load(Relaxed) {
            res.metadata.response_code = ResponseCode::NoError;
            return Ok(res);
        }

        // 4. 路由核心：只有 A 和 AAAA 记录参与本地策略分配，其余一律转发给上游
        if qtype != RecordType::A && qtype != RecordType::AAAA {
            return self.exchange(req).await;
        }

        // --- 策略链开始 ---
        let mut resolved_ips: Vec<net::IpAddr> = Vec::new();

        // 策略 A: IP 字面量尝试解析 (例如直连 IP 查询)
        if let Ok(ip) = host.parse::<net::IpAddr>() {
            match (qtype, ip) {
                (RecordType::A, net::IpAddr::V4(_)) => resolved_ips.push(ip),
                (RecordType::AAAA, net::IpAddr::V6(_)) => resolved_ips.push(ip),
                // The name parses as an IP literal of the other family: the
                // name exists, it just has no record of the requested type.
                // That is NODATA, not NXDomain.
                _ => {
                    res.metadata.response_code = ResponseCode::NoError;
                    return Ok(res);
                }
            }
        }

        // 策略 B: 本地 Hosts 文件匹配
        if resolved_ips.is_empty()
            && let Some(hosts) = &self.hosts
            && let Some(v) = hosts.search(&host)
        {
            if let Some(ip) = v.get_data() {
                match (qtype, ip) {
                    (RecordType::A, net::IpAddr::V4(_)) => resolved_ips.push(*ip),
                    (RecordType::AAAA, net::IpAddr::V6(_)) => resolved_ips.push(*ip),
                    _ => {}
                }
            }
        }

        // 策略 C: Fake IP 逻辑拦截
        if resolved_ips.is_empty() && self.fake_ip_enabled() {
            let fake_dns = self.fake_dns.as_ref().unwrap();
            if !fake_dns.should_skip(&host) {
                match qtype {
                    RecordType::A => {
                        let ip = fake_dns.lookup(&host).await;
                        debug!("fake dns lookup_v4: {} -> {:?}", host, ip);
                        resolved_ips.push(ip);
                        current_ttl = 1;
                        if let Some(collector) = &self.collector {
                            collector.record(&host, true);
                        }
                    }
                    RecordType::AAAA => {
                        let ip = fake_dns.lookupv6(&host).await;
                        debug!("fake dns lookup_v6: {} -> {:?}", host, ip);
                        resolved_ips.push(ip);
                        current_ttl = 1;
                        if let Some(collector) = &self.collector {
                            collector.record(&host, true);
                        }
                    }
                    _ => {}
                }
            } else {
                return self.exchange(req).await;
            }
        }

        // --- 策略链结束，组装最终报文 ---
        // Nothing was answered locally. This is reachable when fake-ip is off
        // (`exchange_all` is part of the `ClashResolver` trait, so callers
        // other than the DNS server can hit it) or when the only matching
        // `hosts` entry was of the other family. Forward upstream rather than
        // fabricating an NXDomain for a name we simply know nothing about.
        if resolved_ips.is_empty() {
            return self.exchange(req).await;
        }

        if current_ttl != 1 {
            if let Some(collector) = &self.collector {
                collector.record(&host, false);
            }
        }
        let records: Vec<Record> = resolved_ips
            .into_iter()
            .map(|ip| {
                let rdata = match ip {
                    net::IpAddr::V4(v4) => RData::A(A(v4)),
                    net::IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
                };
                Record::from_rdata(name.clone(), current_ttl, rdata)
            })
            .collect();

        res.metadata.response_code = ResponseCode::NoError;
        res.add_answers(records);

        Ok(res)
    }

    #[instrument(skip(self), level = "trace")]
    async fn resolve_v4(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<net::Ipv4Addr>> {
        if self.is_blacklisted(host) {
            debug!("dns resolve_v4 domain in blacklist: {}", host);
            return Ok(None);
        }
        // A `hosts` entry for the other address family is not an error — it
        // just means this name has no locally configured A record, so fall
        // through to normal resolution. Note `Config::parse_hosts` always
        // seeds `localhost -> 127.0.0.1`, so the mismatching case is reachable
        // for every deployment with `dns.ipv6` enabled.
        if enhanced
            && let Some(hosts) = &self.hosts
            && let Some(v) = hosts.search(host)
            && let Some(net::IpAddr::V4(v4)) = v.get_data()
        {
            return Ok(Some(*v4));
        }

        if let Ok(ip) = host.parse::<net::Ipv4Addr>() {
            return Ok(Some(ip));
        }

        if enhanced && self.fake_ip_enabled() {
            let fake_dns = self.fake_dns.as_ref().unwrap();
            if !fake_dns.should_skip(host) {
                let ip = fake_dns.lookup(host).await;
                debug!("fake dns lookup: {} -> {:?}", host, ip);
                match ip {
                    net::IpAddr::V4(v4) => {
                        if let Some(collector) = &self.collector {
                            collector.record(host, true);
                        }
                        return Ok(Some(v4));
                    }
                    net::IpAddr::V6(v6) => {
                        return Err(anyhow!(
                            "fake ip store returned v6 address {} for an A \
                             lookup of {}",
                            v6,
                            host
                        ));
                    }
                }
            }
        }

        let result = self.lookup_ip(host, rr::RecordType::A).await?;
        // `ip_list_of_message` keeps both A and AAAA answers, so a broken or
        // hostile upstream can put AAAA records in the answer section of an A
        // query. Drop them instead of treating them as unreachable.
        let v4s = result
            .into_iter()
            .filter_map(|ip| match ip {
                net::IpAddr::V4(v4) => Some(v4),
                net::IpAddr::V6(_) => None,
            })
            .collect::<Vec<_>>();
        match v4s.choose(&mut rand::rng()) {
            Some(v4) => {
                if let Some(collector) = &self.collector {
                    collector.record(host, false);
                }
                Ok(Some(*v4))
            }
            None => Err(anyhow!("no A record for hostname: {}", host)),
        }
    }

    #[instrument(skip(self), level = "trace")]
    async fn resolve_v6(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<net::Ipv6Addr>> {
        if self.is_blacklisted(host) {
            debug!("dns resolve_v6 domain in blacklist: {}", host);
            return Ok(None);
        }
        if let Some(std::net::IpAddr::V6(ip)) = parse_ip_literal(host) {
            return Ok(Some(ip));
        }

        if !self.ipv6.load(Relaxed) {
            return Err(Error::DNSError("ipv6 disabled".into()).into());
        }

        // See the matching comment in `resolve_v4`: a `hosts` entry of the
        // other family means "no local AAAA record", not "impossible".
        if enhanced
            && let Some(hosts) = &self.hosts
            && let Some(v) = hosts.search(host)
            && let Some(net::IpAddr::V6(v6)) = v.get_data()
        {
            return Ok(Some(*v6));
        }

        if enhanced && self.fake_ip_enabled() {
            let fake_dns = self.fake_dns.as_ref().unwrap();
            if !fake_dns.should_skip(host) {
                let ip = fake_dns.lookupv6(host).await;
                debug!("fake dns lookupv6: {} -> {:?}", host, ip);
                match ip {
                    net::IpAddr::V6(v6) => {
                        if let Some(collector) = &self.collector {
                            collector.record(host, true);
                        }
                        return Ok(Some(v6));
                    }
                    net::IpAddr::V4(v4) => {
                        return Err(anyhow!(
                            "fake ip store returned v4 address {} for an AAAA \
                             lookup of {}",
                            v4,
                            host
                        ));
                    }
                }
            }
        }

        let result = self.lookup_ip(host, rr::RecordType::AAAA).await?;
        // Same as `resolve_v4`: tolerate A records showing up in the answer
        // section of an AAAA query rather than panicking on them.
        let v6s = result
            .into_iter()
            .filter_map(|ip| match ip {
                net::IpAddr::V6(v6) => Some(v6),
                net::IpAddr::V4(_) => None,
            })
            .collect::<Vec<_>>();
        match v6s.choose(&mut rand::rng()) {
            Some(v6) => {
                if let Some(collector) = &self.collector {
                    collector.record(host, false);
                }
                Ok(Some(*v6))
            }
            None => Err(anyhow!("no AAAA record for hostname: {}", host)),
        }
    }

    #[instrument(skip(self))]
    async fn cached_for(&self, ip: net::IpAddr) -> Option<String> {
        if let Some(cache) = &self.reverse_lookup_cache
            && let Some(cached) = cache.get(&ip).await
        {
            trace!("reverse lookup cache hit: {cached} -> {ip}");
            return Some(cached);
        }

        None
    }

    #[instrument(skip(self), level = "trace")]
    async fn exchange(&self, message: &op::Message) -> anyhow::Result<op::Message> {
        let rv = self.exchange(message).await?;
        let hostname = message
            .queries
            .first()
            .unwrap()
            .name()
            .to_utf8()
            .trim_end_matches('.')
            .to_owned();
        let ip_list = EnhancedResolver::ip_list_of_message(&rv);
        if !ip_list.is_empty() {
            if let Some(collector) = &self.collector {
                collector.record(&hostname, false);
            }
            for ip in ip_list {
                self.save_reverse_lookup(ip, hostname.clone()).await;
            }
        }
        Ok(rv)
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

    fn fake_ip_enabled(&self) -> bool {
        self.fake_dns.is_some()
    }

    async fn after_router_inited(&self, r: Arc<Router>) {
        if self.fake_ip_enabled() {
            self.fake_dns
                .as_ref()
                .unwrap()
                .add_rule_set(r.get_rule_providers())
                .await;
        }
        if let Some(black_filter) = &self.black_domain_filter {
            black_filter.add_rule_set(r.get_rule_providers());
        }
        if let Some(fallback_filter) = &self.fallback_filter {
            fallback_filter.add_rule_set(r.get_rule_providers());
        }
        if let Some(policy) = &self.policy {
            policy.add_rule_set(r.as_ref());
        }
    }

    async fn is_fake_ip(&self, ip: std::net::IpAddr) -> bool {
        if !self.fake_ip_enabled() {
            return false;
        }

        self.fake_dns.as_ref().unwrap().is_fake_ip(ip).await
    }

    async fn reverse_lookup(&self, ip: net::IpAddr) -> Option<String> {
        debug!("reverse lookup: {}", ip);
        if !self.fake_ip_enabled() {
            return None;
        }

        self.fake_dns.as_ref().unwrap().reverse_lookup(ip).await
    }
}
