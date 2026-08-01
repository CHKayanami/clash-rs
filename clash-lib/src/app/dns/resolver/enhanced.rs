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
        filters::{
            BlackDomainFilter, DomainFilter, FallbackDomainFilter, FallbackIPFilter,
            GeoIPFilter, IPNetFilter, PendingMmdb,
        },
        helper::make_clients,
        parse_ip_literal,
    },
};
use anyhow::anyhow;
use async_trait::async_trait;
use futures::{FutureExt, TryFutureExt};
use hickory_proto::op;
use hickory_proto::rr;
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{
        RData, Record, RecordType,
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
    fallback_domain_filters: Option<Vec<Box<dyn FallbackDomainFilter>>>,
    fallback_ip_filters: Option<Vec<Box<dyn FallbackIPFilter>>>,

    lru_cache: Option<hickory_resolver::ResponseCache>,
    policy: Option<trie::StringTrie<Vec<ThreadSafeDNSClient>>>,

    proxy_resolver: Option<Vec<ThreadSafeDNSClient>>,
    direct_resolver: Option<Vec<ThreadSafeDNSClient>>,
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

        use crate::app::dns::dns_client::DNSNetMode;

        use crate::app::dns::config::NameServer;

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
            fallback_domain_filters: None,
            fallback_ip_filters: None,
            lru_cache: None,
            policy: None,

            proxy_resolver: None,
            direct_resolver: None,
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
            fallback_domain_filters: None,
            fallback_ip_filters: None,
            lru_cache: None,
            policy: None,

            proxy_resolver: None,
            direct_resolver: None,
            proxy_server_domains: None,

            fake_dns: None,

            reverse_lookup_cache: None,
            black_domain_filter: None,
            collector: None,
        });

        let proxy_resolver = if let Some(proxy_resolver) =
            cfg.proxy_server_nameserver
        {
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

        let direct_resolver = if let Some(direct_resolver) = cfg.direct_nameserver {
            let clients = make_clients(
                direct_resolver,
                Some(default_resolver.clone()),
                outbounds.clone(),
                edns_client_subnet.clone(),
                cfg.fw_mark,
                rule_dispatch.clone(),
            )
            .await;
            if clients.is_empty() {
                warn!(
                    "no usable direct-nameserver clients were \
                         initialized; direct DNS resolution will fall \
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
            fallback_domain_filters: if !cfg.fallback_filter.domain.is_empty() {
                Some(vec![Box::new(DomainFilter::new(
                    cfg.fallback_filter
                        .domain
                        .iter()
                        .map(|x| x.as_str())
                        .collect(),
                )) as Box<dyn FallbackDomainFilter>])
            } else {
                None
            },
            fallback_ip_filters: if cfg.fallback_filter.ip_cidr.is_some()
                || cfg.fallback_filter.geo_ip
            {
                let mut filters = vec![];

                filters.push(Box::new(GeoIPFilter::new(
                    &cfg.fallback_filter.geo_ip_code,
                    mmdb,
                )) as Box<dyn FallbackIPFilter>);

                if let Some(ipcidr) = &cfg.fallback_filter.ip_cidr {
                    for subnet in ipcidr {
                        filters.push(Box::new(IPNetFilter::new(*subnet))
                            as Box<dyn FallbackIPFilter>)
                    }
                }

                Some(filters)
            } else {
                None
            },
            lru_cache: Some(hickory_resolver::ResponseCache::new(
                4096,
                hickory_resolver::TtlConfig::default(),
            )),
            policy: if !cfg.nameserver_policy.is_empty() {
                let mut p = trie::StringTrie::new();
                for (domain, ns) in &cfg.nameserver_policy {
                    p.insert(
                        domain.as_str(),
                        Arc::new(
                            make_clients(
                                vec![ns.to_owned()],
                                Some(default_resolver.clone()),
                                outbounds.clone(),
                                edns_client_subnet.clone(),
                                cfg.fw_mark,
                                rule_dispatch.clone(),
                            )
                            .await,
                        ),
                    );
                }
                Some(p)
            } else {
                None
            },
            fake_dns: match cfg.enhance_mode {
                DNSMode::FakeIp => Some(Arc::new(
                    fakeip::FakeDns::new(fakeip::Opts {
                        ipnet: cfg.fake_ip_range,
                        ipnet6: cfg.fake_ip_range6,
                        skipped_hostnames: if !cfg.fake_ip_filter.is_empty() {
                            let mut host = trie::StringTrie::new();
                            for domain in cfg.fake_ip_filter.iter() {
                                if !domain.starts_with("rule-set:") {
                                    host.insert(domain.as_str(), Arc::new(true));
                                }
                            }
                            Some(host)
                        } else {
                            None
                        },
                        ruleset_names: if !cfg.fake_ip_filter.is_empty() {
                            let mut rs_names: Vec<String> = Vec::new();
                            for domain in cfg.fake_ip_filter.iter() {
                                if domain.starts_with("rule-set:") {
                                    rs_names.push(domain.replace("rule-set:", ""));
                                }
                            }
                            Some(rs_names)
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
                DNSMode::RedirHost => {
                    warn!(
                        "dns redir-host is not supported and will not do anything"
                    );
                    None
                }
                _ => None,
            },

            proxy_resolver,
            direct_resolver,
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
                Some(BlackDomainFilter::new(
                    cfg.black_filter.iter().map(|s| s.as_str()).collect(),
                ))
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
            return Err(Error::DNSError(
                "no DNS clients available for query".into(),
            )
            .into());
        }
        let mut queries = Vec::new();
        let domain =
            EnhancedResolver::domain_name_of_message(message).unwrap_or_default();
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

        let timeout = tokio::time::sleep(Duration::from_secs(10));

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
            && let Some(Ok(cached)) = lru.get(q, Instant::now()).map(|c| {
                c.inspect_err(|x| warn!("failed to get cached message: {}", x))
            })
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

    async fn exchange_no_cache(
        &self,
        message: &op::Message,
    ) -> anyhow::Result<op::Message> {
        let q = message.queries.first().unwrap();

        let query = async move {
            if let (Some(proxy_resolver), Some(proxy_domains)) =
                (&self.proxy_resolver, &self.proxy_server_domains)
                && let Some(domain) =
                    EnhancedResolver::domain_name_of_message(message)
                && proxy_domains.search(&domain).is_some()
            {
                debug!(
                    "using proxy-server-nameserver for proxy server domain: {}",
                    domain
                );
                return EnhancedResolver::batch_exchange(proxy_resolver, message)
                    .await;
            }

            if self.fake_ip_enabled()
                && let Some(domain) =
                    EnhancedResolver::domain_name_of_message(message)
                && let Some(direct_resolver) = &self.direct_resolver
                && self
                    .fake_dns
                    .as_ref()
                    .map_or(false, |fd| fd.should_skip(&domain))
            {
                debug!(
                    "using direct-nameserver for fake-ip-filter domain: {}",
                    domain
                );
                return EnhancedResolver::batch_exchange(direct_resolver, message)
                    .await;
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
            // `StringTrie::search` only returns nodes that carry data.
            return policy.search(&domain).and_then(|n| n.get_data());
        }
        None
    }

    #[instrument(skip_all, level = "trace")]
    async fn ip_exchange(
        &self,
        message: &op::Message,
    ) -> anyhow::Result<op::Message> {
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

        let fallback_query = EnhancedResolver::batch_exchange(
            self.fallback.as_ref().unwrap(),
            message,
        );

        if let Ok(main_result) = main_query.await {
            let ip_list = EnhancedResolver::ip_list_of_message(&main_result);
            if !ip_list.is_empty() && !self.should_ip_fallback(&ip_list[0]) {
                return Ok(main_result);
            }
        }

        fallback_query.await
    }

    fn should_only_query_fallback(&self, message: &op::Message) -> bool {
        if let (Some(_), Some(fallback_domain_filters)) =
            (&self.fallback, &self.fallback_domain_filters)
            && let Some(domain) = EnhancedResolver::domain_name_of_message(message)
        {
            for f in fallback_domain_filters.iter() {
                if f.apply(domain.as_str()) {
                    return true;
                }
            }
        }
        false
    }

    fn should_ip_fallback(&self, ip: &net::IpAddr) -> bool {
        if let Some(filers) = &self.fallback_ip_filters {
            for f in filers.iter() {
                if f.apply(ip) {
                    return true;
                }
            }
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
                r.record_type() == rr::RecordType::A
                    || r.record_type() == rr::RecordType::AAAA
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

#[cfg(test)]
mod tests {

    use hickory_net::{DnsHandle, client, udp::UdpClientStream, xfer::FirstAnswer};
    use hickory_proto::{
        op::{self, DnsRequest, DnsRequestOptions},
        rr,
    };
    use std::{net::Ipv4Addr, sync::Arc, time::Instant};

    use crate::{
        app::dns::{
            ClashResolver, ThreadSafeDNSClient,
            config::{Config, NameServer},
            dns_client::{DNSNetMode, DnsClient, Opts},
            resolver::enhanced::EnhancedResolver,
            runtime::DnsRuntimeProvider,
        },
        proxy,
    };

    /// Regression test for https://github.com/Watfaq/clash-rs/issues/976
    /// IPv6 literal addresses must be returned directly even when dns.ipv6 is
    /// disabled, because they do not require DNS resolution.
    #[tokio::test]
    async fn test_resolve_ipv6_literal_when_ipv6_disabled() {
        let resolver = EnhancedResolver::new_default().await;
        // Ensure ipv6 is disabled, mirroring `dns.ipv6 = false`.
        resolver.set_ipv6(false);
        assert!(!resolver.ipv6(), "ipv6 should be disabled");

        // Resolving an IPv6 literal must succeed even with ipv6 disabled.
        let result = resolver
            .resolve("::1", false)
            .await
            .expect("resolve should not error for IPv6 literal");
        assert_eq!(
            result,
            Some(std::net::IpAddr::V6("::1".parse().unwrap())),
            "IPv6 literal should be returned as-is"
        );
    }

    /// Resolving a plain IPv4 literal must still work when ipv6 is disabled.
    #[tokio::test]
    async fn test_resolve_ipv4_literal_when_ipv6_disabled() {
        let resolver = EnhancedResolver::new_default().await;
        resolver.set_ipv6(false);

        let result = resolver
            .resolve("127.0.0.1", false)
            .await
            .expect("resolve should not error for IPv4 literal");
        assert_eq!(
            result,
            Some(std::net::IpAddr::V4("127.0.0.1".parse().unwrap())),
            "IPv4 literal should be returned as-is"
        );
    }

    /// resolve_v6 must return an IPv6 literal directly even when ipv6 is
    /// disabled (no DNS lookup needed for a literal).
    #[tokio::test]
    async fn test_resolve_v6_literal_when_ipv6_disabled() {
        let resolver = EnhancedResolver::new_default().await;
        resolver.set_ipv6(false);

        let result = resolver.resolve_v6("::1", false).await.expect(
            "resolve_v6 should not error for IPv6 literal when ipv6 disabled",
        );
        assert_eq!(
            result,
            Some("::1".parse::<std::net::Ipv6Addr>().unwrap()),
            "IPv6 literal should be returned directly"
        );
    }

    #[tokio::test]
    async fn test_lru_cache_hit_with_recursion_desired() {
        use hickory_proto::op;

        let mut resolver = EnhancedResolver::new_default().await;
        resolver.main.clear(); // ensure cache miss would fail deterministically
        resolver.lru_cache = Some(hickory_resolver::ResponseCache::new(
            16,
            hickory_resolver::TtlConfig::default(),
        ));

        let mut request = op::Message::query();
        let mut query = op::Query::new();
        let name = rr::Name::from_str_relaxed("example.com")
            .unwrap()
            .append_domain(&rr::Name::root())
            .unwrap();
        query.set_name(name.clone());
        query.set_query_type(rr::RecordType::A);
        request.add_query(query);
        request.metadata.recursion_desired = true;

        let mut cached = op::Message::response(0, op::OpCode::Query);
        let ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
        cached.add_answer(rr::Record::from_rdata(
            name,
            300,
            rr::RData::A(rr::rdata::A(ip)),
        ));

        let lru = resolver.lru_cache.as_ref().unwrap();
        let q = request.queries.first().unwrap().clone();
        lru.insert(q, Ok(cached), Instant::now());

        let response = resolver
            .exchange(&request)
            .await
            .expect("should be served from cache");
        assert_eq!(response.answers.len(), 1);
        match &response.answers[0].data {
            rr::RData::A(a) => assert_eq!(a.0, ip),
            other => panic!("expected A record, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_bad_labels_with_custom_resolver() {
        use hickory_net::proto::{op, rr};

        let name = rr::Name::from_str_relaxed("some_domain.understore")
            .unwrap()
            .append_domain(&rr::Name::root())
            .unwrap();
        assert_eq!(name.to_string(), "some_domain.understore.");

        let mut m = op::Message::query();
        let mut q = op::Query::new();

        q.set_name(name);
        q.set_query_type(rr::RecordType::A);
        m.add_query(q);
        m.metadata.recursion_desired = true;

        let stream = UdpClientStream::builder(
            "1.1.1.1:53".parse().unwrap(),
            DnsRuntimeProvider::new_direct(None, None),
        )
        .build();
        let (client, bg) = client::Client::<DnsRuntimeProvider>::from_sender(stream);
        tokio::spawn(bg);

        let mut req = DnsRequest::new(m, DnsRequestOptions::default());
        req.metadata.id = rand::random::<u16>();
        let res = client.send(req).first_answer().await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    #[ignore = "network unstable on CI"]
    async fn test_udp_resolve() {
        let c = DnsClient::new_client(Opts {
            father: None,
            host: url::Host::Ipv4(Ipv4Addr::from([114, 114, 114, 114])),
            port: 53,
            net: DNSNetMode::Udp,
            iface: None,
            proxy: get_default_outbound(),
            ecs: None,
            fw_mark: None,
            rule_dispatch: None,
        })
        .await
        .expect("build client");

        test_client(c).await;
    }

    #[tokio::test]
    #[ignore = "network unstable on CI"]
    async fn test_tcp_resolve() {
        let c = DnsClient::new_client(Opts {
            father: None,
            host: url::Host::Ipv4(Ipv4Addr::from([1, 1, 1, 1])),
            port: 53,
            net: DNSNetMode::Tcp,
            iface: None,
            proxy: get_default_outbound(),
            ecs: None,
            fw_mark: None,
            rule_dispatch: None,
        })
        .await
        .expect("build client");

        test_client(c).await;
    }

    #[tokio::test]
    #[ignore = "network unstable on CI"]
    async fn test_dot_resolve() {
        let c = DnsClient::new_client(Opts {
            father: Some(Arc::new(EnhancedResolver::new_default().await)),
            host: url::Host::Domain("dns.google".to_string()),
            port: 853,
            net: DNSNetMode::DoT,
            iface: None,
            proxy: get_default_outbound(),
            ecs: None,
            fw_mark: None,
            rule_dispatch: None,
        })
        .await
        .expect("build client");

        test_client(c).await;
    }

    #[tokio::test]
    #[ignore = "network unstable on CI"]
    async fn test_doh_resolve() {
        let default_resolver = Arc::new(EnhancedResolver::new_default().await);

        let c = DnsClient::new_client(Opts {
            father: Some(default_resolver.clone()),
            host: url::Host::Domain("cloudflare-dns.com".to_string()),
            port: 443,
            net: DNSNetMode::DoH,
            iface: None,
            proxy: get_default_outbound(),
            ecs: None,
            fw_mark: None,
            rule_dispatch: None,
        })
        .await
        .expect("build client");

        test_client(c).await;
    }

    #[tokio::test]
    #[ignore = "network unstable on CI"]
    async fn test_dhcp_client() {
        let c = DnsClient::new_client(Opts {
            father: None,
            host: url::Host::Domain("en0".to_string()),
            port: 0,
            net: DNSNetMode::Dhcp,
            iface: None,
            proxy: get_default_outbound(),
            ecs: None,
            fw_mark: None,
            rule_dispatch: None,
        })
        .await
        .expect("build client");

        test_client(c).await;
    }

    async fn test_client(c: ThreadSafeDNSClient) {
        let mut m = op::Message::query();
        let mut q = op::Query::new();
        q.set_name(rr::Name::from_utf8("www.google.com").unwrap());
        q.set_query_type(rr::RecordType::A);
        m.add_query(q);

        let r = EnhancedResolver::batch_exchange(&vec![c.clone()], &m)
            .await
            .expect("should exchange");

        let ips = EnhancedResolver::ip_list_of_message(&r);

        assert!(!ips.is_empty());
        assert!(!ips[0].is_unspecified());
        assert!(ips[0].is_ipv4());

        let mut m = op::Message::query();
        let mut q = op::Query::new();
        q.set_name(rr::Name::from_utf8("www.google.com").unwrap());
        q.set_query_type(rr::RecordType::AAAA);
        m.add_query(q);

        let r = EnhancedResolver::batch_exchange(&vec![c.clone()], &m)
            .await
            .expect("should exchange");

        let ips = EnhancedResolver::ip_list_of_message(&r);

        assert!(!ips.is_empty());
        assert!(!ips[0].is_unspecified());
        assert!(ips[0].is_ipv6());
    }
    fn get_default_outbound() -> Arc<dyn crate::proxy::OutboundHandler> {
        Arc::new(proxy::direct::Handler::new("default_direct"))
    }

    #[tokio::test]
    async fn test_proxy_server_nameserver_initialization() {
        use crate::app::{
            dns::{
                config::{Config, NameServer},
                dns_client::DNSNetMode,
            },
            profile::ThreadSafeCacheFile,
        };
        use std::collections::HashMap;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let cache_store = ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );

        let mut config = Config::default();
        config.enable = true;
        config.ipv6 = false;

        // Set up proxy server nameserver
        config.proxy_server_nameserver = Some(vec![NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4("8.8.8.8".parse().unwrap()),
            port: 53,
            interface: None,
            proxy: None,
        }]);

        config.default_nameserver = vec![NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4("114.114.114.114".parse().unwrap()),
            port: 53,
            interface: None,
            proxy: None,
        }];

        config.nameserver = vec![NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4("223.5.5.5".parse().unwrap()),
            port: 53,
            interface: None,
            proxy: None,
        }];

        let resolver = EnhancedResolver::new(
            config,
            cache_store,
            None,
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            None,
            None,
        )
        .await;

        // proxy_resolver is set from config; proxy_server_domains is None because
        // no outbound handlers are registered (domains come from server_name()).
        assert!(resolver.proxy_resolver.is_some());
        assert!(resolver.proxy_server_domains.is_none());
    }

    #[tokio::test]
    async fn test_proxy_server_nameserver_without_config() {
        use crate::app::{
            dns::{
                config::{Config, NameServer},
                dns_client::DNSNetMode,
            },
            profile::ThreadSafeCacheFile,
        };
        use std::collections::HashMap;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let cache_store = ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );

        let mut config = Config::default();
        config.enable = true;
        config.ipv6 = false;

        // No proxy server nameserver configured
        config.proxy_server_nameserver = None;

        config.default_nameserver = vec![NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4("114.114.114.114".parse().unwrap()),
            port: 53,
            interface: None,
            proxy: None,
        }];

        config.nameserver = vec![NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4("223.5.5.5".parse().unwrap()),
            port: 53,
            interface: None,
            proxy: None,
        }];

        let resolver = EnhancedResolver::new(
            config,
            cache_store,
            None,
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            None,
            None,
        )
        .await;

        // Should not have proxy_resolver when proxy_server_nameserver is empty
        assert!(resolver.proxy_resolver.is_none());
        assert!(resolver.proxy_server_domains.is_none());
    }

    /// Build a test outbound registry containing socks5 handlers whose
    /// server fields are the given (name, server) pairs.
    fn make_outbound_registry(
        entries: &[(&str, &str)],
    ) -> Arc<
        parking_lot::RwLock<
            std::collections::HashMap<
                String,
                Arc<dyn crate::proxy::OutboundHandler>,
            >,
        >,
    > {
        use crate::proxy::{
            HandlerCommonOptions,
            socks::outbound::{
                Handler as SocksHandler, HandlerOptions as SocksHandlerOptions,
            },
        };
        let mut map = std::collections::HashMap::new();
        for (name, server) in entries {
            let h: Arc<dyn crate::proxy::OutboundHandler> =
                Arc::new(SocksHandler::new(SocksHandlerOptions {
                    name: name.to_string(),
                    common_opts: HandlerCommonOptions::default(),
                    server: server.to_string(),
                    port: 1080,
                    user: None,
                    password: None,
                    udp: false,
                    tls_client: None,
                }));
            map.insert(name.to_string(), h);
        }
        Arc::new(parking_lot::RwLock::new(map))
    }

    fn make_proxy_nameserver_config() -> (
        crate::app::dns::config::Config,
        crate::app::dns::config::NameServer,
    ) {
        let ns = NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4("8.8.8.8".parse().unwrap()),
            port: 53,
            interface: None,
            proxy: None,
        };
        let mut config = Config::default();
        config.enable = true;
        config.ipv6 = false;
        config.proxy_server_nameserver = Some(vec![ns.clone()]);
        config.default_nameserver = vec![NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4("114.114.114.114".parse().unwrap()),
            port: 53,
            interface: None,
            proxy: None,
        }];
        config.nameserver = vec![NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4("223.5.5.5".parse().unwrap()),
            port: 53,
            interface: None,
            proxy: None,
        }];
        (config, ns)
    }

    #[tokio::test]
    async fn test_proxy_server_domains_populated_from_outbounds() {
        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );

        let (config, _) = make_proxy_nameserver_config();
        // Two domain-based proxies and one IP-based — IP should not appear in trie.
        let outbounds = make_outbound_registry(&[
            ("proxy-a", "proxy.example.com"),
            ("proxy-b", "vpn.example.net"),
            ("proxy-ip", "1.2.3.4"),
        ]);

        let resolver =
            EnhancedResolver::new(config, cache_store, None, outbounds, None, None)
                .await;

        assert!(resolver.proxy_resolver.is_some());
        let domains = resolver.proxy_server_domains.as_ref().expect(
            "proxy_server_domains should be Some when domain-named outbounds exist",
        );
        assert!(domains.search("proxy.example.com").is_some());
        assert!(domains.search("vpn.example.net").is_some());
        // IP entries are inserted but DNS queries will never match them
        assert!(domains.search("1.2.3.4").is_some());
    }

    #[tokio::test]
    async fn test_proxy_server_domain_resolved_via_proxy_nameserver() {
        use crate::dns::ClashResolver;
        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );

        let (config, _) = make_proxy_nameserver_config();
        // Register "one.one.one.one" as a proxy server domain.
        let outbounds = make_outbound_registry(&[("cf-proxy", "one.one.one.one")]);

        let resolver =
            EnhancedResolver::new(config, cache_store, None, outbounds, None, None)
                .await;

        // Sanity: the trie was built
        assert!(resolver.proxy_server_domains.is_some());
        assert!(
            resolver
                .proxy_server_domains
                .as_ref()
                .unwrap()
                .search("one.one.one.one")
                .is_some()
        );

        // The domain should resolve successfully through the proxy nameserver path.
        let ip = resolver
            .resolve("one.one.one.one", false)
            .await
            .expect("should resolve one.one.one.one")
            .expect("should return an IP for one.one.one.one");
        // one.one.one.one always resolves to 1.1.1.1 or 1.0.0.1
        assert!(
            ip.to_string() == "1.1.1.1" || ip.to_string() == "1.0.0.1",
            "unexpected IP: {}",
            ip
        );
    }

    #[tokio::test]
    async fn test_black_domain_filter() {
        use crate::app::remote_content_manager::providers::rule_provider::{
            RuleProviderImpl, RuleSetBehavior, RuleSetFormat, ThreadSafeRuleProvider,
        };
        use std::collections::HashMap;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );

        let mut config = Config::default();
        config.enable = true;
        config.black_filter = vec![
            "*.bad.domain".to_string(),
            "exact-bad.domain".to_string(),
            "rule-set:adblock".to_string(),
        ];
        config.default_nameserver = vec![NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4("114.114.114.114".parse().unwrap()),
            port: 53,
            interface: None,
            proxy: None,
        }];
        config.nameserver = vec![NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4("223.5.5.5".parse().unwrap()),
            port: 53,
            interface: None,
            proxy: None,
        }];

        let outbounds = make_outbound_registry(&[]);
        let resolver =
            EnhancedResolver::new(config, cache_store, None, outbounds, None, None)
                .await;

        // Verify string rules match
        assert!(resolver.is_blacklisted("exact-bad.domain"));
        assert!(resolver.is_blacklisted("test.bad.domain"));
        assert!(!resolver.is_blacklisted("good.domain"));

        // Register rule-set and initialize
        let rule_provider = Arc::new(RuleProviderImpl::new(
            "adblock".to_string(),
            RuleSetBehavior::Domain,
            RuleSetFormat::Text,
            None,
            None,
            None,
            None,
            Some(vec!["+.google.com".to_owned()]),
        )) as ThreadSafeRuleProvider;
        rule_provider.initialize().await.unwrap();

        let mut rp_map = HashMap::new();
        rp_map.insert("adblock".to_string(), rule_provider);

        // Before add_rule_set: shouldn't match ruleset blacklisted domain
        assert!(!resolver.is_blacklisted("test.google.com"));

        // Bind rule providers
        if let Some(black_filter) = &resolver.black_domain_filter {
            black_filter.add_rule_set(&rp_map);
        }

        // After add_rule_set: should match ruleset blacklisted domain
        assert!(resolver.is_blacklisted("test.google.com"));
        assert!(!resolver.is_blacklisted("other.com"));

        // Verify resolve_v4 and resolve_v6 block matches
        let ip_v4 = resolver
            .resolve_v4("exact-bad.domain", false)
            .await
            .unwrap();
        assert!(ip_v4.is_none());

        let ip_v4_ruleset =
            resolver.resolve_v4("test.google.com", false).await.unwrap();
        assert!(ip_v4_ruleset.is_none());

        let ip_v6 = resolver.resolve_v6("test.bad.domain", false).await.unwrap();
        assert!(ip_v6.is_none());

        // Verify exchange returns NXDomain
        let mut msg = op::Message::query();
        let mut query = op::Query::new();
        let name = rr::Name::from_str_relaxed("exact-bad.domain").unwrap();
        query.set_name(name);
        query.set_query_type(rr::RecordType::A);
        msg.add_query(query);

        let response = resolver.exchange(&msg).await.unwrap();
        assert_eq!(response.metadata.response_code, op::ResponseCode::NXDomain);

        let response_all = resolver.exchange_all(&msg).await.unwrap();
        assert_eq!(
            response_all.metadata.response_code,
            op::ResponseCode::NXDomain
        );
    }

    #[tokio::test]
    async fn test_direct_nameserver_routing_logic() {
        use crate::app::dns::Client;
        use crate::config::def::DNSMode;
        use crate::dns::ClashResolver;
        use hickory_proto::rr::{RData, Record, rdata::A};
        use std::sync::atomic::{AtomicBool, Ordering};
        use tempfile::tempdir;

        #[derive(Debug)]
        struct TestDnsClient {
            id: String,
            called: Arc<AtomicBool>,
        }
        #[async_trait::async_trait]
        impl Client for TestDnsClient {
            fn id(&self) -> String {
                self.id.clone()
            }
            async fn exchange(
                &self,
                msg: &op::Message,
            ) -> anyhow::Result<op::Message> {
                self.called.store(true, Ordering::Relaxed);
                let mut response =
                    crate::app::dns::helper::build_dns_response_message(
                        msg, true, false,
                    );

                // Add a dummy IP answer so that ip_list is not empty
                let name = msg.queries.first().unwrap().name().clone();
                let rdata = RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4)));
                let record = Record::from_rdata(name, 60, rdata);
                response.add_answers(vec![record]);
                Ok(response)
            }
        }

        let temp_dir = tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );

        let mut config = Config::default();
        config.enable = true;
        config.ipv6 = false;
        config.enhance_mode = DNSMode::FakeIp;
        config.fake_ip_range = "198.18.0.1/16".parse().unwrap();
        config.fake_ip_range6 = "fc00::/18".parse().unwrap();
        config.fake_ip_filter = vec!["bypass.example.com".to_string()];

        let mut resolver = EnhancedResolver::new(
            config,
            cache_store,
            None,
            Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
            None,
            None,
        )
        .await;

        let main_called = Arc::new(AtomicBool::new(false));
        let direct_called = Arc::new(AtomicBool::new(false));

        // Inject our mock clients
        resolver.main = vec![Arc::new(TestDnsClient {
            id: "main-client".to_string(),
            called: main_called.clone(),
        })];
        resolver.direct_resolver = Some(vec![Arc::new(TestDnsClient {
            id: "direct-client".to_string(),
            called: direct_called.clone(),
        })]);

        // A query for "bypass.example.com" (Type A) should go to direct_resolver because it is in fake_ip_filter.
        let mut msg = op::Message::query();
        let mut query = op::Query::new();
        let name = rr::Name::from_str_relaxed("bypass.example.com").unwrap();
        query.set_name(name);
        query.set_query_type(rr::RecordType::A);
        msg.add_query(query);

        let _res = resolver.exchange_all(&msg).await.unwrap();
        assert!(
            direct_called.load(Ordering::Relaxed),
            "direct_resolver should have been called for A query"
        );
        assert!(
            !main_called.load(Ordering::Relaxed),
            "main resolver should NOT have been called for A query"
        );

        // Reset flags
        direct_called.store(false, Ordering::Relaxed);
        main_called.store(false, Ordering::Relaxed);

        // A non-IP query (Type TXT) for "bypass.example.com" should also go to direct_resolver because of fake_ip_filter.
        let mut txt_msg = op::Message::query();
        let mut txt_query = op::Query::new();
        let txt_name = rr::Name::from_str_relaxed("bypass.example.com").unwrap();
        txt_query.set_name(txt_name);
        txt_query.set_query_type(rr::RecordType::TXT);
        txt_msg.add_query(txt_query);

        let _txt_res = resolver.exchange_all(&txt_msg).await.unwrap();
        assert!(
            direct_called.load(Ordering::Relaxed),
            "direct_resolver should have been called for TXT query"
        );
        assert!(
            !main_called.load(Ordering::Relaxed),
            "main resolver should NOT have been called for TXT query"
        );
    }
}
