use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::Arc,
    time::Instant,
};

use crate::{
    app::{
        dns::{
            ClashResolver, Config, EnhancedResolver, ThreadSafeDNSClient,
            config::NameServer,
            dns_client::{DNSNetMode, DnsClient, Opts},
        },
        profile::ThreadSafeCacheFile,
        remote_content_manager::providers::rule_provider::{
            RuleProviderImpl, RuleSetBehavior, RuleSetFormat, ThreadSafeRuleProvider,
        },
    },
    proxy,
};
use hickory_net::{DnsHandle, client, udp::UdpClientStream, xfer::FirstAnswer};
use hickory_proto::{
    op::{self, DnsRequest, DnsRequestOptions},
    rr,
};
use tempfile::tempdir;

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
        crate::app::dns::runtime::DnsRuntimeProvider::new_direct(None, None),
    )
    .build();
    let (client, bg) = client::Client::<crate::app::dns::runtime::DnsRuntimeProvider>::from_sender(stream);
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
            Arc::new(SocksHandler::new(
                SocksHandlerOptions {
                    name: name.to_string(),
                    common_opts: HandlerCommonOptions::default(),
                    server: server.to_string(),
                    port: 1080,
                    user: None,
                    password: None,
                    udp: false,
                    tls_client: None,
                },
                None,
            ));
        map.insert(name.to_string(), h);
    }
    Arc::new(parking_lot::RwLock::new(map))
}

fn make_proxy_nameserver_config() -> (Config, NameServer) {
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
    config.enhance_mode = crate::config::def::DNSMode::Normal;
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
    let temp_dir = tempdir().unwrap();
    let cache_store = ThreadSafeCacheFile::new(
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
#[ignore = "requires public network"]
async fn test_proxy_server_domain_resolved_via_proxy_nameserver() {
    let temp_dir = tempdir().unwrap();
    let cache_store = ThreadSafeCacheFile::new(
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
    let temp_dir = tempdir().unwrap();
    let cache_store = ThreadSafeCacheFile::new(
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


