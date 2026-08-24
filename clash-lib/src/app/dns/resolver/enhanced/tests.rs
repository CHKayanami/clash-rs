use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::app::dns::{ClashResolver, EnhancedResolver};
use crate::app::dns::resolver::enhanced::EnhancedResolverInner;
use crate::app::dns::singleflight::Singleflight;
use crate::app::dns::upstream_pool::UpstreamPool;

impl EnhancedResolver {
    pub async fn new_default() -> Self {
        Self {
            inner: Arc::new(EnhancedResolverInner {
                ipv6: AtomicBool::new(false),
                hosts: None,
                pool: UpstreamPool::new(
                    std::collections::HashMap::new(),
                    Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
                    None,
                    None,
                    None,
                    None,
                ),
                main_upstreams: vec![],
                fallback_upstreams: None,
                fallback_filter: None,
                lru_cache: None,
                policy: None,
                proxy_upstreams: None,
                proxy_server_domains: None,
                fake_dns: None,
                fake_ip_ttl: 1,
                reverse_lookup_cache: None,
                black_domain_filter: None,
                collector: None,
                singleflight: Singleflight::new(),
                optimistic_cache_ttl: 0,
                stale_cache_retention: Duration::from_secs(3600),
                fixed_domain_ttl: None,
                resolution_hook: OnceLock::new(),
            }),
        }
    }
}

/// IPv6 literal addresses must be returned directly even when dns.ipv6 is disabled.
#[tokio::test]
async fn test_resolve_ipv6_literal_when_ipv6_disabled() {
    let resolver = EnhancedResolver::new_default().await;
    resolver.set_ipv6(false);
    assert!(!resolver.ipv6(), "ipv6 should be disabled");

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

#[tokio::test]
async fn test_dns_resolution_hook_triggered() {
    use std::sync::Mutex;
    use crate::app::dns::ClashResolver;
    use crate::app::dns::query::{DnsName, QType};
    use crate::app::dns::response::build_dns_ip_response;

    let resolver = EnhancedResolver::new_default().await;
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let recorded_clone = recorded.clone();

    resolver.register_resolution_hook(Arc::new(move |domain, ips, ttl| {
        recorded_clone.lock().unwrap().push((domain.to_string(), ips.to_vec(), ttl));
    }));

    let name = DnsName::from_domain("hook-test.com").unwrap();
    let query_wire = crate::app::dns::query::build_dns_query_wire_with_id(0x1234, &name, QType::A);

    // Build mock response and test hook
    if let Some(hook) = resolver.resolution_hook.get() {
        let resp = build_dns_ip_response(&query_wire, &["93.184.216.34".parse().unwrap()], 120).unwrap();
        let ips = crate::app::dns::wire::extract_ips_from_dns_response(&resp);
        hook("hook-test.com", &ips, Duration::from_secs(120));
    }

    let records = recorded.lock().unwrap().clone();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0, "hook-test.com");
    assert_eq!(records[0].1, vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]);
    assert_eq!(records[0].2, Duration::from_secs(120));
}

#[tokio::test]
async fn test_dns_resolution_hook_end_to_end_on_exchange() {
    use std::sync::Mutex;
    use tokio::net::UdpSocket;
    use crate::app::dns::config::{DNSNetMode, NameServer};
    use crate::app::dns::query::{DnsName, QType, build_dns_query_wire_with_id};
    use crate::app::dns::response::build_dns_ip_response;
    use crate::app::dns::resolver::enhanced::cache::DnsCache;
    use crate::app::dns::upstream_pool::UpstreamEntry;

    let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_sock.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        if let Ok((len, src)) = server_sock.recv_from(&mut buf).await {
            let req = &buf[..len];
            let resp = build_dns_ip_response(req, &["93.184.216.34".parse().unwrap()], 120).unwrap();
            let _ = server_sock.send_to(&resp, src).await;
        }
    });

    let ns = NameServer {
        net: DNSNetMode::Udp,
        host: url::Host::Ipv4(match server_addr.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => unreachable!(),
        }),
        port: server_addr.port(),
        path: None,
        interface: None,
        proxy: None,
    };
    let entry = UpstreamEntry::from_nameserver(&ns, None).unwrap();
    let ns_key = ns.to_string();
    let mut entries = std::collections::HashMap::new();
    entries.insert(ns_key.clone(), entry);

    let pool = UpstreamPool::new(
        entries,
        Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
        None,
        None,
        None,
        None,
    );

    let resolver = EnhancedResolver {
        inner: Arc::new(EnhancedResolverInner {
            ipv6: AtomicBool::new(false),
            hosts: None,
            pool,
            main_upstreams: vec![ns_key],
            fallback_upstreams: None,
            fallback_filter: None,
            lru_cache: Some(DnsCache::new(100)),
            policy: None,
            proxy_upstreams: None,
            proxy_server_domains: None,
            fake_dns: None,
            fake_ip_ttl: 1,
            reverse_lookup_cache: None,
            black_domain_filter: None,
            collector: None,
            singleflight: Singleflight::new(),
            optimistic_cache_ttl: 0,
            stale_cache_retention: Duration::from_secs(3600),
            fixed_domain_ttl: None,
            resolution_hook: OnceLock::new(),
        }),
    };

    let recorded = Arc::new(Mutex::new(Vec::new()));
    let recorded_clone = recorded.clone();
    resolver.register_resolution_hook(Arc::new(move |domain, ips, ttl| {
        recorded_clone.lock().unwrap().push((domain.to_string(), ips.to_vec(), ttl));
    }));

    let name = DnsName::from_domain("hook-e2e.com").unwrap();
    let query_wire = build_dns_query_wire_with_id(0x5678, &name, QType::A);

    let resp = resolver.exchange(&query_wire).await.expect("query exchange should succeed");
    let ips = crate::app::dns::wire::extract_ips_from_dns_response(&resp);
    assert_eq!(ips, vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]);

    let _ = server_task.await;

    let records = recorded.lock().unwrap().clone();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0, "hook-e2e.com");
    assert_eq!(records[0].1, vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]);
    assert_eq!(records[0].2, Duration::from_secs(120));
}

#[tokio::test]
async fn test_fake_ip_exchange() {
    use crate::app::dns::fakeip::{FakeDns, InMemStore, Opts};
    use crate::app::dns::query::{DnsName, QType, build_dns_query_wire_with_id};
    use crate::config::def::FakeIpFilterMode;

    let fake_dns = Arc::new(
        FakeDns::new(Opts {
            ipnet: "198.18.0.1/16".parse().unwrap(),
            ipnet6: "fc00::/18".parse().unwrap(),
            domain_filter: None,
            filter_mode: FakeIpFilterMode::Blacklist,
            store: Box::new(InMemStore::new(1000)),
        })
        .unwrap(),
    );

    let resolver = EnhancedResolver {
        inner: Arc::new(EnhancedResolverInner {
            ipv6: AtomicBool::new(false),
            hosts: None,
            pool: UpstreamPool::new(
                std::collections::HashMap::new(),
                Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
                None,
                None,
                None,
                None,
            ),
            main_upstreams: vec![],
            fallback_upstreams: None,
            fallback_filter: None,
            lru_cache: None,
            policy: None,
            proxy_upstreams: None,
            proxy_server_domains: None,
            fake_dns: Some(fake_dns),
            fake_ip_ttl: 1,
            reverse_lookup_cache: None,
            black_domain_filter: None,
            collector: None,
            singleflight: Singleflight::new(),
            optimistic_cache_ttl: 0,
            stale_cache_retention: Duration::from_secs(3600),
            fixed_domain_ttl: None,
            resolution_hook: OnceLock::new(),
        }),
    };

    let name = DnsName::from_domain("example.com").unwrap();
    let query_wire = build_dns_query_wire_with_id(0x1122, &name, QType::A);

    let resp = resolver.exchange(&query_wire).await.expect("fake ip exchange should succeed");
    let ips = crate::app::dns::wire::extract_ips_from_dns_response(&resp);
    assert_eq!(ips.len(), 1);
    assert!(resolver.is_fake_ip(ips[0]));
}

#[tokio::test]
async fn test_udp_pool_outbound_resolution() {
    use crate::app::dns::config::{DNSNetMode, NameServer};
    use crate::app::dns::upstream_pool::UpstreamEntry;

    let ns = NameServer {
        host: url::Host::Ipv4("1.1.1.1".parse().unwrap()),
        port: 53,
        path: None,
        net: DNSNetMode::Udp,
        interface: None,
        proxy: Some("test_proxy".to_string()),
    };

    let entry = UpstreamEntry::from_nameserver(&ns, None).unwrap();
    let pool = UpstreamPool::new(
        std::collections::HashMap::new(),
        Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
        None,
        None,
        None,
        None,
    );

    // When outbound is not found in registry, it falls back to direct
    let addr = "1.1.1.1:53".parse().unwrap();
    let res = pool.udp_pool(&entry, addr, None).await;
    assert!(res.is_ok(), "udp_pool direct fallback should succeed");
}

#[tokio::test]
async fn test_respect_rules_upstream_routing() {
    use crate::app::dns::config::{DNSNetMode, NameServer};
    use crate::app::dns::upstream_pool::UpstreamEntry;
    use crate::app::dns::RuleDispatch;

    let ns = NameServer {
        host: url::Host::Ipv4("8.8.8.8".parse().unwrap()),
        port: 53,
        path: None,
        net: DNSNetMode::Udp,
        interface: None,
        proxy: None,
    };

    let entry = UpstreamEntry::from_nameserver(&ns, None).unwrap();
    let rd = RuleDispatch::new();

    let pool = UpstreamPool::new(
        std::collections::HashMap::new(),
        Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
        None,
        None,
        None,
        Some(rd),
    );

    // Before router & outbound_manager are populated in OnceLock, falls back gracefully to direct
    let addr = "8.8.8.8:53".parse().unwrap();
    let res = pool.udp_pool(&entry, addr, None).await;
    assert!(res.is_ok(), "udp_pool with uninitialized RuleDispatch should fallback to direct");
}

#[test]
fn test_custom_doh_path_parsing() {
    use crate::app::dns::config::Config;
    use crate::app::dns::upstream_pool::UpstreamEntry;

    let servers = vec![
        "https://dns.nextdns.io/abcdef".to_string(),
        "h3://dns.adguard-dns.com/dns-query".to_string(),
    ];
    let nss = Config::parse_nameserver(&servers).unwrap();
    assert_eq!(nss[0].path.as_deref(), Some("/abcdef"));
    assert_eq!(nss[1].path.as_deref(), Some("/dns-query"));

    let entry0 = UpstreamEntry::from_nameserver(&nss[0], None).unwrap();
    assert_eq!(entry0.endpoint.path, "/abcdef");

    let entry1 = UpstreamEntry::from_nameserver(&nss[1], None).unwrap();
    assert_eq!(entry1.endpoint.path, "/dns-query");
}

#[tokio::test]
async fn test_optimistic_cache_ttl_and_never_cache() {
    use crate::app::dns::config::Config;
    use crate::app::dns::resolver::enhanced::EnhancedResolver;
    use crate::app::profile::ThreadSafeCacheFile;
    use std::collections::HashMap;

    let mut fixed_ttl = HashMap::new();
    fixed_ttl.insert("never-cache.com".to_string(), 0);

    let cfg = Config {
        enable: true,
        nameserver: Config::parse_nameserver(&["114.114.114.114".to_string()]).unwrap(),
        default_nameserver: Config::parse_nameserver(&["114.114.114.114".to_string()]).unwrap(),
        optimistic_cache_ttl: 300,
        fixed_domain_ttl: fixed_ttl,
        stale_cache_retention: 7200,
        ..Default::default()
    };

    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("cache.db");
    let store = ThreadSafeCacheFile::new(cache_path.to_str().unwrap(), true);
    let resolver = EnhancedResolver::new(
        cfg,
        store,
        None,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
        None,
        None,
    )
    .await;

    assert_eq!(resolver.optimistic_cache_ttl, 300);
    assert_eq!(resolver.stale_cache_retention, Duration::from_secs(7200));

    // fixed_domain_ttl == Some(0) returns 0 for never-cache.com
    assert_eq!(resolver.match_fixed_domain_ttl("never-cache.com"), Some(0));
}

#[tokio::test]
async fn test_reverse_lookup_cache_integration_and_conflict() {
    use crate::app::dns::config::Config;
    use crate::app::dns::query::{build_dns_query_wire_with_id, DnsName, QType, QueryContext};
    use crate::app::dns::response::build_dns_ip_response;
    use crate::app::profile::ThreadSafeCacheFile;
    use crate::config::def::DNSMode;
    use std::collections::HashMap;

    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("cache.db");
    let store = ThreadSafeCacheFile::new(cache_path.to_str().unwrap(), true);

    let cfg = Config {
        enable: true,
        enhance_mode: DNSMode::FakeIp,
        nameserver: Config::parse_nameserver(&["114.114.114.114".to_string()]).unwrap(),
        default_nameserver: Config::parse_nameserver(&["114.114.114.114".to_string()]).unwrap(),
        ..Default::default()
    };

    let resolver = EnhancedResolver::new(
        cfg,
        store,
        None,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
        None,
        None,
    )
    .await;

    // 1. Process fresh real DNS response for domain-a.com -> 1.2.3.4 (TTL 120)
    let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
    let name_a = DnsName::from_domain("domain-a.com").unwrap();
    let query_wire_a = build_dns_query_wire_with_id(0x1234, &name_a, QType::A);
    let resp_a = build_dns_ip_response(&query_wire_a, &[ip], 120).unwrap();
    let query_a = QueryContext::parse(&query_wire_a).unwrap();

    resolver.process_fresh_response(&query_a, "domain-a.com", &resp_a, None).await;

    // Reverse lookup in Fake-IP mode for non-fake IP should hit reverse cache
    assert_eq!(resolver.reverse_lookup(ip), Some("domain-a.com".to_string()));

    // 2. Now process another real DNS response for domain-b.com -> 1.2.3.4 (same IP, different domain)
    let name_b = DnsName::from_domain("domain-b.com").unwrap();
    let query_wire_b = build_dns_query_wire_with_id(0x5678, &name_b, QType::A);
    let resp_b = build_dns_ip_response(&query_wire_b, &[ip], 120).unwrap();
    let query_b = QueryContext::parse(&query_wire_b).unwrap();

    resolver.process_fresh_response(&query_b, "domain-b.com", &resp_b, None).await;

    // Since domain-b.com and domain-a.com share 1.2.3.4, it should be marked as ambiguous -> None
    assert_eq!(resolver.reverse_lookup(ip), None);
}



