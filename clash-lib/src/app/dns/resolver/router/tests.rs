use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::IpNet;

use crate::app::dns::query::{build_dns_query_wire, DnsName, QType, QueryContext};
use crate::app::dns::wire::extract_ips_from_dns_response;
use super::config::{
    RejectCode, RequestAction, RequestRule, ResponseAction, ResponseRule, RouterConfig,
};
use super::hosts::HostsSnapshot;
use super::matcher::DomainMatcher;
use super::routing::DnsRouter;

#[test]
fn test_domain_matcher() {
    let patterns = vec![
        "example.com".to_string(),
        "+.google.com".to_string(),
        "*.apple.com".to_string(),
    ];
    let matcher = DomainMatcher::new(&patterns);

    // 精确匹配
    assert!(matcher.matches("example.com"));
    assert!(matcher.matches("EXAMPLE.COM."));
    assert!(!matcher.matches("sub.example.com"));

    // + (包含自身与子域名)
    assert!(matcher.matches("google.com"));
    assert!(matcher.matches("www.google.com"));
    assert!(matcher.matches("mail.google.com."));
    assert!(!matcher.matches("notgoogle.com"));

    // * (仅子域名)
    assert!(matcher.matches("test.apple.com"));
    assert!(!matcher.matches("apple.com"));
    assert!(!matcher.matches("otherapple.com"));
}

#[test]
fn test_hosts_snapshot() {
    let mut inline_hosts = HashMap::new();
    inline_hosts.insert(
        "localhost".to_string(),
        vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ],
    );
    inline_hosts.insert(
        "myrouter.local".to_string(),
        vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
    );

    // 创建一个临时 hosts 文件
    let tmp_dir = std::env::temp_dir();
    let tmp_hosts_file = tmp_dir.join("test_clash_hosts");
    std::fs::write(
        &tmp_hosts_file,
        "# This is a comment\n1.2.3.4 custom.host\n2001:db8::1 ipv6.host\n",
    )
    .expect("write tmp hosts file");

    let snapshot = HostsSnapshot::new(
        &inline_hosts,
        &[tmp_hosts_file.to_string_lossy().to_string()],
    );

    // 测试内联 hosts
    let v4_only = snapshot.lookup("localhost", false).expect("lookup localhost v4");
    assert_eq!(v4_only.len(), 1);
    assert_eq!(v4_only[0], IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

    let v4_and_v6 = snapshot.lookup("localhost", true).expect("lookup localhost v6");
    assert_eq!(v4_and_v6.len(), 2);

    // 测试文件解析加载
    let file_v4 = snapshot.lookup("custom.host", false).expect("lookup custom.host");
    assert_eq!(file_v4[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

    let file_v6 = snapshot.lookup("ipv6.host", true).expect("lookup ipv6.host");
    assert_eq!(file_v6[0], IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap()));

    // 测试 make_response
    let name = DnsName::from_domain("localhost").unwrap();
    let q_a = build_dns_query_wire(&name, QType::A);
    let resp_a = snapshot
        .make_response(&q_a, "localhost", QType::A, true)
        .expect("make_response A");
    let ips_a = extract_ips_from_dns_response(&resp_a);
    assert_eq!(ips_a, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);

    let q_aaaa = build_dns_query_wire(&name, QType::AAAA);
    let resp_aaaa = snapshot
        .make_response(&q_aaaa, "localhost", QType::AAAA, true)
        .expect("make_response AAAA");
    let ips_aaaa = extract_ips_from_dns_response(&resp_aaaa);
    assert_eq!(ips_aaaa, vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);

    // ipv6 为 false 时，AAAA 请求返回 None
    assert!(snapshot
        .make_response(&q_aaaa, "localhost", QType::AAAA, false)
        .is_none());

    // 非 A/AAAA 请求返回 None
    assert!(snapshot
        .make_response(&q_a, "localhost", QType::TXT, true)
        .is_none());

    let _ = std::fs::remove_file(tmp_hosts_file);
}

#[test]
fn test_request_routing() {
    let mut qtypes = HashSet::new();
    qtypes.insert(QType::HTTPS);

    let rules = vec![
        // 规则 1: 阻断 HTTPS 记录
        RequestRule {
            domain: vec![],
            rule_set: vec![],
            query_type: qtypes,
            source_ip_cidr: vec![],
            action: RequestAction::Reject(RejectCode::Nodata),
            invert: false,
        },
        // 规则 2: 国内直连域名走 local
        RequestRule {
            domain: vec!["+.baidu.com".to_string()],
            rule_set: vec![],
            query_type: HashSet::new(),
            source_ip_cidr: vec![],
            action: RequestAction::Route("local-dns".to_string()),
            invert: false,
        },
        // 规则 3: 默认国外走 foreign
        RequestRule {
            domain: vec!["+.google.com".to_string()],
            rule_set: vec![],
            query_type: HashSet::new(),
            source_ip_cidr: vec![],
            action: RequestAction::Route("foreign-dns".to_string()),
            invert: false,
        },
    ];

    let cfg = RouterConfig {
        request_rules: rules,
        request_fallback: RequestAction::Route("default-dns".to_string()),
        ..Default::default()
    };
    let router = DnsRouter::new(&cfg);

    // 测试 HTTPS 规则阻断
    let act1 = router.route_request("www.baidu.com", QType::HTTPS, None);
    assert_eq!(*act1, RequestAction::Reject(RejectCode::Nodata));

    // 测试 A 记录匹配
    let act2 = router.route_request("tieba.baidu.com", QType::A, None);
    assert_eq!(*act2, RequestAction::Route("local-dns".to_string()));

    let act3 = router.route_request("youtube.google.com", QType::A, None);
    assert_eq!(*act3, RequestAction::Route("foreign-dns".to_string()));

    // 测试 Fallback
    let act4 = router.route_request("github.com", QType::A, None);
    assert_eq!(*act4, RequestAction::Route("default-dns".to_string()));
}

#[test]
fn test_response_routing_with_from_upstream() {
    let polluted_cidr = IpNet::from_str("127.0.0.0/8").unwrap();

    let response_rules = vec![
        // 仅当来自 local-dns 时，若返回 127.0.0.0/8 则认为被污染，转去 foreign-dns 重查
        ResponseRule {
            from_upstream: Some("local-dns".to_string()),
            domain: vec![],
            rule_set: vec![],
            query_type: HashSet::new(),
            ip_cidr: vec![polluted_cidr],
            action: ResponseAction::Requery("foreign-dns".to_string()),
            invert: false,
        },
    ];

    let cfg = RouterConfig {
        response_rules,
        response_fallback: ResponseAction::Accept,
        ..Default::default()
    };
    let router = DnsRouter::new(&cfg);

    let polluted_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let normal_ip = IpAddr::V4(Ipv4Addr::new(110, 242, 68, 66));

    // 1. 来自 local-dns 且 IP 命中 127.0.0.0/8 -> 触发 Requery
    let res1 = router.route_response(
        "local-dns",
        "polluted.com",
        QType::A,
        &[polluted_ip],
    );
    assert_eq!(*res1, ResponseAction::Requery("foreign-dns".to_string()));

    // 2. 来自 local-dns 但 IP 正常 -> Accept
    let res2 = router.route_response(
        "local-dns",
        "normal.com",
        QType::A,
        &[normal_ip],
    );
    assert_eq!(*res2, ResponseAction::Accept);

    // 3. 同样的 127.0.0.1 IP，但来自 foreign-dns（非 local-dns）-> from_upstream 不匹配，不会误拦截 -> Accept
    let res3 = router.route_response(
        "foreign-dns",
        "some.host",
        QType::A,
        &[polluted_ip],
    );
    assert_eq!(*res3, ResponseAction::Accept);
}

#[test]
fn test_response_routing_empty_ips_and_invert() {
    let internal_cidr = IpNet::from_str("10.0.0.0/8").unwrap();

    let response_rules = vec![
        // 配置了 invert: true（若非 10.0.0.0/8 则重查）
        ResponseRule {
            from_upstream: None,
            domain: vec![],
            rule_set: vec![],
            query_type: HashSet::new(),
            ip_cidr: vec![internal_cidr],
            action: ResponseAction::Requery("foreign-dns".to_string()),
            invert: true,
        },
    ];

    let cfg = RouterConfig {
        response_rules,
        response_fallback: ResponseAction::Accept,
        ..Default::default()
    };
    let router = DnsRouter::new(&cfg);

    // 1. 普通非 10.0.0.0/8 IP -> 命中 invert，触发 Requery
    let public_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let res1 = router.route_response("local-dns", "example.com", QType::A, &[public_ip]);
    assert_eq!(*res1, ResponseAction::Requery("foreign-dns".to_string()));

    // 2. NODATA 或非 IP 请求（answer_ips 为空）-> 不应被 invert 误判为触发 Requery，应安全放行走 fallback (Accept)
    let res2 = router.route_response("local-dns", "example.com", QType::TXT, &[]);
    assert_eq!(*res2, ResponseAction::Accept);
}

#[tokio::test]
async fn test_fakeip_transport_ttl() {
    use crate::app::dns::fakeip::{FakeDns, Opts as FakeDnsOpts};
    use crate::app::dns::resolver::router::transport::{DnsTransport, FakeIpTransport};
    use crate::app::dns::wire::extract_ips_with_ttl;
    use crate::config::def::FakeIpFilterMode;
    use std::sync::Arc;

    let fake = Arc::new(
        FakeDns::new(FakeDnsOpts {
            ipnet: "198.18.0.1/16".parse().unwrap(),
            ipnet6: "fc00::/18".parse().unwrap(),
            domain_filter: None,
            filter_mode: FakeIpFilterMode::Blacklist,
            cache_file: None,
            store: None,
        })
        .unwrap(),
    );

    let custom_ttl = 60;
    let transport = FakeIpTransport::new("fakeip".to_string(), fake, custom_ttl);

    let name = DnsName::from_domain("google.com").unwrap();
    let raw_query = build_dns_query_wire(&name, QType::A);
    let query_ctx = QueryContext::parse(&raw_query).unwrap();

    let resp = transport.exchange(&raw_query, &query_ctx).await.unwrap();
    let records = extract_ips_with_ttl(&resp.wire);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1, custom_ttl);
}

#[test]
fn test_request_routing_or_and_empty_conditions() {
    let rules = vec![
        // 规则 1: 空规则（没有任何条件）-> 不应截断流量，应跳过
        RequestRule {
            domain: vec![],
            rule_set: vec![],
            query_type: HashSet::new(),
            source_ip_cidr: vec![],
            action: RequestAction::Route("empty-dns".to_string()),
            invert: false,
        },
        // 规则 2: domain (baidu.com) 且 query_type (A)
        RequestRule {
            domain: vec!["+.baidu.com".to_string()],
            rule_set: vec![],
            query_type: [QType::A].into_iter().collect(),
            source_ip_cidr: vec![],
            action: RequestAction::Route("baidu-a-dns".to_string()),
            invert: false,
        },
    ];

    let cfg = RouterConfig {
        request_rules: rules,
        request_fallback: RequestAction::Route("fallback-dns".to_string()),
        ..Default::default()
    };
    let router = DnsRouter::new(&cfg);

    // 1. 空规则不匹配，继续走规则 2
    let act_a = router.route_request("www.baidu.com", QType::A, None);
    assert_eq!(*act_a, RequestAction::Route("baidu-a-dns".to_string()));

    // 2. 命中 domain 但未命中 QType -> 跳过规则 2，走 fallback
    let act_https = router.route_request("www.baidu.com", QType::HTTPS, None);
    assert_eq!(*act_https, RequestAction::Route("fallback-dns".to_string()));

    // 3. 完全不相关域名 -> 走 fallback
    let act_other = router.route_request("google.com", QType::A, None);
    assert_eq!(*act_other, RequestAction::Route("fallback-dns".to_string()));
}

#[test]
fn test_dns2_cache_policy_effective_ttl() {
    use crate::app::dns::resolver::router::transport::DnsCachePolicy;
    use crate::app::dns::response::build_dns_ip_response;

    let policy_default = DnsCachePolicy::default();
    assert_eq!(policy_default.optimistic_cache_ttl, 0);
    assert_eq!(policy_default.stale_cache_retention, std::time::Duration::from_secs(3600));

    let qname = DnsName::from_domain("example.com").unwrap();
    let query_wire = build_dns_query_wire(&qname, QType::A);

    // 构造一个原始 TTL 为 60 的响应
    let resp = build_dns_ip_response(&query_wire, &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))], 60).unwrap();

    // 1. 无 optimistic TTL 时保持原上游 TTL
    assert_eq!(policy_default.calculate_effective_ttl(None, &resp), 60);

    // 2. 有 override_ttl 时优先使用 override_ttl
    assert_eq!(policy_default.calculate_effective_ttl(Some(120), &resp), 120);

    // 3. 配置 optimistic_cache_ttl = 300 时提升保底
    let policy_optimistic = DnsCachePolicy::new(300, 7200);
    assert_eq!(policy_optimistic.calculate_effective_ttl(None, &resp), 300);

    // 4. override_ttl 优先于 optimistic_cache_ttl
    assert_eq!(policy_optimistic.calculate_effective_ttl(Some(10), &resp), 10);
}

#[test]
fn test_dns2_config_cache_fields_from_def() {
    use crate::config::def::Dns2Config as DefDns2Config;

    let yaml_str = r#"
enable: true
optimistic-cache-ttl: 300
stale-cache-retention: 7200
cache-capacity: 8192
"#;
    let def: DefDns2Config = serde_yaml::from_str(yaml_str).expect("deserialize Dns2Config");
    assert_eq!(def.optimistic_cache_ttl, 300);
    assert_eq!(def.stale_cache_retention, 7200);
    assert_eq!(def.cache_capacity, Some(8192));

    let cfg = RouterConfig::from_def(&def, true).expect("RouterConfig::from_def");
    assert_eq!(cfg.optimistic_cache_ttl, 300);
    assert_eq!(cfg.stale_cache_retention, 7200);
    assert_eq!(cfg.cache_capacity, 8192);
}

#[tokio::test]
async fn test_router_resolver_fresh_vs_cache_hit_notification() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use crate::app::dns::config::{DNSNetMode, NameServer};
    use crate::app::dns::query::build_dns_query_wire;
    use crate::app::dns::resolver::router::config::{UpstreamConfig, UpstreamType};
    use crate::app::dns::resolver::router::RouterResolver;
    use crate::app::dns::response::build_dns_ip_response;
    use crate::app::dns::ClashResolver;

    let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_sock.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        while let Ok((len, src)) = server_sock.recv_from(&mut buf).await {
            let req = &buf[..len];
            let resp = build_dns_ip_response(req, &["93.184.216.34".parse().unwrap()], 60).unwrap();
            let _ = server_sock.send_to(&resp, src).await;
        }
    });

    let ns = NameServer {
        net: DNSNetMode::Udp,
        host: url::Host::Ipv4(match server_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => unreachable!(),
        }),
        port: server_addr.port(),
        path: None,
        interface: None,
        proxy: None,
    };

    let mut cfg = RouterConfig::default();
    cfg.use_hosts = false;
    cfg.upstreams = vec![
        UpstreamConfig {
            tag: "mock-ns".to_string(),
            upstream_type: UpstreamType::Remote,
            servers: vec![ns],
            proxy: None,
            client_subnet: None,
            inet4_range: "198.18.0.0/16".parse().unwrap(),
            inet6_range: "::/0".parse().unwrap(),
            ttl: None,
        }
    ];
    cfg.request_fallback = RequestAction::Route("mock-ns".to_string());

    let resolver = RouterResolver::new(
        cfg,
        None,
        None,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
        None,
    ).await;

    let hook_calls = Arc::new(AtomicUsize::new(0));
    let hook_calls_clone = Arc::clone(&hook_calls);
    resolver.register_resolution_hook(Arc::new(move |_domain, _ips, _ttl| {
        hook_calls_clone.fetch_add(1, Ordering::SeqCst);
    }));

    let name = DnsName::from_domain("example.com").unwrap();
    let query_wire = build_dns_query_wire(&name, QType::A);

    // 1. 第一次请求：Cache Miss，产生真实网络查询并写入缓存 -> is_fresh = true，触发 1 次 hook
    let resp1 = resolver.exchange(&query_wire).await.unwrap();
    assert_eq!(extract_ips_from_dns_response(&resp1), vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
    assert_eq!(resolver.cached_for("93.184.216.34".parse::<IpAddr>().unwrap()), Some("example.com".to_string()));

    // 2. 第二次请求：Cache Hit -> is_fresh = false，直接从缓存出，绝不重复触发 hook！
    let resp2 = resolver.exchange(&query_wire).await.unwrap();
    assert_eq!(extract_ips_from_dns_response(&resp2), vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 1); // 仍然是 1，未重复触发！

    server_task.abort();
}

#[tokio::test]
async fn test_router_resolver_polluted_requery_prevents_dirty_cache_and_hook() {
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use crate::app::dns::config::{DNSNetMode, NameServer};
    use crate::app::dns::query::build_dns_query_wire;
    use crate::app::dns::resolver::router::config::{UpstreamConfig, UpstreamType};
    use crate::app::dns::resolver::router::RouterResolver;
    use crate::app::dns::response::build_dns_ip_response;
    use crate::app::dns::ClashResolver;

    // Local mock server：返回污染 IP 198.18.0.1
    let local_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local_sock.local_addr().unwrap();
    let local_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        while let Ok((len, src)) = local_sock.recv_from(&mut buf).await {
            let req = &buf[..len];
            let resp = build_dns_ip_response(req, &["198.18.0.1".parse().unwrap()], 60).unwrap();
            let _ = local_sock.send_to(&resp, src).await;
        }
    });

    // Remote mock server：返回合法真实 IP 93.184.216.34
    let remote_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote_sock.local_addr().unwrap();
    let remote_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        while let Ok((len, src)) = remote_sock.recv_from(&mut buf).await {
            let req = &buf[..len];
            let resp = build_dns_ip_response(req, &["93.184.216.34".parse().unwrap()], 60).unwrap();
            let _ = remote_sock.send_to(&resp, src).await;
        }
    });

    let local_ns = NameServer {
        net: DNSNetMode::Udp,
        host: url::Host::Ipv4(match local_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => unreachable!(),
        }),
        port: local_addr.port(),
        path: None,
        interface: None,
        proxy: None,
    };

    let remote_ns = NameServer {
        net: DNSNetMode::Udp,
        host: url::Host::Ipv4(match remote_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => unreachable!(),
        }),
        port: remote_addr.port(),
        path: None,
        interface: None,
        proxy: None,
    };

    let mut cfg = RouterConfig::default();
    cfg.use_hosts = false;
    cfg.upstreams = vec![
        UpstreamConfig {
            tag: "local-up".to_string(),
            upstream_type: UpstreamType::Remote,
            servers: vec![local_ns],
            proxy: None,
            client_subnet: None,
            inet4_range: "198.18.0.0/16".parse().unwrap(),
            inet6_range: "::/0".parse().unwrap(),
            ttl: None,
        },
        UpstreamConfig {
            tag: "remote-up".to_string(),
            upstream_type: UpstreamType::Remote,
            servers: vec![remote_ns],
            proxy: None,
            client_subnet: None,
            inet4_range: "198.18.0.0/16".parse().unwrap(),
            inet6_range: "::/0".parse().unwrap(),
            ttl: None,
        },
    ];
    cfg.request_fallback = RequestAction::Route("local-up".to_string());
    // Response 规则：如果来自 local-up 且命中 198.18.0.0/16 污染段，则 Requery remote-up！
    cfg.response_rules = vec![
        ResponseRule {
            from_upstream: Some("local-up".to_string()),
            domain: vec![],
            rule_set: vec![],
            query_type: HashSet::new(),
            ip_cidr: vec!["198.18.0.0/16".parse().unwrap()],
            action: ResponseAction::Requery("remote-up".to_string()),
            invert: false,
        }
    ];

    let resolver = RouterResolver::new(
        cfg,
        None,
        None,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
        None,
    ).await;

    let hooked_ips = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let hooked_ips_clone = Arc::clone(&hooked_ips);
    resolver.register_resolution_hook(Arc::new(move |_domain, ips, _ttl| {
        hooked_ips_clone.lock().extend_from_slice(ips);
    }));

    let name = DnsName::from_domain("polluted-domain.com").unwrap();
    let query_wire = build_dns_query_wire(&name, QType::A);

    let resp = resolver.exchange(&query_wire).await.unwrap();
    let final_ips = extract_ips_from_dns_response(&resp);

    // 最终返回的一定是 remote 的真实 IP
    assert_eq!(final_ips, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);

    // 污染 IP 绝对没有写入反查缓存！
    assert_eq!(resolver.cached_for("198.18.0.1".parse::<IpAddr>().unwrap()), None);
    // 合法 IP 正常反查
    assert_eq!(resolver.cached_for("93.184.216.34".parse::<IpAddr>().unwrap()), Some("polluted-domain.com".to_string()));

    // Hook 中只有真实 IP，绝没有污染 IP！
    assert_eq!(*hooked_ips.lock(), vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);

    local_task.abort();
    remote_task.abort();
}

#[tokio::test]
async fn test_router_resolver_stale_refresh_notification_with_rule_filter() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use crate::app::dns::config::{DNSNetMode, NameServer};
    use crate::app::dns::query::build_dns_query_wire;
    use crate::app::dns::resolver::router::config::{UpstreamConfig, UpstreamType};
    use crate::app::dns::resolver::router::RouterResolver;
    use crate::app::dns::response::build_dns_ip_response;
    use crate::app::dns::ClashResolver;
    use super::config::RouterConfig;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let query_count = Arc::new(AtomicUsize::new(0));
    let query_count_clone = Arc::clone(&query_count);

    let server_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let count = query_count_clone.fetch_add(1, Ordering::SeqCst);
            // 第一次返回 1.1.1.1，TTL = 1 秒；第二次（后台刷新）返回 1.1.1.2
            let ip_to_return = if count == 0 {
                "1.1.1.1".parse::<IpAddr>().unwrap()
            } else {
                "1.1.1.2".parse::<IpAddr>().unwrap()
            };
            let req = &buf[..len];
            if let Some(resp) = build_dns_ip_response(req, &[ip_to_return], 1) {
                let _ = socket.send_to(&resp, peer).await;
            }
        }
    });

    let ns = NameServer {
        net: DNSNetMode::Udp,
        host: url::Host::Ipv4(match server_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => unreachable!(),
        }),
        port: server_addr.port(),
        path: None,
        interface: None,
        proxy: None,
    };

    let mut cfg = RouterConfig::default();
    cfg.use_hosts = false;
    cfg.stale_cache_retention = 60;
    cfg.upstreams = vec![
        UpstreamConfig {
            tag: "main-up".to_string(),
            upstream_type: UpstreamType::Remote,
            servers: vec![ns],
            proxy: None,
            client_subnet: None,
            inet4_range: "198.18.0.0/16".parse().unwrap(),
            inet6_range: "::/0".parse().unwrap(),
            ttl: None,
        },
    ];
    cfg.request_fallback = RequestAction::Route("main-up".to_string());

    let resolver = RouterResolver::new(
        cfg,
        None,
        None,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
        None,
    ).await;

    let hooked_ips = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let hooked_ips_clone = Arc::clone(&hooked_ips);
    resolver.register_resolution_hook(Arc::new(move |_domain, ips, _ttl| {
        hooked_ips_clone.lock().extend_from_slice(ips);
    }));

    let name = DnsName::from_domain("stale-domain.com").unwrap();
    let query_wire = build_dns_query_wire(&name, QType::A);

    // 1. 第一次查询：命中网络，拿到 1.1.1.1
    let resp1 = resolver.exchange(&query_wire).await.unwrap();
    assert_eq!(extract_ips_from_dns_response(&resp1), vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
    assert_eq!(*hooked_ips.lock(), vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
    assert_eq!(resolver.cached_for("1.1.1.1".parse::<IpAddr>().unwrap()), Some("stale-domain.com".to_string()));

    // 2. 睡眠等待 1.1 秒，使 TTL = 1 过期并进入 Stale 状态
    tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;

    // 3. 第二次查询：前台极速命中 Stale 缓存，返回 1.1.1.1，同时后台发起异步刷新
    let resp2 = resolver.exchange(&query_wire).await.unwrap();
    assert_eq!(extract_ips_from_dns_response(&resp2), vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);

    // 4. 等待后台刷新任务完成
    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    // 5. 验证：后台刷新拉取到的 1.1.1.2 成功触发了通知，更新了反查缓存和直连 hook！
    assert_eq!(query_count.load(Ordering::SeqCst), 2);
    assert_eq!(
        *hooked_ips.lock(),
        vec![
            "1.1.1.1".parse::<IpAddr>().unwrap(),
            "1.1.1.2".parse::<IpAddr>().unwrap(),
        ]
    );
    assert_eq!(
        resolver.cached_for("1.1.1.2".parse::<IpAddr>().unwrap()),
        Some("stale-domain.com".to_string())
    );

    server_task.abort();
}

