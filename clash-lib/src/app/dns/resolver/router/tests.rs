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
    let records = extract_ips_with_ttl(&resp);
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

