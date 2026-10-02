use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::RouterResolver;
use super::config::{
    RejectCode, RequestAction, RequestRule, ResponseAction, ResponseRule,
    RouterConfig, UpstreamConfig, UpstreamType,
};
use crate::app::dns::ClashResolver;
use crate::app::dns::config::{DNSNetMode, NameServer};
use crate::app::dns::query::{DnsName, QType, QueryContext, build_dns_query_wire};
use crate::app::dns::response::{
    ResponseTemplate, build_dns_ip_response, build_dns_nxdomain,
};
use crate::app::dns::wire::{extract_ips_from_dns_response, skip_dns_name};
use crate::config::def::{Dns2Config, Dns2StringOrList, Dns2UpstreamDef};
use crate::proxy::socks::outbound::{Handler, HandlerOptions};
use crate::proxy::utils::OutboundHandlerRegistry;

struct TestServer {
    ns: NameServer,
    requests: mpsc::UnboundedReceiver<()>,
    task: JoinHandle<()>,
}

#[tokio::test]
async fn configured_client_subnet_reaches_upstream_without_crossing_scopes() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = format!("udp://{}", socket.local_addr().unwrap());
    let (tx, mut requests) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        for _ in 0..4 {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = &buf[..len];
            let mut end = 12;
            assert!(skip_dns_name(request, &mut end));
            end += 4;
            let opt = &request[end..];
            tx.send(opt.to_vec()).unwrap();
            let ip: IpAddr = if request[end - 4..end - 2] == 28u16.to_be_bytes() {
                "2001:db8::1".parse().unwrap()
            } else {
                "192.0.2.1".parse().unwrap()
            };
            let mut response = build_dns_ip_response(request, &[ip], 60).unwrap();
            // Echo ECS so the resolver must validate and strip the injected OPT.
            response[10..12].copy_from_slice(&u16::from(!opt.is_empty()).to_be_bytes());
            response.extend_from_slice(opt);
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    let mut def = Dns2Config::default();
    def.ipv6 = true;
    for (tag, subnet) in [("v4", Some("192.0.2.129/25")),
        ("v6", Some("2001:db8:abcd:ffff::/57")), ("plain", None)] {
        def.upstreams.push(Dns2UpstreamDef {
            tag: tag.into(), r#type: "remote".into(),
            servers: Some(Dns2StringOrList::Single(server.clone())),
            client_subnet: subnet.map(str::to_string), ..Default::default()
        });
    }
    let mut cfg = RouterConfig::from_def(&def, true).unwrap();
    cfg.request_fallback = RequestAction::Route("v4".into());
    for tag in ["v6", "plain"] {
        cfg.request_rules.push(RequestRule {
            domain: vec![format!("{tag}.test")], rule_set: vec![],
            query_type: HashSet::new(), source_ip_cidr: vec![],
            action: RequestAction::Route(tag.into()), invert: false,
        });
    }
    let resolver = resolver(cfg).await;
    for (domain, qtype, expected) in [
        ("v4.test", QType::A, vec![0, 1, 25, 0, 192, 0, 2, 128]),
        ("v6.test", QType::A, vec![0, 2, 57, 0, 0x20, 1, 0x0d, 0xb8, 0xab, 0xcd, 0xff, 0x80]),
        ("v6.test", QType::AAAA, vec![0, 2, 57, 0, 0x20, 1, 0x0d, 0xb8, 0xab, 0xcd, 0xff, 0x80]),
        ("plain.test", QType::A, vec![]),
    ] {
        let query = build_dns_query_wire(&DnsName::from_domain(domain).unwrap(), qtype);
        let response = resolver.exchange(&query).await.unwrap();
        assert_eq!(&response[10..12], &[0, 0]);
        let opt = tokio::time::timeout(Duration::from_secs(2), requests.recv())
            .await.unwrap().unwrap();
        if expected.is_empty() {
            assert!(opt.is_empty());
        } else {
            assert_eq!(&opt[11..13], &8u16.to_be_bytes());
            assert_eq!(&opt[15..], expected.as_slice());
        }
    }
    task.await.unwrap();
}

impl TestServer {
    async fn new(ips: Vec<IpAddr>) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let (tx, requests) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut buf = [0; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let query = QueryContext::parse(&buf[..len]).unwrap();
                let matching: Vec<_> = ips.iter().copied().filter(|ip| {
                    match query.qtype() {
                        Some(QType::A) => ip.is_ipv4(),
                        Some(QType::AAAA) => ip.is_ipv6(),
                        _ => false,
                    }
                }).collect();
                let response = if matching.is_empty() {
                    build_dns_nxdomain(&buf[..len])
                } else {
                    build_dns_ip_response(&buf[..len], &matching, 60).unwrap()
                };
                socket.send_to(&response, peer).await.unwrap();
                let _ = tx.send(());
            }
        });
        Self {
            ns: NameServer {
                net: DNSNetMode::Udp,
                host: url::Host::Ipv4("127.0.0.1".parse().unwrap()),
                port: addr.port(),
                path: None,
                interface: None,
                proxy: None,
            },
            requests,
            task,
        }
    }

    async fn received(&mut self) {
        tokio::time::timeout(Duration::from_secs(2), self.requests.recv())
            .await.unwrap().unwrap();
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn upstream(tag: &str, ns: Option<NameServer>) -> UpstreamConfig {
    UpstreamConfig {
        tag: tag.to_string(),
        upstream_type: if ns.is_some() { UpstreamType::Remote } else { UpstreamType::FakeIp },
        servers: ns.into_iter().collect(),
        proxy: None,
        client_subnet: None,
        inet4_range: "198.18.0.0/16".parse().unwrap(),
        inet6_range: "fc00::/64".parse().unwrap(),
        ttl: None,
    }
}

fn response_rule(from: &str, action: ResponseAction) -> ResponseRule {
    ResponseRule {
        from_upstream: Some(from.to_string()),
        domain: vec![],
        rule_set: vec![],
        query_type: HashSet::new(),
        ip_cidr: vec![],
        action,
        invert: false,
    }
}

async fn resolver(cfg: RouterConfig) -> RouterResolver {
    RouterResolver::new(cfg, None, None, Arc::new(RwLock::new(HashMap::new())), None).await.unwrap()
}

fn query(qtype: QType) -> Vec<u8> {
    build_dns_query_wire(&DnsName::from_domain("example.test").unwrap(), qtype)
}

#[tokio::test]
async fn real_resolution_bypasses_fakeip_for_both_families() {
    let server = TestServer::new(vec![
        "192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap(),
    ]).await;
    for bootstrap_only in [false, true] {
        let mut cfg = RouterConfig::default();
        cfg.upstreams.push(upstream("fake", None));
        if bootstrap_only {
            cfg.default_nameserver.push(server.ns.clone());
        } else {
            cfg.upstreams.push(upstream("real", Some(server.ns.clone())));
        }
        cfg.request_fallback = RequestAction::Route("fake".into());
        let resolver = resolver(cfg).await;
        assert_eq!(resolver.resolve_v4("example.test", false).await.unwrap(), Some("192.0.2.1".parse().unwrap()));
        assert_eq!(resolver.resolve_v6("example.test", false).await.unwrap(), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(resolver.resolve("example.test", false).await.unwrap(), Some("192.0.2.1".parse().unwrap()));
        let fake_ip = resolver.resolve("example.test", true).await.unwrap().unwrap();
        assert!(resolver.is_fake_ip(fake_ip));
        let wire = resolver.exchange(&query(QType::A)).await.unwrap();
        assert!(resolver.is_fake_ip(extract_ips_from_dns_response(&wire)[0]));
    }
}

#[tokio::test]
async fn independent_proxy_nameserver_resolves_node_domain() {
    let mut server = TestServer::new(vec!["192.0.2.2".parse().unwrap()]).await;
    let mut cfg = RouterConfig::default();
    cfg.proxy_server_nameserver.push(server.ns.clone());
    // No remote upstream contains this nameserver; fallback rejects everything.
    let outbounds: OutboundHandlerRegistry = Arc::new(RwLock::new(HashMap::new()));
    outbounds.write().insert("node".into(), Arc::new(Handler::new(HandlerOptions {
        name: "node".into(), server: "example.test".into(), port: 1080,
        ..Default::default()
    }, None)));
    let resolver = RouterResolver::new(cfg, None, None, outbounds, None).await.unwrap();
    assert_eq!(resolver.resolve("example.test", false).await.unwrap(), Some("192.0.2.2".parse().unwrap()));
    server.received().await;
}

#[tokio::test]
async fn source_ip_selects_request_rule() {
    let mut cfg = RouterConfig::default();
    cfg.request_rules.push(RequestRule {
        domain: vec![], rule_set: vec![], query_type: HashSet::new(),
        source_ip_cidr: vec!["192.0.2.0/24".parse().unwrap()],
        action: RequestAction::Reject(RejectCode::Refused), invert: false,
    });
    cfg.request_fallback = RequestAction::Reject(RejectCode::Nxdomain);
    let resolver = resolver(cfg).await;
    let query = query(QType::A);
    for (source, code) in [(Some("192.0.2.1".parse().unwrap()), 5), (Some("198.51.100.1".parse().unwrap()), 3), (None, 3)] {
        let wire = resolver.exchange_from(&query, source).await.unwrap();
        assert_eq!(wire[3] & 0xf, code);
    }
}

#[tokio::test]
async fn responses_without_ips_obey_response_rules_and_fallback() {
    let server = TestServer::new(vec![]).await;
    let replacement = TestServer::new(vec!["192.0.2.3".parse().unwrap()]).await;
    for qtype in [QType::A, QType::TXT, QType::MX] {
        for use_rule in [false, true] {
            let mut cfg = RouterConfig::default();
            cfg.upstreams.push(upstream("empty", Some(server.ns.clone())));
            cfg.request_fallback = RequestAction::Route("empty".into());
            if use_rule {
                let mut rule = response_rule("empty", ResponseAction::Reject);
                rule.query_type.insert(qtype);
                rule.domain.push("example.test".into());
                cfg.response_rules.push(rule);
            } else {
                cfg.response_fallback = ResponseAction::Reject;
            }
            let resolver = resolver(cfg).await;
            let wire = resolver.exchange(&query(qtype)).await.unwrap();
            assert_eq!(wire[3] & 0xf, 0); // Reject produces NODATA, not upstream NXDOMAIN.
        }
    }
    let mut cfg = RouterConfig::default();
    cfg.upstreams = vec![upstream("empty", Some(server.ns.clone())), upstream("real", Some(replacement.ns.clone()))];
    cfg.request_fallback = RequestAction::Route("empty".into());
    cfg.response_rules.push(response_rule("empty", ResponseAction::Requery("real".into())));
    let resolver = resolver(cfg).await;
    assert_eq!(extract_ips_from_dns_response(&resolver.exchange(&query(QType::A)).await.unwrap()), vec!["192.0.2.3".parse::<IpAddr>().unwrap()]);
}

#[tokio::test]
async fn requery_schedules_stale_target_refresh() {
    let initial = TestServer::new(vec!["198.51.100.1".parse().unwrap()]).await;
    let mut replacement = TestServer::new(vec!["192.0.2.4".parse().unwrap()]).await;
    let mut cfg = RouterConfig::default();
    cfg.upstreams = vec![upstream("initial", Some(initial.ns.clone())), upstream("replacement", Some(replacement.ns.clone()))];
    cfg.request_fallback = RequestAction::Route("initial".into());
    cfg.response_rules.push(response_rule("initial", ResponseAction::Requery("replacement".into())));
    let resolver = resolver(cfg).await;
    let wire = query(QType::A);
    let context = QueryContext::parse(&wire).unwrap();
    let old = build_dns_ip_response(&wire, &["192.0.2.5".parse().unwrap()], 1).unwrap();
    resolver.cache.insert_scoped(&Arc::from("replacement"), &context,
        Arc::new(ResponseTemplate::validate(&context, &old).unwrap()), 1, Duration::from_secs(60));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let response = resolver.exchange(&wire).await.unwrap();
    assert_eq!(extract_ips_from_dns_response(&response), vec!["192.0.2.5".parse::<IpAddr>().unwrap()]);
    replacement.received().await;
    // Wait for response processing, then confirm subsequent requery uses refreshed data.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let response = resolver.exchange(&wire).await.unwrap();
            if extract_ips_from_dns_response(&response) == vec!["192.0.2.4".parse::<IpAddr>().unwrap()] { break; }
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    assert_eq!(resolver.cached_for("192.0.2.4".parse().unwrap()).as_deref(), Some("example.test"));
}

#[tokio::test]
async fn real_requery_to_fakeip_keeps_current_real_result_and_notification() {
    let server = TestServer::new(vec!["192.0.2.6".parse().unwrap()]).await;
    let mut cfg = RouterConfig::default();
    cfg.upstreams = vec![upstream("real", Some(server.ns.clone())), upstream("fake", None)];
    cfg.request_fallback = RequestAction::Route("real".into());
    cfg.response_rules.push(response_rule("real", ResponseAction::Requery("fake".into())));
    let resolver = resolver(cfg).await;
    assert_eq!(resolver.resolve("example.test", false).await.unwrap(), Some("192.0.2.6".parse().unwrap()));
    assert_eq!(resolver.cached_for("192.0.2.6".parse().unwrap()).as_deref(), Some("example.test"));
}

#[tokio::test]
async fn real_resolution_preserves_reject_and_errors_without_real_upstream() {
    let mut cfg = RouterConfig::default();
    cfg.upstreams.push(upstream("fake", None));
    cfg.request_fallback = RequestAction::Route("fake".into());
    let fake_only = resolver(cfg.clone()).await;
    assert!(fake_only.resolve("example.test", false).await.is_err());
    cfg.request_fallback = RequestAction::Reject(RejectCode::Nodata);
    let rejected = resolver(cfg).await;
    assert_eq!(rejected.resolve("example.test", false).await.unwrap(), None);
}

#[test]
fn configuration_rejects_multiple_fakeip_and_small_ranges() {
    use crate::config::def::{Dns2Config, Dns2UpstreamDef};
    let fake = Dns2UpstreamDef {
        tag: "first".into(), r#type: "fakeip".into(), ..Default::default()
    };
    let mut def = Dns2Config::default();
    def.upstreams = vec![fake.clone(), Dns2UpstreamDef {
        tag: "second".into(), ..fake.clone()
    }];
    let error = RouterConfig::from_def(&def, true).unwrap_err().to_string();
    assert!(error.contains("only one fakeip"));
    assert!(error.contains("first") && error.contains("second"));
    for (v4, v6, field) in [
        ("198.18.0.1/32", "fc00::/64", "inet4-range"),
        ("198.18.0.0/16", "fc00::1/128", "inet6-range"),
    ] {
        def.upstreams = vec![Dns2UpstreamDef {
            inet4_range: v4.into(), inet6_range: v6.into(), ..fake.clone()
        }];
        let error = RouterConfig::from_def(&def, true).unwrap_err().to_string();
        assert!(error.contains("first") && error.contains(field));
    }
    def.upstreams = vec![fake];
    def.stale_cache_retention = 0;
    assert_eq!(RouterConfig::from_def(&def, true).unwrap().stale_cache_retention, 0);
}

#[tokio::test]
async fn constructor_returns_error_for_invalid_fakeip_configuration() {
    let mut cfg = RouterConfig::default();
    cfg.upstreams = vec![upstream("first", None), upstream("second", None)];
    assert!(RouterResolver::new(cfg.clone(), None, None,
        Arc::new(RwLock::new(HashMap::new())), None).await.is_err());
    cfg.upstreams.pop();
    cfg.upstreams[0].inet4_range = "198.18.0.1/32".parse().unwrap();
    assert!(RouterResolver::new(cfg, None, None,
        Arc::new(RwLock::new(HashMap::new())), None).await.is_err());
}

#[tokio::test]
async fn stale_response_ttl_is_sixty_even_with_override() {
    use super::transport::DnsTransport;
    use crate::app::dns::wire::extract_min_ttl_from_dns_response;
    let server = TestServer::new(vec!["192.0.2.10".parse().unwrap()]).await;
    for override_ttl in [None, Some(300)] {
        let mut cfg = RouterConfig::default();
        let mut real = upstream("real", Some(server.ns.clone()));
        real.ttl = override_ttl;
        cfg.upstreams.push(real);
        let resolver = resolver(cfg).await;
        let wire = query(QType::A);
        let context = QueryContext::parse(&wire).unwrap();
        let old = build_dns_ip_response(&wire, &["192.0.2.11".parse().unwrap()], 1).unwrap();
        resolver.cache.insert_scoped(&Arc::from("real"), &context,
            Arc::new(ResponseTemplate::validate(&context, &old).unwrap()), 1, Duration::from_secs(60));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let result = resolver.transports["real"].exchange(&wire, &context).await.unwrap();
        assert!(!result.is_fresh && result.refresh_ticket.is_some());
        assert_eq!(extract_min_ttl_from_dns_response(&result.wire), Some(60));
    }
}

#[tokio::test]
async fn fresh_cache_hit_uses_remaining_ttl_even_with_override() {
    use super::transport::DnsTransport;
    use crate::app::dns::wire::extract_min_ttl_from_dns_response;
    let server = TestServer::new(vec!["192.0.2.10".parse().unwrap()]).await;
    let mut cfg = RouterConfig::default();
    let mut real = upstream("real", Some(server.ns.clone()));
    real.ttl = Some(300);
    cfg.upstreams.push(real);
    let resolver = resolver(cfg).await;
    let wire = query(QType::A);
    let context = QueryContext::parse(&wire).unwrap();
    let old = build_dns_ip_response(&wire, &["192.0.2.11".parse().unwrap()], 60).unwrap();
    resolver.cache.insert_scoped(&Arc::from("real"), &context,
        Arc::new(ResponseTemplate::validate(&context, &old).unwrap()), 60, Duration::from_secs(60));
    let result = resolver.transports["real"].exchange(&wire, &context).await.unwrap();
    assert!(!result.is_fresh);
    assert!(extract_min_ttl_from_dns_response(&result.wire).unwrap() <= 60);
}

#[tokio::test]
async fn grouped_cache_report_keeps_counts_and_caps_every_scope() {
    let mut cfg = RouterConfig::default();
    cfg.upstreams.push(upstream("configured", Some(TestServer::new(vec![]).await.ns.clone())));
    let resolver = resolver(cfg).await;
    for scope in ["configured", "__extra"] {
        for index in 0..55 {
            let wire = build_dns_query_wire(
                &DnsName::from_domain(&format!("{index}.example.test")).unwrap(), QType::A,
            );
            let context = QueryContext::parse(&wire).unwrap();
            let response = build_dns_ip_response(&wire, &["192.0.2.1".parse().unwrap()], 60).unwrap();
            resolver.cache.insert_scoped(&Arc::from(scope), &context,
                Arc::new(ResponseTemplate::validate(&context, &response).unwrap()), 60, Duration::ZERO);
        }
    }
    let report = resolver.search_cache("*");
    assert_eq!(report.total, 110);
    assert_eq!(report.upstreams.len(), 2);
    for scope in report.upstreams {
        assert_eq!(scope.count, 55);
        assert_eq!(scope.items.len(), 50);
    }
    assert_eq!(resolver.search_cache("7.example.test").total, 2);
    assert_eq!(resolver.search_cache("missing.test").total, 0);
}

#[tokio::test]
async fn internal_queries_reuse_cached_addresses_for_both_families() {
    let mut server = TestServer::new(vec!["192.0.2.1".parse().unwrap(),
        "2001:db8::1".parse().unwrap()]).await;
    let mut cfg = RouterConfig::default();
    cfg.ipv6 = true;
    cfg.use_hosts = false;
    cfg.upstreams = vec![upstream("remote", Some(server.ns.clone()))];
    cfg.request_fallback = RequestAction::Route("remote".into());
    let resolver = resolver(cfg).await;
    for qtype in [QType::A, QType::AAAA] {
        let wire = query(qtype);
        let fresh = resolver.exchange_query(&wire, None, true).await.unwrap();
        server.received().await;
        let cached = resolver.exchange_query(&wire, None, true).await.unwrap();
        assert!(Arc::ptr_eq(&fresh.answer_ips, &cached.answer_ips));
        assert_eq!(cached.answer_ips.as_ref(), extract_ips_from_dns_response(&cached.wire));
    }
    assert_eq!(resolver.resolve_v4("example.test", true).await.unwrap(),
        Some("192.0.2.1".parse().unwrap()));
    assert_eq!(resolver.resolve_v6("example.test", true).await.unwrap(),
        Some("2001:db8::1".parse().unwrap()));
    assert!(server.requests.try_recv().is_err());
}
