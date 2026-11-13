use super::*;
use super::super::rules;

#[test]
fn dns_nat_preserves_scope_and_matches_configured_protocols_and_destinations() {
    let cfg = TunConfig { auto_redirect: true, gateway: "198.18.0.1/30".parse().unwrap(),
        gateway_v6: Some("fd00::1/64".parse().unwrap()),
        auto_redirect_dns_address: (Some("198.18.0.2".parse().unwrap()), Some("fd00::2".parse().unwrap())),
        dns_hijack: DnsHijack::Rules(vec!["udp://192.0.2.53:5353".parse().unwrap(),
            "tcp://any:53".parse().unwrap(), "udp://fd00:1::/64:54".parse().unwrap()]),
        include_interface: vec!["eth0".into()], exclude_uid: vec![1000],
        route_address_set: vec!["routes".into()], ..Default::default() };
    let script = rules(&cfg, "tun0", "test", Some(12345)).unwrap();
    for hook in ["prerouting"] {
        let chain = format!("{hook}_dns");
        let dnat = script.find(&format!("{chain} meta nfproto ipv4 ip daddr 192.0.2.53/32 udp dport 5353 dnat ip to 198.18.0.2")).unwrap();
        for rule in ["meta mark 354 return", "ct direction reply return",
            "fib daddr type local return", "meta mark != 355 return",
            "ip daddr @exclude4 return", "ip daddr != @route4 return"] {
            assert!(script.find(&format!("{chain} {rule}")).unwrap() < dnat);
        }
        assert!(script.contains(&format!("{chain} meta nfproto ipv6 ip6 daddr fd00:1::/64 udp dport 54 dnat ip6 to fd00::2")));
        assert!(script.contains(&format!("{chain} meta nfproto ipv4 tcp dport 53 redirect to :12345")));
    }
    assert!(!script.contains("output_dns"));
    assert!(!script.contains("prerouting_dns oifname"));
    assert!(script.contains("prerouting_dns iifname \"tun0\" return"));
    assert!(!script.contains("udp dport 53 dnat"));
    let hijack = hijack_config(&cfg, cfg.dns_hijack.clone());
    for (address, network, expected) in [("198.18.0.2:5353", Network::Udp, true),
        ("198.18.0.2:5353", Network::Tcp, false), ("[fd00::2]:54", Network::Udp, true),
        ("198.18.0.2:54", Network::Udp, false)] {
        assert_eq!(hijack.is_hijacked(network, &address.parse().unwrap()), expected);
    }
}

#[test]
fn disabled_dns_does_not_require_a_synthetic_address() {
    let mut cfg = TunConfig { auto_redirect: true, gateway: "198.18.0.1/32".parse().unwrap(),
        ..Default::default() };
    assert!(rules(&cfg, "tun0", "test", None).is_ok());
    cfg.dns_hijack = DnsHijack::All;
    assert!(rules(&cfg, "tun0", "test", None).is_err());
    cfg.dns_hijack = DnsHijack::Rules(vec!["tcp://any:53".parse().unwrap()]);
    assert!(rules(&cfg, "tun0", "test", Some(12345)).is_ok());
}

#[test]
fn synthetic_dns_rules_are_deduplicated() {
    let cfg = TunConfig { auto_redirect: true,
        auto_redirect_dns_address: (Some("172.18.0.2".parse().unwrap()), None),
        dns_hijack: DnsHijack::Rules(vec!["udp://192.0.2.53:53".parse().unwrap(),
            "udp://203.0.113.53:53".parse().unwrap()]), ..Default::default() };
    let DnsHijack::Rules(rules) = hijack_config(&cfg, cfg.dns_hijack.clone()) else { panic!() };
    assert_eq!(rules.len(), 3);
}

#[test]
fn local_dns_checks_on_link_sources_before_local_destination_bypass() {
    let cfg = TunConfig { dns_hijack: DnsHijack::All,
        gateway_v6: Some("fd00::1/64".parse().unwrap()),
        auto_redirect_dns_address: (Some("172.18.0.2".parse().unwrap()), Some("fd00::2".parse().unwrap())),
        routes: vec!["203.0.113.0/24".parse().unwrap()],
        route_exclude_address: vec!["10.23.0.0/24".parse().unwrap()],
        ..Default::default() };
    let sources = vec![
        "10.23.0.0/24".parse().unwrap(),
        "fd00:23::/64".parse().unwrap(),
    ];
    let script = super::super::rules_with_sources(&cfg, "tun0", "test", Some(12345), &sources).unwrap();
    assert!(script.contains("prerouting priority dstnat - 2"));
    assert!(script.contains("add element inet test local_source4 { 10.23.0.0/24 }"));
    assert!(script.contains("add element inet test local_source6 { fd00:23::/64 }"));
    for rule in ["ip saddr != @local_source4 return", "ip6 saddr != @local_source6 return",
        "fib daddr type != local return", "ct direction reply return"] {
        let position = script.find(&format!("prerouting_local_dns {rule}")).unwrap();
        assert!(position < script.find("prerouting_local_dns meta nfproto ipv4 udp dport 53 goto local_dns_udp").unwrap());
    }
    assert!(!script.contains("prerouting_local_dns ip daddr @exclude4 return"));
    assert!(!script.contains("prerouting_local_dns ip daddr != @route4 return"));
    assert!(script.contains("prerouting meta l4proto { tcp, udp } ct mark"));
    assert!(script.find(&format!("prerouting meta l4proto {{ tcp, udp }} ct mark {} meta mark set", super::super::INPUT_MARK)).unwrap()
        < script.find("prerouting fib daddr type local return").unwrap());
    assert!(script.contains("local_dns_udp jump selected"));
    assert!(script.contains("local_dns_udp meta nfproto ipv4 dnat ip to 172.18.0.2"));
    assert!(script.contains("prerouting_local_dns meta nfproto ipv4 tcp dport 53 redirect to :12345"));
    assert!(!script.contains("1053"));
}
