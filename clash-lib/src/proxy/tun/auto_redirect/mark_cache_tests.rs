use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, process::Command, time::Duration};

use serde_json::Value;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{net::UdpSocket, time::timeout};
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::{config::internal::config::TunConfig, proxy::tun::routes};
use super::{AutoRedirect, INPUT_MARK, BYPASS_MARK, nft};

fn ip(args: &[&str]) {
    assert!(Command::new("ip").args(args).status().unwrap().success());
}

async fn receive(device: &AsyncDevice) -> Vec<u8> {
    let mut buffer = [0u8; 1500];
    loop {
        let length = device.recv(&mut buffer).await.unwrap();
        if length >= 28 && buffer[0] >> 4 == 4 && buffer[9] == 17
            && buffer[22..24] == 53000u16.to_be_bytes()
        {
            return buffer[28..length].to_vec();
        }
    }
}

pub(super) fn count(table: &str, comment: &str) -> u64 {
    let output = Command::new("nft").args(["-j", "list", "chain", "inet", table, "after"])
        .output().unwrap();
    assert!(output.status.success());
    let data: Value = serde_json::from_slice(&output.stdout).unwrap();
    data["nftables"].as_array().unwrap().iter().filter_map(|item| item.get("rule"))
        .find(|rule| rule["comment"] == comment).unwrap()["expr"].as_array().unwrap()
        .iter().find_map(|expr| expr.get("counter")).unwrap()["packets"].as_u64().unwrap()
}

// Run only in a fresh unshare -Urn namespace. Exercise actual nft evaluation,
// masked policy routing and conntrack caching, rather than checking rule text.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TUN and an isolated network namespace"]
async fn auto_redirect_full_marks_and_conntrack_cache() {
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "wan-test", "type", "dummy"]);
    ip(&["addr", "add", "192.0.2.1/24", "dev", "wan-test"]);
    ip(&["link", "set", "wan-test", "up"]);
    ip(&["route", "add", "default", "dev", "wan-test"]);
    let device = DeviceBuilder::new().name("tun0").ipv4("198.18.0.1", 24, None)
        .enable(true).offload(false).build_async().unwrap();
    let cfg = TunConfig { enable: true, route_all: true, auto_redirect: true,
        device_id: "tun0".into(), route_table: 2022,
        route_address_set: vec!["networks".into()],
        routes: vec!["203.0.113.0/24".parse().unwrap()], ..Default::default() };
    routes::maybe_add_routes(&cfg, "tun0").unwrap();
    let guard = AutoRedirect::start(&cfg, "tun0", None).unwrap().unwrap();
    nft(&format!(
        "add table inet mark_probe\n\
         add chain inet mark_probe before {{ type route hook output priority -151; policy accept; }}\n\
         add rule inet mark_probe before udp dport 53000 meta mark set 0x80000042\n\
         add chain inet mark_probe after {{ type filter hook output priority -149; policy accept; }}\n\
         add rule inet mark_probe after udp dport 53000 meta mark {{ {INPUT_MARK}, 0x80000042 }} counter comment \"correct\"\n\
         add rule inet mark_probe after udp dport 53000 meta mark {INPUT_MARK} ct mark {INPUT_MARK} counter comment \"selected\"\n\
         add rule inet mark_probe after udp dport 53000 meta mark 0x80000042 ct mark {BYPASS_MARK} counter comment \"bypassed\"\n"
    )).unwrap();
    let address = (Ipv4Addr::new(203, 0, 113, 9), 53000);
    let selected = UdpSocket::bind("192.0.2.1:0").await.unwrap();
    selected.send_to(b"first", address).await.unwrap();
    assert_eq!(timeout(Duration::from_secs(2), receive(&device)).await.unwrap(), b"first");
    let mut empty = cfg.clone();
    empty.routes.clear();
    AutoRedirect::update_sets(&guard.table, &empty).unwrap();
    // Existing selected flow ignores the now-empty include set.
    selected.send_to(b"cached", address).await.unwrap();
    assert_eq!(timeout(Duration::from_secs(2), receive(&device)).await.unwrap(), b"cached");
    let bypassed = UdpSocket::bind("192.0.2.1:0").await.unwrap();
    bypassed.send_to(b"new-bypass", address).await.unwrap();
    assert!(timeout(Duration::from_millis(150), receive(&device)).await.is_err());
    AutoRedirect::update_sets(&guard.table, &cfg).unwrap();
    // Existing bypassed flow also retains its first decision after refresh.
    bypassed.send_to(b"cached-bypass", address).await.unwrap();
    assert!(timeout(Duration::from_millis(150), receive(&device)).await.is_err());
    let fresh = UdpSocket::bind("192.0.2.1:0").await.unwrap();
    fresh.send_to(b"fresh", address).await.unwrap();
    assert_eq!(timeout(Duration::from_secs(2), receive(&device)).await.unwrap(), b"fresh");
    assert_eq!(count("mark_probe", "correct"), 5);
    assert_eq!(count("mark_probe", "selected"), 3);
    assert_eq!(count("mark_probe", "bypassed"), 2);
    // Nonzero marks owned by another firewall must survive both verdicts.
    // Such a flow is deliberately not cached, so a set update can reclassify it.
    let foreign = UdpSocket::bind("192.0.2.1:0").await.unwrap();
    let port = foreign.local_addr().unwrap().port();
    nft(&format!(
        "add rule inet mark_probe before udp sport {port} udp dport 53000 ct mark set 0x40000055\n\
         add rule inet mark_probe after udp sport {port} meta mark 0x80000042 ct mark 0x40000055 counter comment \"foreign-bypass\"\n\
         add rule inet mark_probe after udp sport {port} meta mark {INPUT_MARK} ct mark 0x40000055 counter comment \"foreign-selected\"\n"
    )).unwrap();
    AutoRedirect::update_sets(&guard.table, &empty).unwrap();
    foreign.send_to(b"foreign-bypass", address).await.unwrap();
    assert!(timeout(Duration::from_millis(150), receive(&device)).await.is_err());
    assert_eq!(count("mark_probe", "foreign-bypass"), 1);
    AutoRedirect::update_sets(&guard.table, &cfg).unwrap();
    foreign.send_to(b"foreign-selected", address).await.unwrap();
    assert_eq!(timeout(Duration::from_secs(2), receive(&device)).await.unwrap(), b"foreign-selected");
    assert_eq!(count("mark_probe", "foreign-selected"), 1);
    guard.close().unwrap();
    routes::maybe_routes_clean_up(&cfg).unwrap();
}

async fn receive_icmp(device: &AsyncDevice, ipv6: bool) {
    let mut buffer = [0u8; 1500];
    loop {
        let length = device.recv(&mut buffer).await.unwrap();
        if (!ipv6 && length >= 28 && buffer[0] >> 4 == 4 && buffer[9] == 1 && buffer[20] == 8)
            || (ipv6 && length >= 48 && buffer[0] >> 4 == 6 && buffer[6] == 58 && buffer[40] == 128)
        {
            return;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TUN and an isolated network namespace"]
async fn auto_redirect_icmp_is_classified_per_packet() {
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "wan-test", "type", "dummy"]);
    ip(&["addr", "add", "192.0.2.1/24", "dev", "wan-test"]);
    ip(&["-6", "addr", "add", "2001:db8::1/64", "dev", "wan-test", "nodad"]);
    ip(&["link", "set", "wan-test", "up"]);
    ip(&["route", "add", "default", "dev", "wan-test"]);
    ip(&["-6", "route", "add", "default", "dev", "wan-test"]);
    let device = DeviceBuilder::new().name("tun0").ipv4("198.18.0.1", 24, None)
        .ipv6("fd00::1", 64).enable(true).offload(false).build_async().unwrap();
    let cfg = TunConfig { enable: true, route_all: true, auto_redirect: true,
        device_id: "tun0".into(), route_table: 2022,
        gateway_v6: Some("fd00::1/64".parse().unwrap()),
        route_address_set: vec!["networks".into()],
        routes: vec!["203.0.113.0/24".parse().unwrap(), "2001:db8:1::/64".parse().unwrap()],
        ..Default::default() };
    routes::maybe_add_routes(&cfg, "tun0").unwrap();
    let guard = AutoRedirect::start(&cfg, "tun0", None).unwrap().unwrap();
    // Force an existing selected ct mark: ICMP must neither consult this cached
    // decision nor overwrite it when a refreshed set bypasses the next packet.
    nft(&format!(
        "add table inet icmp_probe\n\
         add chain inet icmp_probe before {{ type filter hook output priority -151; policy accept; }}\n\
         add rule inet icmp_probe before meta l4proto {{ icmp, ipv6-icmp }} ct mark set {INPUT_MARK}\n\
         add chain inet icmp_probe after {{ type filter hook output priority -149; policy accept; }}\n\
         add rule inet icmp_probe after meta l4proto {{ icmp, ipv6-icmp }} ct mark {INPUT_MARK} counter comment \"uncached\"\n"
    )).unwrap();
    for (source, target) in [("192.0.2.1", "203.0.113.9"), ("2001:db8::1", "2001:db8:1::9")] {
        let source: IpAddr = source.parse().unwrap();
        let target: IpAddr = target.parse().unwrap();
        let ipv6 = target.is_ipv6();
        let protocol = if ipv6 { Protocol::ICMPV6 } else { Protocol::ICMPV4 };
        let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
        let socket = Socket::new(domain, Type::RAW, Some(protocol)).unwrap();
        socket.bind(&SockAddr::from(SocketAddr::new(source, 0))).unwrap();
        let target = SockAddr::from(SocketAddr::new(target, 0));
        for sequence in 1u16..=3 {
            let mut next = cfg.clone();
            if sequence == 2 { next.routes.clear(); }
            AutoRedirect::update_sets(&guard.table, &next).unwrap();
            let mut echo = [0u8; 8];
            echo[0] = if ipv6 { 128 } else { 8 };
            echo[4..6].copy_from_slice(&123u16.to_be_bytes());
            echo[6..8].copy_from_slice(&sequence.to_be_bytes());
            if !ipv6 {
                // Eight-byte echo header, code/checksum zero and no payload.
                echo[2..4].copy_from_slice(&(!(0x0800u16 + 123 + sequence)).to_be_bytes());
            }
            // Linux generates the ICMPv6 checksum for raw ICMPv6 sockets.
            socket.send_to(&echo, &target).unwrap();
            let received = timeout(Duration::from_millis(250), receive_icmp(&device, ipv6)).await;
            if sequence == 2 { assert!(received.is_err()); }
            else { received.unwrap(); }
        }
    }
    assert_eq!(count("icmp_probe", "uncached"), 6);
    guard.close().unwrap();
    routes::maybe_routes_clean_up(&cfg).unwrap();
}
