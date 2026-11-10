use std::{fs, mem::MaybeUninit, net::{Ipv4Addr, SocketAddr}, process::Command, time::Duration};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{net::UdpSocket, time::timeout};
use tun_rs::DeviceBuilder;

use crate::{config::internal::config::TunConfig, proxy::tun::routes};
use super::{AutoRedirect, INPUT_MARK, nft};

fn ip(args: &[&str]) {
    let output = Command::new("ip").args(args).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes.chunks(2).map(|chunk| {
        u16::from_be_bytes([chunk[0], chunk.get(1).copied().unwrap_or(0)]) as u32
    }).sum();
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

fn reply(protocol: u8, destination: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    let mut body = vec![0u8; 8];
    body.extend_from_slice(b"tun-reply");
    if protocol == 17 {
        body[..2].copy_from_slice(&53000u16.to_be_bytes());
        body[2..4].copy_from_slice(&port.to_be_bytes());
        let length = body.len() as u16;
        body[4..6].copy_from_slice(&length.to_be_bytes());
        // Zero UDP checksum is valid for IPv4.
    } else {
        body[4..6].copy_from_slice(&123u16.to_be_bytes());
        let sum = checksum(&body);
        body[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    packet[0] = 0x45;
    let length = (20 + body.len()) as u16;
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&[203, 0, 113, 9]);
    packet[16..20].copy_from_slice(&destination.octets());
    let sum = checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(&body);
    packet
}

// Run only under unshare -Urn. This test modifies namespace-local sysctls/routes
// and writes genuine IPv4 reply packets through the TUN descriptor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TUN and an isolated network namespace"]
async fn auto_redirect_strict_rp_filter_local_and_forwarded_replies() {
    fs::write("/proc/sys/net/ipv4/ip_forward", "1\n").unwrap();
    fs::write("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1\n").unwrap();
    fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "1\n").unwrap();
    fs::write("/proc/sys/net/ipv4/conf/default/rp_filter", "1\n").unwrap();
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "wan-test", "type", "dummy"]);
    ip(&["addr", "add", "192.0.2.1/24", "dev", "wan-test"]);
    ip(&["link", "set", "wan-test", "up"]);
    ip(&["route", "add", "default", "dev", "wan-test"]);
    let tun = DeviceBuilder::new().name("tun0").ipv4("198.18.0.1", 24, None)
        .enable(true).offload(false).build_async().unwrap();
    let lan = DeviceBuilder::new().name("lan-test").ipv4("10.23.0.1", 24, None)
        .enable(true).offload(false).build_async().unwrap();
    let cfg = TunConfig { enable: true, route_all: true, auto_redirect: true,
        device_id: "tun0".into(), route_table: 2022, ..Default::default() };
    routes::maybe_add_routes(&cfg, "tun0").unwrap();
    let client = UdpSocket::bind("192.0.2.1:0").await.unwrap();
    let icmp = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap();
    let address: SocketAddr = "192.0.2.1:0".parse().unwrap();
    icmp.bind(&SockAddr::from(address)).unwrap();
    icmp.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
    let local_udp = reply(17, Ipv4Addr::new(192, 0, 2, 1), client.local_addr().unwrap().port());
    let local_icmp = reply(1, Ipv4Addr::new(192, 0, 2, 1), 0);
    let mut buffer = [0u8; 1500];
    let mut raw = [MaybeUninit::<u8>::uninit(); 1500];
    tun.send(&local_udp).await.unwrap();
    assert!(timeout(Duration::from_millis(150), client.recv(&mut buffer)).await.is_err());
    tun.send(&local_icmp).await.unwrap();
    assert!(icmp.recv(&mut raw).is_err());
    for protocol in [17, 1] {
        tun.send(&reply(protocol, Ipv4Addr::new(10, 23, 0, 2), 53001)).await.unwrap();
        assert!(timeout(Duration::from_millis(150), lan.recv(&mut buffer)).await.is_err());
    }
    let guard = AutoRedirect::start(&cfg, "tun0", None).unwrap().unwrap();
    // Emulate another firewall restoring a selected connection mark on replies.
    // Our ingress rule must clear its complete mark before forwarding to LAN.
    let restored = INPUT_MARK;
    nft(&format!(
        "add table inet rp_probe\n\
         add chain inet rp_probe before {{ type filter hook prerouting priority -151; policy accept; }}\n\
         add rule inet rp_probe before iifname \"tun0\" meta mark set {restored}\n\
         add chain inet rp_probe after {{ type filter hook prerouting priority -149; policy accept; }}\n\
         add rule inet rp_probe after iifname \"tun0\" meta mark != 0 drop\n"
    )).unwrap();
    assert_eq!(fs::read_to_string("/proc/sys/net/ipv4/conf/tun0/rp_filter").unwrap().trim(), "2");
    assert_eq!(fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter").unwrap().trim(), "1");
    tun.send(&local_udp).await.unwrap();
    let length = timeout(Duration::from_secs(2), client.recv(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(&buffer[..length], b"tun-reply");
    tun.send(&local_icmp).await.unwrap();
    assert!(icmp.recv(&mut raw).unwrap() >= 28);
    for protocol in [17, 1] {
        tun.send(&reply(protocol, Ipv4Addr::new(10, 23, 0, 2), 53001)).await.unwrap();
        let length = timeout(Duration::from_secs(2), lan.recv(&mut buffer)).await.unwrap().unwrap();
        assert!(length >= 28);
        assert_eq!(buffer[9], protocol);
        assert_eq!(&buffer[16..20], &[10, 23, 0, 2]);
    }
    guard.close().unwrap();
    assert_eq!(fs::read_to_string("/proc/sys/net/ipv4/conf/tun0/rp_filter").unwrap().trim(), "1");
    routes::maybe_routes_clean_up(&cfg).unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated network namespace"]
async fn auto_redirect_rp_filter_only_relaxes_effective_strict_mode() {
    super::test_interface();
    let all_path = "/proc/sys/net/ipv4/conf/all/rp_filter";
    let device_path = "/proc/sys/net/ipv4/conf/tun0/rp_filter";
    for all in 0..=2 {
        for device in 0..=2 {
            fs::write(all_path, format!("{all}\n")).unwrap();
            fs::write(device_path, format!("{device}\n")).unwrap();
            let guard = super::rp_filter::ReversePathFilter::enable("tun0").unwrap();
            let expected = if all.max(device) == 1 { 2 } else { device };
            assert_eq!(fs::read_to_string(device_path).unwrap().trim(), expected.to_string());
            assert_eq!(guard.is_some(), all.max(device) == 1);
            drop(guard);
            assert_eq!(fs::read_to_string(device_path).unwrap().trim(), device.to_string());
            assert_eq!(fs::read_to_string(all_path).unwrap().trim(), all.to_string());
        }
    }
}
