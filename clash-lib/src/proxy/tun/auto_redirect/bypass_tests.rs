use tokio::net::UdpSocket;

use crate::config::internal::config::TunConfig;
use super::{AutoRedirect, BYPASS_MARK, mark_cache_tests::count, nft, test_interface};

#[tokio::test]
#[ignore = "requires an isolated network namespace"]
async fn auto_redirect_bypass_preserves_foreign_packet_and_connection_marks() {
    use std::process::Command;
    test_interface();
    for args in [vec!["link", "set", "lo", "up"],
        vec!["link", "add", "wan-test", "type", "dummy"],
        vec!["addr", "add", "192.0.2.1/24", "dev", "wan-test"],
        vec!["link", "set", "wan-test", "up"],
        vec!["route", "add", "default", "dev", "wan-test"]]
    {
        assert!(Command::new("ip").args(args).status().unwrap().success());
    }
    for case in 0..8 {
        for original_ct in [0, 0x40000055, BYPASS_MARK] {
            let mut cfg = TunConfig { enable: true, route_all: true, auto_redirect: true,
                ..Default::default() };
            let target = match case {
                0 => "127.0.0.1:53001",
                1 => "224.0.0.1:53001",
                _ => "203.0.113.9:53001",
            };
            match case {
                2 => cfg.exclude_interface = vec!["wan-test".into()],
                3 => cfg.include_interface = vec!["no-match".into()],
                4 => cfg.exclude_uid = vec![0],
                5 => cfg.include_uid = vec![1],
                6 => cfg.route_exclude_address = vec!["203.0.113.0/24".parse().unwrap()],
                7 => cfg.routes = vec!["192.0.2.0/24".parse().unwrap()],
                _ => {}
            }
            let guard = AutoRedirect::start(&cfg, "tun0", None).unwrap().unwrap();
            let expected_ct = if original_ct == 0 && case >= 2 { BYPASS_MARK } else { original_ct };
            let seed = if original_ct == 0 { String::new() } else {
                format!("add rule inet bypass_probe before udp dport 53001 ct mark set {original_ct}\n")
            };
            nft(&format!(
                "add table inet bypass_probe\n\
                 add chain inet bypass_probe before {{ type route hook output priority -151; policy accept; }}\n\
                 add rule inet bypass_probe before udp dport 53001 meta mark set 0x80000\n\
                 {seed}\
                 add chain inet bypass_probe after {{ type filter hook output priority -149; policy accept; }}\n\
                 add rule inet bypass_probe after udp dport 53001 meta mark 0x80000 counter comment \"packet\"\n\
                 add rule inet bypass_probe after udp dport 53001 ct mark != {expected_ct} counter comment \"changed-connection\"\n"
            )).unwrap();
            let socket = UdpSocket::bind("192.0.2.1:0").await.unwrap();
            for _ in 0..2 { socket.send_to(b"bypass", target).await.unwrap(); }
            assert_eq!(count("bypass_probe", "packet"), 2, "case {case}, ct {original_ct}");
            assert_eq!(count("bypass_probe", "changed-connection"), 0, "case {case}, ct {original_ct}");
            guard.close().unwrap();
            nft("delete table inet bypass_probe\n").unwrap();
        }
    }
}
