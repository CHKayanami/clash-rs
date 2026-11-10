#[cfg(all(test, target_os = "linux"))]
mod bypass_tests;
#[cfg(all(test, target_os = "linux"))]
mod mark_cache_tests;
#[cfg(all(test, target_os = "linux"))]
mod rp_filter_tests;
#[cfg(all(test, target_os = "linux"))]
mod address_set_tests;
mod nft_sets;
#[cfg(target_os = "linux")]
mod rp_filter;
#[cfg(target_os = "linux")]
use rp_filter::ReversePathFilter;
#[cfg(target_os = "linux")]
pub(super) mod address_sets;

#[cfg(target_os = "linux")]
pub(super) mod tcp;

use std::{
    io::{self, Write},
    process::{Command, Stdio, id},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use tracing::warn;

use crate::config::internal::{config::TunConfig, tun::validate_interface_name};
use nft_sets::write_sets;

// Distinct from the outbound socket bypass mark. Only packets selected by our
// nftables chains may use the TUN policy routing table.
pub(super) use crate::config::internal::tun::{
    AUTO_REDIRECT_INPUT_MARK as INPUT_MARK,
};
use crate::config::internal::tun::AUTO_REDIRECT_BYPASS_MARK as BYPASS_MARK;
static NEXT_TABLE: AtomicU64 = AtomicU64::new(0);

pub(super) struct AutoRedirect {
    table: String,
    closed: AtomicBool,
    #[cfg(target_os = "linux")]
    reverse_path_filter: Option<ReversePathFilter>,
}

impl AutoRedirect {
    pub fn start(cfg: &TunConfig, device: &str, tcp_port: Option<u16>) -> io::Result<Option<Self>> {
        if !cfg.auto_redirect { return Ok(None); }
        let table = format!("clash_tun_{}_{}", id(),
            NEXT_TABLE.fetch_add(1, Ordering::Relaxed));
        let script = rules(cfg, device, &table, tcp_port)?;
        // nft applies the complete batch atomically. A failure leaves no partial
        // table behind; never flush or replace another application's rules.
        #[cfg(target_os = "linux")]
        let reverse_path_filter = ReversePathFilter::enable(device)?;
        nft(&script)?;
        Ok(Some(Self { table, closed: AtomicBool::new(false),
            #[cfg(target_os = "linux")]
            reverse_path_filter,
        }))
    }

    // Normal shutdown invokes this on spawn_blocking before dropping the guard.
    // Drop remains a synchronous best-effort fallback for aborted initialization
    // or a forcibly aborted service task, where awaiting cleanup is impossible.
    fn cleanup(&self) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) { return Ok(()); }
        let deletion = nft(&format!("delete table inet {}\n", self.table));
        if deletion.is_ok() { self.closed.store(true, Ordering::Release); }
        #[cfg(target_os = "linux")]
        let restoration = self.reverse_path_filter.as_ref().map_or(Ok(()), ReversePathFilter::restore);
        #[cfg(not(target_os = "linux"))]
        let restoration = Ok(());
        deletion.and(restoration)
    }

    #[cfg(target_os = "linux")]
    pub fn close(&self) -> io::Result<()> { self.cleanup() }

    #[cfg(target_os = "linux")]
    pub fn update_sets(table: &str, cfg: &TunConfig) -> io::Result<()> {
        let mut script = String::new();
        write_sets(&mut script, cfg, table, false);
        nft(&script)
    }
}

impl Drop for AutoRedirect {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            warn!("failed to remove TUN auto-redirect table {}: {error}", self.table);
        }
    }
}

fn nft(script: &str) -> io::Result<()> {
    let mut child = Command::new("nft").args(["-f", "-"])
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped())
        .spawn().map_err(|error| io::Error::new(error.kind(),
            format!("TUN auto-redirect requires nftables (nft): {error}")))?;
    let written = child.stdin.take().expect("piped nft stdin").write_all(script.as_bytes());
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!("TUN auto-redirect nftables: {}",
            String::from_utf8_lossy(&output.stderr).trim())));
    }
    written
}

fn quote(value: &str) -> io::Result<String> {
    // Reject ambiguous syntax rather than depending on nft string escapes.
    // This is also the script boundary for callers supplying an internal config
    // directly, so it uses the same validator as configuration conversion.
    validate_interface_name(value).map_err(io::Error::other)?;
    Ok(format!("\"{value}\""))
}

fn rules(cfg: &TunConfig, device: &str, table: &str, tcp_port: Option<u16>) -> io::Result<String> {
    let bypass = cfg.so_mark.unwrap_or(0x162);
    debug_assert!(!matches!(bypass, 0 | INPUT_MARK | BYPASS_MARK));
    let device = quote(device)?;
    let mut script = format!("add table inet {table}\n");
    write_sets(&mut script, cfg, table, true);
    // Only selected packets need a routing mark. Cache decisions exclusively in
    // previously unclaimed TCP/UDP conntrack entries; leave third-party marks
    // untouched. Goto returns to the base-chain policy when these chains end.
    script.push_str(&format!(
        "add chain inet {table} selected\n\
         add rule inet {table} selected meta mark set {INPUT_MARK}\n\
         add rule inet {table} selected meta l4proto {{ tcp, udp }} ct mark 0 ct mark set {INPUT_MARK}\n\
         add chain inet {table} bypassed\n\
         add rule inet {table} bypassed meta l4proto {{ tcp, udp }} ct mark 0 ct mark set {BYPASS_MARK}\n\
         add chain inet {table} return_traffic\n\
         add rule inet {table} return_traffic meta mark {INPUT_MARK} meta mark set 0\n"
    ));
    let selected = "goto selected";
    let bypassed = "goto bypassed";
    for (chain, hook, kind, interface) in [
        ("prerouting", "prerouting", "filter", "iifname"),
        ("output", "output", "route", "oifname"),
    ] {
        script.push_str(&format!("add chain inet {table} {chain} {{ type {kind} hook {hook} priority mangle; policy accept; }}\n"));
        let prefix = format!("add rule inet {table} {chain} ");
        let mut add = |rule: String| {
            script.push_str(&prefix);
            script.push_str(&rule);
            script.push('\n');
        };
        add(format!("meta mark {bypass} return"));
        add(format!("iifname {} goto return_traffic", device));
        if chain == "output" {
            add(format!("oifname {} return", device));
        }
        // Preserve replies to connections accepted by local services and TUN
        // return packets instead of proxying them as new outbound connections.
        add("ct direction reply goto return_traffic".into());
        add("ct state { invalid, untracked } goto return_traffic".into());
        // These cheap checks do not claim conntrack marks, even on a cache hit.
        add("fib daddr type local return".into());
        add("ip daddr { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/3 } return".into());
        add("ip6 daddr { ::/128, ::1/128, fe80::/10, ff00::/8 } return".into());
        if cfg.gateway_v6.is_none() { add("meta nfproto ipv6 return".into()); }
        if chain == "output" {
            // Conntrack applies the existing TCP destination NAT later in this
            // hook. Do not mark/reroute an already redirected connection again.
            add("meta l4proto tcp ct status dnat return".into());
        }
        // ICMP/ICMPv6 ignore the cache. A cached bypass must not alter the
        // packet mark used by Tailscale, WireGuard or other policy routing.
        add(format!("meta l4proto {{ tcp, udp }} ct mark {BYPASS_MARK} return"));
        add(format!("meta l4proto {{ tcp, udp }} ct mark {INPUT_MARK} meta mark set {INPUT_MARK} return"));
        for name in &cfg.exclude_interface {
            add(format!("{interface} {} {bypassed}", quote(name)?));
        }
        if !cfg.include_interface.is_empty() {
            let names = cfg.include_interface.iter().map(|name| quote(name))
                .collect::<io::Result<Vec<_>>>()?.join(", ");
            add(format!("{interface} != {{ {names} }} {bypassed}"));
        }
        if chain == "output" {
            for uid in &cfg.exclude_uid { add(format!("meta skuid {uid} {bypassed}")); }
            if !cfg.include_uid.is_empty() {
                let users = cfg.include_uid.iter().map(u32::to_string).collect::<Vec<_>>().join(", ");
                add(format!("meta skuid != {{ {users} }} {bypassed}"));
            }
        }
        add(format!("ip daddr @exclude4 {bypassed}"));
        add(format!("ip6 daddr @exclude6 {bypassed}"));
        if cfg.routes.is_empty() && cfg.route_address_set.is_empty() {
            add(selected.into());
        } else {
            add(format!("ip daddr @route4 {selected}"));
            add(format!("ip6 daddr @route6 {selected}"));
            add(bypassed.into());
        }
    }
    if let Some(port) = tcp_port {
        for hook in ["prerouting", "output"] {
            let chain = format!("{hook}_tcp");
            script.push_str(&format!(
                "add chain inet {table} {chain} {{ type nat hook {hook} priority dstnat; policy accept; }}\n\
                 add rule inet {table} {chain} meta mark {INPUT_MARK} meta l4proto tcp redirect to :{port}\n"
            ));
        }
    }
    Ok(script)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_select_traffic_and_preserve_bypass_and_replies() {
        assert!(AutoRedirect::start(&TunConfig::default(), "tun0", None).unwrap().is_none());
        let cfg = TunConfig { auto_redirect: true, so_mark: Some(123),
            routes: vec!["10.0.0.0/8".parse().unwrap()],
            route_exclude_address: vec!["10.1.0.0/16".parse().unwrap()],
            include_interface: vec!["eth0".into()], exclude_uid: vec![1000],
            ..Default::default() };
        let script = rules(&cfg, "tun0", "test", Some(12345)).unwrap();
        assert!(script.contains("type route hook output priority mangle"));
        assert!(script.contains("type nat hook output priority dstnat"));
        assert!(script.contains("meta l4proto tcp redirect to :12345"));
        assert!(script.contains("type filter hook prerouting priority mangle"));
        for chain in ["output", "prerouting"] {
            let bypass = script.find(&format!("{chain} meta mark 123 return")).unwrap();
            let reply = script.find(&format!("{chain} ct direction reply goto return_traffic")).unwrap();
            let excluded = script.find(&format!("{chain} ip daddr @exclude4 goto bypassed")).unwrap();
            let selected = script.find(&format!("{chain} ip daddr @route4 goto selected")).unwrap();
            let cached = script.find(&format!("{chain} meta l4proto {{ tcp, udp }} ct mark {INPUT_MARK}")).unwrap();
            assert!(cached < excluded && cached < selected);
            if chain == "output" {
                let redirected = script.find("output meta l4proto tcp ct status dnat return").unwrap();
                assert!(redirected < cached);
            }
            assert!(bypass < selected && reply < selected && excluded < selected);
        }
        assert!(script.contains("output meta skuid 1000 goto bypassed"));
        assert!(!script.contains("prerouting meta skuid"));
        assert!(script.contains("iifname != { \"eth0\" } goto bypassed"));
        assert!(script.contains("oifname != { \"eth0\" } goto bypassed"));
        assert!(script.contains("meta nfproto ipv6 return"));
    }

    #[test]
    fn bypass_preserves_marks_and_only_claims_empty_conntrack_entries() {
        let script = rules(&TunConfig::default(), "tun0", "test", None).unwrap();
        for line in script.lines().filter(|line| line.contains("ct mark set")) {
            assert!(line.contains("ct mark 0 ct mark set"), "{line}");
        }
        assert!(!script.contains("bypassed meta mark set"));
        for chain in ["prerouting", "output"] {
            assert!(script.contains(&format!("{chain} meta l4proto {{ tcp, udp }} ct mark {BYPASS_MARK} return")));
            assert!(script.contains(&format!("{chain} fib daddr type local return")));
        }
    }

    #[test]
    fn icmp_does_not_read_or_write_cached_verdicts() {
        let script = rules(&TunConfig::default(), "tun0", "test", None).unwrap();
        for line in script.lines().filter(|line| line.contains("ct mark")) {
            assert!(line.contains("meta l4proto { tcp, udp }"), "{line}");
        }
        assert!(!script.contains("meta mark &"));
        assert!(!script.contains("ct mark &"));
    }

    #[test]
    fn empty_address_set_never_turns_into_catch_all() {
        let cfg = TunConfig { route_address_set: vec!["empty".into()], ..Default::default() };
        let script = rules(&cfg, "tun0", "test", None).unwrap();
        assert!(script.contains("output ip daddr @route4 goto selected"));
        assert!(!script.contains("output goto selected"));
        assert!(!script.contains("prerouting goto selected"));
    }

    #[test]
    fn interface_injection_is_rejected_before_generating_a_batch() {
        for name in ["a\"; flush ruleset; \"", "a\"; flush ruleset; #", "a\"", "a;", "a\\", "a\n", "1234567890123456"] {
            assert!(rules(&TunConfig::default(), name, "test", None).is_err());
            let cfg = TunConfig { include_interface: vec![name.into()], ..Default::default() };
            assert!(rules(&cfg, "tun0", "test", None).is_err());
            let cfg = TunConfig { exclude_interface: vec![name.into()], ..Default::default() };
            assert!(rules(&cfg, "tun0", "test", None).is_err());
        }
        assert_eq!(quote("eth0").unwrap(), "\"eth0\"");
    }

}

#[cfg(all(test, target_os = "linux"))]
fn test_interface() {
    for args in [["link", "add", "tun0", "type", "dummy"].as_slice(),
        ["link", "set", "tun0", "up"].as_slice()]
    {
        assert!(Command::new("ip").args(args).status().unwrap().success());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires nftables and an isolated network namespace"]
    async fn nftables_tcp_redirect_preserves_original_destination() {
        test_interface();
        use std::{net::SocketAddr, time::Duration};
        use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, time::timeout};
        use super::mark_cache_tests::count;
        use crate::proxy::utils::{ToCanonical, get_original_destination_addr};

        for args in [vec!["link", "set", "lo", "up"],
            vec!["addr", "add", "192.0.2.1/32", "dev", "lo"],
            vec!["-6", "addr", "add", "fd00::1/128", "dev", "lo", "nodad"],
            vec!["route", "add", "default", "dev", "lo"],
            vec!["-6", "route", "add", "default", "dev", "lo"]] {
            assert!(Command::new("ip").args(args).status().unwrap().success());
        }
        let cfg = TunConfig { auto_redirect: true, enable_tcp: true,
            gateway_v6: Some("fd00::1/64".parse().unwrap()), ..Default::default() };
        let listener = tcp::bind(&cfg).unwrap().unwrap();
        let port = listener.local_addr().unwrap().port();
        let _guard = AutoRedirect::start(&cfg, "tun0", Some(port)).unwrap();
        nft(&format!(
            "add table inet tcp_probe\n\
             add chain inet tcp_probe before {{ type filter hook output priority -151; policy accept; }}\n\
             add rule inet tcp_probe before tcp dport 80 meta mark set 0x80000042\n\
             add chain inet tcp_probe after {{ type filter hook output priority -149; policy accept; }}\n\
             add rule inet tcp_probe after tcp dport 80 ct status dnat meta mark 0x80000042 counter comment \"cached-tcp\"\n\
             add rule inet tcp_probe after tcp dport 80 ct status dnat meta mark {INPUT_MARK} counter comment \"remarked\"\n"
        )).unwrap();
        for destination in ["198.18.0.2:80", "[fd01::2]:80"] {
            let destination: SocketAddr = destination.parse().unwrap();
            let mut client = timeout(Duration::from_secs(3), TcpStream::connect(destination))
                .await.unwrap().unwrap();
            let (mut server, _) = timeout(Duration::from_secs(3), listener.accept())
                .await.unwrap().unwrap();
            assert_eq!(get_original_destination_addr(&server).unwrap().to_canonical(), destination);
            assert!(server.nodelay().unwrap());
            client.write_all(b"redirect-data").await.unwrap();
            let mut data = [0u8; 13];
            timeout(Duration::from_secs(3), server.read_exact(&mut data)).await.unwrap().unwrap();
            assert_eq!(&data, b"redirect-data");
        }
        assert!(count("tcp_probe", "cached-tcp") > 0);
        assert_eq!(count("tcp_probe", "remarked"), 0);
    }

    // Run in a fresh user/network namespace, never against the host firewall:
    // unshare -Urn <test-binary> nftables_lifecycle --ignored
    #[test]
    #[ignore = "requires nftables and an isolated network namespace"]
    fn nftables_lifecycle() {
        test_interface();
        let cfg = TunConfig { auto_redirect: true,
            gateway_v6: Some("fd00::1/64".parse().unwrap()),
            routes: vec!["10.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()],
            route_exclude_address: ["10.1.0.0/16", "255.255.255.255/32", "ffff::/16"]
                .map(|network| network.parse().unwrap()).to_vec(),
            include_interface: vec!["eth0".into()],
            include_uid: vec![1000, 1001], exclude_uid: vec![1002],
            ..Default::default() };
        let guard = AutoRedirect::start(&cfg, "tun0", Some(12345)).unwrap().unwrap();
        let table = guard.table.clone();
        let output = Command::new("nft").args(["list", "table", "inet", &table]).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let listing = String::from_utf8_lossy(&output.stdout);
        assert!(listing.contains("hook prerouting"));
        assert!(listing.contains("hook output"));
        drop(guard);
        assert!(!Command::new("nft").args(["list", "table", "inet", &table])
            .output().unwrap().status.success());
    }
}
