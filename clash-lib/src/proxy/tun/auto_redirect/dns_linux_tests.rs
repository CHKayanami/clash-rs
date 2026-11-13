use std::{fs, net::IpAddr, process::{Command, Stdio}, time::Duration};

use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines},
    net::{TcpListener, UdpSocket},
    process::{Child, ChildStdin, ChildStdout, Command as AsyncCommand},
    time::timeout,
};
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::{config::internal::config::{DnsHijack, TunConfig}, proxy::tun::routes};
use super::super::{AutoRedirect, tcp};

fn ip(args: &[&str]) {
    let output = Command::new("ip").args(args).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}

// A separate network namespace supplies real ingress traffic through a veth,
// without raw sockets, host routes or synthetic addresses assigned to lo.
const PEER: &str = r#"
import socket, subprocess, sys
print('ready', flush=True)
sys.stdin.readline()
for path in [ '/proc/sys/net/ipv6/conf/all/accept_dad',
              '/proc/sys/net/ipv6/conf/default/accept_dad',
              '/proc/sys/net/ipv6/conf/peer-test/accept_dad' ]:
    with open(path, 'w') as f:
        f.write('0')
for args in [ ['link','set','lo','up'], ['link','set','peer-test','up'],
              ['addr','add','10.23.0.2/24','dev','peer-test'],
              ['route','add','default','via','10.23.0.1'],
              ['-6','addr','add','fd00:23::2/64','dev','peer-test','nodad'],
              ['-6','route','add','default','via','fd00:23::1'],
              ['addr','add','198.51.100.2/32','dev','lo'],
              ['-6','addr','add','2001:db8:ffff::2/128','dev','lo','nodad'] ]:
    subprocess.run(['ip'] + args, check=True)
print('configured', flush=True)
for line in sys.stdin:
    fields = line.split()
    protocol, address = fields[:2]
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    kind = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
    with socket.socket(family, kind) as s:
        s.settimeout(3)
        if len(fields) > 2 and fields[2] != '-': s.bind((fields[2], 0))
        s.connect((address, 53))
        s.sendall(b'query')
        print('sent', flush=True)
        if protocol != 'send':
            data = s.recv(64)
            assert data == b'query', data
            print('reply', flush=True)
        if len(fields) > 3 and fields[3] == 'reuse':
            s.sendall(b'query')
            print('sent', flush=True)
            data = s.recv(64)
            assert data == b'query', data
            print('reply', flush=True)
"#;

struct Peer {
    _child: Child,
    input: ChildStdin,
    output: Lines<BufReader<ChildStdout>>,
}

impl Peer {
    async fn new() -> Self {
        let mut child = AsyncCommand::new("unshare").args(["-n", "python3", "-u", "-c", PEER])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).kill_on_drop(true).spawn().unwrap();
        let mut peer = Self { input: child.stdin.take().unwrap(),
            output: BufReader::new(child.stdout.take().unwrap()).lines(), _child: child };
        peer.expect("ready").await;
        ip(&["link", "set", "peer-test", "netns", &peer._child.id().unwrap().to_string()]);
        peer.input.write_all(b"\n").await.unwrap();
        peer.expect("configured").await;
        peer
    }

    async fn expect(&mut self, expected: &str) {
        assert_eq!(timeout(Duration::from_secs(5), self.output.next_line()).await.unwrap()
            .unwrap().as_deref(), Some(expected));
    }

    async fn send(&mut self, protocol: &str, address: &str) {
        self.input.write_all(format!("{protocol} {address}\n").as_bytes()).await.unwrap();
        self.expect("sent").await;
    }

    async fn send_reuse(&mut self, protocol: &str, address: &str) {
        self.input.write_all(format!("{protocol} {address} - reuse\n").as_bytes()).await.unwrap();
        self.expect("sent").await;
    }

    async fn send_external(&mut self, protocol: &str, address: &str) {
        let source = if address.contains(':') { "2001:db8:ffff::2" } else { "198.51.100.2" };
        self.input.write_all(format!("{protocol} {address} {source}\n").as_bytes()).await.unwrap();
        self.expect("sent").await;
    }
}

async fn setup() -> (AsyncDevice, TunConfig, Peer) {
    for (path, value) in [("/proc/sys/net/ipv4/ip_forward", "1"),
        ("/proc/sys/net/ipv6/conf/all/forwarding", "1"),
        ("/proc/sys/net/ipv6/conf/all/accept_dad", "0"),
        ("/proc/sys/net/ipv6/conf/default/accept_dad", "0"),
        ("/proc/sys/net/ipv4/conf/all/rp_filter", "0"),
        ("/proc/sys/net/ipv4/conf/default/rp_filter", "0")] {
        fs::write(path, value).unwrap();
    }
    for args in [vec!["link", "set", "lo", "up"],
        vec!["link", "add", "wan-route", "type", "dummy"],
        vec!["addr", "add", "192.0.2.1/24", "dev", "wan-route"],
        vec!["-6", "addr", "add", "2001:db8:1::1/64", "dev", "wan-route", "nodad"],
        vec!["link", "set", "wan-route", "up"],
        vec!["route", "add", "default", "dev", "wan-route"],
        vec!["-6", "route", "add", "default", "dev", "wan-route"],
        vec!["link", "add", "docker-test", "type", "bridge"],
        vec!["addr", "add", "172.17.0.1/16", "dev", "docker-test"],
        vec!["link", "set", "docker-test", "up"],
        vec!["link", "add", "wan-test", "type", "veth", "peer", "name", "peer-test"],
        vec!["addr", "add", "10.23.0.1/24", "dev", "wan-test"],
        vec!["-6", "addr", "add", "fd00:23::1/64", "dev", "wan-test", "nodad"],
        vec!["link", "set", "wan-test", "up"]] { ip(&args); }
    let tun = DeviceBuilder::new().name("tun0").ipv4("172.18.0.1", 30, None)
        .ipv6("fdfe:dcba:9876::1", 126).enable(true).offload(false).build_async().unwrap();
    let cfg = TunConfig { enable: true, route_all: true, auto_redirect: true,
        device_id: "tun0".into(), route_table: 2022,
        gateway: "172.18.0.1/30".parse().unwrap(),
        gateway_v6: Some("fdfe:dcba:9876::1/126".parse().unwrap()),
        auto_redirect_dns_address: (Some("172.18.0.2".parse().unwrap()), Some("fdfe:dcba:9876::2".parse().unwrap())),
        dns_hijack: DnsHijack::All, ..Default::default() };
    routes::maybe_add_routes(&cfg, "tun0").unwrap();
    let peer = Peer::new().await;
    ip(&["route", "add", "198.51.100.2/32", "via", "10.23.0.2", "dev", "wan-test"]);
    ip(&["-6", "route", "add", "2001:db8:ffff::2/128", "via", "fd00:23::2", "dev", "wan-test"]);
    (tun, cfg, peer)
}

async fn receive(tun: &AsyncDevice) -> (Vec<u8>, IpAddr) {
    let mut packet = vec![0; 1500];
    loop {
        let length = tun.recv(&mut packet).await.unwrap();
        let (offset, destination) = if length >= 28 && packet[0] >> 4 == 4 && packet[9] == 17 {
            (usize::from(packet[0] & 15) * 4, IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).unwrap()))
        } else if length >= 48 && packet[0] >> 4 == 6 && packet[6] == 17 {
            (40, IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()))
        } else { continue; };
        if length < offset + 8 || packet[offset + 2..offset + 4] != 53u16.to_be_bytes() { continue; }
        assert_eq!(&packet[offset + 8..length], b"query");
        packet.truncate(length);
        return (packet, destination);
    }
}

async fn echo(tun: &AsyncDevice, mut packet: Vec<u8>) {
    // Swapping equal-sized source/destination fields preserves both the IP
    // checksum and UDP pseudo-header/transport checksum; payload is unchanged.
    let offset = if packet[0] >> 4 == 4 {
        packet[12..20].rotate_left(4);
        usize::from(packet[0] & 15) * 4
    } else {
        packet[8..40].rotate_left(16);
        40
    };
    packet[offset..offset + 4].rotate_left(2);
    tun.send(&packet).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TUN, python3 and an isolated network namespace"]
async fn auto_redirect_dns_uses_real_tun_and_policy_routes() {
    let (tun, cfg, mut peer) = setup().await;
    let guard = AutoRedirect::start(&cfg, "tun0", None).unwrap().unwrap();
    for (source, destination) in [("192.0.2.1:0", "203.0.113.53:53"),
        ("[2001:db8:1::1]:0", "[2001:db8:53::53]:53")] {
        let client = UdpSocket::bind(source).await.unwrap();
        client.connect(destination).await.unwrap();
        client.send(b"query").await.unwrap();
        let (packet, address) = timeout(Duration::from_secs(2), receive(&tun)).await.unwrap();
        assert_eq!(address, client.peer_addr().unwrap().ip()); // output keeps original destination.
        echo(&tun, packet).await;
        let mut buffer = [0; 64];
        let length = timeout(Duration::from_secs(2), client.recv(&mut buffer)).await.unwrap().unwrap();
        assert_eq!(&buffer[..length], b"query");
    }
    for (destination, synthetic) in [("203.0.113.53", "172.18.0.2"),
        ("2001:db8:53::53", "fdfe:dcba:9876::2")] {
        peer.send("udp", destination).await;
        let (packet, address) = timeout(Duration::from_secs(2), receive(&tun)).await.unwrap();
        assert_eq!(address, synthetic.parse::<IpAddr>().unwrap()); // prerouting DNAT actually reaches TUN.
        echo(&tun, packet).await;
        peer.expect("reply").await; // connected peer only accepts the original DNS endpoint.
    }
    guard.close().unwrap();
    routes::maybe_routes_clean_up(&cfg).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TUN, python3 and an isolated network namespace"]
async fn auto_redirect_dns_preserves_host_services_and_exclusions() {
    let (tun, cfg, mut peer) = setup().await;
    let redirect = tcp::bind(&cfg).unwrap().unwrap();
    let guard = AutoRedirect::start(&cfg, "tun0", Some(redirect.local_addr().unwrap().port())).unwrap().unwrap();
    for address in ["192.0.2.1", "10.23.0.1", "172.17.0.1", "2001:db8:1::1"] {
        let socket = (address.parse::<IpAddr>().unwrap(), 53);
        let server = UdpSocket::bind(socket).await.unwrap();
        peer.send_external("udp", address).await;
        let mut buffer = [0; 64];
        let (length, client) = timeout(Duration::from_secs(2), server.recv_from(&mut buffer)).await.unwrap().unwrap();
        server.send_to(&buffer[..length], client).await.unwrap();
        peer.expect("reply").await;
        let listener = TcpListener::bind(socket).await.unwrap();
        peer.send_external("tcp", address).await;
        let (mut stream, _) = timeout(Duration::from_secs(2), listener.accept()).await.unwrap().unwrap();
        let mut query = [0; 5];
        stream.read_exact(&mut query).await.unwrap();
        stream.write_all(&query).await.unwrap();
        peer.expect("reply").await;
    }
    assert!(timeout(Duration::from_millis(100), receive(&tun)).await.is_err());
    assert!(timeout(Duration::from_millis(100), redirect.accept()).await.is_err());
    guard.close().unwrap();
    for case in 0..6 {
        let mut scoped = cfg.clone();
        match case {
            0 => scoped.exclude_uid = vec![0],
            1 => scoped.exclude_interface = vec!["wan-route".into()],
            2 => scoped.include_interface = vec!["other0".into()],
            3 => scoped.route_exclude_address = vec!["203.0.113.53/32".parse().unwrap()],
            4 => scoped.routes = vec!["192.0.2.0/24".parse().unwrap()],
            5 => scoped.route_address_set = vec!["empty".into()],
            _ => unreachable!(),
        }
        let guard = AutoRedirect::start(&scoped, "tun0", None).unwrap().unwrap();
        let client = UdpSocket::bind("192.0.2.1:0").await.unwrap();
        client.send_to(b"query", "203.0.113.53:53").await.unwrap();
        assert!(timeout(Duration::from_millis(100), receive(&tun)).await.is_err(), "case {case}");
        guard.close().unwrap();
    }
    routes::maybe_routes_clean_up(&cfg).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TUN, python3 and an isolated network namespace"]
async fn auto_redirect_lan_gateway_dns_enters_tun_with_fw4_drop_policy() {
    use crate::proxy::utils::{ToCanonical, get_original_destination_addr};
    use super::super::{nft, openwrt::Firewall};

    let (tun, mut cfg, mut peer) = setup().await;
    cfg.route_exclude_address = vec!["10.23.0.0/24".parse().unwrap(), "fd00:23::/64".parse().unwrap()];
    let redirect = tcp::bind(&cfg).unwrap().unwrap();
    let guard = AutoRedirect::start(&cfg, "tun0", Some(redirect.local_addr().unwrap().port())).unwrap().unwrap();
    // Model fw4's actual chains and include order, not an independent accept
    // base chain. Forwarding remains DROP except for managed TUN traffic.
    let include = Firewall::rules("tun0", "test").unwrap();
    nft(&format!("table inet fw4 {{\n{include}\n\
        chain input {{ type filter hook input priority filter; policy drop; iifname {{ \"wan-test\", \"lo\" }} accept; }}\n\
        chain forward {{ type filter hook forward priority filter; policy drop; }}\n}}\n")).unwrap();
    for (gateway, synthetic) in [("10.23.0.1", "172.18.0.2"),
        ("fd00:23::1", "fdfe:dcba:9876::2")] {
        let original = (gateway.parse::<IpAddr>().unwrap(), 53);
        let dnsmasq = UdpSocket::bind(original).await.unwrap();
        // Send two queries on the same UDP socket/flow to verify conntrack-cached DNAT
        // packets still recover INPUT_MARK before mangle's local-destination bypass.
        peer.send_reuse("udp", gateway).await;
        for iteration in 0..2 {
            let (packet, destination) = timeout(Duration::from_secs(2), receive(&tun)).await.unwrap();
            assert_eq!(destination, synthetic.parse::<IpAddr>().unwrap());
            echo(&tun, packet).await;
            peer.expect("reply").await;
            if iteration == 0 {
                peer.expect("sent").await;
            }
        }
        let mut buffer = [0; 64];
        assert!(timeout(Duration::from_millis(50), dnsmasq.recv_from(&mut buffer)).await.is_err());
        let host_tcp = TcpListener::bind(original).await.unwrap();
        peer.send("tcp", gateway).await;
        let (mut accepted, _) = timeout(Duration::from_secs(2), redirect.accept()).await.unwrap().unwrap();
        assert_eq!(get_original_destination_addr(&accepted).unwrap().to_canonical(), original.into());
        let mut query = [0; 5];
        accepted.read_exact(&mut query).await.unwrap();
        accepted.write_all(&query).await.unwrap();
        peer.expect("reply").await;
        assert!(timeout(Duration::from_millis(50), host_tcp.accept()).await.is_err());
    }
    let policy = Command::new("nft").args(["list", "chain", "inet", "fw4", "forward"]).output().unwrap();
    assert!(String::from_utf8(policy.stdout).unwrap().contains("policy drop"));
    guard.close().unwrap();
    routes::maybe_routes_clean_up(&cfg).unwrap();
}
