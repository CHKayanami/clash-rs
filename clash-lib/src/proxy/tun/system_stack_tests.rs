use super::*;
use std::{io::ErrorKind, sync::Arc};
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr};

#[tokio::test]
async fn cancelling_system_listener_closes_accepted_connections() {
    use crate::{app::{dispatcher::{Dispatcher, StatisticsManager},
        dns::{MockClashResolver, ThreadSafeDNSResolver},
        outbound::manager::OutboundManager, router::Router},
        config::{def::RunMode, internal::config::DnsHijack},
        proxy::tun::{stream::TcpContext, tcp::run_system_listener}};
    use tokio::{io::AsyncReadExt, net::{TcpListener, TcpStream}, time::timeout};

    let resolver: ThreadSafeDNSResolver = Arc::new(MockClashResolver::new());
    let router = Arc::new(Router::new(vec![], HashMap::new(), resolver.clone(),
        None, None, None, None, None, String::new()).await.unwrap());
    let dispatcher = Arc::new(Dispatcher::new(
        Arc::new(OutboundManager::new_for_test(HashMap::new())), router,
        resolver.clone(), RunMode::Direct, StatisticsManager::new(), None, None, true,
    ));
    let context = Arc::new(TcpContext { dispatcher, resolver, so_mark: None,
        dns_hijack: DnsHijack::All, strict_route: false, exclude_routes: Arc::new(vec![]) });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let source = client.local_addr().unwrap();
    let destination = "192.0.2.1:53".parse().unwrap();
    let nat = Arc::new(SystemTcpNat::new());
    {
        let mut state = nat.state.write();
        state.addresses.insert((source, destination), source.port());
        state.ports.insert(source.port(), TcpSession::new(source, destination));
    }
    // The hijacked stream waits for a DNS length prefix. Wait until the relay
    // owns its context before cancelling, so a queued accept cannot pass this test.
    let task = tokio::spawn(run_system_listener(listener, nat, context.clone()));
    timeout(Duration::from_secs(2), async {
        while Arc::strong_count(&context) < 3 { tokio::task::yield_now().await; }
    }).await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let result = timeout(Duration::from_secs(2), client.read(&mut [0u8; 1])).await
        .expect("accepted stream survived listener cancellation");
    match result {
        Ok(count) => assert_eq!(count, 0),
        Err(error) => assert_eq!(error.kind(), ErrorKind::ConnectionReset),
    }
}

#[test]
fn test_system_tcp_nat_lookup() {
    let nat = SystemTcpNat::new();
    let src: SocketAddr = "192.168.1.100:54321".parse().unwrap();
    let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();

    let port1 = nat.lookup(src, dst).unwrap();
    assert!(port1 >= 10000);

    let port2 = nat.lookup(src, dst).unwrap();
    assert_eq!(port1, port2);

    let session = nat.lookup_back(port1).expect("session must exist");
    assert_eq!(session.0, src);
    assert_eq!(session.1, dst);
}

#[test]
fn test_system_ipv4_tcp_bidirectional_rewrite() {
    let nat = SystemTcpNat::new();
    let server_addr = Ipv4Addr::new(198, 18, 0, 1);
    let client_addr = Ipv4Addr::new(198, 18, 0, 2);
    let listener_port = 54321;

    let client_src = Ipv4Address::new(10, 0, 0, 5);
    let target_dst = Ipv4Address::new(1, 1, 1, 1);
    let client_port = 12345;
    let target_port = 80;

    // 1. Build an outbound client -> target TCP SYN packet
    let mut packet = vec![0u8; 40];
    let ip_repr = Ipv4Repr {
        src_addr: client_src,
        dst_addr: target_dst,
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    };
    let tcp_repr = TcpRepr {
        src_port: client_port,
        dst_port: target_port,
        control: TcpControl::Syn,
        seq_number: smoltcp::wire::TcpSeqNumber(100),
        ack_number: None,
        window_len: 65535,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    ip_repr.emit(&mut Ipv4Packet::new_unchecked(&mut packet[..20]), &smoltcp::phy::ChecksumCapabilities::default());
    tcp_repr.emit(
        &mut TcpPacket::new_unchecked(&mut packet[20..]),
        &IpAddress::Ipv4(client_src),
        &IpAddress::Ipv4(target_dst),
        &smoltcp::phy::ChecksumCapabilities::default(),
    );

    // 2. Process outbound packet (Client -> Target)
    let res = process_ipv4_tcp(&mut packet, server_addr, client_addr, listener_port, &nat);
    assert_eq!(res, Some(true));

    let rewritten_ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
    let rewritten_tcp = TcpPacket::new_checked(&packet[20..]).unwrap();

    assert_eq!(rewritten_ip.src_addr(), Ipv4Address::from(client_addr));
    assert_eq!(rewritten_ip.dst_addr(), Ipv4Address::from(server_addr));
    let nat_port = rewritten_tcp.src_port();
    assert_eq!(rewritten_tcp.dst_port(), listener_port);
    assert!(nat_port >= 10000);

    // 3. Build return packet from OS kernel (Server -> Client nat_port)
    let mut reply_packet = vec![0u8; 40];
    let reply_ip_repr = Ipv4Repr {
        src_addr: Ipv4Address::from(server_addr),
        dst_addr: Ipv4Address::from(client_addr),
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    };
    let reply_tcp_repr = TcpRepr {
        src_port: listener_port,
        dst_port: nat_port,
        control: TcpControl::Syn,
        seq_number: smoltcp::wire::TcpSeqNumber(500),
        ack_number: Some(smoltcp::wire::TcpSeqNumber(101)),
        window_len: 65535,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    reply_ip_repr.emit(&mut Ipv4Packet::new_unchecked(&mut reply_packet[..20]), &smoltcp::phy::ChecksumCapabilities::default());
    reply_tcp_repr.emit(
        &mut TcpPacket::new_unchecked(&mut reply_packet[20..]),
        &IpAddress::Ipv4(Ipv4Address::from(server_addr)),
        &IpAddress::Ipv4(Ipv4Address::from(client_addr)),
        &smoltcp::phy::ChecksumCapabilities::default(),
    );

    // 4. Process return packet (Server -> Client)
    let res_reply = process_ipv4_tcp(&mut reply_packet, server_addr, client_addr, listener_port, &nat);
    assert_eq!(res_reply, Some(true));

    let restored_ip = Ipv4Packet::new_checked(&reply_packet[..]).unwrap();
    let restored_tcp = TcpPacket::new_checked(&reply_packet[20..]).unwrap();

    assert_eq!(restored_ip.src_addr(), target_dst);
    assert_eq!(restored_ip.dst_addr(), client_src);
    assert_eq!(restored_tcp.src_port(), target_port);
    assert_eq!(restored_tcp.dst_port(), client_port);
}

#[test]
fn test_system_tcp_nat_different_destinations() {
    let nat = SystemTcpNat::new();
    let src: SocketAddr = "192.168.1.100:54321".parse().unwrap();
    let dst1: SocketAddr = "8.8.8.8:443".parse().unwrap();
    let dst2: SocketAddr = "1.1.1.1:443".parse().unwrap();

    let port1 = nat.lookup(src, dst1).unwrap();
    let port2 = nat.lookup(src, dst2).unwrap();
    assert_ne!(port1, port2, "different destinations must not share the same nat port");

    let session1 = nat.lookup_back(port1).expect("session1 must exist");
    let session2 = nat.lookup_back(port2).expect("session2 must exist");
    assert_eq!(session1.1, dst1);
    assert_eq!(session2.1, dst2);

    // Verify cleanup removes specific 4-tuple
    nat.cleanup_timeout(Duration::from_secs(0));
    assert!(nat.lookup_back(port1).is_none());
    assert!(nat.lookup_back(port2).is_none());
}

#[test]
fn full_nat_table_never_overwrites_an_existing_mapping() {
    let nat = SystemTcpNat::new();
    let source: SocketAddr = "192.0.2.1:12345".parse().unwrap();
    let first_target: SocketAddr = "198.51.100.1:1".parse().unwrap();
    let first = nat.lookup(source, first_target).unwrap();
    for port in 2..=NAT_PORT_COUNT as u16 {
        let target = SocketAddr::from(([198, 51, 100, 1], port));
        assert!(nat.lookup(source, target).is_some());
    }
    assert!(nat.lookup(source, "203.0.113.1:443".parse().unwrap()).is_none());
    assert_eq!(nat.lookup_back(first).unwrap().1, first_target);
    assert_eq!(nat.lookup(source, first_target), Some(first));
    nat.cleanup_timeout(Duration::ZERO);
    assert!(nat.lookup(source, "203.0.113.1:443".parse().unwrap()).is_some());
}

#[test]
fn idle_cleanup_reclaims_expired_mappings() {
    let nat = SystemTcpNat::new();
    let port = nat.lookup("192.0.2.1:12345".parse().unwrap(),
        "198.51.100.1:443".parse().unwrap()).unwrap();
    let endpoints = nat.lookup_back(port).unwrap();
    nat.state.read().ports[&port].last_active_us.store(0, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(2));
    nat.cleanup_timeout(Duration::from_micros(1));
    assert!(nat.lookup_back(port).is_none());
    assert!(nat.state.read().addresses.is_empty());
    assert_eq!(endpoints.0, "192.0.2.1:12345".parse::<SocketAddr>().unwrap());
}

#[test]
fn incremental_nat_checksums_match_full_checksums_for_both_ip_families() {
    for ipv6 in [false, true] {
        for payload_len in [0, 1, 1399, 1400, 64000] {
            let header_len = if ipv6 { 40 } else { 20 };
            let mut packet = vec![0; header_len + 20 + payload_len];
            let (source, target, server, client) = if ipv6 {
                ("2001:db8::1234", "2001:db8:1::abcd", "fd00::1", "fd00::2")
            } else {
                ("192.0.2.123", "198.51.100.234", "198.18.0.1", "198.18.0.2")
            };
            let source: IpAddr = source.parse().unwrap();
            let target: IpAddr = target.parse().unwrap();
            let server: IpAddr = server.parse().unwrap();
            let client: IpAddr = client.parse().unwrap();
            let src = IpAddress::from(source);
            let dst = IpAddress::from(target);
            if ipv6 {
                packet[0] = 0x60;
                packet[4..6].copy_from_slice(&((20 + payload_len) as u16).to_be_bytes());
                packet[6] = 6;
                packet[7] = 64;
                let (IpAddr::V6(source), IpAddr::V6(target)) = (source, target) else { unreachable!() };
                packet[8..24].copy_from_slice(&source.octets());
                packet[24..40].copy_from_slice(&target.octets());
            } else {
                let repr = Ipv4Repr { src_addr: match src { IpAddress::Ipv4(ip) => ip, _ => unreachable!() },
                    dst_addr: match dst { IpAddress::Ipv4(ip) => ip, _ => unreachable!() },
                    next_header: IpProtocol::Tcp, payload_len: 20 + payload_len, hop_limit: 64 };
                repr.emit(&mut Ipv4Packet::new_unchecked(&mut packet[..20]),
                    &smoltcp::phy::ChecksumCapabilities::default());
            }
            packet[header_len + 12] = 0x50;
            for (index, byte) in packet[header_len + 20..].iter_mut().enumerate() { *byte = index as u8; }
            let mut tcp = TcpPacket::new_unchecked(&mut packet[header_len..]);
            tcp.set_src_port(12345);
            tcp.set_dst_port(443);
            tcp.fill_checksum(&src, &dst);
            let nat = SystemTcpNat::new();
            let info4 = match (server, client) {
                (IpAddr::V4(server), IpAddr::V4(client)) => Some((server, client, 23456)),
                _ => None,
            };
            let info6 = match (server, client) {
                (IpAddr::V6(server), IpAddr::V6(client)) => Some((server, client, 23456)),
                _ => None,
            };
            assert_eq!(process_system_tcp_packet(&mut packet, info4, info6, &nat), Some(true));
            let tcp = TcpPacket::new_checked(&packet[header_len..]).unwrap();
            assert!(tcp.verify_checksum(&IpAddress::from(client), &IpAddress::from(server)));
            if !ipv6 { assert!(Ipv4Packet::new_checked(&packet[..]).unwrap().verify_checksum()); }
        }
    }
}
