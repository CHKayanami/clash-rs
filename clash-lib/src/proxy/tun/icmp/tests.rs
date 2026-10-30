use super::*;
use bytes::BytesMut;
use smoltcp::{phy::ChecksumCapabilities, wire::{IpProtocol, Ipv4Packet, Ipv4Repr,
    Ipv6Packet, Ipv6Repr, Icmpv4Packet, Icmpv4Message, Icmpv6Packet, Icmpv6Message}};
use super::super::packet_queue;

fn request(ipv6: bool, sequence: u16) -> BytesMut {
    let length = if ipv6 { 56 } else { 36 };
    let mut bytes = BytesMut::zeroed(length);
    if ipv6 {
        let source = "2001:db8::2".parse().unwrap();
        let destination = "2001:db8::3".parse().unwrap();
        let mut ip = Ipv6Packet::new_unchecked(&mut bytes[..]);
        Ipv6Repr { src_addr: source, dst_addr: destination, next_header: IpProtocol::Icmpv6,
            payload_len: 16, hop_limit: 47 }.emit(&mut ip);
        let mut echo = Icmpv6Packet::new_unchecked(ip.payload_mut());
        echo.set_msg_type(Icmpv6Message::EchoRequest);
        echo.set_msg_code(0);
        echo.set_echo_ident(1234);
        echo.set_echo_seq_no(sequence);
        echo.payload_mut().copy_from_slice(b"testdata");
        echo.fill_checksum(&source, &destination);
    } else {
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
        Ipv4Repr { src_addr: "192.0.2.2".parse().unwrap(), dst_addr: "198.51.100.3".parse().unwrap(),
            next_header: IpProtocol::Icmp, payload_len: 16, hop_limit: 47 }
            .emit(&mut ip, &ChecksumCapabilities::default());
        let mut echo = Icmpv4Packet::new_unchecked(ip.payload_mut());
        echo.set_msg_type(Icmpv4Message::EchoRequest);
        echo.set_msg_code(0);
        echo.set_echo_ident(1234);
        echo.set_echo_seq_no(sequence);
        echo.data_mut().copy_from_slice(b"testdata");
        echo.fill_checksum();
    }
    bytes
}

fn kernel_reply(request: &Request) -> Vec<u8> {
    let mut payload = request.payload.clone();
    if request.flow.source.is_ipv4() {
        let mut echo = Icmpv4Packet::new_unchecked(&mut payload[..]);
        echo.set_msg_type(Icmpv4Message::EchoReply);
        echo.set_echo_ident(4567);
        echo.fill_checksum();
    } else {
        let mut echo = Icmpv6Packet::new_unchecked(&mut payload[..]);
        echo.set_msg_type(Icmpv6Message::EchoReply);
        echo.set_echo_ident(4567);
        // Production receives a kernel-validated checksum against physical
        // addresses. The reply builder must replace it for the virtual pair.
        echo.set_checksum(0x1234);
    }
    payload
}

fn check_reply(bytes: &[u8], expected: Flow, sequence: u16, hop_limit: u8) {
    if expected.source.is_ipv4() {
        let ip = Ipv4Packet::new_checked(bytes).unwrap();
        assert_eq!(ip.hop_limit(), hop_limit);
        assert_eq!(IpAddr::from(ip.src_addr()), expected.destination);
        assert_eq!(IpAddr::from(ip.dst_addr()), expected.source);
        assert!(ip.verify_checksum());
        let echo = Icmpv4Packet::new_checked(ip.payload()).unwrap();
        assert_eq!(echo.msg_type(), Icmpv4Message::EchoReply);
        assert_eq!(echo.echo_ident(), expected.identifier);
        assert_eq!(echo.echo_seq_no(), sequence);
        assert_eq!(echo.data(), b"testdata");
        assert!(echo.verify_checksum());
    } else {
        let ip = Ipv6Packet::new_checked(bytes).unwrap();
        assert_eq!(ip.hop_limit(), hop_limit);
        assert_eq!(IpAddr::from(ip.src_addr()), expected.destination);
        assert_eq!(IpAddr::from(ip.dst_addr()), expected.source);
        let echo = Icmpv6Packet::new_checked(ip.payload()).unwrap();
        assert_eq!(echo.msg_type(), Icmpv6Message::EchoReply);
        assert_eq!(echo.echo_ident(), expected.identifier);
        assert_eq!(echo.echo_seq_no(), sequence);
        assert_eq!(echo.payload(), b"testdata");
        assert!(echo.verify_checksum(&ip.src_addr(), &ip.dst_addr()));
    }
}

#[test]
fn echo_translation_preserves_addresses_identifiers_sequence_and_payload() {
    for ipv6 in [false, true] {
        let parsed = packet::decode(&request(ipv6, 42), 1500).unwrap().unwrap();
        assert_eq!(parsed.hop_limit, 47);
        let bytes = packet::reply(parsed.flow, &kernel_reply(&parsed), 1500, 37).unwrap();
        check_reply(&bytes, parsed.flow, 42, 37);
        assert!(packet::reply(parsed.flow, &parsed.payload, 1500, 37).is_none());
        assert!(packet::reply(parsed.flow, &kernel_reply(&parsed), 20, 37).is_none());
    }
}

#[test]
fn corrupted_echo_and_fragmented_ipv4_are_rejected() {
    for ipv6 in [false, true] {
        let mut bytes = request(ipv6, 1);
        *bytes.last_mut().unwrap() ^= 1;
        assert!(packet::decode(&bytes, 1500).is_err());
    }
    let mut bytes = request(false, 1);
    let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
    ip.set_more_frags(true);
    ip.fill_checksum();
    assert!(packet::decode(&bytes, 1500).is_err());
}

#[test]
fn local_echo_is_left_to_stack_and_direct_admission_is_bounded() {
    let (replies, _receiver) = packet_queue::channel();
    let (client, mut relay) = channel(1500, replies, None);
    assert!(!client.intercept(&request(false, 1), |_| true));
    assert!(relay.receiver.try_recv().is_err());
    for sequence in 0..INBOUND_PACKETS as u16 + 5 {
        assert!(client.intercept(&request(false, sequence), |_| false));
    }
    assert_eq!(relay.receiver.len(), INBOUND_PACKETS);
    assert!(!client.intercept(&[0x45; 20], |_| false));
}

#[tokio::test]
async fn forwarding_waits_for_real_reply_and_restores_virtual_packet() {
    for ipv6 in [false, true] {
        let bind = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" };
        let host = UdpSocket::bind(bind).await.unwrap();
        socket::set_hop_limit(&host, ipv6, 73).unwrap();
        let outbound = UdpSocket::bind(bind).await.unwrap();
        socket::enable_receive_hop_limit(&outbound, ipv6).unwrap();
        outbound.connect(host.local_addr().unwrap()).await.unwrap();
        let (replies, mut receiver) = packet_queue::channel();
        let (requests, incoming) = mpsc::channel(SESSION_PACKETS);
        let parsed = packet::decode(&request(ipv6, 99), 1500).unwrap().unwrap();
        let flow = parsed.flow;
        let response = kernel_reply(&parsed);
        let task = tokio::spawn(session(outbound, flow, incoming, replies, 1500));
        requests.send(parsed).await.unwrap();
        let mut buffer = [0; 128];
        let (length, peer) = timeout(Duration::from_secs(1), host.recv_from(&mut buffer)).await.unwrap().unwrap();
        assert_eq!(length, 16);
        assert!(timeout(Duration::from_millis(20), receiver.recv()).await.is_err(),
            "must not fabricate remote success before an actual reply");
        host.send_to(&response, peer).await.unwrap();
        let reply = timeout(Duration::from_secs(1), receiver.recv()).await.unwrap().unwrap();
        check_reply(&reply.bytes, flow, 99, 73);
        drop(requests);
        timeout(Duration::from_secs(1), task).await.unwrap().unwrap().unwrap();
    }
}

#[tokio::test]
async fn relay_exits_cleanly_when_input_closes() {
    let (replies, _receiver) = packet_queue::channel();
    let (client, relay) = channel(1500, replies, None);
    drop(client);
    timeout(Duration::from_secs(1), relay.run()).await.unwrap().unwrap();
}


#[test]
fn gateway_exemption_does_not_include_other_hosts_in_its_subnet() {
    let ipv4 = "10.0.0.1/24".parse().unwrap();
    let ipv6 = Some("fd00::1/64".parse().unwrap());
    assert!(is_gateway("10.0.0.1".parse().unwrap(), ipv4, ipv6));
    assert!(is_gateway("fd00::1".parse().unwrap(), ipv4, ipv6));
    assert!(!is_gateway("10.0.0.99".parse().unwrap(), ipv4, ipv6));
    assert!(!is_gateway("fd00::99".parse().unwrap(), ipv4, ipv6));
    assert!(!is_gateway("fd00::1".parse().unwrap(), ipv4, None));
}

#[tokio::test]
async fn missing_hop_limit_is_reported_instead_of_fabricated() {
    let host = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    host.send_to(b"reply", receiver.local_addr().unwrap()).await.unwrap();
    let mut buffer = [0; 32];
    let error = timeout(Duration::from_secs(1), socket::receive(&receiver, &mut buffer, false))
        .await.unwrap().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}
