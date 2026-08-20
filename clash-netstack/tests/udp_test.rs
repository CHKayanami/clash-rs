use bytes::Bytes;
use std::net::SocketAddr;
use watfaq_netstack::{NetStack, Packet, UdpPacket, parse_udp_packet};

#[test]
fn test_parse_udp_v4() {
    // Construct valid IPv4 + UDP packet
    // IPv4: src 192.168.1.100, dst 8.8.8.8, total_len = 28 + 5 = 33
    // UDP: src_port 12345, dst_port 53, len = 8 + 5 = 13, payload = b"hello"
    let raw = vec![
        0x45, 0x00, 0x00, 0x21, // Version 4, IHL 5, Total Len 33
        0x00, 0x01, 0x40, 0x00, // ID 1, DF flag
        0x40, 0x11, 0x00, 0x00, // TTL 64, Proto 17 (UDP), checksum 0
        192, 168, 1, 100,       // Src IP
        8, 8, 8, 8,             // Dst IP
        0x30, 0x39, 0x00, 0x35, // Src Port 12345, Dst Port 53
        0x00, 0x0d, 0x00, 0x00, // UDP Len 13, Checksum 0
        b'h', b'e', b'l', b'l', b'o', // Payload
    ];

    let parsed = parse_udp_packet(&raw);
    assert!(parsed.is_some());
    let (src, dst, payload_range) = parsed.unwrap();
    assert_eq!(src, "192.168.1.100:12345".parse::<SocketAddr>().unwrap());
    assert_eq!(dst, "8.8.8.8:53".parse::<SocketAddr>().unwrap());
    assert_eq!(&raw[payload_range], b"hello");
}

#[test]
fn test_parse_udp_v6() {
    // IPv6: src 2001:db8::1, dst 2001:4860:4860::8888
    // UDP: src_port 54321, dst_port 443, payload = b"quic_packet"
    let mut raw = vec![0u8; 40 + 8 + 11];
    raw[0] = 0x60; // Version 6
    let payload_len = 8 + 11;
    raw[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    raw[6] = 17; // UDP
    raw[7] = 64; // Hop limit

    let src_ip: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_ip: std::net::Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
    raw[8..24].copy_from_slice(&src_ip.octets());
    raw[24..40].copy_from_slice(&dst_ip.octets());

    // UDP header
    raw[40..42].copy_from_slice(&54321u16.to_be_bytes());
    raw[42..44].copy_from_slice(&443u16.to_be_bytes());
    raw[44..46].copy_from_slice(&(payload_len as u16).to_be_bytes());
    raw[48..].copy_from_slice(b"quic_packet");

    let parsed = parse_udp_packet(&raw);
    assert!(parsed.is_some());
    let (src, dst, payload_range) = parsed.unwrap();
    assert_eq!(src, "[2001:db8::1]:54321".parse::<SocketAddr>().unwrap());
    assert_eq!(dst, "[2001:4860:4860::8888]:443".parse::<SocketAddr>().unwrap());
    assert_eq!(&raw[payload_range], b"quic_packet");
}

#[tokio::test]
async fn test_udp_roundtrip_and_batch() {
    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut sink, _stream) = stack.split();
    let (mut r, mut w) = udp_socket.split();

    use futures::SinkExt;

    // Send 10 packets into stack sink
    for i in 0..10 {
        let mut raw = vec![
            0x45, 0x00, 0x00, 0x22,
            0x00, 0x01, 0x40, 0x00,
            0x40, 0x11, 0x00, 0x00,
            10, 0, 0, 2,
            1, 1, 1, 1,
            0x10, 0x00, 0x00, 0x35,
            0x00, 0x0e, 0x00, 0x00,
        ];
        raw.extend_from_slice(format!("pkt_{i:02}").as_bytes());

        sink.send(Packet::new(raw)).await.unwrap();
    }

    // Batch receive
    let mut batch = Vec::new();
    let count = r.recv_many(&mut batch, 32).await;
    assert_eq!(count, 10);
    assert_eq!(batch.len(), 10);

    for (i, pkt) in batch.into_iter().enumerate() {
        assert_eq!(pkt.local_addr, "10.0.0.2:4096".parse::<SocketAddr>().unwrap());
        assert_eq!(pkt.remote_addr, "1.1.1.1:53".parse::<SocketAddr>().unwrap());
        assert_eq!(pkt.data(), format!("pkt_{i:02}").as_bytes());
    }

    // Test send back with SplitWrite
    let reply = UdpPacket {
        data: Packet::new(Bytes::from_static(b"dns_reply")),
        local_addr: "1.1.1.1:53".parse().unwrap(),
        remote_addr: "10.0.0.2:4096".parse().unwrap(),
    };
    w.send(reply).await.unwrap();
}
