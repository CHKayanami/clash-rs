use bytes::{Bytes, BytesMut};
use smoltcp::wire::{
    IpAddress, IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet, TcpPacket,
};

/// Splits a large GSO IP packet into standard MTU-sized IP packets.
pub fn split_gso_packet(packet: Bytes, mtu: usize) -> Vec<BytesMut> {
    if packet.len() <= mtu {
        return vec![BytesMut::from(&packet[..])];
    }

    match IpVersion::of_packet(&packet) {
        Ok(IpVersion::Ipv4) => split_ipv4_gso(packet, mtu),
        Ok(IpVersion::Ipv6) => split_ipv6_gso(packet, mtu),
        Err(_) => vec![BytesMut::from(&packet[..])],
    }
}

fn split_ipv4_gso(packet: Bytes, mtu: usize) -> Vec<BytesMut> {
    let Ok(ipv4) = Ipv4Packet::new_checked(&packet[..]) else {
        return vec![BytesMut::from(&packet[..])];
    };

    if ipv4.next_header() != IpProtocol::Tcp {
        return vec![BytesMut::from(&packet[..])];
    }

    let ip_header_len = ipv4.header_len() as usize;
    if packet.len() <= ip_header_len {
        return vec![BytesMut::from(&packet[..])];
    }

    let Ok(tcp) = TcpPacket::new_checked(&packet[ip_header_len..]) else {
        return vec![BytesMut::from(&packet[..])];
    };

    let tcp_header_len = tcp.header_len() as usize;
    let headers_len = ip_header_len + tcp_header_len;
    if packet.len() <= headers_len {
        return vec![BytesMut::from(&packet[..])];
    }

    let payload = &packet[headers_len..];
    let max_seg_payload = mtu.saturating_sub(headers_len);
    if max_seg_payload == 0 {
        return vec![BytesMut::from(&packet[..])];
    }

    let num_segments = payload.len().div_ceil(max_seg_payload);
    let mut segments = Vec::with_capacity(num_segments);
    let src_ip = ipv4.src_addr();
    let dst_ip = ipv4.dst_addr();
    let mut seq_num = tcp.seq_number();

    for (i, chunk) in payload.chunks(max_seg_payload).enumerate() {
        let is_last = (i + 1) * max_seg_payload >= payload.len();
        let total_packet_len = headers_len + chunk.len();
        let mut buf = BytesMut::with_capacity(total_packet_len);
        buf.resize(total_packet_len, 0);

        // 1. Copy & update IPv4 header
        buf[..ip_header_len].copy_from_slice(&packet[..ip_header_len]);
        let mut new_ip = Ipv4Packet::new_unchecked(&mut buf[..ip_header_len]);
        new_ip.set_total_len(total_packet_len as u16);
        new_ip.fill_checksum();

        // 2. Copy original TCP header (preserving all TCP options)
        buf[ip_header_len..headers_len].copy_from_slice(&packet[ip_header_len..headers_len]);

        // 3. Copy payload chunk
        buf[headers_len..total_packet_len].copy_from_slice(chunk);

        // 4. Update TCP header fields & recalculate checksum
        let mut new_tcp =
            TcpPacket::new_unchecked(&mut buf[ip_header_len..total_packet_len]);
        new_tcp.set_seq_number(seq_num);
        if !is_last {
            new_tcp.set_fin(false);
            new_tcp.set_psh(false);
        }
        new_tcp.fill_checksum(&IpAddress::Ipv4(src_ip), &IpAddress::Ipv4(dst_ip));

        segments.push(buf);
        seq_num = seq_num + chunk.len();
    }

    segments
}

fn split_ipv6_gso(packet: Bytes, mtu: usize) -> Vec<BytesMut> {
    let Ok(ipv6) = Ipv6Packet::new_checked(&packet[..]) else {
        return vec![BytesMut::from(&packet[..])];
    };

    if ipv6.next_header() != IpProtocol::Tcp {
        return vec![BytesMut::from(&packet[..])];
    }

    let ip_header_len = 40;
    if packet.len() <= ip_header_len {
        return vec![BytesMut::from(&packet[..])];
    }

    let Ok(tcp) = TcpPacket::new_checked(&packet[ip_header_len..]) else {
        return vec![BytesMut::from(&packet[..])];
    };

    let tcp_header_len = tcp.header_len() as usize;
    let headers_len = ip_header_len + tcp_header_len;
    if packet.len() <= headers_len {
        return vec![BytesMut::from(&packet[..])];
    }

    let payload = &packet[headers_len..];
    let max_seg_payload = mtu.saturating_sub(headers_len);
    if max_seg_payload == 0 {
        return vec![BytesMut::from(&packet[..])];
    }

    let num_segments = payload.len().div_ceil(max_seg_payload);
    let mut segments = Vec::with_capacity(num_segments);
    let src_ip = ipv6.src_addr();
    let dst_ip = ipv6.dst_addr();
    let mut seq_num = tcp.seq_number();

    for (i, chunk) in payload.chunks(max_seg_payload).enumerate() {
        let is_last = (i + 1) * max_seg_payload >= payload.len();
        let total_packet_len = headers_len + chunk.len();
        let mut buf = BytesMut::with_capacity(total_packet_len);
        buf.resize(total_packet_len, 0);

        // 1. Copy & update IPv6 header
        buf[..ip_header_len].copy_from_slice(&packet[..ip_header_len]);
        let mut new_ip = Ipv6Packet::new_unchecked(&mut buf[..ip_header_len]);
        new_ip.set_payload_len((tcp_header_len + chunk.len()) as u16);

        // 2. Copy original TCP header (preserving all TCP options)
        buf[ip_header_len..headers_len].copy_from_slice(&packet[ip_header_len..headers_len]);

        // 3. Copy payload chunk
        buf[headers_len..total_packet_len].copy_from_slice(chunk);

        // 4. Update TCP header fields & recalculate checksum
        let mut new_tcp =
            TcpPacket::new_unchecked(&mut buf[ip_header_len..total_packet_len]);
        new_tcp.set_seq_number(seq_num);
        if !is_last {
            new_tcp.set_fin(false);
            new_tcp.set_psh(false);
        }
        new_tcp.fill_checksum(&IpAddress::Ipv6(src_ip), &IpAddress::Ipv6(dst_ip));

        segments.push(buf);
        seq_num = seq_num + chunk.len();
    }

    segments
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{Ipv4Address, Ipv4Repr, TcpControl, TcpRepr, TcpTimestampRepr};

    #[test]
    fn test_gso_split_small_packet() {
        let small_pkt = Bytes::from_static(b"short packet");
        let res = split_gso_packet(small_pkt.clone(), 1500);
        assert_eq!(res.len(), 1);
        assert_eq!(&res[0][..], &small_pkt[..]);
    }

    #[test]
    fn test_gso_split_ipv4_tcp() {
        let src = Ipv4Address::new(192, 168, 1, 100);
        let dst = Ipv4Address::new(1, 1, 1, 1);
        let payload = vec![0x42; 3000];

        let ip_repr = Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: 20 + payload.len(),
            hop_limit: 64,
        };

        let tcp_repr = TcpRepr {
            src_port: 12345,
            dst_port: 80,
            control: TcpControl::Psh,
            seq_number: smoltcp::wire::TcpSeqNumber(1000),
            ack_number: Some(smoltcp::wire::TcpSeqNumber(2000)),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &payload,
        };

        let mut buffer = vec![0u8; ip_repr.buffer_len() + tcp_repr.buffer_len()];
        let mut ip_packet = Ipv4Packet::new_unchecked(&mut buffer);
        ip_repr.emit(&mut ip_packet, &smoltcp::phy::ChecksumCapabilities::default());

        let mut tcp_packet = TcpPacket::new_unchecked(ip_packet.payload_mut());
        tcp_repr.emit(
            &mut tcp_packet,
            &IpAddress::Ipv4(src),
            &IpAddress::Ipv4(dst),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );

        let gso_pkt = Bytes::from(buffer);
        let segments = split_gso_packet(gso_pkt, 1500);

        // 3000 bytes payload with 1460 MSS -> 1460 + 1460 + 80 = 3 segments
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].len(), 1500); // 40 hdr + 1460
        assert_eq!(segments[1].len(), 1500); // 40 hdr + 1460
        assert_eq!(segments[2].len(), 120);  // 40 hdr + 80

        // Verify each segment is valid IPv4 TCP
        for seg in &segments {
            let seg_ip = Ipv4Packet::new_checked(&seg[..]).unwrap();
            assert_eq!(seg_ip.next_header(), IpProtocol::Tcp);
            let seg_tcp = TcpPacket::new_checked(seg_ip.payload()).unwrap();
            assert_eq!(seg_tcp.src_port(), 12345);
            assert_eq!(seg_tcp.dst_port(), 80);
        }
    }

    #[test]
    fn test_gso_split_ipv6_tcp() {
        use smoltcp::wire::{Ipv6Address, Ipv6Repr};

        let src = Ipv6Address::new(0xfc00, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Address::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let payload = vec![0x42; 3000];

        let ip_repr = Ipv6Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: 20 + payload.len(),
            hop_limit: 64,
        };

        let tcp_repr = TcpRepr {
            src_port: 54321,
            dst_port: 443,
            control: TcpControl::Psh,
            seq_number: smoltcp::wire::TcpSeqNumber(5000),
            ack_number: Some(smoltcp::wire::TcpSeqNumber(6000)),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &payload,
        };

        let mut buffer = vec![0u8; ip_repr.buffer_len() + tcp_repr.buffer_len()];
        let mut ip_packet = Ipv6Packet::new_unchecked(&mut buffer);
        ip_repr.emit(&mut ip_packet);

        let mut tcp_packet = TcpPacket::new_unchecked(ip_packet.payload_mut());
        tcp_repr.emit(
            &mut tcp_packet,
            &IpAddress::Ipv6(src),
            &IpAddress::Ipv6(dst),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );

        let gso_pkt = Bytes::from(buffer);
        let segments = split_gso_packet(gso_pkt, 1500);

        // IPv6 hdr (40) + TCP hdr (20) = 60 bytes hdr
        // 1500 - 60 = 1440 max payload per seg
        // 3000 payload -> 1440 + 1440 + 120 = 3 segments
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].len(), 1500);
        assert_eq!(segments[1].len(), 1500);
        assert_eq!(segments[2].len(), 180); // 60 hdr + 120 payload

        for seg in &segments {
            let seg_ip = Ipv6Packet::new_checked(&seg[..]).unwrap();
            assert_eq!(seg_ip.next_header(), IpProtocol::Tcp);
            let seg_tcp = TcpPacket::new_checked(seg_ip.payload()).unwrap();
            assert_eq!(seg_tcp.src_port(), 54321);
            assert_eq!(seg_tcp.dst_port(), 443);
        }
    }

    #[test]
    fn test_gso_split_ipv4_tcp_with_options() {
        let src = Ipv4Address::new(192, 168, 1, 100);
        let dst = Ipv4Address::new(1, 1, 1, 1);
        let mut payload = vec![0u8; 3000];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }

        let tcp_repr = TcpRepr {
            src_port: 12345,
            dst_port: 80,
            control: TcpControl::Psh,
            seq_number: smoltcp::wire::TcpSeqNumber(1000),
            ack_number: Some(smoltcp::wire::TcpSeqNumber(2000)),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: Some(TcpTimestampRepr {
                tsval: 123456,
                tsecr: 654321,
            }), // 12-byte TCP option -> 32-byte header
            payload: &payload,
        };

        let ip_repr = Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.header_len() + payload.len(),
            hop_limit: 64,
        };

        let mut buffer = vec![0u8; ip_repr.buffer_len() + tcp_repr.buffer_len()];
        let mut ip_packet = Ipv4Packet::new_unchecked(&mut buffer);
        ip_repr.emit(&mut ip_packet, &smoltcp::phy::ChecksumCapabilities::default());

        let mut tcp_packet = TcpPacket::new_unchecked(ip_packet.payload_mut());
        tcp_repr.emit(
            &mut tcp_packet,
            &IpAddress::Ipv4(src),
            &IpAddress::Ipv4(dst),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );

        let gso_pkt = Bytes::from(buffer);
        let segments = split_gso_packet(gso_pkt, 1500);

        // Header is 20 (IP) + 32 (TCP with timestamp) = 52 bytes
        // Max payload per segment is 1500 - 52 = 1448
        // 3000 payload -> 1448 + 1448 + 104 = 3 segments
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].len(), 52 + 1448);
        assert_eq!(segments[1].len(), 52 + 1448);
        assert_eq!(segments[2].len(), 52 + 104);

        let mut reconstructed_payload = Vec::new();
        for (i, seg) in segments.iter().enumerate() {
            let seg_ip = Ipv4Packet::new_checked(&seg[..]).unwrap();
            assert_eq!(seg_ip.next_header(), IpProtocol::Tcp);
            let seg_tcp = TcpPacket::new_checked(seg_ip.payload()).unwrap();
            assert_eq!(seg_tcp.header_len(), 32, "TCP options must be preserved");
            assert_eq!(seg_tcp.src_port(), 12345);
            assert_eq!(seg_tcp.dst_port(), 80);
            if i < segments.len() - 1 {
                assert!(!seg_tcp.psh());
                assert!(!seg_tcp.fin());
            } else {
                assert!(seg_tcp.psh());
            }
            reconstructed_payload.extend_from_slice(seg_tcp.payload());
        }

        assert_eq!(reconstructed_payload, payload, "Payload must not be corrupted");
    }
}
