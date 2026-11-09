use super::*;
use smoltcp::{phy::ChecksumCapabilities, wire::{IpAddress, Ipv4Repr, TcpControl, TcpRepr, TcpSeqNumber, UdpPacket as WireUdpPacket, checksum}};

fn tcp_frame(length: usize, ipv6: bool) -> Vec<u8> {
    let (source, destination) = if ipv6 {
        ("2001:db8::1".parse::<IpAddress>().unwrap(), "2001:db8::2".parse().unwrap())
    } else { (IpAddress::v4(192, 0, 2, 1), IpAddress::v4(192, 0, 2, 2)) };
    let payload = vec![0x5a; length];
    let tcp = TcpRepr { src_port: 1234, dst_port: 443, control: TcpControl::Psh,
        seq_number: TcpSeqNumber(1), ack_number: Some(TcpSeqNumber(1)), window_len: 8192,
        window_scale: None, max_seg_size: None, sack_permitted: false, sack_ranges: [None; 3],
        timestamp: None, payload: &payload };
    let ip_length = if ipv6 { 40 } else { 20 };
    let mut data = vec![0; ip_length + tcp.buffer_len()];
    let checksums = ChecksumCapabilities::default();
    if ipv6 {
        let mut ip = Ipv6Packet::new_unchecked(&mut data[..40]);
        ip.set_version(6); ip.set_next_header(IpProtocol::Tcp); ip.set_payload_len(tcp.buffer_len() as u16);
        let (IpAddress::Ipv6(source), IpAddress::Ipv6(destination)) = (source, destination) else { unreachable!() };
        ip.set_src_addr(source); ip.set_dst_addr(destination);
    } else {
        let (IpAddress::Ipv4(source), IpAddress::Ipv4(destination)) = (source, destination) else { unreachable!() };
        Ipv4Repr { src_addr: source, dst_addr: destination,
            next_header: IpProtocol::Tcp, payload_len: tcp.buffer_len(), hop_limit: 64 }
            .emit(&mut Ipv4Packet::new_unchecked(&mut data[..20]), &checksums);
    }
    tcp.emit(&mut TcpPacket::new_unchecked(&mut data[ip_length..]), &source, &destination, &checksums);
    data
}

#[test]
fn tcp_super_packet_keeps_payload_and_validates_checksum_metadata() {
    for ipv6 in [false, true] {
        let data = tcp_frame(32 * 1024, ipv6);
        let header = transmit_header(&data, Some(1448)).unwrap();
        let packet = receive_tcp(&header, &data).unwrap().unwrap();
        assert_eq!(packet.data(), data);
        assert_eq!(header[1], if ipv6 { 4 } else { 1 });
        assert_eq!(u16::from_ne_bytes([header[4], header[5]]), 1448);
        let mut bad = header;
        bad[8] = 6;
        assert!(receive_tcp(&bad, &data).is_err());
        bad = header; bad[4..6].fill(0);
        assert!(receive_tcp(&bad, &data).is_err());
        bad = header; bad[1] = 3;
        assert!(receive_tcp(&bad, &data).is_err());
        for length in 0..40 { assert!(receive_tcp(&header, &data[..length]).is_err()); }
    }
}

#[test]
fn ordinary_frames_have_no_offload_header_flags() {
    let data = tcp_frame(32, false);
    assert_eq!(transmit_header(&data, None).unwrap(), [0; HEADER_LEN]);
    assert!(transmit_header(&data, Some(1448)).is_err());
    assert!(transmit_header(&data, Some(0)).is_err());
}

#[test]
fn udp_group_keeps_datagram_boundaries_and_stops_at_different_flows() {
    use std::net::SocketAddr;
    use clash_netstack::UdpPacket as StackUdpPacket;
    for ipv6 in [false, true] {
        let source: SocketAddr = if ipv6 { "[2001:db8::1]:1234" } else { "192.0.2.1:1234" }.parse().unwrap();
        let destination = if ipv6 { "[2001:db8::2]:4321" } else { "192.0.2.2:4321" }.parse().unwrap();
        let mut packets = (0..4).map(|value| StackUdpPacket::from((Bytes::from(vec![value; 1200]), source, destination))
            .encode().unwrap()).collect::<Vec<_>>();
        let mut header = [0; 68];
        let group = udp::group(&packets, &mut header).unwrap();
        assert_eq!(group.count, 4);
        assert_eq!(group.payload_len, 1200);
        assert_eq!(group.header_len, if ipv6 { 48 } else { 28 });
        assert_eq!(group.virtio[0..2], [1, 5]);
        assert_eq!(u16::from_ne_bytes([group.virtio[4], group.virtio[5]]), 1200);
        let ip_len = group.header_len - 8;
        assert_eq!(WireUdpPacket::new_unchecked(&header[ip_len..]).len(), 4808);
        if !ipv6 { assert!(Ipv4Packet::new_unchecked(&header[..20]).verify_checksum()); }
        let outgoing = write::WriteFrame::new(&packets, true, 1500).unwrap();
        assert_eq!(outgoing.count, 4);
        // Offload segments must fit the link MTU; jumbo datagrams remain plain.
        assert_eq!(write::WriteFrame::new(&packets, true, 1200).unwrap().count, 1);
        let mut frame = outgoing.vectors()[..outgoing.vector_count()].iter()
            .flat_map(|slice| slice.iter().copied()).collect::<Vec<_>>();
        assert_eq!(frame.len(), outgoing.length());
        let mut decoded = Vec::new();
        receive::decode(&mut frame, &mut decoded).unwrap();
        assert_eq!(decoded.len(), 4);
        for (index, packet) in decoded.iter().enumerate() {
            let udp = WireUdpPacket::new_checked(&packet[ip_len..]).unwrap();
            assert_eq!(udp.payload(), vec![index as u8; 1200]);
            assert!(udp.verify_checksum(&IpAddress::from(source.ip()), &IpAddress::from(destination.ip())));
        }
        packets[2] = StackUdpPacket::from((Bytes::from(vec![2; 1200]), source,
            if ipv6 { "[2001:db8::3]:4321" } else { "192.0.2.3:4321" }.parse().unwrap())).encode().unwrap();
        assert_eq!(udp::group(&packets, &mut header).unwrap().count, 2);
        assert!(udp::group(&packets[..1], &mut header).is_none());
        let mut bad = frame.clone(); bad[4..6].fill(0);
        assert!(receive::decode(&mut bad, &mut Vec::new()).is_err());
    }
}

#[test]
fn ordinary_partial_udp_checksum_completes_seed_once() {
    use std::net::SocketAddr;
    use clash_netstack::UdpPacket as StackUdpPacket;
    for ipv6 in [false, true] {
        let source: SocketAddr = if ipv6 { "[2001:db8::1]:1234" } else { "192.0.2.1:1234" }.parse().unwrap();
        let destination = if ipv6 { "[2001:db8::2]:4321" } else { "192.0.2.2:4321" }.parse().unwrap();
        let packet = StackUdpPacket::from((Bytes::from(vec![0x5a; 1201]), source, destination)).encode().unwrap();
        let mut header = [0; HEADER_LEN];
        let ip_len = if ipv6 { 40 } else { 20 };
        header[0] = 1;
        header[6..8].copy_from_slice(&(ip_len as u16).to_ne_bytes());
        header[8..10].copy_from_slice(&6u16.to_ne_bytes());
        let mut frame = header.to_vec(); frame.extend_from_slice(packet.data());
        let length = frame.len() - HEADER_LEN - ip_len;
        let seed = checksum::pseudo_header(&IpAddress::from(source.ip()),
            &IpAddress::from(destination.ip()), IpProtocol::Udp, length as u32);
        WireUdpPacket::new_unchecked(&mut frame[HEADER_LEN + ip_len..]).set_checksum(seed);
        let mut packets = Vec::new();
        receive::decode(&mut frame, &mut packets).unwrap();
        assert_eq!(packets[0].data(), packet.data());
    }
}

#[test]
fn native_tcp_write_borrows_payload_and_retains_segmentation_header() {
    use super::super::frame::Frame;
    struct TcpGso(Vec<u8>);
    impl AsRef<[u8]> for TcpGso { fn as_ref(&self) -> &[u8] { &self.0 } }
    impl Frame for TcpGso { fn tcp_segmentation(&self) -> Option<u16> { Some(1448) } }
    for ipv6 in [false, true] {
        let packets = [TcpGso(tcp_frame(32 * 1024, ipv6))];
        let frame = write::WriteFrame::new(&packets, true, 1500).unwrap();
        let vectors = frame.vectors();
        assert_eq!(frame.count, 1);
        assert_eq!(frame.vector_count(), 2);
        assert_eq!(vectors[1].as_ptr(), packets[0].0.as_ptr());
        assert_eq!(&vectors[0][..], transmit_header(&packets[0].0, Some(1448)).unwrap());
        assert_eq!(frame.length(), HEADER_LEN + packets[0].0.len());
    }
}

#[test]
fn native_udp_segments_encode_once_and_survive_device_framing() {
    use std::net::SocketAddr;
    use clash_netstack::UdpPacket as StackUdpPacket;
    for ipv6 in [false, true] {
        let source: SocketAddr = if ipv6 { "[2001:db8::1]:1" } else { "192.0.2.1:1" }.parse().unwrap();
        let destination = if ipv6 { "[2001:db8::2]:2" } else { "192.0.2.2:2" }.parse().unwrap();
        let data = (0..3).flat_map(|index| vec![index as u8; if index == 2 { 101 } else { 1200 }]).collect::<Vec<_>>();
        let packet = StackUdpPacket::from((Bytes::from(data.clone()), source, destination)).encode_segments(1200).unwrap();
        assert_eq!(packet.udp_segmentation(), Some(1200));
        let packets = [packet];
        let frame = write::WriteFrame::new(&packets, true, 1500).unwrap();
        assert_eq!(frame.count, 1);
        assert_eq!(frame.vector_count(), 2);
        let mut encoded = frame.vectors()[..frame.vector_count()].iter().flat_map(|slice| slice.iter().copied()).collect::<Vec<_>>();
        let mut decoded = Vec::new(); receive::decode(&mut encoded, &mut decoded).unwrap();
        assert_eq!(decoded.len(), 3);
        let mut rebuilt = Vec::new();
        for packet in &decoded {
            let (_, _, payload) = clash_netstack::parse_udp_packet(packet).unwrap();
            rebuilt.extend_from_slice(&packet[payload]);
        }
        assert_eq!(rebuilt, data);
        assert!(write::WriteFrame::new(&packets, false, 1500).is_err());
    }
}

#[test]
fn owned_receive_retains_original_allocation_until_last_packet_is_dropped() {
    for ipv6 in [false, true] {
        let data = tcp_frame(32 * 1024, ipv6);
        let header = transmit_header(&data, Some(1448)).unwrap();
        let pool = super::super::receive_pool::Pool::default();
        let mut frame = pool.acquire();
        frame.as_mut()[..HEADER_LEN].copy_from_slice(&header);
        frame.as_mut()[HEADER_LEN..HEADER_LEN + data.len()].copy_from_slice(&data);
        frame.truncate(HEADER_LEN + data.len());
        let pointer = frame.as_ref()[HEADER_LEN..].as_ptr();
        let mut packets = Vec::new();
        receive::decode_shared(Bytes::from_owner(frame), 65535 + 80, &mut packets).unwrap();
        assert_eq!(packets[0].as_ptr(), pointer, "TCP input must not copy payload");
        assert_eq!(packets[0].data(), data);
        let retained = packets[0].clone();
        packets.clear();
        let other = pool.acquire();
        assert_ne!(other.as_ref()[HEADER_LEN..].as_ptr(), pointer);
        drop(other);
        drop(retained);
        let reused = pool.acquire();
        assert_eq!(reused.as_ref()[HEADER_LEN..].as_ptr(), pointer);
    }
}

#[test]
fn small_udp_shares_read_storage_until_the_last_slice_is_released() {
    use std::net::SocketAddr;
    use clash_netstack::{parse_udp_packet, UdpPacket as StackPacket};
    let data = StackPacket::from((Bytes::from(vec![0x5a; 1472]),
        "192.0.2.1:1234".parse::<SocketAddr>().unwrap(),
        "192.0.2.2:4321".parse::<SocketAddr>().unwrap())).encode().unwrap();
    let pool = super::super::receive_pool::Pool::default();
    let mut frame = pool.acquire();
    frame.as_mut()[..HEADER_LEN].fill(0);
    frame.as_mut()[HEADER_LEN..HEADER_LEN + data.len()].copy_from_slice(data.data());
    frame.truncate(HEADER_LEN + data.len());
    receive::prepare_shared(frame.as_mut()).unwrap();
    let pointer = frame.as_ref()[HEADER_LEN..].as_ptr();
    let storage = Bytes::from_owner(frame);
    let retained = storage.clone();
    let mut packets = Vec::new();
    receive::decode_shared(storage, 65535 + 80, &mut packets).unwrap();
    assert_eq!(packets[0].as_ptr(), pointer, "ordinary UDP must borrow the read slab");
    let (_, _, payload) = parse_udp_packet(&packets[0]).unwrap();
    assert_eq!(&packets[0][payload], &[0x5a; 1472]);
    packets.clear();
    let other = pool.acquire();
    assert_ne!(other.as_ref()[HEADER_LEN..].as_ptr(), pointer);
    drop(other);
    drop(retained);
    assert_eq!(pool.acquire().as_ref()[HEADER_LEN..].as_ptr(), pointer);
}

#[test]
fn owned_udp_gso_keeps_the_aggregate_until_a_routing_boundary_needs_datagrams() {
    use std::net::SocketAddr;
    use clash_netstack::{parse_udp_packet, split_udp_packet, UdpPacket as StackPacket};
    let packet = StackPacket::from((Bytes::from(vec![0x5a; 2501]),
        "192.0.2.1:1234".parse::<SocketAddr>().unwrap(), "192.0.2.2:4321".parse::<SocketAddr>().unwrap()))
        .encode_segments(1200).unwrap();
    let header = udp::transmit_header(packet.data(), 1200, 1500).unwrap();
    let mut storage = Vec::from(header);
    storage.extend_from_slice(packet.data());
    let pointer = storage[HEADER_LEN..].as_ptr();
    let capacity = storage.capacity();
    let mut packets = Vec::new();
    receive::decode_shared(Bytes::from(storage), capacity, &mut packets).unwrap();
    assert_eq!(packets.len(), 1);
    let aggregate = packets.pop().unwrap();
    assert_eq!(aggregate.as_ptr(), pointer);
    assert_eq!(aggregate.udp_segmentation(), Some(1200));
    let packets = split_udp_packet(aggregate).unwrap();
    for (packet, expected) in packets.iter().zip([1200, 1200, 101]) {
        assert!(packet.udp_segmentation().is_none());
        let (_, _, range) = parse_udp_packet(packet).unwrap();
        assert_eq!(range.len(), expected);
        assert!(packet[range].iter().all(|byte| *byte == 0x5a));
    }
    assert_eq!(packets.len(), 3);
}

#[test]
fn checksum_verified_udp_gso_does_not_require_partial_checksum_offsets() {
    use std::net::SocketAddr;
    use clash_netstack::UdpPacket as StackPacket;
    let packet = StackPacket::from((Bytes::from(vec![0x5a; 2501]),
        "192.0.2.1:1".parse::<SocketAddr>().unwrap(), "192.0.2.2:2".parse::<SocketAddr>().unwrap()))
        .encode_segments(1200).unwrap();
    let mut header = udp::transmit_header(packet.data(), 1200, 1500).unwrap();
    header[0] = DATA_VALID;
    header[6..10].fill(0);
    let mut frame = Vec::from(header);
    frame.extend_from_slice(packet.data());
    let mut packets = Vec::new();
    receive::decode_shared(Bytes::from(frame), 65535, &mut packets).unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].udp_segmentation(), Some(1200));
}

#[test]
fn split_udp_vectors_preserve_payloads_and_encode_a_short_final_segment() {
    use std::net::SocketAddr;
    use clash_netstack::{parse_udp_packet, UdpPacket as StackPacket};
    for ipv6 in [false, true] {
        let source: SocketAddr = if ipv6 { "[2001:db8::1]:1234" } else { "192.0.2.1:1234" }.parse().unwrap();
        let destination: SocketAddr = if ipv6 { "[2001:db8::2]:4321" } else { "192.0.2.2:4321" }.parse().unwrap();
        let data: Vec<_> = [1200, 1200, 71].into_iter().map(|length| Bytes::from(vec![0x5a; length])).collect();
        let packets: Vec<_> = data.iter().map(|payload|
            StackPacket::from((payload.clone(), source, destination)).into_parts(None, true).unwrap()).collect();
        for (packet, payload) in packets.iter().zip(&data) {
            assert_eq!(packet.parts().unwrap().1.as_ptr(), payload.as_ptr());
        }
        let frame = write::WriteFrame::new(&packets, true, 1500).unwrap();
        assert_eq!(frame.count, 3);
        let mut encoded = Vec::new();
        for vector in frame.vectors().iter().take(frame.vector_count()) { encoded.extend_from_slice(vector); }
        let mut decoded = Vec::new(); receive::decode(&mut encoded, &mut decoded).unwrap();
        assert_eq!(decoded.len(), 3);
        for (packet, payload) in decoded.iter().zip(data) {
            let (src, dst, range) = parse_udp_packet(packet).unwrap();
            assert_eq!((src, dst), (source, destination)); assert_eq!(&packet[range], payload.as_ref());
        }
    }
}

#[test]
fn adjacent_gro_groups_merge_only_before_the_first_short_tail() {
    use std::net::SocketAddr;
    use clash_netstack::{parse_udp_packet, UdpPacket as StackPacket};
    let source: SocketAddr = "192.0.2.1:1234".parse().unwrap();
    let destination: SocketAddr = "192.0.2.2:4321".parse().unwrap();
    let make = |length| StackPacket::from((Bytes::from(vec![0x5a; length]), source, destination))
        .into_parts(Some(1200), true).unwrap();
    let packets = [make(2400), make(2471), make(2400)];
    let frame = write::WriteFrame::new(&packets, true, 1500).unwrap();
    assert_eq!(frame.count, 2, "a short logical tail terminates the merged group");
    let mut encoded = Vec::new();
    for vector in frame.vectors().iter().take(frame.vector_count()) { encoded.extend_from_slice(vector); }
    let mut decoded = Vec::new(); receive::decode(&mut encoded, &mut decoded).unwrap();
    assert_eq!(decoded.len(), 5);
    let lengths: Vec<_> = decoded.iter().map(|packet| parse_udp_packet(packet).unwrap().2.len()).collect();
    assert_eq!(lengths, [1200, 1200, 1200, 1200, 71]);
    assert_eq!(write::WriteFrame::new(&packets[1..], true, 1500).unwrap().count, 1);
}

#[tokio::test]
async fn proxy_udp_reply_preserves_payload_and_partial_checksum_through_stack_output() {
    use std::net::SocketAddr;
    use futures::StreamExt;
    use clash_netstack::{NetStack, UdpPacket as StackPacket};
    let source: SocketAddr = "192.0.2.1:1234".parse().unwrap();
    let destination: SocketAddr = "192.0.2.2:4321".parse().unwrap();
    let payload = Bytes::from(vec![0x5a; 1200]);
    let (stack, _, mut udp) = NetStack::new_with_mtu(false, false, 1500).unwrap();
    udp.enable_output_offload();
    let (_, mut output) = stack.split(); let (_, mut sender) = udp.split();
    let result = sender.send_batch(&[StackPacket::from((payload.clone(), source, destination))]);
    assert_eq!(result.sent, 1); assert!(result.error.is_none());
    let packet = output.next().await.unwrap().unwrap();
    assert!(packet.udp_checksum_partial());
    assert_eq!(packet.parts().unwrap().1.as_ptr(), payload.as_ptr(), "normal output tracing must not flatten the payload");
    let packets = [packet];
    let frame = write::WriteFrame::new(&packets, true, 1500).unwrap();
    let mut encoded = Vec::new();
    for vector in frame.vectors().iter().take(frame.vector_count()) { encoded.extend_from_slice(vector); }
    let mut decoded = Vec::new(); receive::decode(&mut encoded, &mut decoded).unwrap();
    let ip = Ipv4Packet::new_checked(decoded[0].data()).unwrap();
    let udp = WireUdpPacket::new_checked(ip.payload()).unwrap();
    assert!(udp.verify_checksum(&IpAddress::from(ip.src_addr()), &IpAddress::from(ip.dst_addr())));
    assert_eq!(udp.payload(), payload.as_ref());
}

#[test]
fn merging_gro_groups_respects_the_logical_segment_limit() {
    use std::net::SocketAddr;
    use clash_netstack::UdpPacket as StackPacket;
    let source: SocketAddr = "192.0.2.1:1".parse().unwrap();
    let destination: SocketAddr = "192.0.2.2:2".parse().unwrap();
    let packets: Vec<_> = (0..2).map(|_| StackPacket::from((Bytes::from(vec![0; 640]), source, destination))
        .into_parts(Some(10), true).unwrap()).collect();
    assert_eq!(write::WriteFrame::new(&packets, true, 1500).unwrap().count, 1);
}
