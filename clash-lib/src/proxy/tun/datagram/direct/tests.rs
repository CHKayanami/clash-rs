use super::*;
use bytes::Bytes;
use std::{net::SocketAddr, num::NonZeroU16};
use clash_netstack::parse_udp_packet;
use crate::proxy::datagram::UdpPacket;

#[test]
fn replies_encode_both_families_and_invalid_datagrams_preserve_the_valid_suffix() {
    let v4: SocketAddr = "192.0.2.1:1234".parse().unwrap();
    let v4_client: SocketAddr = "192.0.2.2:5000".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
    let v6_client: SocketAddr = "[2001:db8::2]:5000".parse().unwrap();
    let mut output = VecDeque::new();
    for packet in [
        UdpPacket::new(Bytes::from_static(b"v4"), v4.into(), v4_client.into()),
        UdpPacket::new(Bytes::from_static(b"bad"), v4.into(), v6_client.into()),
        UdpPacket::new(Bytes::from(vec![0; 65527]), v6.into(), v6_client.into()),
        UdpPacket::new(Bytes::from_static(b"v6"), v6.into(), v6_client.into()),
    ] { encode(packet.into(), None, &mut output); }
    for (source, destination, payload) in [(v4, v4_client, b"v4"), (v6, v6_client, b"v6")] {
        let packet = output.pop_front().unwrap();
        let (actual_source, actual_destination, range) = parse_udp_packet(&packet).unwrap();
        assert_eq!((actual_source, actual_destination), (source, destination));
        assert_eq!(&packet[range], payload);
    }
    assert!(output.is_empty());
}

#[test]
fn gro_metadata_reaches_the_writer_and_fallback_preserves_datagram_boundaries() {
    for mtu in [None, Some(1200), Some(1500)] {
        let source: SocketAddr = "192.0.2.1:1234".parse().unwrap();
        let destination: SocketAddr = "192.0.2.2:4321".parse().unwrap();
        let packet = UdpPacket::new(Bytes::from(vec![0x5a; 2501]), source.into(), destination.into());
        let group = DatagramSegments::new(packet, NonZeroU16::new(1200)).unwrap();
        let mut output = VecDeque::new();
        encode(group, mtu, &mut output);
        if mtu == Some(1500) {
            let packet = output.pop_front().unwrap();
            assert_eq!(packet.udp_segmentation(), Some(1200));
            let (_, _, payload) = parse_udp_packet(&packet).unwrap();
            assert_eq!(payload.len(), 2501);
        } else {
            for expected in [1200, 1200, 101] {
                let packet = output.pop_front().unwrap();
                assert!(packet.udp_segmentation().is_none());
                let (_, _, payload) = parse_udp_packet(&packet).unwrap(); assert_eq!(payload.len(), expected);
            }
        }
        assert!(output.is_empty());
    }
}
