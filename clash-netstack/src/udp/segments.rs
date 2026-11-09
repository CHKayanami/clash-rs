//! UDP aggregate materialization at explicit routing/transport boundaries.
use std::net::SocketAddr;
use crate::udp::socket::UdpPacket as PayloadPacket;
use bytes::Bytes;
use std::io;
use bytes::BytesMut;
use smoltcp::wire::{Ipv4Packet, Ipv6Packet, UdpPacket as WireUdpPacket};
use crate::Packet;
use super::socket::parse_udp_packet;

/// Materialize only at a consumer that needs individual UDP messages (routing,
/// sniffing or a transport without segmentation support). Original IP options,
/// hop limits and datagram boundaries are retained.
pub fn split_udp_packet(packet: Packet) -> io::Result<Vec<Packet>> {
    let Some(size) = packet.udp_segmentation() else { return Ok(vec![packet]); };
    let (source, destination, payload) = parse_udp_packet(packet.data())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid segmented UDP packet"))?;
    let size = usize::from(size);
    if size == 0 || payload.is_empty() || payload.len().div_ceil(size) > 128 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid UDP segmentation size"));
    }
    let ip_len = payload.start - 8;
    let ipv6 = packet[0] >> 4 == 6;
    let ident = if ipv6 { 0 } else { Ipv4Packet::new_unchecked(packet.data()).ident() };
    let mut output = Vec::with_capacity(payload.len().div_ceil(size));
    for (index, chunk) in packet.data()[payload.clone()].chunks(size).enumerate() {
        let mut data = BytesMut::with_capacity(payload.start + chunk.len());
        data.extend_from_slice(&packet.data()[..payload.start]);
        data.extend_from_slice(chunk);
        if ipv6 {
            Ipv6Packet::new_unchecked(&mut data[..ip_len]).set_payload_len((8 + chunk.len()) as u16);
        } else {
            let len = data.len();
            let mut ip = Ipv4Packet::new_unchecked(&mut data[..ip_len]);
            ip.set_total_len(len as u16); ip.set_ident(ident.wrapping_add(index as u16)); ip.fill_checksum();
        }
        let mut udp = WireUdpPacket::new_unchecked(&mut data[ip_len..]);
        udp.set_len((8 + chunk.len()) as u16);
        udp.fill_checksum(&source.ip().into(), &destination.ip().into());
        output.push(Packet::from(data));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::net::SocketAddr;
    use crate::UdpPacket;

    #[test]
    fn materialization_preserves_headers_boundaries_and_valid_checksums() {
        for (source, destination) in [("192.0.2.1:1234", "192.0.2.2:4321"),
            ("[2001:db8::1]:1234", "[2001:db8::2]:4321")] {
            let source: SocketAddr = source.parse().unwrap();
            let destination: SocketAddr = destination.parse().unwrap();
            let aggregate = UdpPacket::from((Bytes::from(vec![0x5a; 2501]), source, destination))
                .encode_segments(1200).unwrap();
            let mut bytes = aggregate.into_bytes().to_vec();
            if source.is_ipv4() {
                let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
                ip.set_hop_limit(37); ip.set_ident(u16::MAX); ip.fill_checksum();
            } else { Ipv6Packet::new_unchecked(&mut bytes).set_hop_limit(37); }
            let parts = split_udp_packet(Packet::new(bytes).with_udp_segmentation(1200)).unwrap();
            assert_eq!(parts.len(), 3);
            for (index, (part, length)) in parts.iter().zip([1200, 1200, 101]).enumerate() {
                let (src, dst, payload) = parse_udp_packet(part).unwrap();
                assert_eq!((src, dst), (source, destination));
                assert_eq!(payload.len(), length);
                assert!(part[payload.clone()].iter().all(|byte| *byte == 0x5a));
                assert!(part.udp_segmentation().is_none());
                if source.is_ipv4() {
                    let ip = Ipv4Packet::new_checked(part.data()).unwrap();
                    assert_eq!(ip.hop_limit(), 37); assert!(ip.verify_checksum());
                    assert_eq!(ip.ident(), u16::MAX.wrapping_add(index as u16));
                } else { assert_eq!(Ipv6Packet::new_checked(part.data()).unwrap().hop_limit(), 37); }
                let udp = WireUdpPacket::new_checked(&part[payload.start - 8..]).unwrap();
                assert!(udp.verify_checksum(&source.ip().into(), &destination.ip().into()));
            }
        }
    }
    #[test]
    fn invalid_segmentation_metadata_is_rejected() {
        let source: SocketAddr = "192.0.2.1:1".parse().unwrap();
        let destination: SocketAddr = "192.0.2.2:2".parse().unwrap();
        for size in [0, 1] {
            let packet = UdpPacket::from((Bytes::from(vec![0; 129]), source, destination)).encode().unwrap();
            assert!(split_udp_packet(packet.with_udp_segmentation(size)).is_err());
        }
    }
}

/// Decode into logical datagrams without rebuilding IP packets/checksums.
/// Compact each small payload at its first asynchronous queue boundary so a
/// slow consumer cannot pin an entire TUN burst through one tiny segment.
pub struct UdpPayloadSegments {
    data: Bytes, offset: usize, size: usize, backing: usize,
    source: SocketAddr, destination: SocketAddr,
}
pub fn udp_payload_segments(packet: Packet) -> io::Result<UdpPayloadSegments> {
    let (source, destination, range) = parse_udp_packet(&packet)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid UDP aggregate"))?;
    let size = packet.udp_segmentation().map(usize::from)
        .filter(|size| *size > 0 && !range.is_empty() && range.len().div_ceil(*size) <= 128)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid UDP segment count"))?;
    let backing = packet.backing_capacity();
    Ok(UdpPayloadSegments { data: packet.into_bytes().slice(range), offset: 0, size, backing, source, destination })
}
impl Iterator for UdpPayloadSegments {
    type Item = PayloadPacket;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.data.len() { return None; }
        let end = (self.offset + self.size).min(self.data.len());
        let data = if self.backing > 4096 && end - self.offset < self.backing / 4 {
            Bytes::copy_from_slice(&self.data[self.offset..end])
        } else { self.data.slice(self.offset..end) };
        self.offset = end;
        Some(PayloadPacket::from((data, self.source, self.destination)))
    }
}

#[cfg(test)]
mod payload_tests {
    use super::*;
    #[test]
    fn logical_split_keeps_addresses_and_releases_large_backing_at_the_queue_boundary() {
        let source: SocketAddr = "192.0.2.1:1234".parse().unwrap();
        let destination: SocketAddr = "192.0.2.2:4321".parse().unwrap();
        let packet = PayloadPacket::from((Bytes::from(vec![0x5a; 2471]), source, destination))
            .encode_segments(1200).unwrap().with_backing_capacity(128 * 1024);
        let original = packet.as_ptr();
        let segments: Vec<_> = udp_payload_segments(packet).unwrap().collect();
        assert_eq!(segments.len(), 3);
        for (packet, length) in segments.iter().zip([1200, 1200, 71]) {
            assert_eq!((packet.local_addr, packet.remote_addr), (source, destination));
            assert_eq!(packet.data.len(), length);
            assert_eq!(packet.data.data(), vec![0x5a; length]);
            assert_ne!(packet.data.as_ptr(), original.wrapping_add(28));
        }
    }
}
