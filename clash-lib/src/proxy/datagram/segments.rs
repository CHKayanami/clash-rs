//! Offload metadata lives outside UdpPacket, whose public contract remains one
//! datagram. Generic transports materialize datagrams only at their boundary.
use std::{io, num::NonZeroU16};
use super::UdpPacket;

pub struct DatagramSegments {
    pub packet: UdpPacket,
    pub size: Option<NonZeroU16>,
}
impl From<UdpPacket> for DatagramSegments {
    fn from(packet: UdpPacket) -> Self { Self { packet, size: None } }
}
impl DatagramSegments {
    pub fn new(packet: UdpPacket, size: Option<NonZeroU16>) -> io::Result<Self> {
        if size.is_some_and(|size| packet.data.len().div_ceil(usize::from(size.get())) > 128) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "UDP GRO segment limit exceeded"));
        }
        let size = size.filter(|size| usize::from(size.get()) < packet.data.len());
        Ok(Self { packet, size })
    }
    pub fn count(&self) -> usize {
        self.size.map_or(1, |size| self.packet.data.len().div_ceil(usize::from(size.get())))
    }
    pub fn into_packets(self) -> impl Iterator<Item = UdpPacket> {
        let count = self.count();
        let step = self.size.map_or(self.packet.data.len(), |size| usize::from(size.get()));
        (0..count).map(move |index| {
            let mut packet = self.packet.clone();
            let start = index * step;
            packet.data = packet.data.slice(start..(start + step).min(packet.data.len()));
            packet
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::net::SocketAddr;
    #[test]
    fn segments_materialize_without_changing_payloads_or_addresses() {
        for size in [1u16, 1200] {
            let data = Bytes::from(vec![0x5a; size as usize * 2 + 1]);
            let packet = UdpPacket::new(data.clone(), "192.0.2.1:1".parse::<SocketAddr>().unwrap().into(), "192.0.2.2:2".parse::<SocketAddr>().unwrap().into());
            let group = DatagramSegments::new(packet.clone(), NonZeroU16::new(size)).unwrap();
            assert_eq!(group.count(), 3);
            let packets = group.into_packets().collect::<Vec<_>>();
            assert_eq!(packets.iter().flat_map(|packet| packet.data.iter().copied()).collect::<Vec<_>>(), data);
            for item in packets { assert_eq!(item.src_addr, packet.src_addr); assert_eq!(item.dst_addr, packet.dst_addr); }
        }
        let empty = DatagramSegments::new(UdpPacket::default(), NonZeroU16::new(1200)).unwrap();
        assert_eq!(empty.count(), 1); assert_eq!(empty.into_packets().count(), 1);
        let large = UdpPacket { data: Bytes::from(vec![0; 129]), ..Default::default() };
        assert!(DatagramSegments::new(large, NonZeroU16::new(1)).is_err());
    }
}

/// Successful byte prefix and, on error, the immediately following datagram.
/// Offsets stay aligned to logical datagrams so a retry never replays a prefix.
#[cfg(feature = "tun")]
pub(crate) struct SegmentSendResult {
    pub bytes: usize,
    pub failed: usize,
    pub error: Option<io::Error>,
    pub fatal: bool,
}
