//! A checked IP view shared by dispatch and transport admission. Checksum
//! validation remains the responsibility of the consuming protocol.
use std::{net::SocketAddr, ops::Range};
use smoltcp::wire::IpProtocol;
use crate::link::packet::IpPacket;

pub struct PacketHeaders<'a> { packet: IpPacket<&'a [u8]> }
impl<'a> PacketHeaders<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        data.first()?;
        Some(Self { packet: IpPacket::new_checked(data).ok()? })
    }
    pub fn protocol(&self) -> IpProtocol { self.packet.protocol() }
    pub fn udp(&self) -> Option<(SocketAddr, SocketAddr, Range<usize>)> {
        if self.protocol() != IpProtocol::Udp { return None; }
        let offset = match &self.packet {
            IpPacket::Ipv4(ip) => {
                if ip.more_frags() || ip.frag_offset() != 0 { return None; }
                usize::from(ip.header_len())
            },
            IpPacket::Ipv6(_) => 40,
        };
        let payload = self.packet.payload();
        if payload.len() < 8 { return None; }
        let length = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
        if length < 8 || length > payload.len() { return None; }
        Some((SocketAddr::new(self.packet.src_addr(), u16::from_be_bytes([payload[0], payload[1]])),
            SocketAddr::new(self.packet.dst_addr(), u16::from_be_bytes([payload[2], payload[3]])),
            offset + 8..offset + length))
    }
}
