//! DIRECT UDP replies stay in the TUN owner and preserve GRO metadata until
//! encoding. At most one group's bounded fallback segments are materialized.
use std::{collections::VecDeque, io};
use clash_netstack::{Packet, UdpPacket as StackPacket};
use tracing::warn;
use crate::{proxy::datagram::{UdpPacket, segments::DatagramSegments}, session::SocksAddr};

pub(in crate::proxy::tun) fn encode(group: DatagramSegments, mtu: Option<usize>, packets: &mut VecDeque<Packet>) {
    let header = if group.packet.src_addr.ip().is_some_and(|ip| ip.is_ipv6()) { 48 } else { 28 };
    let segmentation = group.size.filter(|size| mtu.is_some_and(|mtu|
        header + usize::from(size.get()) <= mtu) && header + group.packet.data.len() <= 65535);
    if let Some(size) = segmentation {
        append(packets, group.packet, Some(size.get()), mtu.is_some());
    } else {
        for packet in group.into_packets() { append(packets, packet, None, mtu.is_some()); }
    }
}
fn append(packets: &mut VecDeque<Packet>, packet: UdpPacket, size: Option<u16>, offload: bool) {
    let encoded = match (&packet.src_addr, &packet.dst_addr) {
        (SocksAddr::Ip(source), SocksAddr::Ip(destination)) => {
            let packet = StackPacket::from((packet.data, *source, *destination));
            if cfg!(target_os = "linux") {
                packet.into_parts(size, offload)
            } else { match size { Some(size) => packet.encode_segments(size), None => packet.encode() } }
        },
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "TUN UDP reply requires IP addresses")),
    };
    match encoded {
        Ok(packet) => packets.push_back(packet),
        Err(error) => warn!("dropping invalid DIRECT UDP reply: {error}"),
    }
}
#[cfg(test)]
mod tests;
