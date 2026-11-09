//! Merge equal-sized, adjacent UDP datagrams using payload iovecs. Headers are
//! copied once; datagram payloads remain in their owning queue batch.
use std::io;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, UdpPacket, checksum};
use super::HEADER_LEN;
use super::super::frame::Frame;

pub(in crate::proxy::tun::device_io) struct Group {
    pub count: usize,
    pub header_len: usize,
    pub payload_len: usize,
    pub virtio: [u8; HEADER_LEN],
}

struct View<'a> { data: &'a [u8], ip: usize, payload: usize }
fn view(data: &[u8]) -> Option<View<'_>> {
    let ip = match data.first()? >> 4 {
        4 => {
            let packet = Ipv4Packet::new_checked(data).ok()?;
            if packet.header_len() != 20 || packet.next_header() != IpProtocol::Udp
                || packet.more_frags() || packet.frag_offset() != 0 || packet.ident() != 0
                || usize::from(packet.total_len()) != data.len() { return None; }
            20
        }
        6 => {
            let packet = Ipv6Packet::new_checked(data).ok()?;
            if packet.next_header() != IpProtocol::Udp || 40 + usize::from(packet.payload_len()) != data.len() { return None; }
            40
        }
        _ => return None,
    };
    let udp = UdpPacket::new_checked(&data[ip..]).ok()?;
    if usize::from(udp.len()) != data.len() - ip || udp.payload().is_empty() { return None; }
    Some(View { data, ip, payload: udp.payload().len() })
}

pub(in crate::proxy::tun::device_io) fn transmit_header(data: &[u8], size: u16, mtu: usize) -> io::Result<[u8; HEADER_LEN]> {
    let packet = view(data).ok_or_else(|| super::invalid("invalid UDP offload frame"))?;
    if size == 0 || packet.payload <= usize::from(size) || packet.ip + 8 + usize::from(size) > mtu {
        return Err(super::invalid("invalid UDP offload segment size"));
    }
    let mut header = [0; HEADER_LEN];
    header[0] = 1; header[1] = 5;
    header[2..4].copy_from_slice(&((packet.ip + 8) as u16).to_ne_bytes());
    header[4..6].copy_from_slice(&size.to_ne_bytes());
    header[6..8].copy_from_slice(&(packet.ip as u16).to_ne_bytes());
    header[8..10].copy_from_slice(&6u16.to_ne_bytes());
    Ok(header)
}

pub(in crate::proxy::tun::device_io) fn group<P: Frame>(packets: &[P], header: &mut [u8; 68]) -> Option<Group> {
    let first = packets.first()?;
    if first.parts().is_some() { return None; }
    let first = view(first.as_ref())?;
    let header_len = first.ip + 8;
    let mut count = 1;
    for packet in &packets[1..] {
        if packet.parts().is_some() { break; }
        let Some(next) = view(packet.as_ref()) else { break; };
        if next.ip != first.ip || next.payload != first.payload
            || next.data[..first.ip + 6] != first.data[..first.ip + 6]
            || header_len + first.payload * (count + 1) > 65535 { break; }
        count += 1;
    }
    if count < 2 { return None; }
    header[..header_len].copy_from_slice(&first.data[..header_len]);
    let length = first.payload * count + 8;
    let (source, destination) = if first.ip == 20 {
        let mut ip = Ipv4Packet::new_unchecked(&mut header[..20]);
        ip.set_total_len((20 + length) as u16);
        ip.fill_checksum();
        (IpAddress::from(ip.src_addr()), IpAddress::from(ip.dst_addr()))
    } else {
        let mut ip = Ipv6Packet::new_unchecked(&mut header[..40]);
        ip.set_payload_len(length as u16);
        (IpAddress::from(ip.src_addr()), IpAddress::from(ip.dst_addr()))
    };
    let mut udp = UdpPacket::new_unchecked(&mut header[first.ip..header_len]);
    udp.set_len(length as u16);
    udp.set_checksum(checksum::pseudo_header(&source, &destination, IpProtocol::Udp, length as u32));
    let mut virtio = [0; HEADER_LEN];
    virtio[0] = 1;
    virtio[1] = 5;
    virtio[2..4].copy_from_slice(&(header_len as u16).to_ne_bytes());
    virtio[4..6].copy_from_slice(&(first.payload as u16).to_ne_bytes());
    virtio[6..8].copy_from_slice(&(first.ip as u16).to_ne_bytes());
    virtio[8..10].copy_from_slice(&6u16.to_ne_bytes());
    Some(Group { count, header_len, payload_len: first.payload, virtio })
}

/// Rewrite only the small IP/UDP header; payload iovecs stay untouched.
pub(in crate::proxy::tun::device_io) fn parts_header(header: &mut [u8], payload: usize,
    segmentation: Option<usize>, partial: bool, mtu: usize) -> io::Result<[u8; HEADER_LEN]> {
    if !matches!(header.len(), 28 | 48) || header.len() + payload > 65535
        || segmentation.is_some_and(|size| size == 0 || header.len() + size > mtu || size >= payload) {
        return Err(super::invalid("invalid split UDP frame"));
    }
    let ip_length = header.len() - 8;
    if (ip_length == 20 && (header[0] != 0x45 || header[9] != 17))
        || (ip_length == 40 && (header[0] >> 4 != 6 || header[6] != 17)) {
        return Err(super::invalid("split packet is not a plain UDP frame"));
    }
    let length = payload + 8;
    let (source, destination) = if ip_length == 20 {
        let mut ip = Ipv4Packet::new_unchecked(&mut header[..20]);
        ip.set_total_len((20 + length) as u16); ip.fill_checksum();
        (IpAddress::from(ip.src_addr()), IpAddress::from(ip.dst_addr()))
    } else {
        let mut ip = Ipv6Packet::new_unchecked(&mut header[..40]); ip.set_payload_len(length as u16);
        (IpAddress::from(ip.src_addr()), IpAddress::from(ip.dst_addr()))
    };
    let mut udp = UdpPacket::new_unchecked(&mut header[ip_length..]); udp.set_len(length as u16);
    let mut virtio = [0; HEADER_LEN];
    if partial {
        udp.set_checksum(checksum::pseudo_header(&source, &destination, IpProtocol::Udp, length as u32));
        virtio[0] = 1;
        virtio[6..8].copy_from_slice(&(ip_length as u16).to_ne_bytes());
        virtio[8..10].copy_from_slice(&6u16.to_ne_bytes());
    }
    if let Some(size) = segmentation {
        if !partial { return Err(super::invalid("UDP segmentation requires partial checksum")); }
        virtio[1] = 5;
        virtio[2..4].copy_from_slice(&((ip_length + 8) as u16).to_ne_bytes());
        virtio[4..6].copy_from_slice(&(size as u16).to_ne_bytes());
    }
    Ok(virtio)
}
