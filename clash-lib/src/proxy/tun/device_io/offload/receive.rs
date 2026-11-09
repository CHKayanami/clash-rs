//! Decode kernel offload metadata once. TCP stays aggregated; UDP datagrams
//! share bounded read storage until a downstream queue explicitly retains them.
use std::io;
use bytes::{Bytes, BytesMut};
use clash_netstack::Packet;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, UdpPacket, checksum};
use super::{HEADER_LEN, invalid, receive_tcp_verified};

pub(in crate::proxy::tun::device_io) fn decode(frame: &mut [u8], packets: &mut Vec<Packet>) -> io::Result<()> {
    if frame.len() <= HEADER_LEN { return Err(invalid("truncated virtio frame")); }
    let (header, data) = frame.split_at_mut(HEADER_LEN);
    if let Some(verified) = receive_tcp_verified(header, data)? {
        let packet = Packet::from(BytesMut::from(data as &[u8]));
        packets.push(if verified { packet.with_verified_rx_checksum() } else { packet });
        return Ok(());
    }
    if header[1] == 0 {
        complete_checksum(header, data)?;
        packets.push(Packet::from(BytesMut::from(data as &[u8])));
        return Ok(());
    }
    let (start, size) = udp_metadata(header, data)?;
    let (source, destination, v6) = udp_layout(data, start)?;
    let payload = &data[start + 8..];
    if payload.is_empty() || payload.len().div_ceil(usize::from(size)) > 128 {
        return Err(invalid("UDP GSO segment limit exceeded"));
    }
    let ident = if v6 { 0 } else { Ipv4Packet::new_unchecked(&*data).ident() };
    for (index, payload) in payload.chunks(usize::from(size)).enumerate() {
        let mut segment = BytesMut::with_capacity(start + 8 + payload.len());
        segment.extend_from_slice(&data[..start + 8]);
        segment.extend_from_slice(payload);
        if v6 {
            Ipv6Packet::new_unchecked(&mut segment[..start]).set_payload_len((8 + payload.len()) as u16);
        } else {
            let mut ip = Ipv4Packet::new_unchecked(&mut segment[..start]);
            ip.set_total_len((start + 8 + payload.len()) as u16);
            ip.set_ident(ident.wrapping_add(index as u16));
            ip.fill_checksum();
        }
        let mut udp = UdpPacket::new_unchecked(&mut segment[start..]);
        udp.set_len((8 + payload.len()) as u16);
        udp.fill_checksum(&source, &destination);
        packets.push(Packet::from(segment));
    }
    Ok(())
}

fn udp_layout(data: &[u8], start: usize) -> io::Result<(IpAddress, IpAddress, bool)> {
    let layout = match data.first().map(|byte| byte >> 4) {
        Some(4) => Ipv4Packet::new_checked(data).ok().filter(|ip|
            ip.next_header() == IpProtocol::Udp && !ip.more_frags() && ip.frag_offset() == 0
                && usize::from(ip.header_len()) == start && usize::from(ip.total_len()) == data.len())
            .map(|ip| (IpAddress::from(ip.src_addr()), IpAddress::from(ip.dst_addr()), false)),
        Some(6) => Ipv6Packet::new_checked(data).ok().filter(|ip|
            ip.next_header() == IpProtocol::Udp && start == 40
                && 40 + usize::from(ip.payload_len()) == data.len())
            .map(|ip| (IpAddress::from(ip.src_addr()), IpAddress::from(ip.dst_addr()), true)),
        _ => None,
    };
    let layout = layout.ok_or_else(|| invalid("UDP GSO metadata does not match IP header"))?;
    if !UdpPacket::new_checked(&data[start..]).is_ok_and(|udp| usize::from(udp.len()) == data.len() - start) {
        return Err(invalid("invalid UDP GSO length"));
    }
    Ok(layout)
}

fn complete_checksum(header: &[u8], data: &mut [u8]) -> io::Result<()> {
    if header[0] & 1 == 0 { return Ok(()); }
    let start = u16::from_ne_bytes([header[6], header[7]]) as usize;
    let offset = u16::from_ne_bytes([header[8], header[9]]) as usize;
    let at = start + offset;
    if start >= data.len() || at + 2 > data.len() { return Err(invalid("invalid checksum offset")); }
    // The kernel-provided pseudo-header seed is included exactly once.
    let mut sum = !checksum::data(&data[start..]);
    if sum == 0 && offset == 6 { sum = u16::MAX; }
    data[at..at + 2].copy_from_slice(&sum.to_be_bytes());
    Ok(())
}

fn udp_metadata(header: &[u8], data: &[u8]) -> io::Result<(usize, u16)> {
    if header[1] != 5 { return Err(invalid("invalid UDP GSO type")); }
    let start = match data.first().map(|byte| byte >> 4) {
        Some(4) => usize::from(Ipv4Packet::new_checked(data)
            .map_err(|_| invalid("invalid UDP IPv4 header"))?.header_len()),
        Some(6) => 40,
        _ => return Err(invalid("invalid UDP IP version")),
    };
    // csum_start/csum_offset are meaningful only for NEEDS_CSUM. DATA_VALID
    // aggregates may leave them zero; the IP header still defines UDP's start.
    if header[0] & 1 != 0 && (usize::from(u16::from_ne_bytes([header[6], header[7]])) != start
        || u16::from_ne_bytes([header[8], header[9]]) != 6) {
        return Err(invalid("invalid UDP checksum metadata"));
    }
    udp_layout(data, start)?;
    let size = u16::from_ne_bytes([header[4], header[5]]);
    let length = data.len() - start - 8;
    if size == 0 || length == 0 || length.div_ceil(usize::from(size)) > 128 {
        return Err(invalid("invalid UDP GSO metadata"));
    }
    Ok((start, size))
}

/// Complete partial checksums before the slab is exposed as immutable Bytes.
#[cfg(any(target_os = "linux", test))]
pub(in crate::proxy::tun::device_io) fn prepare_shared(frame: &mut [u8]) -> io::Result<()> {
    if frame.len() <= HEADER_LEN { return Err(invalid("truncated virtio frame")); }
    let (header, data) = frame.split_at_mut(HEADER_LEN);
    // TCP's partial checksum is trusted by receive_tcp_verified; do not scan
    // its payload here. Full IP/TCP validation happens in decode_shared.
    let tcp = Some(u8::from(IpProtocol::Tcp));
    let is_tcp = match data.first().map(|byte| byte >> 4) {
        Some(4) => data.get(9).copied() == tcp,
        Some(6) => data.get(6).copied() == tcp,
        _ => false,
    };
    if header[1] == 0 && !is_tcp { complete_checksum(header, data)?; }
    Ok(())
}

/// All slices borrow one owned read burst. The final Bytes reference returns
/// its storage to the reader pool; no slot is reused while a slice is live.
#[cfg(any(target_os = "linux", test))]
pub(in crate::proxy::tun::device_io) fn decode_shared(frame: Bytes, capacity: usize,
    packets: &mut Vec<Packet>) -> io::Result<()> {
    if frame.len() <= HEADER_LEN { return Err(invalid("truncated virtio frame")); }
    let (header, data) = frame.split_at(HEADER_LEN);
    let verified = receive_tcp_verified(header, data)?;
    if let Some(verified) = verified {
        let packet = Packet::new(frame.slice(HEADER_LEN..)).with_backing_capacity(capacity);
        packets.push(if verified { packet.with_verified_rx_checksum() } else { packet });
    } else if header[1] == 5 {
        let (_, size) = udp_metadata(header, data)?;
        packets.push(Packet::new(frame.slice(HEADER_LEN..)).with_backing_capacity(capacity)
            .with_udp_segmentation(size));
    } else if header[1] == 0 {
        packets.push(Packet::new(frame.slice(HEADER_LEN..)).with_backing_capacity(capacity));
    } else {
        // Legacy UFO requires materializing individual IP packets.
        decode(&mut frame.to_vec(), packets)?;
    }
    Ok(())
}
