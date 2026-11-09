//! Checked virtio framing. No packet buffer is shared across an asynchronous
//! write; callers keep the owning batch alive until the syscall completes.
pub(super) mod udp;
pub(super) mod receive;
pub(super) mod write;
#[cfg(any(target_os = "linux", all(test, unix)))]
pub(super) mod borrowed;
use std::io;
#[cfg(test)]
use bytes::Bytes;
#[cfg(test)]
use clash_netstack::Packet;
use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket};

pub(super) const HEADER_LEN: usize = 10;
const NEEDS_CSUM: u8 = 1;
const DATA_VALID: u8 = 2;

pub(super) struct TcpLayout { pub ip: usize, pub header: usize, pub v6: bool }

pub(super) fn tcp_layout(data: &[u8]) -> Option<TcpLayout> {
    let (ip, v6) = match data.first()? >> 4 {
        4 => {
            let ip = Ipv4Packet::new_checked(data).ok()?;
            if ip.next_header() != IpProtocol::Tcp || ip.more_frags() || ip.frag_offset() != 0
                || usize::from(ip.total_len()) != data.len() { return None; }
            (usize::from(ip.header_len()), false)
        }
        6 => {
            let ip = Ipv6Packet::new_checked(data).ok()?;
            if ip.next_header() != IpProtocol::Tcp || 40 + usize::from(ip.payload_len()) != data.len() { return None; }
            (40, true)
        }
        _ => return None,
    };
    let tcp = TcpPacket::new_checked(&data[ip..]).ok()?;
    Some(TcpLayout { ip, header: ip + usize::from(tcp.header_len()), v6 })
}

pub(super) fn transmit_header(data: &[u8], segmentation: Option<u16>) -> io::Result<[u8; HEADER_LEN]> {
    let mut header = [0; HEADER_LEN];
    let Some(size) = segmentation else { return Ok(header); };
    let layout = tcp_layout(data).ok_or_else(|| invalid("invalid TCP segmentation frame"))?;
    if size == 0 || data.len() - layout.header <= usize::from(size) {
        return Err(invalid("invalid TCP segmentation size"));
    }
    header[0] = NEEDS_CSUM;
    header[1] = if layout.v6 { 4 } else { 1 };
    header[2..4].copy_from_slice(&(layout.header as u16).to_ne_bytes());
    header[4..6].copy_from_slice(&size.to_ne_bytes());
    header[6..8].copy_from_slice(&(layout.ip as u16).to_ne_bytes());
    header[8..10].copy_from_slice(&16u16.to_ne_bytes());
    Ok(header)
}

/// Keep TCP super-packets intact. UDP keeps datagram boundaries through the
/// existing splitter; offload metadata must never hide malformed TCP headers.
#[cfg(test)]
pub(super) fn receive_tcp(header: &[u8], data: &[u8]) -> io::Result<Option<Packet>> {
    Ok(receive_tcp_verified(header, data)?.map(|verified| {
        let packet = Packet::new(Bytes::copy_from_slice(data));
        if verified { packet.with_verified_rx_checksum() } else { packet }
    }))
}

pub(super) fn receive_tcp_verified(header: &[u8], data: &[u8]) -> io::Result<Option<bool>> {
    if header.len() != HEADER_LEN || header[0] & !(NEEDS_CSUM | DATA_VALID) != 0 {
        return Err(invalid("unsupported virtio header"));
    }
    let kind = header[1] & 0x7f;
    if !matches!(kind, 0 | 1 | 4 | 5) { return Err(invalid("unsupported GSO type")); }
    let Some(layout) = tcp_layout(data) else {
        return if matches!(kind, 1 | 4) { Err(invalid("invalid TCP GSO packet")) } else { Ok(None) };
    };
    if kind == 5 || kind == 1 && layout.v6 || kind == 4 && !layout.v6 {
        return Err(invalid("GSO type does not match TCP packet"));
    }
    if kind != 0 {
        let size = u16::from_ne_bytes([header[4], header[5]]);
        let tcp = TcpPacket::new_unchecked(&data[layout.ip..]);
        if size == 0 || tcp.syn() || tcp.rst() {
            return Err(invalid("invalid TCP GSO segment"));
        }
    }
    if header[0] & NEEDS_CSUM != 0 {
        let start = u16::from_ne_bytes([header[6], header[7]]) as usize;
        let offset = u16::from_ne_bytes([header[8], header[9]]);
        if start != layout.ip || offset != 16 { return Err(invalid("invalid TCP checksum metadata")); }
    }
    Ok(Some(header[0] & (NEEDS_CSUM | DATA_VALID) != 0))
}

fn invalid(message: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, message) }

#[cfg(test)]
mod tests;
