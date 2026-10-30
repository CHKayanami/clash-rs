use std::net::IpAddr;
use bytes::BytesMut;
use smoltcp::{phy::ChecksumCapabilities, wire::{IpProtocol, Ipv4Packet, Ipv4Repr,
    Ipv6Packet, Ipv6Repr, Icmpv4Packet, Icmpv4Message, Icmpv6Packet, Icmpv6Message}};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct Flow {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub identifier: u16,
}

pub(super) struct Request {
    pub flow: Flow,
    pub payload: Vec<u8>,
    pub hop_limit: u8,
}

// Inspect the protocol before parsing: ordinary TCP/UDP retain their fast path.
// Fragmented echo and IPv6 extension headers are not reassembled here.
pub(super) fn decode(packet: &[u8], mtu: usize) -> Result<Option<Request>, ()> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.get(9) == Some(&1) => {
            let ip = Ipv4Packet::new_checked(packet).map_err(|_| ())?;
            if packet.len() > mtu || !ip.verify_checksum() || ip.more_frags() || ip.frag_offset() != 0 {
                return Err(());
            }
            let echo = Icmpv4Packet::new_checked(ip.payload()).map_err(|_| ())?;
            if !echo.verify_checksum() { return Err(()); }
            if echo.msg_type() != Icmpv4Message::EchoRequest { return Ok(None); }
            if echo.msg_code() != 0 { return Err(()); }
            Ok(Some(Request {
                flow: Flow { source: ip.src_addr().into(), destination: ip.dst_addr().into(),
                    identifier: echo.echo_ident() },
                payload: ip.payload().to_vec(), hop_limit: ip.hop_limit(),
            }))
        }
        Some(6) if packet.get(6) == Some(&58) => {
            let ip = Ipv6Packet::new_checked(packet).map_err(|_| ())?;
            if packet.len() > mtu { return Err(()); }
            let echo = Icmpv6Packet::new_checked(ip.payload()).map_err(|_| ())?;
            if !echo.verify_checksum(&ip.src_addr(), &ip.dst_addr()) { return Err(()); }
            if echo.msg_type() != Icmpv6Message::EchoRequest { return Ok(None); }
            if echo.msg_code() != 0 { return Err(()); }
            Ok(Some(Request {
                flow: Flow { source: ip.src_addr().into(), destination: ip.dst_addr().into(),
                    identifier: echo.echo_ident() },
                payload: ip.payload().to_vec(), hop_limit: ip.hop_limit(),
            }))
        }
        _ => Ok(None),
    }
}

pub(super) fn valid_address(address: IpAddr) -> bool {
    !address.is_unspecified() && !address.is_multicast()
        && !matches!(address, IpAddr::V4(ip) if ip.is_broadcast())
}

// Ping sockets rewrite the identifier to their local port. Restore the app's
// identifier and rebuild checksums against the virtual addresses, not the
// physical socket's local address. Sequence and payload remain unchanged.
pub(super) fn reply(flow: Flow, payload: &[u8], mtu: usize, hop_limit: u8) -> Option<BytesMut> {
    match (flow.destination, flow.source) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let echo = Icmpv4Packet::new_checked(payload).ok()?;
            if echo.msg_type() != Icmpv4Message::EchoReply || echo.msg_code() != 0 { return None; }
            let length = 20 + payload.len();
            if length > mtu { return None; }
            let mut bytes = BytesMut::zeroed(length);
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
            Ipv4Repr { src_addr: source, dst_addr: destination, next_header: IpProtocol::Icmp,
                payload_len: payload.len(), hop_limit }.emit(&mut ip, &ChecksumCapabilities::default());
            ip.payload_mut().copy_from_slice(payload);
            let mut echo = Icmpv4Packet::new_unchecked(ip.payload_mut());
            echo.set_echo_ident(flow.identifier);
            echo.fill_checksum();
            Some(bytes)
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let echo = Icmpv6Packet::new_checked(payload).ok()?;
            if echo.msg_type() != Icmpv6Message::EchoReply || echo.msg_code() != 0 { return None; }
            let length = 40 + payload.len();
            if length > mtu { return None; }
            let mut bytes = BytesMut::zeroed(length);
            let mut ip = Ipv6Packet::new_unchecked(&mut bytes[..]);
            Ipv6Repr { src_addr: source, dst_addr: destination, next_header: IpProtocol::Icmpv6,
                payload_len: payload.len(), hop_limit }.emit(&mut ip);
            ip.payload_mut().copy_from_slice(payload);
            let mut echo = Icmpv6Packet::new_unchecked(ip.payload_mut());
            echo.set_echo_ident(flow.identifier);
            echo.fill_checksum(&source, &destination);
            Some(bytes)
        }
        _ => None,
    }
}
