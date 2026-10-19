//! Common linear headers only; options, extensions and non-linear headers
//! return to the full parser. Packet references never survive a modifying helper.
use core::{mem::size_of, ptr::{addr_of_mut, copy_nonoverlapping, write_bytes}};
use aya_ebpf::programs::TcContext;
use clash_ebpf_common::{In6Addr, RedirectTuple};
use crate::maps::PARSED_PKT_MAP;
use super::ParsedPacket;
use super::{ETH_HLEN, ETH_P_IP, ETH_P_IPV6, IPPROTO_TCP, IPPROTO_UDP};

#[derive(Default)]
pub struct Packet {
    pub tuple: RedirectTuple,
    pub smac: [u8; 6],
    pub dmac: [u8; 6],
    pub flags: u8,
}

/// Bounds checks cover each direct packet access. Arrays have byte alignment;
/// no unaligned Rust header references or packet pointers escape this module.
#[inline(always)]
fn bytes<const N: usize>(ctx: &TcContext, offset: usize) -> Option<&[u8; N]> {
    let data = ctx.data();
    if data + offset + N > ctx.data_end() { return None; }
    Some(unsafe { &*((data + offset) as *const [u8; N]) })
}

#[inline(always)]
pub fn parse_ip(ctx: &TcContext, link: usize, tuple: &mut RedirectTuple) -> Option<usize> {
    let protocol = if link == ETH_HLEN as usize {
        let eth = bytes::<14>(ctx, 0)?;
        u16::from_be_bytes([eth[12], eth[13]])
    } else if link == 0 { u16::from_be(ctx.skb.protocol() as u16) }
    else { return None; };
    if protocol == ETH_P_IP {
        let ip = bytes::<20>(ctx, link)?;
        if ip[0] != 0x45 || u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0 {
            return None;
        }
        tuple.src_ip = [0; 16]; tuple.dst_ip = [0; 16];
        tuple.src_ip[10] = 0xff; tuple.src_ip[11] = 0xff;
        tuple.dst_ip[10] = 0xff; tuple.dst_ip[11] = 0xff;
        tuple.src_ip[12..].copy_from_slice(&ip[12..16]);
        tuple.dst_ip[12..].copy_from_slice(&ip[16..20]);
        tuple.proto = ip[9]; tuple.ip_version = 4;
        Some(link + 20)
    } else if protocol == ETH_P_IPV6 {
        let ip = bytes::<40>(ctx, link)?;
        if ip[0] >> 4 != 6 { return None; }
        tuple.src_ip.copy_from_slice(&ip[8..24]);
        tuple.dst_ip.copy_from_slice(&ip[24..40]);
        tuple.proto = ip[6]; tuple.ip_version = 6;
        if tuple.proto != IPPROTO_TCP && tuple.proto != IPPROTO_UDP { return None; }
        Some(link + 40)
    } else { None }
}

#[inline(always)]
pub fn parse_forward(ctx: &TcContext, link: usize, packet: &mut Packet) -> bool {
    let Some(offset) = parse_ip(ctx, link, &mut packet.tuple) else { return false; };
    parse_ports(ctx, offset, packet)
}

#[inline(always)]
pub fn parse_ports(ctx: &TcContext, offset: usize, packet: &mut Packet) -> bool {
    let ports = if packet.tuple.proto == IPPROTO_TCP {
        let Some(tcp) = bytes::<20>(ctx, offset) else { return false; };
        packet.flags = tcp[13];
        [tcp[0], tcp[1], tcp[2], tcp[3]]
    } else if packet.tuple.proto == IPPROTO_UDP {
        let Some(udp) = bytes::<8>(ctx, offset) else { return false; };
        [udp[0], udp[1], udp[2], udp[3]]
    } else { return false; };
    packet.tuple.src_port = u16::from_be_bytes([ports[0], ports[1]]);
    packet.tuple.dst_port = u16::from_be_bytes([ports[2], ports[3]]);
    true
}

#[inline(always)]
pub fn read_macs(ctx: &TcContext, link: usize, packet: &mut Packet) -> bool {
    if link == ETH_HLEN as usize {
        let Some(eth) = bytes::<14>(ctx, 0) else { return false; };
        packet.dmac.copy_from_slice(&eth[..6]);
        packet.smac.copy_from_slice(&eth[6..12]);
    }
    true
}

#[inline(always)]
pub fn udp_header_present(ctx: &TcContext, offset: usize) -> bool {
    bytes::<8>(ctx, offset).is_some()
}

/// Read only the group bit before the cached direct decision.
#[inline(always)]
pub fn group_destination(ctx: &TcContext, link: usize) -> bool {
    link == ETH_HLEN as usize && bytes::<1>(ctx, 0).is_some_and(|b| b[0] & 1 != 0)
}

/// Materialize the cold-path input from already validated linear headers.
/// The per-CPU allocation is used only within this invocation, before redirect.
#[inline(never)]
pub fn prepare_miss(ctx: &TcContext, link: usize, packet: &mut Packet) -> bool {
    if !read_macs(ctx, link, packet) { return false; }
    let Some(ip) = bytes::<2>(ctx, link) else { return false; };
    let Some(ptr) = PARSED_PKT_MAP.get_ptr_mut(0) else { return false; };
    // All fields are initialized, including unused transport fields. No packet
    // pointers are stored in the map; only copied values survive this call.
    unsafe { write_bytes(ptr.cast::<u8>(), 0, size_of::<ParsedPacket>()); }
    let out = unsafe { &mut *ptr };
    out.ethh.src_addr = packet.smac;
    out.ethh.dst_addr = packet.dmac;
    out.ethh.ether_type = if packet.tuple.ip_version == 4 { ETH_P_IP } else { ETH_P_IPV6 }.to_be();
    out.tuples.five.src_ip = In6Addr { u6_addr8: packet.tuple.src_ip };
    out.tuples.five.dst_ip = In6Addr { u6_addr8: packet.tuple.dst_ip };
    out.tuples.five.src_port = packet.tuple.src_port;
    out.tuples.five.dst_port = packet.tuple.dst_port;
    out.tuples.five.l4proto = packet.tuple.proto;
    out.tuples.dscp = if packet.tuple.ip_version == 4 { ip[1] >> 2 }
        else { ((ip[0] & 0x0f) << 2) | (ip[1] >> 6) };
    out.l4proto = packet.tuple.proto;
    let offset = link + if packet.tuple.ip_version == 4 { 20 } else { 40 };
    if packet.tuple.proto == IPPROTO_TCP {
        let Some(header) = bytes::<20>(ctx, offset) else { return false; };
        // Copy wire bytes into the initialized header, without unaligned Rust
        // references. The packet and map allocations do not overlap.
        unsafe { copy_nonoverlapping(header.as_ptr(),
            addr_of_mut!(out.tcph).cast::<u8>(), 20); }
        out.listener_l4proto = if packet.flags & 0x12 == 0x02 { IPPROTO_TCP } else { 0 };
    } else {
        let Some(header) = bytes::<8>(ctx, offset) else { return false; };
        unsafe { copy_nonoverlapping(header.as_ptr(),
            addr_of_mut!(out.udph).cast::<u8>(), 8); }
        out.listener_l4proto = IPPROTO_UDP;
    }
    true
}
