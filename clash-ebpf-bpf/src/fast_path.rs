//! Cached forwarding never re-evaluates routing rules. Lifecycle mutations keep
//! the same gates and generation checks as the full-parser fallback.
use aya_ebpf::{bindings::{TC_ACT_OK, TC_ACT_SHOT}, programs::TcContext};
use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;
use clash_ebpf_common::{DaeParam, RedirectEntry, RedirectTuple, UdpReplyKey};
use network_types::eth::EthHdr;
use crate::{maps::FLOW_SCRATCH, tracking, udp_reply, do_redirect, packet_reverse_redirect_tuple,
    transport::{fast::{Packet, parse_forward, parse_reply_ip, parse_tcp_ports, read_macs, group_destination, prepare_miss, udp_destination_port}, parse_packet, dst_ip_is_special, ETH_P_IP, ETH_P_IPV6, IPPROTO_TCP, IPPROTO_UDP}};

pub const CACHE_MISS: i32 = -1;
pub const FULL_PARSE: i32 = -2;

#[inline(never)]
pub fn forward(ctx: &TcContext, param: &DaeParam, link: usize, wan: bool, tcp_policy: *mut u32) -> i32 {
    let mut packet = Packet::default();
    if !parse_forward(ctx, link, &mut packet) { return FULL_PARSE; }
    if group_destination(ctx, link) || dst_ip_is_special(&packet.tuple.dst_ip) {
        return TC_ACT_OK;
    }
    let tcp = packet.tuple.proto == IPPROTO_TCP;
    if wan && tcp && tcp_policy.is_null() { return TC_ACT_OK; }
    let socket_proxied = wan && tcp && unsafe { *tcp_policy == 2 };
    let now = if packet.tuple.proto == IPPROTO_UDP { unsafe { bpf_ktime_get_ns() } } else { 0 };
    let pure_syn = tcp && packet.flags & 0x12 == 0x02;
    let finish = tcp && packet.flags & 0x05 != 0;
    let mut flags = 0;
    let ptr = tracking::lookup_ref(&packet.tuple, pure_syn, finish, now, &mut flags);
    if flags & tracking::BUSY != 0 { return TC_ACT_SHOT; }
    let direct = flags & tracking::DIRECT_HIT != 0;
    if ptr.is_null() || (direct && socket_proxied) {
        let Some(scratch) = FLOW_SCRATCH.get_ptr_mut(0) else { return TC_ACT_SHOT; };
        let scratch = unsafe { &mut *scratch };
        if ptr.is_null() { scratch.observed = tracking::Decision::default(); }
        else { unsafe { tracking::read_into(ptr, &mut scratch.observed); } }
        if !prepare_miss(ctx, link, &mut packet) { return TC_ACT_SHOT; }
        return CACHE_MISS;
    }
    let verdict = if direct { TC_ACT_OK } else {
        if !read_macs(ctx, link, &mut packet) { return TC_ACT_SHOT; }
        let route = RedirectEntry { ifindex: unsafe { (*ctx.skb.skb).ifindex },
            from_wan: wan as u8, _pad0: [0; 3], smac: packet.smac, dmac: packet.dmac };
        if !unsafe { tracking::route_matches(ptr, &route) } {
            let Some(scratch) = FLOW_SCRATCH.get_ptr_mut(0) else { return TC_ACT_SHOT; };
            let scratch = unsafe { &mut *scratch };
            // Read identity from the same RCU allocation only when replacing.
            unsafe { tracking::read_into(ptr, &mut scratch.observed); }
            if !tracking::publish_into(&packet.tuple, &scratch.observed, Some(&route), &mut scratch.result) {
                return TC_ACT_SHOT;
            }
            if scratch.result.is_direct() { return TC_ACT_OK; }
        }
        if packet.tuple.proto == IPPROTO_UDP && !udp_reply::publish(&packet.tuple, route, now) {
            return TC_ACT_SHOT;
        }
        let listener = if tcp { if pure_syn { IPPROTO_TCP } else { 0 } } else { IPPROTO_UDP };
        let protocol = if packet.tuple.ip_version == 4 { ETH_P_IP } else { ETH_P_IPV6 };
        unsafe { do_redirect(ctx.skb.skb, param, link, listener, protocol, wan) }
    };
    if wan && tcp { unsafe { *tcp_policy = if verdict == TC_ACT_OK { 3 } else { 2 }; } }
    verdict
}

#[inline(never)]
pub fn reply(ctx: &TcContext, out: &mut RedirectEntry) -> i32 {
    let mut tuple = RedirectTuple::default();
    let mut parsed = false;
    if let Some(offset) = parse_reply_ip(ctx, EthHdr::LEN, &mut tuple) {
        if tuple.proto == IPPROTO_UDP {
            if let Some(port) = udp_destination_port(ctx, offset) {
                let key = UdpReplyKey { client_ip: tuple.dst_ip, client_port: port,
                    ip_version: tuple.ip_version, _pad: [0; 5] };
                return udp_reply::lookup_into(&key, unsafe { bpf_ktime_get_ns() }, out);
            }
        } else if tuple.proto == IPPROTO_TCP {
            parsed = parse_tcp_ports(ctx, offset, &mut tuple);
        }
    }
    if parsed { tuple = tuple.reverse(); }
    else {
        let pkt = match parse_packet(ctx, EthHdr::LEN as u32) {
            Ok(pkt) => pkt,
            Err(_) => return 0,
        };
        let version = if pkt.ethh.ether_type == ETH_P_IP.to_be() { 4 } else { 6 };
        if pkt.l4proto == IPPROTO_UDP {
            // Complex-header fallback already has the client endpoint. Avoid
            // constructing a reverse five-tuple or copying the remote address.
            let key = UdpReplyKey { client_ip: *pkt.tuples.five.dst_ip.as_bytes(),
                client_port: pkt.tuples.five.dst_port, ip_version: version, _pad: [0; 5] };
            return udp_reply::lookup_into(&key, unsafe { bpf_ktime_get_ns() }, out);
        }
        packet_reverse_redirect_tuple(pkt, version, &mut tuple);
    }
    let mut flags = 0;
    let ptr = tracking::lookup_ref(&tuple, false, false, 0, &mut flags);
    if flags & tracking::BUSY != 0 { return -1; }
    if ptr.is_null() || flags & tracking::DIRECT_HIT != 0 { return 0; }
    *out = unsafe { tracking::route(ptr) };
    1
}
