#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

mod maps;
mod transport;
mod fast_path;
mod routing;
mod udp_reply;
mod tracking;
mod gate;

// Invoked only through BPF_PROG_TEST_RUN by the collector, never attached.
#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn tracking_gc(_ctx: *mut __sk_buff) -> i32 {
    let Some(batch) = TRACKING_GC_REQUEST.get(0) else { return 0; };
    if batch.count as usize > GC_BATCH_SIZE { return -1; }
    let mut deleted = 0u32;
    for index in 0..GC_BATCH_SIZE {
        if index >= batch.count as usize { break; }
        // Borrow map storage, never copy the batch onto the BPF stack. Each
        // call releases its own gate before the next candidate is processed.
        let request = &batch.requests[index];
        let result = if request.kind == GC_FLOW { tracking::collect(request) }
            else if request.kind == GC_UDP_REPLY { udp_reply::collect(request) }
            else { 0 };
        if result == 1 { deleted |= 1 << index; }
    }
    deleted as i32
}

use aya_ebpf::bindings::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT, bpf_sk_lookup};
use aya_ebpf::btf_maps::lpm_trie::Key;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_redirect};
use aya_ebpf::macros::{cgroup_sock, cgroup_sock_addr};
use aya_ebpf::programs::{SkLookupContext, SockAddrContext, SockContext, TcContext};
use aya_ebpf_bindings::helpers::{
    bpf_get_current_comm, bpf_get_socket_cookie, bpf_ktime_get_ns, bpf_sk_fullsock,
    bpf_sk_storage_get, bpf_skb_change_head, bpf_skb_store_bytes,
};
use clash_ebpf_common::{
    DAE_BYPASS_MARK, DAE_TPROXY_MARK, DaeEventType, GC_BATCH_SIZE, GC_FLOW, GC_UDP_REPLY,
    DaeParam, PIDName, RedirectEntry, RedirectTuple,
};
use core::mem;
use maps::*;
use network_types::eth::EthHdr;
use transport::*;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

const SK_DROP: u32 = 0;
const SK_PASS: u32 = 1;

// ── SOCKMAP key constants ──
const SK_TCP4: u32 = 0;
const SK_TCP6: u32 = 1;
const SK_UDP4: u32 = 2;
const SK_UDP6: u32 = 3;

// ── Helper functions ──

#[inline(always)]
fn get_param() -> Option<&'static DaeParam> {
    DAE_PARAM.get(0)
}

#[inline(always)]
pub fn send_dae_event(
    type_: u32,
    pid: u32,
    pname: Option<&[u8; 16]>,
    outbound: u8,
    l4proto: u8,
    sip: Option<&[u32; 4]>,
    dip: Option<&[u32; 4]>,
    sport: u16,
    dport: u16,
) {
    let Some(mut event) = EVENT_RINGBUF.reserve(0) else {
        return;
    };
    let ptr = event.as_mut_ptr();
    // Initialize every byte, including padding, before constructing a reference.
    unsafe {
        core::ptr::write_bytes(
            ptr.cast::<u8>(),
            0,
            mem::size_of::<clash_ebpf_common::DaeEvent>(),
        )
    };
    let e = unsafe { &mut *ptr };
    e.timestamp = unsafe { bpf_ktime_get_ns() };
    e.type_ = type_;
    e.pid = pid;
    e.outbound = outbound;
    e.l4proto = l4proto;
    e.sport = sport;
    e.dport = dport;
    if let Some(p) = pname {
        e.pname.copy_from_slice(p);
    }
    if let Some(s) = sip {
        e.sip.copy_from_slice(s);
    }
    if let Some(d) = dip {
        e.dip.copy_from_slice(d);
    }
    event.submit(0);
}

#[inline(always)]
fn get_pid_pname(pid_pname: &mut PIDName) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    pid_pname.pid = (pid_tgid >> 32) as u32;

    let ret = unsafe {
        bpf_get_current_comm(
            pid_pname.pname.as_mut_ptr() as *mut aya_ebpf_cty::c_void,
            pid_pname.pname.len() as u32,
        )
    };
    if ret != 0 {
        pid_pname.pname[0] = 0;
    }
    0
}

#[inline(always)]
fn update_map_elem_by_cookie(cookie: u64) -> i32 {
    if cookie == 0 {
        return 0;
    }
    let mut val: PIDName = unsafe { mem::zeroed() };
    let _ = get_pid_pname(&mut val);
    if unsafe { COOKIE_PID_MAP.get(&cookie) } != Some(&val) {
        // Keep whole-value replacement atomic when shared sockets change owner.
        let _ = COOKIE_PID_MAP.insert(&cookie, &val, 0);
    }
    0
}

#[inline(always)]
fn is_src_port_bypassed(port: u16) -> bool {
    if port == 22
        || port == 53
        || port == 67
        || port == 68
        || port == 123
        || port == 5353
    {
        return true;
    }
    unsafe { BYPASS_SRC_PORTS.get(&port).is_some() }
}

#[inline(always)]
fn is_dst_port_bypassed(port: u16, tproxy_port: u16) -> bool {
    if port == 22 || port == 67 || port == 68 || port == 5353 || port == tproxy_port
    {
        return true;
    }
    unsafe { BYPASS_DST_PORTS.get(&port).is_some() }
}

#[inline(always)]
fn is_src_ip4_bypassed(ip_be: [u8; 4]) -> bool {
    let ip_u32 = u32::from_ne_bytes(ip_be);
    let key = Key::new(32, ip_u32);
    BYPASS_SRC_IPS.get(&key).is_some()
}

#[inline(always)]
fn is_dst_ip4_bypassed(ip_be: [u8; 4]) -> bool {
    let ip_u32 = u32::from_ne_bytes(ip_be);
    let key = Key::new(32, ip_u32);
    BYPASS_DST_IPS.get(&key).is_some()
}

#[inline(always)]
fn is_src_ip4_proxied(ip_be: [u8; 4]) -> bool {
    let ip_u32 = u32::from_ne_bytes(ip_be);
    let key = Key::new(32, ip_u32);
    PROXY_SRC_IPS.get(&key).is_some()
}

#[inline(always)]
fn is_dst_ip4_proxied(ip_be: [u8; 4]) -> bool {
    let ip_u32 = u32::from_ne_bytes(ip_be);
    let key = Key::new(32, ip_u32);
    PROXY_DST_IPS.get(&key).is_some()
}

#[inline(always)]
fn is_dynamic_dst_ip4_bypassed(ip_be: [u8; 4]) -> bool {
    let ip_u32 = u32::from_ne_bytes(ip_be);
    unsafe { DYNAMIC_BYPASS_DST_IPS.get(&ip_u32).is_some() }
}

#[inline(always)]
fn is_src_ip6_bypassed(ip: &[u8; 16]) -> bool {
    let key = Key::new(128, *ip);
    BYPASS_SRC_IP6S.get(&key).is_some()
}

#[inline(always)]
fn is_dst_ip6_bypassed(ip: &[u8; 16]) -> bool {
    let key = Key::new(128, *ip);
    BYPASS_DST_IP6S.get(&key).is_some()
}

#[inline(always)]
fn is_dynamic_dst_ip6_bypassed(ip: &[u8; 16]) -> bool {
    unsafe { DYNAMIC_BYPASS_DST_IP6S.get(ip).is_some() }
}

#[inline(always)]
fn is_src_ip6_proxied(ip: &[u8; 16]) -> bool {
    let key = Key::new(128, *ip);
    PROXY_SRC_IP6S.get(&key).is_some()
}

#[inline(always)]
fn is_dst_ip6_proxied(ip: &[u8; 16]) -> bool {
    let key = Key::new(128, *ip);
    PROXY_DST_IP6S.get(&key).is_some()
}

/// Copy addresses as four aligned words in a separate subprogram. Keeping
/// this out of the WAN control flow avoids spilling individual IPv6 bytes.
#[inline(never)]
fn packet_redirect_tuple(
    pkt: &ParsedPacket,
    ip_version: u8,
    tuple: &mut RedirectTuple,
) {
    write_redirect_tuple(pkt, ip_version, tuple, false);
}

#[inline(never)]
fn packet_reverse_redirect_tuple(
    pkt: &ParsedPacket,
    ip_version: u8,
    tuple: &mut RedirectTuple,
) {
    write_redirect_tuple(pkt, ip_version, tuple, true);
}

#[inline(always)]
fn write_redirect_tuple(
    pkt: &ParsedPacket,
    ip_version: u8,
    tuple: &mut RedirectTuple,
    reverse: bool,
) {
    let (src_ip, dst_ip, src_port, dst_port) = if reverse {
        (
            &pkt.tuples.five.dst_ip,
            &pkt.tuples.five.src_ip,
            pkt.tuples.five.dst_port,
            pkt.tuples.five.src_port,
        )
    } else {
        (
            &pkt.tuples.five.src_ip,
            &pkt.tuples.five.dst_ip,
            pkt.tuples.five.src_port,
            pkt.tuples.five.dst_port,
        )
    };
    unsafe {
        let src = tuple.src_ip.as_mut_ptr().cast::<u64>();
        let dst = tuple.dst_ip.as_mut_ptr().cast::<u64>();
        // RedirectTuple is 8-byte aligned; addresses start at offsets 0/16.
        core::ptr::write(src, src_ip.u6_addr64[0]);
        core::ptr::write(src.add(1), src_ip.u6_addr64[1]);
        core::ptr::write(dst, dst_ip.u6_addr64[0]);
        core::ptr::write(dst.add(1), dst_ip.u6_addr64[1]);
    }
    tuple.src_port = src_port;
    tuple.dst_port = dst_port;
    tuple.proto = pkt.l4proto;
    tuple.ip_version = ip_version;
    tuple._pad = [0; 2];
}

// ── Redirect helper: sets cb[] and performs bpf_redirect ──

/// Perform the redirect to dae0 with cb[0]=TPROXY_MARK, cb[1]=listener_l4proto.
/// For L3-only packets (link_h_len == 0, typical on WAN egress), prepends a 14-byte Ethernet header.
#[inline(always)]
unsafe fn do_redirect(
    ctx: *mut __sk_buff,
    param: &DaeParam,
    link_h_len: usize,
    listener_l4proto: u8,
    eth_proto: u16,
    from_wan: bool,
) -> i32 {
    unsafe {
        if link_h_len == 0 {
            // L3 skb (本机发出的出站裸包): 补齐 14 字节以太网头
            let ret = bpf_skb_change_head(ctx, EthHdr::LEN as u32, 0);
            if ret != 0 {
                return TC_ACT_SHOT;
            }

            let eth = EthHdr {
                dst_addr: param.dae0peer_mac,
                src_addr: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                ether_type: eth_proto.to_be(),
            };
            let ret = bpf_skb_store_bytes(
                ctx,
                0,
                &eth as *const EthHdr as *const _,
                EthHdr::LEN as u32,
                0,
            );
            if ret != 0 {
                return TC_ACT_SHOT;
            }
        } else {
            // L2 skb: 重写以太网目的 MAC 为 dae0peer_mac，确保跨 veth 到达 dae0peer 时目的 MAC 正确
            let ret = bpf_skb_store_bytes(
                ctx,
                0,
                param.dae0peer_mac.as_ptr() as *const _,
                6,
                0,
            );
            if ret != 0 { return TC_ACT_SHOT; }
        }

        // 同时设置 skb->mark 与 cb[]，确保跨 veth 转移时标记不丢失
        (*ctx).mark = DAE_TPROXY_MARK;
        (*ctx).cb[0] = DAE_TPROXY_MARK;
        (*ctx).cb[1] = listener_l4proto as u32;

        if !from_wan && param.use_redirect_peer != 0 {
            aya_ebpf_bindings::helpers::bpf_redirect_peer(
                param.dae0_ifindex as u32,
                0,
            ) as i32
        } else {
            bpf_redirect(param.dae0_ifindex as u32, 0) as i32
        }
    }
}

// ─────────────────────────────────────────────────────────────
// 1. LAN Ingress (局域网转发流量处理)
// ─────────────────────────────────────────────────────────────

#[inline(always)]
fn handle_lan_ipv4(
    ctx: *mut __sk_buff,
    param: &DaeParam,
    link_h_len: usize,
    pkt: &ParsedPacket,
    observed: bool,
) -> i32 {
    let src_port = pkt.tuples.five.src_port;
    let dst_port = pkt.tuples.five.dst_port;

    let is_tcp = pkt.l4proto == IPPROTO_TCP;
    let is_udp = pkt.l4proto == IPPROTO_UDP;
    let is_pure_syn = is_tcp && (pkt.tcph.syn() != 0 && pkt.tcph.ack() == 0);
    let is_fin_rst = is_tcp && (pkt.tcph.fin() != 0 || pkt.tcph.rst() != 0);

    let mut tuple = RedirectTuple::default();
    packet_redirect_tuple(pkt, 4, &mut tuple);
    let Some(scratch) = FLOW_SCRATCH.get_ptr_mut(0) else { return TC_ACT_SHOT; };
    let scratch = unsafe { &mut *scratch };
    let packet_now = if is_udp { unsafe { bpf_ktime_get_ns() } } else { 0 };
    if !observed && tracking::lookup_into(&tuple, is_pure_syn, is_fin_rst, packet_now, &mut scratch.observed)
        & tracking::BUSY != 0 { return TC_ACT_SHOT; }
    let tracked = &scratch.observed;
    let is_redirected = tracked.is_redirect();
    if !is_redirected && tracked.is_direct() { return TC_ACT_OK; }
    if !is_redirected && routing::direct(param, link_h_len, pkt, false, None) {
        if !tracking::publish_into(&tuple, tracked, None, &mut scratch.result) { return TC_ACT_SHOT; }
        if scratch.result.is_direct() { return TC_ACT_OK; }
    }

    let ifindex = unsafe { (*ctx).ifindex };
    let (smac, dmac) = if link_h_len >= EthHdr::LEN {
        (pkt.ethh.src_addr, pkt.ethh.dst_addr)
    } else {
        ([0u8; 6], [0u8; 6])
    };
    let entry = RedirectEntry {
        ifindex,
        from_wan: 0,
        _pad0: [0; 3],
        smac,
        dmac,
    };
    unsafe {
        let is_new_flow = tracked.activity == 0;
        if !tracked.matches_route(&entry) {
            if !tracking::publish_into(&tuple, tracked, Some(&entry), &mut scratch.result) {
                return TC_ACT_SHOT;
            }
            if scratch.result.is_direct() { return TC_ACT_OK; }
        }
        if is_udp && !udp_reply::publish(&tuple, entry, packet_now) {
            return TC_ACT_SHOT;
        }
        let l4proto = if pkt.l4proto == IPPROTO_TCP {
            pkt.listener_l4proto
        } else {
            IPPROTO_UDP
        };

        if is_new_flow && param.log_events != 0 {
            let sip_u32 = [u32::from_be_bytes([tuple.src_ip[12], tuple.src_ip[13], tuple.src_ip[14], tuple.src_ip[15]]), 0, 0, 0];
            let dip_u32 = [u32::from_be_bytes([tuple.dst_ip[12], tuple.dst_ip[13], tuple.dst_ip[14], tuple.dst_ip[15]]), 0, 0, 0];
            send_dae_event(
                DaeEventType::Redirected as u32,
                0,
                None,
                0,
                pkt.l4proto,
                Some(&sip_u32),
                Some(&dip_u32),
                src_port,
                dst_port,
            );
        }

        do_redirect(ctx, param, link_h_len, l4proto, ETH_P_IP, false)
    }
}

#[inline(always)]
fn handle_lan_ipv6(
    ctx: *mut __sk_buff,
    param: &DaeParam,
    link_h_len: usize,
    pkt: &ParsedPacket,
    observed: bool,
) -> i32 {
    let src_port = pkt.tuples.five.src_port;
    let dst_port = pkt.tuples.five.dst_port;

    let is_tcp = pkt.l4proto == IPPROTO_TCP;
    let is_udp = pkt.l4proto == IPPROTO_UDP;
    let is_pure_syn = is_tcp && (pkt.tcph.syn() != 0 && pkt.tcph.ack() == 0);
    let is_fin_rst = is_tcp && (pkt.tcph.fin() != 0 || pkt.tcph.rst() != 0);

    let mut tuple = RedirectTuple::default();
    packet_redirect_tuple(pkt, 6, &mut tuple);
    let Some(scratch) = FLOW_SCRATCH.get_ptr_mut(0) else { return TC_ACT_SHOT; };
    let scratch = unsafe { &mut *scratch };
    let packet_now = if is_udp { unsafe { bpf_ktime_get_ns() } } else { 0 };
    if !observed && tracking::lookup_into(&tuple, is_pure_syn, is_fin_rst, packet_now, &mut scratch.observed)
        & tracking::BUSY != 0 { return TC_ACT_SHOT; }
    let tracked = &scratch.observed;
    let is_redirected = tracked.is_redirect();
    if !is_redirected && tracked.is_direct() { return TC_ACT_OK; }
    if !is_redirected && routing::direct(param, link_h_len, pkt, false, None) {
        if !tracking::publish_into(&tuple, tracked, None, &mut scratch.result) { return TC_ACT_SHOT; }
        if scratch.result.is_direct() { return TC_ACT_OK; }
    }

    let ifindex = unsafe { (*ctx).ifindex };
    let (smac, dmac) = if link_h_len >= EthHdr::LEN {
        (pkt.ethh.src_addr, pkt.ethh.dst_addr)
    } else {
        ([0u8; 6], [0u8; 6])
    };
    let entry = RedirectEntry {
        ifindex,
        from_wan: 0,
        _pad0: [0; 3],
        smac,
        dmac,
    };
    unsafe {
        let is_new_flow = tracked.activity == 0;
        if !tracked.matches_route(&entry) {
            if !tracking::publish_into(&tuple, tracked, Some(&entry), &mut scratch.result) {
                return TC_ACT_SHOT;
            }
            if scratch.result.is_direct() { return TC_ACT_OK; }
        }
        if is_udp && !udp_reply::publish(&tuple, entry, packet_now) {
            return TC_ACT_SHOT;
        }
        let l4proto = if pkt.l4proto == IPPROTO_TCP {
            pkt.listener_l4proto
        } else {
            IPPROTO_UDP
        };

        if is_new_flow && param.log_events != 0 {
            send_dae_event(
                DaeEventType::Redirected as u32,
                0,
                None,
                0,
                pkt.l4proto,
                Some(&pkt.tuples.five.src_ip.u6_addr32),
                Some(&pkt.tuples.five.dst_ip.u6_addr32),
                src_port,
                dst_port,
            );
        }

        do_redirect(ctx, param, link_h_len, l4proto, ETH_P_IPV6, false)
    }
}

#[inline(never)]
fn handle_lan_ingress_impl(tc_ctx: &TcContext, link_h_len: usize) -> i32 {
    let ctx = tc_ctx.skb.skb;
    let mark = unsafe { (*ctx).mark };

    let Some(param) = get_param() else {
        return TC_ACT_OK;
    };
    if param.dae0_ifindex == 0 {
        return TC_ACT_OK;
    }

    if mark == DAE_BYPASS_MARK
        || (param.dae_socket_mark != 0 && mark == param.dae_socket_mark)
        || (param.has_bypass_fwmarks != 0
            && unsafe { BYPASS_FWMARKS.get(&mark).is_some() })
    {
        return TC_ACT_OK;
    }

    let verdict = fast_path::forward(tc_ctx, param, link_h_len, false, core::ptr::null_mut());
    if verdict >= 0 { return verdict; }
    let observed = verdict == fast_path::CACHE_MISS;

    handle_lan_miss(tc_ctx, param, link_h_len, observed)
}

// Cache misses reuse FLOW_SCRATCH.observed from the dedicated parser. No
// intervening parser writes that map, and lifecycle transitions run only once.
#[inline(never)]
fn handle_lan_miss(tc_ctx: &TcContext, param: &DaeParam, link_h_len: usize, observed: bool) -> i32 {
    let ctx = tc_ctx.skb.skb;
    let parsed = if observed {
        PARSED_PKT_MAP.get_ptr(0).map(|ptr| unsafe { &*ptr }).ok_or(ERR_MALFORMED)
    } else { parse_packet(tc_ctx, link_h_len as u32) };
    let pkt = match parsed {
        Ok(p) => p,
        Err(_) => return TC_ACT_OK,
    };

    if dst_is_special(pkt, link_h_len as u32) {
        return TC_ACT_OK;
    }

    if pkt.ethh.ether_type == ETH_P_IP.to_be() {
        handle_lan_ipv4(ctx, param, link_h_len, pkt, observed)
    } else if pkt.ethh.ether_type == ETH_P_IPV6.to_be() {
        handle_lan_ipv6(ctx, param, link_h_len, pkt, observed)
    } else {
        TC_ACT_OK
    }
}

// ─────────────────────────────────────────────────────────────
// 2. WAN Egress (本机出站流量处理)
// ─────────────────────────────────────────────────────────────

#[inline(always)]
fn handle_wan_ipv4(
    ctx: *mut __sk_buff,
    param: &DaeParam,
    link_h_len: usize,
    pkt: &ParsedPacket,
    process: &(Option<&PIDName>, bool, bool),
) -> i32 {
    let (pid_pname, socket_was_proxied, observed) = *process;
    let src_port = pkt.tuples.five.src_port;
    let dst_port = pkt.tuples.five.dst_port;

    let is_tcp = pkt.l4proto == IPPROTO_TCP;
    let is_udp = pkt.l4proto == IPPROTO_UDP;
    let is_pure_syn = is_tcp && (pkt.tcph.syn() != 0 && pkt.tcph.ack() == 0);
    let is_fin_rst = is_tcp && (pkt.tcph.fin() != 0 || pkt.tcph.rst() != 0);

    let ip_be: [u8; 4] = [
        pkt.tuples.five.dst_ip[12],
        pkt.tuples.five.dst_ip[13],
        pkt.tuples.five.dst_ip[14],
        pkt.tuples.five.dst_ip[15],
    ];
    let src_ip_be: [u8; 4] = [
        pkt.tuples.five.src_ip[12],
        pkt.tuples.five.src_ip[13],
        pkt.tuples.five.src_ip[14],
        pkt.tuples.five.src_ip[15],
    ];

    let mut tuple = RedirectTuple::default();
    packet_redirect_tuple(pkt, 4, &mut tuple);
    let Some(scratch) = FLOW_SCRATCH.get_ptr_mut(0) else { return TC_ACT_SHOT; };
    let scratch = unsafe { &mut *scratch };
    let packet_now = if is_udp { unsafe { bpf_ktime_get_ns() } } else { 0 };
    if !observed && tracking::lookup_into(&tuple, is_pure_syn, is_fin_rst, packet_now, &mut scratch.observed)
        & tracking::BUSY != 0 { return TC_ACT_SHOT; }
    let tracked = &scratch.observed;
    let is_redirected = tracked.is_redirect() || socket_was_proxied;
    if !is_redirected && tracked.is_direct() { return TC_ACT_OK; }
    if !is_redirected && routing::direct(param, link_h_len, pkt, true, pid_pname) {
        if !tracking::publish_into(&tuple, tracked, None, &mut scratch.result) { return TC_ACT_SHOT; }
        if scratch.result.is_direct() { return TC_ACT_OK; }
    }

    let ifindex = unsafe { (*ctx).ifindex };
    let (smac, dmac) = if link_h_len >= EthHdr::LEN {
        (pkt.ethh.src_addr, pkt.ethh.dst_addr)
    } else {
        ([0u8; 6], [0u8; 6])
    };
    let entry = RedirectEntry {
        ifindex,
        from_wan: 1,
        _pad0: [0; 3],
        smac,
        dmac,
    };
    unsafe {
        let is_new_flow = tracked.activity == 0;
        if !tracked.matches_route(&entry) {
            if !tracking::publish_into(&tuple, tracked, Some(&entry), &mut scratch.result) {
                return TC_ACT_SHOT;
            }
            if scratch.result.is_direct() { return TC_ACT_OK; }
        }
        if is_udp && !udp_reply::publish(&tuple, entry, packet_now) {
            return TC_ACT_SHOT;
        }
        let l4proto = if pkt.l4proto == IPPROTO_TCP {
            pkt.listener_l4proto
        } else {
            IPPROTO_UDP
        };

        if is_new_flow && param.log_events != 0 {
            let pid = pid_pname.map(|p| p.pid).unwrap_or(0);
            let pname = pid_pname.map(|p| &p.pname);
            let sip_u32 = [u32::from_be_bytes(src_ip_be), 0, 0, 0];
            let dip_u32 = [u32::from_be_bytes(ip_be), 0, 0, 0];
            send_dae_event(
                DaeEventType::Redirected as u32,
                pid,
                pname,
                1,
                pkt.l4proto,
                Some(&sip_u32),
                Some(&dip_u32),
                src_port,
                dst_port,
            );
        }

        do_redirect(ctx, param, link_h_len, l4proto, ETH_P_IP, true)
    }
}

#[inline(always)]
fn handle_wan_ipv6(
    ctx: *mut __sk_buff,
    param: &DaeParam,
    link_h_len: usize,
    pkt: &ParsedPacket,
    process: &(Option<&PIDName>, bool, bool),
) -> i32 {
    let (pid_pname, socket_was_proxied, observed) = *process;
    let src_port = pkt.tuples.five.src_port;
    let dst_port = pkt.tuples.five.dst_port;

    let is_tcp = pkt.l4proto == IPPROTO_TCP;
    let is_udp = pkt.l4proto == IPPROTO_UDP;
    let is_pure_syn = is_tcp && (pkt.tcph.syn() != 0 && pkt.tcph.ack() == 0);
    let is_fin_rst = is_tcp && (pkt.tcph.fin() != 0 || pkt.tcph.rst() != 0);

    let mut tuple = RedirectTuple::default();
    packet_redirect_tuple(pkt, 6, &mut tuple);
    let Some(scratch) = FLOW_SCRATCH.get_ptr_mut(0) else { return TC_ACT_SHOT; };
    let scratch = unsafe { &mut *scratch };
    let packet_now = if is_udp { unsafe { bpf_ktime_get_ns() } } else { 0 };
    if !observed && tracking::lookup_into(&tuple, is_pure_syn, is_fin_rst, packet_now, &mut scratch.observed)
        & tracking::BUSY != 0 { return TC_ACT_SHOT; }
    let tracked = &scratch.observed;
    let is_redirected = tracked.is_redirect() || socket_was_proxied;
    if !is_redirected && tracked.is_direct() { return TC_ACT_OK; }
    if !is_redirected && routing::direct(param, link_h_len, pkt, true, pid_pname) {
        if !tracking::publish_into(&tuple, tracked, None, &mut scratch.result) { return TC_ACT_SHOT; }
        if scratch.result.is_direct() { return TC_ACT_OK; }
    }

    let ifindex = unsafe { (*ctx).ifindex };
    let (smac, dmac) = if link_h_len >= EthHdr::LEN {
        (pkt.ethh.src_addr, pkt.ethh.dst_addr)
    } else {
        ([0u8; 6], [0u8; 6])
    };
    let entry = RedirectEntry {
        ifindex,
        from_wan: 1,
        _pad0: [0; 3],
        smac,
        dmac,
    };
    unsafe {
        let is_new_flow = tracked.activity == 0;
        if !tracked.matches_route(&entry) {
            if !tracking::publish_into(&tuple, tracked, Some(&entry), &mut scratch.result) {
                return TC_ACT_SHOT;
            }
            if scratch.result.is_direct() { return TC_ACT_OK; }
        }
        if is_udp && !udp_reply::publish(&tuple, entry, packet_now) {
            return TC_ACT_SHOT;
        }
        let l4proto = if pkt.l4proto == IPPROTO_TCP {
            pkt.listener_l4proto
        } else {
            IPPROTO_UDP
        };

        if is_new_flow && param.log_events != 0 {
            let pid = pid_pname.map(|p| p.pid).unwrap_or(0);
            let pname = pid_pname.map(|p| &p.pname);
            send_dae_event(
                DaeEventType::Redirected as u32,
                pid,
                pname,
                1,
                pkt.l4proto,
                Some(&pkt.tuples.five.src_ip.u6_addr32),
                Some(&pkt.tuples.five.dst_ip.u6_addr32),
                src_port,
                dst_port,
            );
        }

        do_redirect(ctx, param, link_h_len, l4proto, ETH_P_IPV6, true)
    }
}

#[inline(never)]
fn handle_wan_egress_impl(tc_ctx: &TcContext, link_h_len: usize) -> i32 {
    let ctx = tc_ctx.skb.skb;
    let mark = unsafe { (*ctx).mark };

    let Some(param) = get_param() else {
        return TC_ACT_OK;
    };
    if param.dae0_ifindex == 0 {
        return TC_ACT_OK;
    }

    // 1. Clash 自身发出的出站请求 (带 DAE_BYPASS_MARK 或配置的 dae_socket_mark 或配置的 bypass_fwmarks): 绝对放行防自环/绕过
    if mark == DAE_BYPASS_MARK
        || (param.dae_socket_mark != 0 && mark == param.dae_socket_mark)
        || (param.has_bypass_fwmarks != 0
            && unsafe { BYPASS_FWMARKS.get(&mark).is_some() })
    {
        return TC_ACT_OK;
    }

    // 2. 本机出站总开关: 若未开启本机代理，直接无条件放行
    if param.proxy_local == 0 {
        return TC_ACT_OK;
    }

    // 3. 纯转发流量放行: 从 LAN 等网络接口进来的路由转发包 (ingress_ifindex != 0)
    // 已经在 lan_ingress 中完成准入判定，在 WAN 出口必须放行直连，严禁被当作本机流量误劫持。
    if unsafe { (*ctx).ingress_ifindex } != 0 {
        return TC_ACT_OK;
    }

    let mut tcp_policy = core::ptr::null_mut::<u32>();
    let sk = unsafe { (*ctx).__bindgen_anon_2.sk };
    if !sk.is_null() {
        let full = unsafe { bpf_sk_fullsock(sk) };
        if !full.is_null() && unsafe { (*full).protocol } == IPPROTO_TCP as u32 {
            tcp_policy = unsafe {
                bpf_sk_storage_get(
                    core::ptr::addr_of!(TCP_SOCKET_POLICY).cast_mut().cast(),
                    full.cast(),
                    core::ptr::null_mut(),
                    0,
                )
            }
            .cast::<u32>();
            // Missing storage means passive or predating the connect hooks.
            if tcp_policy.is_null() || unsafe { *tcp_policy } == 3 {
                return TC_ACT_OK;
            }
        }
    }

    let cookie = unsafe { bpf_get_socket_cookie(ctx as *mut _) };
    if cookie == 0 {
        // 无本地 socket 关联的报文（如纯路由转发报文），绝不属于本机出站流量，必须放行
        return TC_ACT_OK;
    }
    let pid_pname = unsafe { COOKIE_PID_MAP.get(&cookie) };

    // Control-plane identity remains an unconditional loop guard. User process
    // routing rules are evaluated and cached only on a connection miss.
    if let Some(pp) = pid_pname {
        if param.control_plane_pid != 0 && pp.pid == param.control_plane_pid {
            return TC_ACT_OK;
        }
    }

    let verdict = fast_path::forward(tc_ctx, param, link_h_len, true, tcp_policy);
    if verdict >= 0 { return verdict; }
    let observed = verdict == fast_path::CACHE_MISS;

    handle_wan_miss(tc_ctx, param, link_h_len, &(pid_pname, tcp_policy, observed))
}

#[inline(never)]
fn handle_wan_miss(tc_ctx: &TcContext, param: &DaeParam, link_h_len: usize,
    state: &(Option<&PIDName>, *mut u32, bool),
) -> i32 {
    let ctx = tc_ctx.skb.skb;
    let (pid_pname, tcp_policy, observed) = *state;
    let parsed = if observed {
        PARSED_PKT_MAP.get_ptr(0).map(|ptr| unsafe { &*ptr }).ok_or(ERR_MALFORMED)
    } else { parse_packet(tc_ctx, link_h_len as u32) };
    let pkt = match parsed {
        Ok(p) => p,
        Err(_) => return TC_ACT_OK,
    };

    if dst_is_special(pkt, link_h_len as u32) {
        return TC_ACT_OK;
    }

    // Only connect hooks grant active-open identity; no flow-LRU dependency.
    if pkt.l4proto == IPPROTO_TCP {
        if tcp_policy.is_null() {
            return TC_ACT_OK;
        }
        let decision = unsafe { *tcp_policy };
        let verdict =
            dispatch_wan(ctx, param, link_h_len, pkt, &(pid_pname, decision == 2, observed));
        unsafe {
            *tcp_policy = if verdict == TC_ACT_OK { 3 } else { 2 };
        }
        return verdict;
    }
    dispatch_wan(ctx, param, link_h_len, pkt, &(pid_pname, false, observed))
}

#[inline(always)]
fn dispatch_wan(
    ctx: *mut __sk_buff,
    param: &DaeParam,
    link_h_len: usize,
    pkt: &ParsedPacket,
    process: &(Option<&PIDName>, bool, bool),
) -> i32 {
    if pkt.ethh.ether_type == ETH_P_IP.to_be() {
        handle_wan_ipv4(ctx, param, link_h_len, pkt, process)
    } else if pkt.ethh.ether_type == ETH_P_IPV6.to_be() {
        handle_wan_ipv6(ctx, param, link_h_len, pkt, process)
    } else {
        TC_ACT_OK
    }
}

// ─────────────────────────────────────────────────────────────
// 3. TC Entrypoints
// ─────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress(ctx: *mut __sk_buff) -> i32 {
    handle_lan_ingress_impl(&TcContext::new(ctx), EthHdr::LEN)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress_l2(ctx: *mut __sk_buff) -> i32 {
    handle_lan_ingress_impl(&TcContext::new(ctx), EthHdr::LEN)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress_l3(ctx: *mut __sk_buff) -> i32 {
    handle_lan_ingress_impl(&TcContext::new(ctx), 0)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_egress(ctx: *mut __sk_buff) -> i32 {
    handle_wan_egress_impl(&TcContext::new(ctx), EthHdr::LEN)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_egress_l2(ctx: *mut __sk_buff) -> i32 {
    handle_wan_egress_impl(&TcContext::new(ctx), EthHdr::LEN)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_egress_l3(ctx: *mut __sk_buff) -> i32 {
    handle_wan_egress_impl(&TcContext::new(ctx), 0)
}

/// dae0peer ingress: runs inside daens namespace.
/// Sets PACKET_HOST + fwmark so the packet is accepted and routed locally (table 100).
#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn dae0peer_ingress(ctx: *mut __sk_buff) -> i32 {
    let tc_ctx = TcContext::new(ctx);

    let cb0 = unsafe { (*ctx).cb[0] };
    let mark = unsafe { (*ctx).mark };
    if cb0 != DAE_TPROXY_MARK && mark != DAE_TPROXY_MARK {
        return TC_ACT_SHOT;
    }

    // Set mark for policy routing (mark → table 100 → local route)
    unsafe {
        (*ctx).mark = DAE_TPROXY_MARK;
    }

    // Force PACKET_HOST so the IP stack accepts this packet
    if tc_ctx.change_type(0).is_err() { return TC_ACT_SHOT; }

    TC_ACT_OK
}

/// Socket-lookup program attached to the daens namespace.
/// When proxy-bound packets arrive in daens, normal socket lookup fails
/// because the destination port is the original remote endpoint port.
/// This program intercepts the lookup and directs the packet to the
/// corresponding transparent proxy listener in LISTEN_SOCKET_MAP.
#[unsafe(no_mangle)]
#[unsafe(link_section = "sk_lookup")]
pub fn tproxy_sk_lookup(ctx: *mut bpf_sk_lookup) -> u32 {
    let ctx = SkLookupContext::new(ctx);
    do_tproxy_sk_lookup(&ctx)
}

#[inline(always)]
fn do_tproxy_sk_lookup(ctx: &SkLookupContext) -> u32 {
    let lookup = unsafe { &*ctx.lookup };
    let protocol = lookup.protocol as u8;
    let family = lookup.family;

    let key = if family == AF_INET as u32 && protocol as u32 == IPPROTO_TCP as u32 {
        SK_TCP4
    } else if family == AF_INET6 as u32 && protocol as u32 == IPPROTO_TCP as u32 {
        SK_TCP6
    } else if protocol as u32 == IPPROTO_UDP as u32 {
        if family == AF_INET as u32 {
            SK_UDP4
        } else {
            SK_UDP6
        }
    } else {
        return SK_PASS;
    };

    match LISTEN_SOCKET_MAP.redirect_sk_lookup(ctx, key, 0) {
        Ok(_) => SK_PASS,
        Err(_) => SK_DROP,
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn dae0_ingress(ctx: *mut __sk_buff) -> i32 {
    handle_dae0_ingress_impl(&TcContext::new(ctx))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn dae0_ingress_l2(ctx: *mut __sk_buff) -> i32 {
    handle_dae0_ingress_impl(&TcContext::new(ctx))
}

#[inline(never)]
fn handle_dae0_ingress_impl(tc_ctx: &TcContext) -> i32 {
    let ctx = tc_ctx.skb.skb;
    let mut entry = RedirectEntry::default();
    let status = fast_path::reply(tc_ctx, &mut entry);
    if status < 0 { return TC_ACT_SHOT; }
    if status == 0 { return TC_ACT_OK; }
    let dmac = entry.smac;
    let smac = entry.dmac;
    let from_wan = entry.from_wan;
    let ifindex = entry.ifindex;

    unsafe {
        if dmac != [0; 6] {
            // Ethernet destination and source addresses occupy the first 12 bytes.
            let mut macs = [0u8; 12];
            macs[..6].copy_from_slice(&dmac);
            macs[6..].copy_from_slice(&smac);
            if bpf_skb_store_bytes(ctx, 0, macs.as_ptr().cast(), 12, 0) != 0 {
                return TC_ACT_SHOT;
            }
        }

        let flags: u64 = if from_wan != 0 { 1 } else { 0 }; // 1 = BPF_F_INGRESS
        if from_wan != 0 {
            if tc_ctx.change_type(0).is_err() { return TC_ACT_SHOT; } // PACKET_HOST
        }
        bpf_redirect(ifindex, flags) as i32
    }
}

// ─────────────────────────────────────────────────────────────
// 4. Cgroup Socket Attachments (用于进程跟踪与自环避免)
// ─────────────────────────────────────────────────────────────

#[cgroup_sock(sock_create)]
pub fn tproxy_wan_cg_sock_create(ctx: SockContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock as *mut _) };
    update_map_elem_by_cookie(cookie);

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if let Some(param) = get_param() {
        if param.control_plane_pid != 0 && pid == param.control_plane_pid {
            unsafe {
                (*ctx.sock).mark = DAE_BYPASS_MARK;
            }
        }
    }

    1
}

#[cgroup_sock(sock_release)]
pub fn tproxy_wan_cg_sock_release(ctx: SockContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock as *mut _) };
    if cookie != 0 {
        let _ = COOKIE_PID_MAP.remove(&cookie);
    }
    1
}

#[cgroup_sock_addr(connect4)]
pub fn tproxy_wan_cg_connect4(ctx: SockAddrContext) -> i32 {
    if unsafe { (*ctx.sock_addr).protocol } == IPPROTO_TCP as u32 {
        let mut active = 1u32;
        // Preserve a decision if connect is called again on the same socket.
        let _ = unsafe {
            TCP_SOCKET_POLICY.get_or_insert_ptr_mut(&ctx, Some(&mut active))
        };
    }

    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut _) };
    update_map_elem_by_cookie(cookie);
    1
}

#[cgroup_sock_addr(connect6)]
pub fn tproxy_wan_cg_connect6(ctx: SockAddrContext) -> i32 {
    if unsafe { (*ctx.sock_addr).protocol } == IPPROTO_TCP as u32 {
        let mut active = 1u32;
        // Preserve a decision if connect is called again on the same socket.
        let _ = unsafe {
            TCP_SOCKET_POLICY.get_or_insert_ptr_mut(&ctx, Some(&mut active))
        };
    }

    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut _) };
    update_map_elem_by_cookie(cookie);
    1
}

#[cgroup_sock_addr(sendmsg4)]
pub fn tproxy_wan_cg_sendmsg4(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut _) };
    update_map_elem_by_cookie(cookie);
    1
}

#[cgroup_sock_addr(sendmsg6)]
pub fn tproxy_wan_cg_sendmsg6(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut _) };
    update_map_elem_by_cookie(cookie);
    1
}
