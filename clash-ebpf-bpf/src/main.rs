#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

mod maps;
mod transport;

use aya_ebpf::bindings::{__sk_buff, TC_ACT_OK, bpf_sk_lookup};
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_redirect};
use aya_ebpf::macros::{cgroup_sock, cgroup_sock_addr};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::programs::{SkLookupContext, SockAddrContext, SockContext, TcContext};
use aya_ebpf_bindings::helpers::{
    bpf_get_current_comm, bpf_get_socket_cookie, bpf_ktime_get_ns,
    bpf_skb_change_head, bpf_skb_store_bytes,
};
use clash_ebpf_common::{
    DIRECT_TRACK_STATE_ACTIVE, DAE_BYPASS_MARK, DAE_TPROXY_MARK, DaeEvent, DaeEventType, DaeParam,
    DirectTrackEntry, PIDName, RedirectEntry, RedirectTuple,
};
use core::mem;
use maps::*;
use network_types::eth::EthHdr;
use transport::*;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

const SK_DROP: u32 = 0;
const SK_PASS: u32 = 1;

// ── Conntrack timeout constants ──
const UDP_CONN_TIMEOUT_NS: u64 = 120_000_000_000; // 120 seconds
const CONN_TRACK_UPDATE_INTERVAL_NS: u64 = 1_000_000_000; // 1 second

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
    let Some(ptr) = EVENT_SCRATCH_MAP.get_ptr_mut(0) else {
        return;
    };
    let e = unsafe { &mut *ptr };
    *e = unsafe { mem::zeroed() };
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
    let _ = EVENT_RINGBUF.output::<DaeEvent>(e, 0);
}

#[inline(always)]
fn get_pid_pname(pid_pname: &mut PIDName) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    pid_pname.last_seen_ns = unsafe { bpf_ktime_get_ns() };
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
    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(ptr) = COOKIE_PID_MAP.get_ptr_mut(&cookie) {
        let entry = unsafe { &mut *ptr };
        entry.last_seen_ns = now;
        return 0;
    }
    let mut val: PIDName = unsafe { mem::zeroed() };
    let _ = get_pid_pname(&mut val);
    let _ = COOKIE_PID_MAP.insert(&cookie, &val, 0);
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
fn is_src_ip6_bypassed(ip: [u8; 16]) -> bool {
    let key = Key::new(128, ip);
    BYPASS_SRC_IP6S.get(&key).is_some()
}


#[inline(always)]
fn is_dst_ip6_bypassed(ip: [u8; 16]) -> bool {
    let key = Key::new(128, ip);
    BYPASS_DST_IP6S.get(&key).is_some()
}

#[inline(always)]
fn is_dynamic_dst_ip6_bypassed(ip: [u8; 16]) -> bool {
    unsafe { DYNAMIC_BYPASS_DST_IP6S.get(&ip).is_some() }
}

#[inline(always)]
fn is_src_ip6_proxied(ip: [u8; 16]) -> bool {
    let key = Key::new(128, ip);
    PROXY_SRC_IP6S.get(&key).is_some()
}

#[inline(always)]
fn is_dst_ip6_proxied(ip: [u8; 16]) -> bool {
    let key = Key::new(128, ip);
    PROXY_DST_IP6S.get(&key).is_some()
}

#[inline(always)]
fn check_direct_track(
    tuple: &RedirectTuple,
    is_tcp: bool,
    is_udp: bool,
    is_fin_rst: bool,
    is_pure_syn: bool,
) -> bool {
    if is_pure_syn {
        return false;
    }
    if let Some(entry) = unsafe { DIRECT_TRACK.get(tuple) } {
        let last_seen_ns = entry.last_seen_ns;
        let now = unsafe { bpf_ktime_get_ns() };

        if is_udp {
            if now.wrapping_sub(last_seen_ns) > UDP_CONN_TIMEOUT_NS {
                let _ = DIRECT_TRACK.remove(tuple);
                return false;
            }
            if now.wrapping_sub(last_seen_ns) > CONN_TRACK_UPDATE_INTERVAL_NS {
                let updated = DirectTrackEntry {
                    last_seen_ns: now,
                    state: DIRECT_TRACK_STATE_ACTIVE,
                    _pad: [0; 7],
                };
                let _ = DIRECT_TRACK.insert(tuple, &updated, 0);
            }
            return true;
        }

        if is_tcp {
            if is_fin_rst {
                let _ = DIRECT_TRACK.remove(tuple);
            } else if now.wrapping_sub(last_seen_ns) > CONN_TRACK_UPDATE_INTERVAL_NS {
                let updated = DirectTrackEntry {
                    last_seen_ns: now,
                    state: DIRECT_TRACK_STATE_ACTIVE,
                    _pad: [0; 7],
                };
                let _ = DIRECT_TRACK.insert(tuple, &updated, 0);
            }
            return true;
        }
    }
    false
}

#[inline(always)]
fn register_direct_track(tuple: &RedirectTuple) {
    let now = unsafe { bpf_ktime_get_ns() };
    let direct_entry = DirectTrackEntry {
        last_seen_ns: now,
        state: DIRECT_TRACK_STATE_ACTIVE,
        _pad: [0; 7],
    };
    let _ = DIRECT_TRACK.insert(tuple, &direct_entry, 0);
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
                return TC_ACT_OK;
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
                return TC_ACT_OK;
            }
        } else {
            // L2 skb: 重写以太网目的 MAC 为 dae0peer_mac，确保跨 veth 到达 dae0peer 时目的 MAC 正确
            let _ = bpf_skb_store_bytes(
                ctx,
                0,
                param.dae0peer_mac.as_ptr() as *const _,
                6,
                0,
            );
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
) -> i32 {
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

    let tuple = RedirectTuple {
        src_ip: *pkt.tuples.five.src_ip.as_bytes(),
        dst_ip: *pkt.tuples.five.dst_ip.as_bytes(),
        src_port,
        dst_port,
        proto: pkt.l4proto,
        ip_version: 4,
        _pad: [0; 2],
    };

    // 1. 源 IP / 源端口 静态 Bypass 与白名单判定
    if is_src_ip4_bypassed(src_ip_be) {
        return TC_ACT_OK;
    }
    if param.has_proxy_src_ips != 0 && !is_src_ip4_proxied(src_ip_be) {
        return TC_ACT_OK;
    }
    if is_src_port_bypassed(src_port) {
        return TC_ACT_OK;
    }
    if param.has_proxy_src_ports != 0
        && unsafe { PROXY_SRC_PORTS.get(&src_port).is_none() }
    {
        return TC_ACT_OK;
    }

    // 2. 常规业务流量目标过滤 (DNS 53 强制劫持到代理)
    if dst_port != 53 {
        // 本机直连流量放行
        if param.local_ip != 0 && ip_be == param.local_ip.to_ne_bytes() {
            return TC_ACT_OK;
        }

        // 静态目标 IP / 目标端口 Bypass 判定 (无需入表)
        if is_dst_ip4_bypassed(ip_be) || is_dst_port_bypassed(dst_port, param.tproxy_port as u16) {
            return TC_ACT_OK;
        }

        // 动态直连流表 Fast-Path 查询 (针对非纯 SYN 报文)
        if check_direct_track(&tuple, is_tcp, is_udp, is_fin_rst, is_pure_syn) {
            return TC_ACT_OK;
        }

        // 动态下发直连判定 (受 DNS TTL 影响，命中则建立 DIRECT_TRACK 连接追踪)
        if is_dynamic_dst_ip4_bypassed(ip_be) {
            register_direct_track(&tuple);
            return TC_ACT_OK;
        }

        // 目标白名单过滤
        if param.has_proxy_dst_ips != 0 && !is_dst_ip4_proxied(ip_be) {
            return TC_ACT_OK;
        }
        if param.has_proxy_dst_ports != 0
            && unsafe { PROXY_DST_PORTS.get(&dst_port).is_none() }
        {
            return TC_ACT_OK;
        }
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
        let is_new_flow = REDIRECT_TRACK.get(&tuple).is_none();
        let _ = REDIRECT_TRACK.insert(&tuple, &entry, 0);
        let l4proto = if pkt.l4proto == IPPROTO_TCP {
            pkt.listener_l4proto
        } else {
            IPPROTO_UDP
        };

        if is_new_flow {
            let sip_u32 = [u32::from_be_bytes(src_ip_be), 0, 0, 0];
            let dip_u32 = [u32::from_be_bytes(ip_be), 0, 0, 0];
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
) -> i32 {
    let src_port = pkt.tuples.five.src_port;
    let dst_port = pkt.tuples.five.dst_port;

    let is_tcp = pkt.l4proto == IPPROTO_TCP;
    let is_udp = pkt.l4proto == IPPROTO_UDP;
    let is_pure_syn = is_tcp && (pkt.tcph.syn() != 0 && pkt.tcph.ack() == 0);
    let is_fin_rst = is_tcp && (pkt.tcph.fin() != 0 || pkt.tcph.rst() != 0);

    let dst_ip = *pkt.tuples.five.dst_ip.as_bytes();
    let src_ip = *pkt.tuples.five.src_ip.as_bytes();

    let tuple = RedirectTuple {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto: pkt.l4proto,
        ip_version: 6,
        _pad: [0; 2],
    };

    // 1. 源 IP / 源端口 静态 Bypass 与白名单判定
    if is_src_ip6_bypassed(src_ip) {
        return TC_ACT_OK;
    }
    if param.has_proxy_src_ips != 0 && !is_src_ip6_proxied(src_ip) {
        return TC_ACT_OK;
    }
    if is_src_port_bypassed(src_port) {
        return TC_ACT_OK;
    }
    if param.has_proxy_src_ports != 0
        && unsafe { PROXY_SRC_PORTS.get(&src_port).is_none() }
    {
        return TC_ACT_OK;
    }

    // 2. 常规业务流量目标过滤 (DNS 53 强制劫持到代理)
    if dst_port != 53 {
        // 静态目标 IP / 目标端口 Bypass 判定 (无需入表)
        if is_dst_ip6_bypassed(dst_ip) || is_dst_port_bypassed(dst_port, param.tproxy_port as u16) {
            return TC_ACT_OK;
        }

        // 动态直连流表 Fast-Path 查询 (针对非纯 SYN 报文)
        if check_direct_track(&tuple, is_tcp, is_udp, is_fin_rst, is_pure_syn) {
            return TC_ACT_OK;
        }

        // 动态下发直连判定 (受 DNS TTL 影响，命中则建立 DIRECT_TRACK 连接追踪)
        if is_dynamic_dst_ip6_bypassed(dst_ip) {
            register_direct_track(&tuple);
            return TC_ACT_OK;
        }

        // 目标白名单过滤
        if param.has_proxy_dst_ips != 0 && !is_dst_ip6_proxied(dst_ip) {
            return TC_ACT_OK;
        }
        if param.has_proxy_dst_ports != 0
            && unsafe { PROXY_DST_PORTS.get(&dst_port).is_none() }
        {
            return TC_ACT_OK;
        }
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
        let is_new_flow = REDIRECT_TRACK.get(&tuple).is_none();
        let _ = REDIRECT_TRACK.insert(&tuple, &entry, 0);
        let l4proto = if pkt.l4proto == IPPROTO_TCP {
            pkt.listener_l4proto
        } else {
            IPPROTO_UDP
        };

        if is_new_flow {
            let mut sip_u32 = [0u32; 4];
            let mut dip_u32 = [0u32; 4];
            for i in 0..4 {
                sip_u32[i] = u32::from_ne_bytes([
                    src_ip[i * 4],
                    src_ip[i * 4 + 1],
                    src_ip[i * 4 + 2],
                    src_ip[i * 4 + 3],
                ]);
                dip_u32[i] = u32::from_ne_bytes([
                    dst_ip[i * 4],
                    dst_ip[i * 4 + 1],
                    dst_ip[i * 4 + 2],
                    dst_ip[i * 4 + 3],
                ]);
            }
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
        || (param.has_bypass_fwmarks != 0 && unsafe { BYPASS_FWMARKS.get(&mark).is_some() })
    {
        return TC_ACT_OK;
    }

    let pkt = match parse_packet(tc_ctx, link_h_len as u32) {
        Ok(p) => p,
        Err(_) => return TC_ACT_OK,
    };

    if param.has_bypass_dscps != 0 && unsafe { BYPASS_DSCPS.get(&pkt.tuples.dscp).is_some() } {
        return TC_ACT_OK;
    }

    if dst_is_special(pkt, link_h_len as u32) {
        return TC_ACT_OK;
    }

    if pkt.ethh.ether_type == ETH_P_IP.to_be() {
        handle_lan_ipv4(ctx, param, link_h_len, pkt)
    } else if pkt.ethh.ether_type == ETH_P_IPV6.to_be() {
        handle_lan_ipv6(ctx, param, link_h_len, pkt)
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
    pid_pname: Option<&PIDName>,
) -> i32 {
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

    let tuple = RedirectTuple {
        src_ip: *pkt.tuples.five.src_ip.as_bytes(),
        dst_ip: *pkt.tuples.five.dst_ip.as_bytes(),
        src_port,
        dst_port,
        proto: pkt.l4proto,
        ip_version: 4,
        _pad: [0; 2],
    };

    // 1. 常规业务流量目标过滤 (DNS 53 强制劫持到代理)
    if dst_port != 53 {
        // 本机直连流量放行
        if param.local_ip != 0 && ip_be == param.local_ip.to_ne_bytes() {
            return TC_ACT_OK;
        }

        // 静态目标 IP / 目标端口 Bypass 判定 (无需入表)
        if is_dst_ip4_bypassed(ip_be) || is_dst_port_bypassed(dst_port, param.tproxy_port as u16) {
            return TC_ACT_OK;
        }

        // 动态直连流表 Fast-Path 查询 (针对非纯 SYN 报文)
        if check_direct_track(&tuple, is_tcp, is_udp, is_fin_rst, is_pure_syn) {
            return TC_ACT_OK;
        }

        // 动态下发直连判定 (受 DNS TTL 影响，命中则建立 DIRECT_TRACK 连接追踪)
        if is_dynamic_dst_ip4_bypassed(ip_be) {
            register_direct_track(&tuple);
            return TC_ACT_OK;
        }

        // 目标白名单过滤
        if param.has_proxy_dst_ips != 0 && !is_dst_ip4_proxied(ip_be) {
            return TC_ACT_OK;
        }
        if param.has_proxy_dst_ports != 0
            && unsafe { PROXY_DST_PORTS.get(&dst_port).is_none() }
        {
            return TC_ACT_OK;
        }
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
        let is_new_flow = REDIRECT_TRACK.get(&tuple).is_none();
        let _ = REDIRECT_TRACK.insert(&tuple, &entry, 0);
        let l4proto = if pkt.l4proto == IPPROTO_TCP {
            pkt.listener_l4proto
        } else {
            IPPROTO_UDP
        };

        if is_new_flow {
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
    pid_pname: Option<&PIDName>,
) -> i32 {
    let src_port = pkt.tuples.five.src_port;
    let dst_port = pkt.tuples.five.dst_port;

    let is_tcp = pkt.l4proto == IPPROTO_TCP;
    let is_udp = pkt.l4proto == IPPROTO_UDP;
    let is_pure_syn = is_tcp && (pkt.tcph.syn() != 0 && pkt.tcph.ack() == 0);
    let is_fin_rst = is_tcp && (pkt.tcph.fin() != 0 || pkt.tcph.rst() != 0);

    let dst_ip = *pkt.tuples.five.dst_ip.as_bytes();
    let src_ip = *pkt.tuples.five.src_ip.as_bytes();

    let tuple = RedirectTuple {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto: pkt.l4proto,
        ip_version: 6,
        _pad: [0; 2],
    };

    // 1. 常规业务流量目标过滤 (DNS 53 强制劫持到代理)
    if dst_port != 53 {
        // 静态目标 IP / 目标端口 Bypass 判定 (无需入表)
        if is_dst_ip6_bypassed(dst_ip) || is_dst_port_bypassed(dst_port, param.tproxy_port as u16) {
            return TC_ACT_OK;
        }

        // 动态直连流表 Fast-Path 查询 (针对非纯 SYN 报文)
        if check_direct_track(&tuple, is_tcp, is_udp, is_fin_rst, is_pure_syn) {
            return TC_ACT_OK;
        }

        // 动态下发直连判定 (受 DNS TTL 影响，命中则建立 DIRECT_TRACK 连接追踪)
        if is_dynamic_dst_ip6_bypassed(dst_ip) {
            register_direct_track(&tuple);
            return TC_ACT_OK;
        }

        // 目标白名单过滤
        if param.has_proxy_dst_ips != 0 && !is_dst_ip6_proxied(dst_ip) {
            return TC_ACT_OK;
        }
        if param.has_proxy_dst_ports != 0
            && unsafe { PROXY_DST_PORTS.get(&dst_port).is_none() }
        {
            return TC_ACT_OK;
        }
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
        let is_new_flow = REDIRECT_TRACK.get(&tuple).is_none();
        let _ = REDIRECT_TRACK.insert(&tuple, &entry, 0);
        let l4proto = if pkt.l4proto == IPPROTO_TCP {
            pkt.listener_l4proto
        } else {
            IPPROTO_UDP
        };

        if is_new_flow {
            let pid = pid_pname.map(|p| p.pid).unwrap_or(0);
            let pname = pid_pname.map(|p| &p.pname);
            let mut sip_u32 = [0u32; 4];
            let mut dip_u32 = [0u32; 4];
            for i in 0..4 {
                sip_u32[i] = u32::from_ne_bytes([
                    src_ip[i * 4],
                    src_ip[i * 4 + 1],
                    src_ip[i * 4 + 2],
                    src_ip[i * 4 + 3],
                ]);
                dip_u32[i] = u32::from_ne_bytes([
                    dst_ip[i * 4],
                    dst_ip[i * 4 + 1],
                    dst_ip[i * 4 + 2],
                    dst_ip[i * 4 + 3],
                ]);
            }
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
        || (param.has_bypass_fwmarks != 0 && unsafe { BYPASS_FWMARKS.get(&mark).is_some() })
    {
        return TC_ACT_OK;
    }

    // 2. 本机出站总开关: 若未开启本机代理，直接无条件放行
    if param.proxy_local == 0 {
        return TC_ACT_OK;
    }

    let cookie = unsafe { bpf_get_socket_cookie(ctx as *mut _) };
    let pid_pname = if cookie != 0 {
        unsafe { COOKIE_PID_MAP.get(&cookie) }
    } else {
        None
    };

    // 3. 进程过滤 (提前短路，避免不必要的数据包解析开销)
    if let Some(pp) = pid_pname {
        // 自身控制面进程防环路
        if param.control_plane_pid != 0 && pp.pid == param.control_plane_pid {
            return TC_ACT_OK;
        }
        // 黑名单：匹配 bypass_processes 直接放行
        if param.has_bypass_processes != 0
            && unsafe { BYPASS_PROCESSES.get(&pp.pname).is_some() }
        {
            return TC_ACT_OK;
        }
        // 白名单：配置了 proxy_processes 且未命中白名单直接放行
        if param.has_proxy_processes != 0 {
            if unsafe { PROXY_PROCESSES.get(&pp.pname).is_none() } {
                return TC_ACT_OK;
            }
        }
    }

    let pkt = match parse_packet(tc_ctx, link_h_len as u32) {
        Ok(p) => p,
        Err(_) => return TC_ACT_OK,
    };

    if param.has_bypass_dscps != 0 && unsafe { BYPASS_DSCPS.get(&pkt.tuples.dscp).is_some() } {
        return TC_ACT_OK;
    }

    if dst_is_special(pkt, link_h_len as u32) {
        return TC_ACT_OK;
    }

    if pkt.ethh.ether_type == ETH_P_IP.to_be() {
        handle_wan_ipv4(ctx, param, link_h_len, pkt, pid_pname)
    } else if pkt.ethh.ether_type == ETH_P_IPV6.to_be() {
        handle_wan_ipv6(ctx, param, link_h_len, pkt, pid_pname)
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
        return TC_ACT_OK;
    }

    // Set mark for policy routing (mark → table 100 → local route)
    unsafe {
        (*ctx).mark = DAE_TPROXY_MARK;
    }

    // Force PACKET_HOST so the IP stack accepts this packet
    let _ = tc_ctx.change_type(0);

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
    let pkt = match parse_packet(tc_ctx, EthHdr::LEN as u32) {
        Ok(p) => p,
        Err(_) => return TC_ACT_OK,
    };

    let is_ipv4 = pkt.ethh.ether_type == ETH_P_IP.to_be();
    let is_ipv6 = pkt.ethh.ether_type == ETH_P_IPV6.to_be();

    let (src_ip, dst_ip, ip_version) = if is_ipv4 {
        (
            *pkt.tuples.five.src_ip.as_bytes(),
            *pkt.tuples.five.dst_ip.as_bytes(),
            4,
        )
    } else if is_ipv6 {
        (
            *pkt.tuples.five.src_ip.as_bytes(),
            *pkt.tuples.five.dst_ip.as_bytes(),
            6,
        )
    } else {
        return TC_ACT_OK;
    };

    let tuple = RedirectTuple {
        src_ip,
        dst_ip,
        src_port: pkt.tuples.five.src_port,
        dst_port: pkt.tuples.five.dst_port,
        proto: pkt.l4proto,
        ip_version,
        _pad: [0; 2],
    };

    let reversed = tuple.reverse();
    if let Some(entry) = unsafe { REDIRECT_TRACK.get(&reversed) } {
        let dmac = entry.smac;
        let smac = entry.dmac;
        let from_wan = entry.from_wan;
        let ifindex = entry.ifindex;

        unsafe {
            if dmac != [0; 6] {
                let _ = bpf_skb_store_bytes(
                    ctx,
                    mem::offset_of!(EthHdr, src_addr) as u32,
                    smac.as_ptr() as *const _,
                    6,
                    0,
                );
                let _ = bpf_skb_store_bytes(
                    ctx,
                    mem::offset_of!(EthHdr, dst_addr) as u32,
                    dmac.as_ptr() as *const _,
                    6,
                    0,
                );
            }

            let flags: u64 = if from_wan != 0 { 1 } else { 0 }; // 1 = BPF_F_INGRESS
            if from_wan != 0 {
                let _ = tc_ctx.change_type(0); // PACKET_HOST
            }
            bpf_redirect(ifindex, flags) as i32
        }
    } else {
        TC_ACT_OK
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
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut _) };
    update_map_elem_by_cookie(cookie);
    1
}

#[cgroup_sock_addr(connect6)]
pub fn tproxy_wan_cg_connect6(ctx: SockAddrContext) -> i32 {
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
