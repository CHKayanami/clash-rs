#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

mod maps;
mod transport;

use aya_ebpf::bindings::{__sk_buff, bpf_sock, TC_ACT_OK};
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_redirect};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::helpers::{bpf_map_lookup_elem, bpf_sk_assign, bpf_sk_release, bpf_skb_change_head, bpf_skb_store_bytes};
use clash_ebpf_common::{DaeParam, RedirectEntry, RedirectTuple, DAE_BYPASS_MARK, DAE_TPROXY_MARK};
use core::ffi::c_void;
use core::mem;
use maps::*;
use network_types::eth::EthHdr;
use transport::*;

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
fn is_src_port_bypassed(port: u16) -> bool {
    if port == 22 || port == 53 || port == 67 || port == 68 || port == 123 || port == 5353 {
        return true;
    }
    unsafe { BYPASS_SRC_PORTS.get(&port).is_some() }
}

#[inline(always)]
fn is_dst_port_bypassed(port: u16, tproxy_port: u16) -> bool {
    if port == 22 || port == 67 || port == 68 || port == 5353 || port == tproxy_port {
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
    // 1. Link-local (169.254.0.0/16) & Loopback (127.0.0.0/8) & 0.0.0.0/8
    // 2. Multicast (224.0.0.0/4 -> 224.0.0.0 ~ 239.255.255.255)
    // 3. Limited global broadcast (255.255.255.255)
    if ip_be[0] == 127
        || ip_be[0] == 0
        || (ip_be[0] == 169 && ip_be[1] == 254)
        || (ip_be[0] >= 224 && ip_be[0] <= 239)
        || ip_be == [255, 255, 255, 255]
    {
        return true;
    }
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
fn is_dst_ip6_bypassed(ip: [u8; 16]) -> bool {
    // 1. Loopback (::1/128) & Unspecified (::/128)
    // 2. Link-local unicast (fe80::/10)
    // 3. Multicast (ff00::/8)
    if ip == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        || ip == [0; 16]
        || (ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80)
        || ip[0] == 0xff
    {
        return true;
    }
    false
}

#[inline(always)]
fn is_dynamic_dst_ip6_bypassed(ip: [u8; 16]) -> bool {
    unsafe { DYNAMIC_BYPASS_DST_IP6S.get(&ip).is_some() }
}

#[allow(dead_code)]
#[inline(always)]
fn is_src_ip6_bypassed(_ip: [u8; 16]) -> bool {
    false
}

#[allow(dead_code)]
#[inline(always)]
fn is_src_ip6_proxied(_ip: [u8; 16]) -> bool {
    true
}

#[inline(always)]
fn is_dst_ip6_proxied(_ip: [u8; 16]) -> bool {
    true
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
        }

        // cb[0] = TPROXY_MARK, cb[1] = listener_l4proto
        (*ctx).cb[0] = DAE_TPROXY_MARK;
        (*ctx).cb[1] = listener_l4proto as u32;

        if param.use_redirect_peer != 0 {
            aya_ebpf_bindings::helpers::bpf_redirect_peer(param.dae0_ifindex as u32, 0) as i32
        } else {
            bpf_redirect(param.dae0_ifindex as u32, 0) as i32
        }
    }
}

// ─────────────────────────────────────────────────────────────
// 1. LAN Ingress (局域网转发流量处理)
// ─────────────────────────────────────────────────────────────
#[inline(always)]
fn handle_lan_ingress_impl(ctx: *mut __sk_buff, link_h_len: usize) -> i32 {
    let tc_ctx = TcContext::new(ctx);
    let mark = unsafe { (*ctx).mark };
    if mark == DAE_BYPASS_MARK {
        return TC_ACT_OK;
    }

    let Some(param) = get_param() else {
        return TC_ACT_OK;
    };
    if param.dae0_ifindex == 0 {
        return TC_ACT_OK;
    }

    let mut pkt: ParsedPacket = unsafe { mem::zeroed() };
    let ret = parse_packet(&tc_ctx, link_h_len as u32, &mut pkt);
    if ret != 0 {
        return TC_ACT_OK;
    }

    if dst_is_special(&pkt, link_h_len as u32) {
        return TC_ACT_OK;
    }

    let is_ipv4 = pkt.ethh.ether_type == ETH_P_IP.to_be();
    let is_ipv6 = pkt.ethh.ether_type == ETH_P_IPV6.to_be();
    let src_port = pkt.tuples.five.src_port;
    let dst_port = pkt.tuples.five.dst_port;

    if is_ipv4 {
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

        // 1. 本机直连流量放行
        if dst_port != 53 && param.local_ip != 0 && ip_be == param.local_ip.to_ne_bytes() {
            return TC_ACT_OK;
        }

        // 2. DNS 流量 (dst_port == 53) 绝对重定向，其它流量执行白名单与 bypass 判定
        if dst_port != 53 {
            if is_src_ip4_bypassed(src_ip_be) {
                return TC_ACT_OK;
            }
            if param.has_proxy_src_ips != 0 && !is_src_ip4_proxied(src_ip_be) {
                return TC_ACT_OK;
            }
            if is_src_port_bypassed(src_port) {
                return TC_ACT_OK;
            }
            if param.has_proxy_src_ports != 0 && unsafe { PROXY_SRC_PORTS.get(&src_port).is_none() } {
                return TC_ACT_OK;
            }

            if is_dst_ip4_bypassed(ip_be) || is_dynamic_dst_ip4_bypassed(ip_be) {
                return TC_ACT_OK;
            }
            if is_dst_port_bypassed(dst_port, param.tproxy_port as u16) {
                return TC_ACT_OK;
            }
            if param.has_proxy_dst_ips != 0 && !is_dst_ip4_proxied(ip_be) {
                return TC_ACT_OK;
            }
            if param.has_proxy_dst_ports != 0 && unsafe { PROXY_DST_PORTS.get(&dst_port).is_none() } {
                return TC_ACT_OK;
            }
        }

        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        src_ip[0..4].copy_from_slice(&src_ip_be);
        dst_ip[0..4].copy_from_slice(&ip_be);

        let tuple = RedirectTuple {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto: pkt.l4proto,
            ip_version: 4,
            _pad: [0; 2],
        };
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
            let _ = REDIRECT_TRACK.insert(&tuple, &entry, 0);
            let l4proto = if pkt.l4proto == IPPROTO_TCP {
                pkt.listener_l4proto
            } else {
                IPPROTO_UDP
            };
            do_redirect(ctx, param, link_h_len, l4proto, ETH_P_IP)
        }
    } else if is_ipv6 {
        let dst_ip = *pkt.tuples.five.dst_ip.as_bytes();
        let src_ip = *pkt.tuples.five.src_ip.as_bytes();

        if dst_port != 53 {
            if is_src_port_bypassed(src_port) {
                return TC_ACT_OK;
            }
            if param.has_proxy_src_ports != 0 && unsafe { PROXY_SRC_PORTS.get(&src_port).is_none() } {
                return TC_ACT_OK;
            }
            if is_dst_ip6_bypassed(dst_ip) || is_dynamic_dst_ip6_bypassed(dst_ip) {
                return TC_ACT_OK;
            }
            if is_dst_port_bypassed(dst_port, param.tproxy_port as u16) {
                return TC_ACT_OK;
            }
            if param.has_proxy_dst_ports != 0 && unsafe { PROXY_DST_PORTS.get(&dst_port).is_none() } {
                return TC_ACT_OK;
            }
        }

        let tuple = RedirectTuple {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto: pkt.l4proto,
            ip_version: 6,
            _pad: [0; 2],
        };
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
            let _ = REDIRECT_TRACK.insert(&tuple, &entry, 0);
            let l4proto = if pkt.l4proto == IPPROTO_TCP {
                pkt.listener_l4proto
            } else {
                IPPROTO_UDP
            };
            do_redirect(ctx, param, link_h_len, l4proto, ETH_P_IPV6)
        }
    } else {
        TC_ACT_OK
    }
}

// ─────────────────────────────────────────────────────────────
// 2. WAN Egress (本机出站流量处理)
// ─────────────────────────────────────────────────────────────
#[inline(always)]
fn handle_wan_egress_impl(ctx: *mut __sk_buff, link_h_len: usize) -> i32 {
    let tc_ctx = TcContext::new(ctx);
    let mark = unsafe { (*ctx).mark };

    // 1. Clash 自身发出的出站请求 (带 DAE_BYPASS_MARK): 100% 绝对放行防自环
    if mark == DAE_BYPASS_MARK {
        return TC_ACT_OK;
    }

    let Some(param) = get_param() else {
        return TC_ACT_OK;
    };
    if param.dae0_ifindex == 0 {
        return TC_ACT_OK;
    }

    let mut pkt: ParsedPacket = unsafe { mem::zeroed() };
    let ret = parse_packet(&tc_ctx, link_h_len as u32, &mut pkt);
    if ret != 0 {
        return TC_ACT_OK;
    }

    if dst_is_special(&pkt, link_h_len as u32) {
        return TC_ACT_OK;
    }

    let is_ipv4 = pkt.ethh.ether_type == ETH_P_IP.to_be();
    let is_ipv6 = pkt.ethh.ether_type == ETH_P_IPV6.to_be();
    let src_port = pkt.tuples.five.src_port;
    let dst_port = pkt.tuples.five.dst_port;

    if is_ipv4 {
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

        // 2. DNS 流量 (dst_port == 53): 100% 绝对重定向至 DNS 模块
        if dst_port != 53 {
            if is_src_port_bypassed(src_port) {
                return TC_ACT_OK;
            }
            if is_dst_ip4_bypassed(ip_be) || is_dynamic_dst_ip4_bypassed(ip_be) {
                return TC_ACT_OK;
            }
            if is_dst_port_bypassed(dst_port, param.tproxy_port as u16) {
                return TC_ACT_OK;
            }
            if param.has_proxy_dst_ips != 0 && !is_dst_ip4_proxied(ip_be) {
                return TC_ACT_OK;
            }
            if param.has_proxy_dst_ports != 0 && unsafe { PROXY_DST_PORTS.get(&dst_port).is_none() } {
                return TC_ACT_OK;
            }
        }

        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        src_ip[0..4].copy_from_slice(&src_ip_be);
        dst_ip[0..4].copy_from_slice(&ip_be);

        let tuple = RedirectTuple {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto: pkt.l4proto,
            ip_version: 4,
            _pad: [0; 2],
        };
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
            let _ = REDIRECT_TRACK.insert(&tuple, &entry, 0);
            let l4proto = if pkt.l4proto == IPPROTO_TCP {
                pkt.listener_l4proto
            } else {
                IPPROTO_UDP
            };
            do_redirect(ctx, param, link_h_len, l4proto, ETH_P_IP)
        }
    } else if is_ipv6 {
        let dst_ip = *pkt.tuples.five.dst_ip.as_bytes();
        let src_ip = *pkt.tuples.five.src_ip.as_bytes();

        if dst_port != 53 {
            if is_src_port_bypassed(src_port) {
                return TC_ACT_OK;
            }
            if is_dst_ip6_bypassed(dst_ip) || is_dynamic_dst_ip6_bypassed(dst_ip) {
                return TC_ACT_OK;
            }
            if is_dst_port_bypassed(dst_port, param.tproxy_port as u16) {
                return TC_ACT_OK;
            }
            if param.has_proxy_dst_ips != 0 && !is_dst_ip6_proxied(dst_ip) {
                return TC_ACT_OK;
            }
            if param.has_proxy_dst_ports != 0 && unsafe { PROXY_DST_PORTS.get(&dst_port).is_none() } {
                return TC_ACT_OK;
            }
        }

        let tuple = RedirectTuple {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto: pkt.l4proto,
            ip_version: 6,
            _pad: [0; 2],
        };
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
            let _ = REDIRECT_TRACK.insert(&tuple, &entry, 0);
            let l4proto = if pkt.l4proto == IPPROTO_TCP {
                pkt.listener_l4proto
            } else {
                IPPROTO_UDP
            };
            do_redirect(ctx, param, link_h_len, l4proto, ETH_P_IPV6)
        }
    } else {
        TC_ACT_OK
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress(ctx: *mut __sk_buff) -> i32 {
    handle_lan_ingress_impl(ctx, EthHdr::LEN)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress_l2(ctx: *mut __sk_buff) -> i32 {
    handle_lan_ingress_impl(ctx, EthHdr::LEN)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress_l3(ctx: *mut __sk_buff) -> i32 {
    handle_lan_ingress_impl(ctx, 0)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_egress(ctx: *mut __sk_buff) -> i32 {
    handle_wan_egress_impl(ctx, EthHdr::LEN)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_egress_l2(ctx: *mut __sk_buff) -> i32 {
    handle_wan_egress_impl(ctx, EthHdr::LEN)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_egress_l3(ctx: *mut __sk_buff) -> i32 {
    handle_wan_egress_impl(ctx, 0)
}

/// dae0peer ingress: runs inside daens namespace.
/// Packets redirected here from wan_egress/lan_ingress carry cb[0]=TPROXY_MARK or skb.mark=TPROXY_MARK.
/// Sets PACKET_HOST + fwmark, then uses bpf_sk_assign from SOCKMAP to deliver
/// the packet to the transparent proxy listener socket, bypassing iptables.
#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn dae0peer_ingress(ctx: *mut __sk_buff) -> i32 {
    let tc_ctx = TcContext::new(ctx);

    let cb0 = unsafe { (*ctx).cb[0] };
    let mark = unsafe { (*ctx).mark };
    if cb0 != DAE_TPROXY_MARK && mark != DAE_TPROXY_MARK {
        return TC_ACT_OK;
    }

    let mut listener_l4proto = unsafe { (*ctx).cb[1] } as u8;

    // Robust fallback: if cb[1] was cleared during veth transit, detect from packet
    if listener_l4proto == 0 {
        let mut pkt: ParsedPacket = unsafe { mem::zeroed() };
        if parse_packet(&tc_ctx, EthHdr::LEN as u32, &mut pkt) == 0 {
            listener_l4proto = if pkt.l4proto == IPPROTO_TCP {
                pkt.listener_l4proto
            } else if pkt.l4proto == IPPROTO_UDP {
                IPPROTO_UDP
            } else {
                0
            };
        }
    }

    // Set mark for policy routing (mark → table 100 → local route)
    unsafe { (*ctx).mark = DAE_TPROXY_MARK; }

    // Force PACKET_HOST so the IP stack accepts this packet
    let _ = tc_ctx.change_type(0);

    // For SYN and UDP: assign the listener socket via SOCKMAP
    // For established TCP (listener_l4proto==0): kernel finds the child socket itself
    if listener_l4proto != 0 {
        let _ = assign_listener_socket(ctx, listener_l4proto);
    }

    TC_ACT_OK
}

/// Look up the listener socket from LISTEN_SOCKET_MAP and assign it to the skb.
#[inline(always)]
fn assign_listener_socket(ctx: *mut __sk_buff, listener_l4proto: u8) -> i32 {
    let proto = unsafe { (*ctx).protocol as u16 };
    let is_v6 = proto == 0x86dd_u16.to_be() || proto == 0x86dd_u16;

    let key: u32 = match (listener_l4proto, is_v6) {
        (IPPROTO_TCP, false) => SK_TCP4,
        (IPPROTO_TCP, true)  => SK_TCP6,
        (IPPROTO_UDP, false) => SK_UDP4,
        (IPPROTO_UDP, true)  => SK_UDP6,
        _ => return -1,
    };

    unsafe {
        let map_ptr = core::ptr::from_ref(&LISTEN_SOCKET_MAP).cast::<c_void>();
        let sk = bpf_map_lookup_elem(
            map_ptr as *mut c_void,
            &key as *const u32 as *const c_void,
        );
        if sk.is_null() {
            return -1;
        }
        let ret = bpf_sk_assign(ctx as *mut c_void, sk as *mut c_void, 0);
        bpf_sk_release(sk as *mut c_void);
        ret as i32
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn dae0_ingress(ctx: *mut __sk_buff) -> i32 {
    let tc_ctx = TcContext::new(ctx);
    let mut pkt: ParsedPacket = unsafe { mem::zeroed() };
    if parse_packet(&tc_ctx, EthHdr::LEN as u32, &mut pkt) != 0 {
        return TC_ACT_OK;
    }

    let is_ipv4 = pkt.ethh.ether_type == ETH_P_IP.to_be();
    let is_ipv6 = pkt.ethh.ether_type == ETH_P_IPV6.to_be();

    let (src_ip, dst_ip, ip_version) = if is_ipv4 {
        let mut s = [0u8; 16];
        let mut d = [0u8; 16];
        s[0..4].copy_from_slice(&pkt.tuples.five.src_ip[12..16]);
        d[0..4].copy_from_slice(&pkt.tuples.five.dst_ip[12..16]);
        (s, d, 4)
    } else if is_ipv6 {
        (*pkt.tuples.five.src_ip.as_bytes(), *pkt.tuples.five.dst_ip.as_bytes(), 6)
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
            bpf_skb_store_bytes(
                ctx,
                mem::offset_of!(EthHdr, src_addr) as u32,
                smac.as_ptr() as *const _,
                6,
                0,
            );
            bpf_skb_store_bytes(
                ctx,
                mem::offset_of!(EthHdr, dst_addr) as u32,
                dmac.as_ptr() as *const _,
                6,
                0,
            );

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
// 5. Cgroup Socket Attachments (用于直连打标，与原项目保持一致)
// ─────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sock_create")]
pub fn tproxy_wan_cg_sock_create(ctx: *mut bpf_sock) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let Some(param) = get_param() else {
        return 1;
    };

    if param.control_plane_pid != 0 && pid == param.control_plane_pid {
        unsafe {
            (*ctx).mark = DAE_BYPASS_MARK;
        }
    }

    1
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sock_release")]
pub fn tproxy_wan_cg_sock_release(_ctx: *mut bpf_sock) -> i32 {
    1
}
