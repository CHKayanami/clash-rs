#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

use aya_ebpf::bindings::{__sk_buff, bpf_sock, TC_ACT_OK};
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_redirect};
use aya_ebpf::macros::map;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{Array, HashMap, LpmTrie, LruHashMap};
use aya_ebpf::programs::{SockContext, TcContext};
use aya_ebpf_bindings::helpers::{bpf_map_lookup_elem, bpf_sk_assign, bpf_sk_release, bpf_skb_change_head, bpf_skb_store_bytes};
use clash_ebpf_common::{DaeParam, RedirectEntry, RedirectTuple, DAE_BYPASS_MARK, DAE_TPROXY_MARK};
use core::ffi::c_void;
use core::mem;
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

// ── Ethernet protocol constants (Host Byte Order) ──
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

// ── BPF Maps ──

#[map]
static DAE_PARAM: Array<DaeParam> = Array::with_max_entries(1, 0);

#[map]
static BYPASS_SRC_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

#[map]
static BYPASS_DST_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

#[map]
static BYPASS_SRC_IPS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
static BYPASS_DST_IPS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
static PROXY_SRC_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

#[map]
static PROXY_DST_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

#[map]
static PROXY_SRC_IPS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
static PROXY_DST_IPS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
static DYNAMIC_BYPASS_DST_IPS: LruHashMap<u32, u8> = LruHashMap::with_max_entries(16384, 0);

#[map]
static DYNAMIC_BYPASS_DST_IP6S: LruHashMap<[u8; 16], u8> = LruHashMap::with_max_entries(4096, 0);

#[map]
static REDIRECT_TRACK: LruHashMap<RedirectTuple, RedirectEntry> = LruHashMap::with_max_entries(32768, 0);

/// SOCKMAP for transparent proxy listener sockets.
/// Keys: 0=TCP4, 1=TCP6, 2=UDP4, 3=UDP6
/// User-space publishes listener fds here after binding.
#[map]
static LISTEN_SOCKET_MAP: aya_ebpf::maps::SockMap = aya_ebpf::maps::SockMap::with_max_entries(4, 0);


// ── SOCKMAP key constants ──
const SK_TCP4: u32 = 0;
const SK_TCP6: u32 = 1;
const SK_UDP4: u32 = 2;
const SK_UDP6: u32 = 3;

// ── L4 protocol constants ──
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

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
    // 1. Loopback (::1)
    if ip == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
        return true;
    }
    // 2. Multicast (ff00::/8)
    if ip[0] == 0xff {
        return true;
    }
    // 3. Link-local (fe80::/10)
    if ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80 {
        return true;
    }
    false
}

#[inline(always)]
fn is_dynamic_dst_ip6_bypassed(ip: [u8; 16]) -> bool {
    unsafe { DYNAMIC_BYPASS_DST_IP6S.get(&ip).is_some() }
}

#[inline(always)]
fn is_src_ip6_bypassed(_ip: [u8; 16]) -> bool {
    false
}

#[inline(always)]
fn is_src_ip6_proxied(_ip: [u8; 16]) -> bool {
    true
}

#[inline(always)]
fn is_dst_ip6_proxied(_ip: [u8; 16]) -> bool {
    true
}

/// Check if a TCP header is a pure SYN (SYN=1, ACK=0).
/// Only pure SYN needs bpf_sk_assign; established TCP connections
/// are matched by the kernel's normal socket lookup on child sockets.
#[inline(always)]
fn is_pure_syn(tcp: &TcpHdr) -> bool {
    tcp.syn() != 0 && tcp.ack() == 0
}

/// Determine the listener l4proto for cb[1]:
/// - TCP SYN → IPPROTO_TCP (6) → needs bpf_sk_assign
/// - UDP → IPPROTO_UDP (17) → always needs bpf_sk_assign
/// - TCP established → 0 → kernel finds child socket itself
#[inline(always)]
fn tcp_listener_l4proto(tcp: &TcpHdr) -> u8 {
    if is_pure_syn(tcp) { IPPROTO_TCP } else { 0 }
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
            // 写入目标 MAC 为 dae0peer_mac
            bpf_skb_store_bytes(
                ctx,
                0, // offsetof(EthHdr, dst_addr)
                param.dae0peer_mac.as_ptr() as *const _,
                6,
                0,
            );
            // 写入以太网协议类型
            let proto_be = eth_proto.to_be();
            bpf_skb_store_bytes(
                ctx,
                12, // offsetof(EthHdr, ether_type)
                &proto_be as *const u16 as *const _,
                2,
                0,
            );
        } else {
            // L2 skb (已带以太网头): 直接改写目标 MAC 为 dae0peer_mac
            bpf_skb_store_bytes(
                ctx,
                mem::offset_of!(EthHdr, dst_addr) as u32,
                param.dae0peer_mac.as_ptr() as *const _,
                6,
                0,
            );
        }

        // Set cb[0] = TPROXY_MARK so dae0peer_ingress recognizes redirected packets
        (*ctx).cb[0] = DAE_TPROXY_MARK;
        // Set cb[1] = l4proto for listener assignment (0 = skip bpf_sk_assign)
        (*ctx).cb[1] = listener_l4proto as u32;
        (*ctx).mark = DAE_TPROXY_MARK;
        bpf_redirect(param.dae0_ifindex, 0) as i32
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

    // 根据挂载时静态确定的 link_h_len 判定协议
    let skb_proto = u16::from_be(unsafe { (*ctx).protocol } as u16);
    let is_ipv4;
    let is_ipv6;

    if link_h_len == 0 {
        // L3 帧: 偏移 0 直接为 IP 头
        is_ipv4 = skb_proto == ETH_P_IP;
        is_ipv6 = skb_proto == ETH_P_IPV6;
    } else {
        // L2 帧: 解析以太网头
        if let Ok(eth) = tc_ctx.load::<EthHdr>(0) {
            let eth_proto = u16::from_be(eth.ether_type as u16);
            is_ipv4 = eth_proto == ETH_P_IP;
            is_ipv6 = eth_proto == ETH_P_IPV6;
        } else {
            return TC_ACT_OK;
        }
    }

    if is_ipv4 {
        let ip: Ipv4Hdr = match tc_ctx.load(link_h_len) {
            Ok(h) => h,
            Err(_) => return TC_ACT_OK,
        };

        let l4_offset = link_h_len + ip.ihl() as usize;
        let ip_proto = ip.proto as u8;

        if ip_proto == (IpProto::Tcp as u8) {
            let tcp: TcpHdr = match tc_ctx.load(l4_offset) {
                Ok(h) => h,
                Err(_) => return TC_ACT_OK,
            };
            let src_port = u16::from_be_bytes(tcp.source);
            let dst_port = u16::from_be_bytes(tcp.dest);

            // 1. 本机直连流量放行
            if dst_port != 53 && param.local_ip != 0 && ip.dst_addr == param.local_ip.to_ne_bytes() {
                return TC_ACT_OK;
            }

            // 2. DNS 流量 (dst_port == 53) 绝对重定向，其它流量执行白名单与 bypass 判定
            if dst_port != 53 {
                if is_src_ip4_bypassed(ip.src_addr) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_src_ips != 0 && !is_src_ip4_proxied(ip.src_addr) {
                    return TC_ACT_OK;
                }
                if is_src_port_bypassed(src_port) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_src_ports != 0 && unsafe { PROXY_SRC_PORTS.get(&src_port).is_none() } {
                    return TC_ACT_OK;
                }

                if is_dst_ip4_bypassed(ip.dst_addr) || is_dynamic_dst_ip4_bypassed(ip.dst_addr) {
                    return TC_ACT_OK;
                }
                if is_dst_port_bypassed(dst_port, param.tproxy_port as u16) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_dst_ips != 0 && !is_dst_ip4_proxied(ip.dst_addr) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_dst_ports != 0 && unsafe { PROXY_DST_PORTS.get(&dst_port).is_none() } {
                    return TC_ACT_OK;
                }
            }

            let mut src_ip = [0u8; 16];
            let mut dst_ip = [0u8; 16];
            src_ip[0..4].copy_from_slice(&ip.src_addr);
            dst_ip[0..4].copy_from_slice(&ip.dst_addr);

            let tuple = RedirectTuple {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                proto: ip_proto,
                ip_version: 4,
                _pad: [0; 2],
            };
            let ifindex = unsafe { (*ctx).ifindex };
            let (smac, dmac) = if link_h_len >= EthHdr::LEN {
                if let Ok(eth) = tc_ctx.load::<EthHdr>(0) {
                    (eth.src_addr, eth.dst_addr)
                } else {
                    ([0u8; 6], [0u8; 6])
                }
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
                let l4proto = tcp_listener_l4proto(&tcp);
                do_redirect(ctx, param, link_h_len, l4proto, ETH_P_IP)
            }
        } else if ip_proto == (IpProto::Udp as u8) {
            let udp: UdpHdr = match tc_ctx.load(l4_offset) {
                Ok(h) => h,
                Err(_) => return TC_ACT_OK,
            };
            let src_port = u16::from_be_bytes(udp.src);
            let dst_port = u16::from_be_bytes(udp.dst);

            if dst_port != 53 && param.local_ip != 0 && ip.dst_addr == param.local_ip.to_ne_bytes() {
                return TC_ACT_OK;
            }

            if dst_port != 53 {
                if is_src_ip4_bypassed(ip.src_addr) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_src_ips != 0 && !is_src_ip4_proxied(ip.src_addr) {
                    return TC_ACT_OK;
                }
                if is_src_port_bypassed(src_port) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_src_ports != 0 && unsafe { PROXY_SRC_PORTS.get(&src_port).is_none() } {
                    return TC_ACT_OK;
                }

                if is_dst_ip4_bypassed(ip.dst_addr) || is_dynamic_dst_ip4_bypassed(ip.dst_addr) {
                    return TC_ACT_OK;
                }
                if is_dst_port_bypassed(dst_port, param.tproxy_port as u16) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_dst_ips != 0 && !is_dst_ip4_proxied(ip.dst_addr) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_dst_ports != 0 && unsafe { PROXY_DST_PORTS.get(&dst_port).is_none() } {
                    return TC_ACT_OK;
                }
            }

            let mut src_ip = [0u8; 16];
            let mut dst_ip = [0u8; 16];
            src_ip[0..4].copy_from_slice(&ip.src_addr);
            dst_ip[0..4].copy_from_slice(&ip.dst_addr);

            let tuple = RedirectTuple {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                proto: ip_proto,
                ip_version: 4,
                _pad: [0; 2],
            };
            let ifindex = unsafe { (*ctx).ifindex };
            let (smac, dmac) = if link_h_len >= EthHdr::LEN {
                if let Ok(eth) = tc_ctx.load::<EthHdr>(0) {
                    (eth.src_addr, eth.dst_addr)
                } else {
                    ([0u8; 6], [0u8; 6])
                }
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
                do_redirect(ctx, param, link_h_len, IPPROTO_UDP, ETH_P_IP)
            }
        } else {
            TC_ACT_OK
        }
    } else if is_ipv6 {
        let ip: Ipv6Hdr = match tc_ctx.load(link_h_len) {
            Ok(h) => h,
            Err(_) => return TC_ACT_OK,
        };
        let next_hdr = ip.next_hdr as u8;
        if next_hdr == 58 {
            return TC_ACT_OK;
        }
        let l4_offset = link_h_len + Ipv6Hdr::LEN;

        if next_hdr == (IpProto::Tcp as u8) {
            let tcp: TcpHdr = match tc_ctx.load(l4_offset) {
                Ok(h) => h,
                Err(_) => return TC_ACT_OK,
            };
            let src_port = u16::from_be_bytes(tcp.source);
            let dst_port = u16::from_be_bytes(tcp.dest);

            if dst_port != 53 {
                if is_src_port_bypassed(src_port) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_src_ports != 0 && unsafe { PROXY_SRC_PORTS.get(&src_port).is_none() } {
                    return TC_ACT_OK;
                }
                if is_dst_ip6_bypassed(ip.dst_addr) || is_dynamic_dst_ip6_bypassed(ip.dst_addr) {
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
                src_ip: ip.src_addr,
                dst_ip: ip.dst_addr,
                src_port,
                dst_port,
                proto: next_hdr,
                ip_version: 6,
                _pad: [0; 2],
            };
            let ifindex = unsafe { (*ctx).ifindex };
            let (smac, dmac) = if link_h_len >= EthHdr::LEN {
                if let Ok(eth) = tc_ctx.load::<EthHdr>(0) {
                    (eth.src_addr, eth.dst_addr)
                } else {
                    ([0u8; 6], [0u8; 6])
                }
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
                let l4proto = tcp_listener_l4proto(&tcp);
                do_redirect(ctx, param, link_h_len, l4proto, ETH_P_IPV6)
            }
        } else if next_hdr == (IpProto::Udp as u8) {
            let udp: UdpHdr = match tc_ctx.load(l4_offset) {
                Ok(h) => h,
                Err(_) => return TC_ACT_OK,
            };
            let src_port = u16::from_be_bytes(udp.src);
            let dst_port = u16::from_be_bytes(udp.dst);

            if dst_port != 53 {
                if is_src_port_bypassed(src_port) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_src_ports != 0 && unsafe { PROXY_SRC_PORTS.get(&src_port).is_none() } {
                    return TC_ACT_OK;
                }
                if is_dst_ip6_bypassed(ip.dst_addr) || is_dynamic_dst_ip6_bypassed(ip.dst_addr) {
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
                src_ip: ip.src_addr,
                dst_ip: ip.dst_addr,
                src_port,
                dst_port,
                proto: next_hdr,
                ip_version: 6,
                _pad: [0; 2],
            };
            let ifindex = unsafe { (*ctx).ifindex };
            let (smac, dmac) = if link_h_len >= EthHdr::LEN {
                if let Ok(eth) = tc_ctx.load::<EthHdr>(0) {
                    (eth.src_addr, eth.dst_addr)
                } else {
                    ([0u8; 6], [0u8; 6])
                }
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
                do_redirect(ctx, param, link_h_len, IPPROTO_UDP, ETH_P_IPV6)
            }
        } else {
            TC_ACT_OK
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

    // 根据挂载时静态确定的 link_h_len 判定协议
    let skb_proto = u16::from_be(unsafe { (*ctx).protocol } as u16);
    let is_ipv4;
    let is_ipv6;

    if link_h_len == 0 {
        // L3 帧: 偏移 0 直接为 IP 头
        is_ipv4 = skb_proto == ETH_P_IP;
        is_ipv6 = skb_proto == ETH_P_IPV6;
    } else {
        // L2 帧: 解析以太网头
        if let Ok(eth) = tc_ctx.load::<EthHdr>(0) {
            let eth_proto = u16::from_be(eth.ether_type as u16);
            is_ipv4 = eth_proto == ETH_P_IP;
            is_ipv6 = eth_proto == ETH_P_IPV6;
        } else {
            return TC_ACT_OK;
        }
    }

    if is_ipv4 {
        let ip: Ipv4Hdr = match tc_ctx.load(link_h_len) {
            Ok(h) => h,
            Err(_) => return TC_ACT_OK,
        };

        let l4_offset = link_h_len + ip.ihl() as usize;
        let ip_proto = ip.proto as u8;

        if ip_proto == (IpProto::Tcp as u8) {
            let tcp: TcpHdr = match tc_ctx.load(l4_offset) {
                Ok(h) => h,
                Err(_) => return TC_ACT_OK,
            };
            let src_port = u16::from_be_bytes(tcp.source);
            let dst_port = u16::from_be_bytes(tcp.dest);

            // 2. DNS 流量 (dst_port == 53): 100% 绝对重定向至 DNS 模块
            if dst_port != 53 {
                // 源端口放行检查 (本机服务端回复流量直连，如本地服务端口)
                if is_src_port_bypassed(src_port) {
                    return TC_ACT_OK;
                }
                // 3. 目标 IP 直连过滤 (静态 bypass_dst_ips 与 DNS 动态下发的直连 IP)
                if is_dst_ip4_bypassed(ip.dst_addr) || is_dynamic_dst_ip4_bypassed(ip.dst_addr) {
                    return TC_ACT_OK;
                }
                // 4. 目标端口放行 (tproxy 监听端口等)
                if is_dst_port_bypassed(dst_port, param.tproxy_port as u16) {
                    return TC_ACT_OK;
                }
                // 5. 目标白名单 (proxy_dst_ips / proxy_dst_ports)
                if param.has_proxy_dst_ips != 0 && !is_dst_ip4_proxied(ip.dst_addr) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_dst_ports != 0 && unsafe { PROXY_DST_PORTS.get(&dst_port).is_none() } {
                    return TC_ACT_OK;
                }
            }

            let mut src_ip = [0u8; 16];
            let mut dst_ip = [0u8; 16];
            src_ip[0..4].copy_from_slice(&ip.src_addr);
            dst_ip[0..4].copy_from_slice(&ip.dst_addr);

            let tuple = RedirectTuple {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                proto: ip_proto,
                ip_version: 4,
                _pad: [0; 2],
            };
            let ifindex = unsafe { (*ctx).ifindex };
            let (smac, dmac) = if link_h_len >= EthHdr::LEN {
                if let Ok(eth) = tc_ctx.load::<EthHdr>(0) {
                    (eth.src_addr, eth.dst_addr)
                } else {
                    ([0u8; 6], [0u8; 6])
                }
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
                let l4proto = tcp_listener_l4proto(&tcp);
                do_redirect(ctx, param, link_h_len, l4proto, ETH_P_IP)
            }
        } else if ip_proto == (IpProto::Udp as u8) {
            let udp: UdpHdr = match tc_ctx.load(l4_offset) {
                Ok(h) => h,
                Err(_) => return TC_ACT_OK,
            };
            let src_port = u16::from_be_bytes(udp.src);
            let dst_port = u16::from_be_bytes(udp.dst);

            // 2. DNS 流量 (dst_port == 53): 100% 绝对重定向至 DNS 模块
            if dst_port != 53 {
                if is_src_port_bypassed(src_port) {
                    return TC_ACT_OK;
                }
                if is_dst_ip4_bypassed(ip.dst_addr) || is_dynamic_dst_ip4_bypassed(ip.dst_addr) {
                    return TC_ACT_OK;
                }
                if is_dst_port_bypassed(dst_port, param.tproxy_port as u16) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_dst_ips != 0 && !is_dst_ip4_proxied(ip.dst_addr) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_dst_ports != 0 && unsafe { PROXY_DST_PORTS.get(&dst_port).is_none() } {
                    return TC_ACT_OK;
                }
            }

            let mut src_ip = [0u8; 16];
            let mut dst_ip = [0u8; 16];
            src_ip[0..4].copy_from_slice(&ip.src_addr);
            dst_ip[0..4].copy_from_slice(&ip.dst_addr);

            let tuple = RedirectTuple {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                proto: ip_proto,
                ip_version: 4,
                _pad: [0; 2],
            };
            let ifindex = unsafe { (*ctx).ifindex };
            let (smac, dmac) = if link_h_len >= EthHdr::LEN {
                if let Ok(eth) = tc_ctx.load::<EthHdr>(0) {
                    (eth.src_addr, eth.dst_addr)
                } else {
                    ([0u8; 6], [0u8; 6])
                }
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
                do_redirect(ctx, param, link_h_len, IPPROTO_UDP, ETH_P_IP)
            }
        } else {
            TC_ACT_OK
        }
    } else if is_ipv6 {
        let ip: Ipv6Hdr = match tc_ctx.load(link_h_len) {
            Ok(h) => h,
            Err(_) => return TC_ACT_OK,
        };
        let next_hdr = ip.next_hdr as u8;
        if next_hdr == 58 {
            return TC_ACT_OK;
        }
        let l4_offset = link_h_len + Ipv6Hdr::LEN;

        if next_hdr == (IpProto::Tcp as u8) {
            let tcp: TcpHdr = match tc_ctx.load(l4_offset) {
                Ok(h) => h,
                Err(_) => return TC_ACT_OK,
            };
            let src_port = u16::from_be_bytes(tcp.source);
            let dst_port = u16::from_be_bytes(tcp.dest);

            if dst_port != 53 {
                if is_src_port_bypassed(src_port) {
                    return TC_ACT_OK;
                }
                if is_dst_ip6_bypassed(ip.dst_addr) || is_dynamic_dst_ip6_bypassed(ip.dst_addr) {
                    return TC_ACT_OK;
                }
                if is_dst_port_bypassed(dst_port, param.tproxy_port as u16) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_dst_ips != 0 && !is_dst_ip6_proxied(ip.dst_addr) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_dst_ports != 0 && unsafe { PROXY_DST_PORTS.get(&dst_port).is_none() } {
                    return TC_ACT_OK;
                }
            }

            let tuple = RedirectTuple {
                src_ip: ip.src_addr,
                dst_ip: ip.dst_addr,
                src_port,
                dst_port,
                proto: next_hdr,
                ip_version: 6,
                _pad: [0; 2],
            };
            let ifindex = unsafe { (*ctx).ifindex };
            let (smac, dmac) = if link_h_len >= EthHdr::LEN {
                if let Ok(eth) = tc_ctx.load::<EthHdr>(0) {
                    (eth.src_addr, eth.dst_addr)
                } else {
                    ([0u8; 6], [0u8; 6])
                }
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
                let l4proto = tcp_listener_l4proto(&tcp);
                do_redirect(ctx, param, link_h_len, l4proto, ETH_P_IPV6)
            }
        } else if next_hdr == (IpProto::Udp as u8) {
            let udp: UdpHdr = match tc_ctx.load(l4_offset) {
                Ok(h) => h,
                Err(_) => return TC_ACT_OK,
            };
            let src_port = u16::from_be_bytes(udp.src);
            let dst_port = u16::from_be_bytes(udp.dst);

            if dst_port != 53 {
                if is_src_port_bypassed(src_port) {
                    return TC_ACT_OK;
                }
                if is_dst_ip6_bypassed(ip.dst_addr) || is_dynamic_dst_ip6_bypassed(ip.dst_addr) {
                    return TC_ACT_OK;
                }
                if is_dst_port_bypassed(dst_port, param.tproxy_port as u16) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_dst_ips != 0 && !is_dst_ip6_proxied(ip.dst_addr) {
                    return TC_ACT_OK;
                }
                if param.has_proxy_dst_ports != 0 && unsafe { PROXY_DST_PORTS.get(&dst_port).is_none() } {
                    return TC_ACT_OK;
                }
            }

            let tuple = RedirectTuple {
                src_ip: ip.src_addr,
                dst_ip: ip.dst_addr,
                src_port,
                dst_port,
                proto: next_hdr,
                ip_version: 6,
                _pad: [0; 2],
            };
            let ifindex = unsafe { (*ctx).ifindex };
            let (smac, dmac) = if link_h_len >= EthHdr::LEN {
                if let Ok(eth) = tc_ctx.load::<EthHdr>(0) {
                    (eth.src_addr, eth.dst_addr)
                } else {
                    ([0u8; 6], [0u8; 6])
                }
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
                do_redirect(ctx, param, link_h_len, IPPROTO_UDP, ETH_P_IPV6)
            }
        } else {
            TC_ACT_OK
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

    // Only packets redirected from wan_egress/lan_ingress carry this cb or mark.
    // Other traffic (e.g. replies to proxy outbound connections) must pass
    // through so the daens IP stack can deliver to the correct local socket.
    let cb0 = unsafe { (*ctx).cb[0] };
    let mark = unsafe { (*ctx).mark };
    if cb0 != DAE_TPROXY_MARK && mark != DAE_TPROXY_MARK {
        // Not a redirected packet — let it pass to normal IP stack
        return TC_ACT_OK;
    }

    // listener_l4proto stored in cb[1]: TCP SYN=6, UDP=17, established TCP=0
    let mut listener_l4proto = unsafe { (*ctx).cb[1] } as u8;

    // Robust fallback: if cb[1] was cleared during veth transit, detect from packet
    if listener_l4proto == 0 {
        if let Ok(eth) = tc_ctx.load::<EthHdr>(0) {
            let eth_type = u16::from_be(eth.ether_type as u16);
            if eth_type == ETH_P_IP {
                if let Ok(ip) = tc_ctx.load::<Ipv4Hdr>(EthHdr::LEN) {
                    if ip.proto == (IpProto::Udp as u8) {
                        listener_l4proto = IPPROTO_UDP;
                    } else if ip.proto == (IpProto::Tcp as u8) {
                        let l4_offset = EthHdr::LEN + ip.ihl() as usize;
                        if let Ok(tcp) = tc_ctx.load::<TcpHdr>(l4_offset) {
                            listener_l4proto = tcp_listener_l4proto(&tcp);
                        }
                    }
                }
            } else if eth_type == ETH_P_IPV6 {
                if let Ok(ip) = tc_ctx.load::<Ipv6Hdr>(EthHdr::LEN) {
                    if ip.next_hdr == (IpProto::Udp as u8) {
                        listener_l4proto = IPPROTO_UDP;
                    } else if ip.next_hdr == (IpProto::Tcp as u8) {
                        let l4_offset = EthHdr::LEN + Ipv6Hdr::LEN;
                        if let Ok(tcp) = tc_ctx.load::<TcpHdr>(l4_offset) {
                            listener_l4proto = tcp_listener_l4proto(&tcp);
                        }
                    }
                }
            }
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
/// This is the TC-side equivalent of honk's `sk::sk_assign_by_index`.
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
    let eth: EthHdr = match tc_ctx.load(0) {
        Ok(h) => h,
        Err(_) => return TC_ACT_OK,
    };

    let proto = u16::from_be(eth.ether_type as u16);
    if proto == ETH_P_IP {
        let ip: Ipv4Hdr = match tc_ctx.load(EthHdr::LEN) {
            Ok(h) => h,
            Err(_) => return TC_ACT_OK,
        };

        let l4_offset = EthHdr::LEN + ip.ihl() as usize;
        let ip_proto = ip.proto as u8;

        let (src_port, dst_port) = if ip_proto == (IpProto::Tcp as u8) {
            let tcp: TcpHdr = match tc_ctx.load(l4_offset) {
                Ok(h) => h,
                Err(_) => return TC_ACT_OK,
            };
            (u16::from_be_bytes(tcp.source), u16::from_be_bytes(tcp.dest))
        } else if ip_proto == (IpProto::Udp as u8) {
            let udp: UdpHdr = match tc_ctx.load(l4_offset) {
                Ok(h) => h,
                Err(_) => return TC_ACT_OK,
            };
            (u16::from_be_bytes(udp.src), u16::from_be_bytes(udp.dst))
        } else {
            return TC_ACT_OK;
        };

        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        src_ip[0..4].copy_from_slice(&ip.src_addr);
        dst_ip[0..4].copy_from_slice(&ip.dst_addr);

        let tuple = RedirectTuple {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto: ip_proto,
            ip_version: 4,
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
    } else if proto == ETH_P_IPV6 {
        let ip: Ipv6Hdr = match tc_ctx.load(EthHdr::LEN) {
            Ok(h) => h,
            Err(_) => return TC_ACT_OK,
        };

        let l4_offset = EthHdr::LEN + Ipv6Hdr::LEN;
        let ip_proto = ip.next_hdr as u8;

        let (src_port, dst_port) = if ip_proto == (IpProto::Tcp as u8) {
            let tcp: TcpHdr = match tc_ctx.load(l4_offset) {
                Ok(h) => h,
                Err(_) => return TC_ACT_OK,
            };
            (u16::from_be_bytes(tcp.source), u16::from_be_bytes(tcp.dest))
        } else if ip_proto == (IpProto::Udp as u8) {
            let udp: UdpHdr = match tc_ctx.load(l4_offset) {
                Ok(h) => h,
                Err(_) => return TC_ACT_OK,
            };
            (u16::from_be_bytes(udp.src), u16::from_be_bytes(udp.dst))
        } else {
            return TC_ACT_OK;
        };

        let tuple = RedirectTuple {
            src_ip: ip.src_addr,
            dst_ip: ip.dst_addr,
            src_port,
            dst_port,
            proto: ip_proto,
            ip_version: 6,
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
    } else {
        TC_ACT_OK
    }
}


#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sock_create")]
pub fn tproxy_wan_cg_sock_create(ctx: *mut bpf_sock) -> i32 {
    let _sock_ctx = SockContext::new(ctx);
    let Some(param) = get_param() else {
        return 1;
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
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
