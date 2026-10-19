//! Rule evaluation happens only when no connection decision has been published.
use clash_ebpf_common::{DaeParam, PIDName};
use network_types::eth::EthHdr;
use crate::{maps::{BYPASS_DSCPS, BYPASS_PROCESSES, PROXY_PROCESSES, PROXY_SRC_MACS, PROXY_SRC_PORTS, PROXY_DST_PORTS},
    transport::{ParsedPacket, ETH_P_IP}, is_src_port_bypassed, is_dst_port_bypassed,
    is_src_ip4_bypassed, is_src_ip4_proxied, is_src_ip6_bypassed, is_src_ip6_proxied,
    is_dst_ip4_bypassed, is_dst_ip4_proxied, is_dst_ip6_bypassed, is_dst_ip6_proxied,
    is_dynamic_dst_ip4_bypassed, is_dynamic_dst_ip6_bypassed};

#[inline(always)]
pub fn direct(param: &DaeParam, link: usize, pkt: &ParsedPacket, wan: bool, process: Option<&PIDName>) -> bool {
    if wan {
        if param.has_proxy_processes != 0 && process.is_none() { return true; }
        if let Some(process) = process {
            if param.has_bypass_processes != 0 && unsafe { BYPASS_PROCESSES.get(&process.pname).is_some() } { return true; }
            if param.has_proxy_processes != 0 && unsafe { PROXY_PROCESSES.get(&process.pname).is_none() } { return true; }
        }
    }
    if param.has_bypass_dscps != 0 && unsafe { BYPASS_DSCPS.get(&pkt.tuples.dscp).is_some() } {
        return true;
    }
    let src = &pkt.tuples.five.src_ip;
    let dst = &pkt.tuples.five.dst_ip;
    let src_port = pkt.tuples.five.src_port;
    let dst_port = pkt.tuples.five.dst_port;
    let ipv4 = pkt.ethh.ether_type == ETH_P_IP.to_be();
    let src4 = [src[12], src[13], src[14], src[15]];
    let dst4 = [dst[12], dst[13], dst[14], dst[15]];
    if !wan {
        if param.has_proxy_src_macs != 0 && (link < EthHdr::LEN
            || unsafe { PROXY_SRC_MACS.get(&pkt.ethh.src_addr).is_none() }) { return true; }
        let src_bypass = if ipv4 { is_src_ip4_bypassed(src4) }
            else { is_src_ip6_bypassed(src.as_bytes()) };
        let src_proxied = param.has_proxy_src_ips == 0 || if ipv4 { is_src_ip4_proxied(src4) }
            else { is_src_ip6_proxied(src.as_bytes()) };
        if src_bypass || !src_proxied || is_src_port_bypassed(src_port)
            || (param.has_proxy_src_ports != 0 && unsafe { PROXY_SRC_PORTS.get(&src_port).is_none() }) {
            return true;
        }
    }
    // Source selection keeps its precedence; destination rules cannot bypass DNS.
    if dst_port == 53 { return false; }
    if ipv4 && param.local_ip != 0 && dst4 == param.local_ip.to_ne_bytes() { return true; }
    if is_dst_port_bypassed(dst_port, param.tproxy_port as u16) { return true; }
    let bypass = if ipv4 { is_dst_ip4_bypassed(dst4) || is_dynamic_dst_ip4_bypassed(dst4) }
        else { is_dst_ip6_bypassed(dst.as_bytes()) || is_dynamic_dst_ip6_bypassed(dst.as_bytes()) };
    if bypass { return true; }
    let proxied = param.has_proxy_dst_ips == 0 || if ipv4 { is_dst_ip4_proxied(dst4) }
        else { is_dst_ip6_proxied(dst.as_bytes()) };
    !proxied || (param.has_proxy_dst_ports != 0 && unsafe { PROXY_DST_PORTS.get(&dst_port).is_none() })
}
