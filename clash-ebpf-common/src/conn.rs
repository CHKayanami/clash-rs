use crate::dae_ip::In6Addr;
use network_types::{
    eth::EthHdr,
    icmp::Icmpv6Hdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct TuplesKey {
    pub src_ip: In6Addr,
    pub dst_ip: In6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub l4proto: u8,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Tuples {
    pub five: TuplesKey,
    pub dscp: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ParseTransportCtx {
    pub ethh: EthHdr,         // struct ethhdr
    pub iph: Ipv4Hdr,         // struct ipv4hdr
    pub ipv6h: Ipv6Hdr,       // struct ipv6hdr
    pub icmp6h: Icmpv6Hdr,    // struct icmp6hdr
    pub tcph: TcpHdr,         // struct tcphdr
    pub udph: UdpHdr,         // struct udphdr
    pub ihl: u8,              // IP header length in 4-byte units
    pub l4proto: u8,          // Actual L4 protocol
    pub listener_l4proto: u8, // Listener protocol
    pub pad: u8,              // Alignment padding
}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for TuplesKey {}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for Tuples {}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for ParseTransportCtx {}
