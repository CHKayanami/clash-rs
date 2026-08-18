#![no_std]

pub mod conn;
pub mod dae_ip;

pub use conn::{ParseTransportCtx, Tuples, TuplesKey};
pub use dae_ip::In6Addr;

pub const DAE_TPROXY_MARK: u32 = 0x1dae;
pub const DAE_BYPASS_MARK: u32 = 0x2dae;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DaeParam {
    pub tproxy_port: u32,
    pub dae0_ifindex: u32,
    pub wan_ifindex: u32,
    pub dae0peer_mac: [u8; 6],
    pub use_redirect_peer: u8,
    pub _pad0: u8,
    pub dae_socket_mark: u32,
    pub control_plane_pid: u32,
    pub local_ip: u32,
    pub has_proxy_src_ips: u8,
    pub has_proxy_dst_ips: u8,
    pub has_proxy_src_ports: u8,
    pub has_proxy_dst_ports: u8,
    pub direct_offload_enabled: u8,
    pub _pad1: [u8; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RedirectTuple {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub ip_version: u8,
    pub _pad: [u8; 2],
}

impl RedirectTuple {
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            proto: self.proto,
            ip_version: self.ip_version,
            _pad: [0; 2],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RedirectEntry {
    pub ifindex: u32,
    pub from_wan: u8,
    pub _pad0: [u8; 3],
    pub smac: [u8; 6],
    pub dmac: [u8; 6],
}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for DaeParam {}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for RedirectTuple {}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for RedirectEntry {}
