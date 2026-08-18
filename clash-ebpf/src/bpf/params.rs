//! eBPF control parameters and common definitions shared between kernel and userspace.

pub const DAE_BYPASS_MARK: u32 = 0x2dae;
pub const DAE_TPROXY_MARK: u32 = 0x1dae;

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
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for DaeParam {}
