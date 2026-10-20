#![no_std]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

pub mod conn;
pub mod dae_ip;
pub mod event;

pub use conn::{ParseTransportCtx, Tuples, TuplesKey};
pub use dae_ip::In6Addr;
pub use event::{DaeEvent, DaeEventType, PIDName};

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
    pub proxy_local: u8,
    pub dae_socket_mark: u32,
    pub control_plane_pid: u32,
    pub local_ip: u32,
    pub has_proxy_src_ips: u8,
    pub has_proxy_dst_ips: u8,
    pub has_proxy_src_ports: u8,
    pub has_proxy_dst_ports: u8,
    pub direct_offload_enabled: u8,
    pub has_proxy_processes: u8,
    pub has_bypass_processes: u8,
    pub has_bypass_dscps: u8,
    pub has_bypass_fwmarks: u8,
    pub has_proxy_src_macs: u8,
    pub _pad1: [u8; 2],
}

// Keep address copies aligned for BPF code generation. The key remains 40
// bytes with the same field offsets; only its alignment changes.
#[repr(C, align(8))]
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

/// Endpoint-independent UDP return route for one client socket. Remote IP
/// and port never restrict Full-Cone replies. Every key byte is initialized.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UdpReplyKey {
    pub client_ip: [u8; 16],
    pub client_port: u16,
    pub ip_version: u8,
    pub _pad: [u8; 5],
}

impl UdpReplyKey {
    pub fn from_request(tuple: &RedirectTuple) -> Self {
        Self { client_ip: tuple.src_ip, client_port: tuple.src_port,
            ip_version: tuple.ip_version, _pad: [0; 5] }
    }
}

/// Shared client-socket route, published as a complete map value.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UdpReplyEntry {
    pub last_seen_ns: u64,
    pub route: RedirectEntry,
    pub _pad: [u8; 4],
    pub generation: u64,
}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for DaeParam {}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for RedirectTuple {}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for RedirectEntry {}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for UdpReplyKey {}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for UdpReplyEntry {}

/// FLOW_TRACK ABI: atomic 32-bit activity fields and a full bucket generation.
/// This layout has no implicit padding; route padding is explicitly initialized.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlowTrackEntry {
    pub last_seen_seconds: u32,
    pub state: u32,
    pub route: RedirectEntry,
    pub _pad: [u8; 4],
    pub generation: u64,
}

/// Only the single collector writes this request slot. The BPF program checks
/// the observed incarnation and activity under the same gate as packet writers.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TrackingGcRequest {
    pub tuple: RedirectTuple,
    pub generation: u64,
    pub activity: u64,
    pub now_ns: u64,
    pub kind: u32,
    pub _pad: u32,
}

pub const GC_BATCH_SIZE: usize = 16;

/// One collector owns this slot. Explicit padding and initialized requests
/// make the complete batch safe to copy through the map syscall ABI.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TrackingGcBatch {
    pub count: u32,
    pub _pad: u32,
    pub requests: [TrackingGcRequest; GC_BATCH_SIZE],
}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for TrackingGcBatch {}

pub const GC_FLOW: u32 = 0;
pub const GC_UDP_REPLY: u32 = 1;

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for TrackingGcRequest {}

impl FlowTrackEntry {
    pub fn activity(&self) -> u64 { tracking::word(self.state, self.last_seen_seconds) }
    pub fn set_activity(&mut self, activity: u64) {
        self.last_seen_seconds = tracking::seconds(activity);
        self.state = tracking::token(activity);
    }
}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for FlowTrackEntry {}

pub mod tracking;

const _: () = {
    assert!(core::mem::size_of::<RedirectEntry>() == 20);
    assert!(core::mem::size_of::<FlowTrackEntry>() == 40);
    assert!(core::mem::align_of::<FlowTrackEntry>() >= 8);
    assert!(core::mem::offset_of!(FlowTrackEntry, last_seen_seconds) == 0);
    assert!(core::mem::offset_of!(FlowTrackEntry, state) == 4);
    assert!(core::mem::size_of::<UdpReplyKey>() == 24);
    assert!(core::mem::size_of::<UdpReplyEntry>() == 40);
    assert!(core::mem::offset_of!(FlowTrackEntry, route) == 8);
    assert!(core::mem::offset_of!(FlowTrackEntry, generation) == 32);
    assert!(core::mem::size_of::<TrackingGcRequest>() == 72);
    assert!(GC_BATCH_SIZE < 32);
    assert!(core::mem::offset_of!(TrackingGcBatch, requests) == 8);
    assert!(core::mem::size_of::<TrackingGcBatch>() == 1160);
    assert!(core::mem::offset_of!(UdpReplyEntry, route) == 8);
};
