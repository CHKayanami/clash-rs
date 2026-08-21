#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct PIDName {
    pub last_seen_ns: u64,
    pub pid: u32,
    pub pname: [u8; 16],
    pub _pad: [u8; 4],
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaeEventType {
    Blocked = 0,
    Redirected = 1,
    UdpConnOverflow = 2,
    TcpConnOverflow = 3,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DaeEvent {
    pub timestamp: u64,
    pub type_: u32,
    pub pid: u32,
    pub pname: [u8; 16],
    pub outbound: u8,
    pub l4proto: u8,
    pub pad: [u8; 2],
    pub sip: [u32; 4],
    pub dip: [u32; 4],
    pub sport: u16,
    pub dport: u16,
}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for PIDName {}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for DaeEvent {}
