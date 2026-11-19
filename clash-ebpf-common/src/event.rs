use core::mem::{offset_of, size_of};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct PIDName {
    pub pid: u32,
    pub pname: [u8; 16],
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

const _: () = {
    const fn field_size<T>(_: fn(&DaeEvent) -> &T) -> usize {
        size_of::<T>()
    }

    macro_rules! assert_field {
        ($field:ident, $offset:expr, $size:expr) => {
            assert!(offset_of!(DaeEvent, $field) == $offset);
            assert!(field_size(|event| &event.$field) == $size);
        };
    }

    assert_field!(timestamp, 0, 8);
    assert_field!(type_, 8, 4);
    assert_field!(pid, 12, 4);
    assert_field!(pname, 16, 16);
    assert_field!(outbound, 32, 1);
    assert_field!(l4proto, 33, 1);
    assert_field!(pad, 34, 2);
    assert_field!(sip, 36, 16);
    assert_field!(dip, 52, 16);
    assert_field!(sport, 68, 2);
    assert_field!(dport, 70, 2);
    assert!(size_of::<DaeEvent>() == 72);
};

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for PIDName {}

// SAFETY: Every field accepts arbitrary bytes, and the ABI assertions above
// account for every byte of the C layout, including the explicit pad field.
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for DaeEvent {}
