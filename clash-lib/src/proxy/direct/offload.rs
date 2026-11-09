//! Linux UDP offload remains opt-in on an association-owned socket.
use std::{io, mem::size_of, num::NonZeroU16, os::fd::AsRawFd, ptr::read_unaligned};
use tokio::net::UdpSocket;
#[cfg(test)]
use std::{mem::zeroed, ptr::copy_nonoverlapping};

pub(super) fn enable_receive(socket: &UdpSocket) -> bool {
    let enabled: libc::c_int = 1;
    // SAFETY: the live socket and correctly sized integer are borrowed only for
    // setsockopt. Other users of NativeDatagram do not enable GRO implicitly.
    let result = unsafe { libc::setsockopt(socket.as_raw_fd(), libc::SOL_UDP, libc::UDP_GRO,
        (&enabled as *const libc::c_int).cast(), size_of::<libc::c_int>() as _) };
    if result == 0 { true } else {
        tracing::debug!("UDP_GRO unavailable: {}", io::Error::last_os_error()); false
    }
}

pub(super) fn gro_size(control: &[u8]) -> io::Result<Option<NonZeroU16>> {
    let mut offset = 0;
    let mut segment = None;
    // Ancillary fields use host ABI alignment and native byte order.
    while offset < control.len() {
        if control.len() - offset < size_of::<libc::cmsghdr>() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated UDP control header"));
        }
        // SAFETY: the initialized byte range above contains a complete header;
        // read_unaligned also accepts fixtures and byte slices without alignment.
        let header = unsafe { read_unaligned(control[offset..].as_ptr().cast::<libc::cmsghdr>()) };
        let length = header.cmsg_len as usize;
        // SAFETY: CMSG_LEN/CMSG_SPACE only perform ABI size/alignment arithmetic.
        let data_start = unsafe { libc::CMSG_LEN(0) } as usize;
        if length < data_start || length > control.len() - offset {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid UDP control length"));
        }
        if header.cmsg_level == libc::SOL_UDP && header.cmsg_type == libc::UDP_GRO {
            if length - data_start < 4 || segment.is_some() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid UDP_GRO control"));
            }
            let size = u32::from_ne_bytes(control[offset + data_start..offset + data_start + 4].try_into().unwrap());
            segment = u16::try_from(size).ok().and_then(NonZeroU16::new);
            if segment.is_none() { return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid UDP_GRO size")); }
        }
        let next = unsafe { libc::CMSG_SPACE((length - data_start) as _) } as usize;
        if next > control.len() - offset {
            if length == control.len() - offset { break; }
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated UDP control padding"));
        }
        offset += next;
    }
    Ok(segment)
}

mod send;
pub(super) use send::poll_send;
#[cfg(feature = "tun")]
pub(super) use send::poll_send_segments;

#[cfg(test)]
mod tests;
