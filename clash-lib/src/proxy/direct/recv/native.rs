//! Initialized syscall ranges only; payload ownership stays in the caller.
use std::{io, mem::MaybeUninit, os::fd::AsRawFd};
#[cfg(target_os = "linux")]
use std::mem::size_of_val;
use socket2::{SockAddr, SockAddrStorage};
use tokio::{io::Interest, net::UdpSocket};
use super::{MAX_DATAGRAM_SIZE, ReceivedPacket};

pub(super) fn receive<const N: usize>(socket: &UdpSocket, limit: usize, gro: bool,
    buffer: &mut [MaybeUninit<u8>], packets: &mut [Option<ReceivedPacket>; N]) -> io::Result<usize> {
    assert!(limit > 0 && limit <= N && buffer.len() >= limit * MAX_DATAGRAM_SIZE);
    #[cfg(not(target_os = "linux"))]
    let _ = gro;

    let slots = std::array::from_fn::<_, N, _>(|i|
        if i < limit { unsafe { buffer.as_mut_ptr().add(i * MAX_DATAGRAM_SIZE) } } else { std::ptr::null_mut() });
    // SAFETY: the checked contiguous buffer contains disjoint full-size slots.
    unsafe { receive_slots(socket, limit, gro, &slots, packets) }
}

/// Each submitted pointer must address a disjoint writable MAX_DATAGRAM_SIZE
/// range, live for the synchronous syscall. Only returned lengths are initialized.
pub(super) unsafe fn receive_slots<const N: usize>(socket: &UdpSocket, limit: usize, gro: bool,
    slots: &[*mut MaybeUninit<u8>; N], packets: &mut [Option<ReceivedPacket>; N]) -> io::Result<usize> {
    assert!(limit > 0 && limit <= N);
    #[cfg(not(target_os = "linux"))]
    let _ = gro;
    let mut addresses = std::array::from_fn::<_, N, _>(|_| {
        SockAddrStorage::zeroed()
    });
    let mut iovecs =
        std::array::from_fn::<_, N, _>(|i| libc::iovec {
            // SAFETY: each slot is a disjoint, live writable range. No Rust
            // reference to uninitialized bytes is created.
            iov_base: slots[i].cast(),
            iov_len: if i < limit { MAX_DATAGRAM_SIZE } else { 0 },
        });
    #[cfg(target_os = "linux")]
    let mut controls = gro.then(|| [[0usize; 8]; N]);
    let mut messages = std::array::from_fn::<_, N, _>(|i| {
        // SAFETY: zero is valid for the scalar and pointer fields.
        let mut message: libc::mmsghdr = unsafe { std::mem::zeroed() };
        message.msg_hdr.msg_name =
            (&mut addresses[i] as *mut SockAddrStorage).cast();
        message.msg_hdr.msg_namelen = addresses[i].size_of();
        message.msg_hdr.msg_iov = &mut iovecs[i];
        message.msg_hdr.msg_iovlen = 1;
        #[cfg(target_os = "linux")]
        if let Some(controls) = &mut controls {
            message.msg_hdr.msg_control = controls[i].as_mut_ptr().cast();
            // musl uses socklen_t here; GNU libc uses size_t. Storage is at most 64 bytes.
            message.msg_hdr.msg_controllen = size_of_val(&controls[i]) as _;
        }
        message
    });
    let count = socket.try_io(Interest::READABLE, || {
        loop {
            // SAFETY: message/address/iovec arrays and all payload slots
            // remain live and stable for the nonblocking syscall.
            let count = unsafe {
                libc::recvmmsg(
                    socket.as_raw_fd(),
                    messages.as_mut_ptr(),
                    limit as u32,
                    libc::MSG_DONTWAIT as _,
                    std::ptr::null_mut(),
                )
            };
            if count >= 0 {
                break Ok(count as usize);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                break Err(err);
            }
        }
    })?;
    for i in 0..count {
        let header = &messages[i].msg_hdr;
        if header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            tracing::debug!(flags = header.msg_flags, "dropping truncated UDP batch message");
            continue;
        }
        let storage =
            std::mem::replace(&mut addresses[i], SockAddrStorage::zeroed());
        // SAFETY: recvmmsg initialized this sender's address and length.
        let Some(address) = (unsafe { SockAddr::new(storage, header.msg_namelen) })
            .as_socket() else {
            tracing::debug!("dropping UDP packet with unexpected sender address family");
            continue;
        };
        let len = messages[i].msg_len as usize;
        let len = len.min(MAX_DATAGRAM_SIZE);
        let segment = {
            #[cfg(target_os = "linux")]
            { if let Some(controls) = &controls {
                let control_len = header.msg_controllen as usize;
                if control_len > size_of_val(&controls[i]) { continue; }
                // SAFETY: control storage is initialized and kernel length
                // is bounded above. No pointer escapes this synchronous call.
                let data = unsafe { std::slice::from_raw_parts(controls[i].as_ptr().cast::<u8>(), control_len) };
                match super::super::offload::gro_size(data) {
                    Ok(size) => size,
                    Err(error) => { tracing::debug!("dropping malformed UDP GRO control: {error}"); continue; }
                }
            } else { None } }
            #[cfg(not(target_os = "linux"))]
            { None }
        };
        packets[i] = Some((i * MAX_DATAGRAM_SIZE, len, address, segment));
    }
    Ok(count)
}
