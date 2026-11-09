//! Reusable syscall descriptors. Payload owners are borrowed only while a send
//! is polled; no descriptor is submitted before its active prefix is rebuilt.
use super::*;
use std::{array::from_fn, mem::MaybeUninit};

pub(crate) struct SendWorkspace {
    pub addresses: [MaybeUninit<SockAddr>; MAX_DIRECT_BATCH_PACKETS],
    pub vectors: [libc::iovec; MAX_DIRECT_BATCH_PACKETS * 2],
    pub messages: [libc::mmsghdr; MAX_DIRECT_BATCH_PACKETS],
    #[cfg(target_os = "linux")]
    pub controls: [[usize; 4]; MAX_DIRECT_BATCH_PACKETS],
}
impl Default for SendWorkspace {
    fn default() -> Self {
        Self { addresses: from_fn(|_| MaybeUninit::uninit()),
            // SAFETY: these C structs contain scalar fields and nullable raw
            // pointers. Their active prefixes are initialized before each call.
            vectors: unsafe { zeroed() }, messages: unsafe { zeroed() },
            #[cfg(target_os = "linux")]
            controls: [[0; 4]; MAX_DIRECT_BATCH_PACKETS] }
    }
}
// SAFETY: descriptors are private scratch, not owners. Cached raw pointers are
// never dereferenced between calls. Each operation exclusively borrows this
// workspace and rebuilds every submitted pointer from its live arguments.
unsafe impl Send for SendWorkspace {}

pub(crate) fn poll_send(socket: &UdpSocket, ipv6: bool, cx: &mut Context<'_>,
    packets: &[DatagramSlice<'_>], workspace: &mut SendWorkspace) -> Poll<BatchResult> {
    assert!(!packets.is_empty() && packets.len() <= MAX_DIRECT_BATCH_PACKETS);
    for (i, packet) in packets.iter().enumerate() {
        let address = workspace.addresses[i].write(SockAddr::from(map_destination(packet.destination, ipv6)));
        workspace.vectors[i * 2] = libc::iovec { iov_base: packet.header.as_ptr().cast_mut().cast(), iov_len: packet.header.len() };
        workspace.vectors[i * 2 + 1] = libc::iovec { iov_base: packet.payload.as_ptr().cast_mut().cast(), iov_len: packet.payload.len() };
        let message = &mut workspace.messages[i];
        // SAFETY: reset the active message, including stale ancillary fields.
        *message = unsafe { zeroed() };
        message.msg_hdr.msg_name = address.as_ptr().cast_mut().cast();
        message.msg_hdr.msg_namelen = address.len();
        message.msg_hdr.msg_iov = workspace.vectors[i * 2..].as_mut_ptr();
        message.msg_hdr.msg_iovlen = 2;
    }
    loop {
        match ready!(socket.poll_send_ready(cx)) {
            Ok(()) => {},
            Err(error) => return Poll::Ready(BatchResult::failed(error)),
        }
        let result = socket.try_io(Interest::WRITABLE, || {
            // SAFETY: active descriptors and their borrowed payload owners stay
            // stationary and live until this synchronous syscall returns.
            let sent = unsafe { libc::sendmmsg(socket.as_raw_fd(), workspace.messages.as_mut_ptr(), packets.len() as u32, libc::MSG_DONTWAIT as _) };
            if sent < 0 { Err(io::Error::last_os_error()) } else { Ok(sent as usize) }
        });
        match result {
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => continue,
            Err(error) => return Poll::Ready(BatchResult::failed(error)),
            Ok(0) => return Poll::Ready(BatchResult::failed(io::Error::new(io::ErrorKind::WriteZero, "zero UDP batch send"))),
            Ok(sent) => {
                for (i, packet) in packets[..sent].iter().enumerate() {
                    if workspace.messages[i].msg_len as usize != packet.header.len() + packet.payload.len() {
                        return Poll::Ready(BatchResult { sent: i, fatal: false,
                            error: Some(io::Error::new(io::ErrorKind::WriteZero, "partial UDP datagram send")) });
                    }
                }
                return Poll::Ready(BatchResult::sent(sent));
            },
        }
    }
}
