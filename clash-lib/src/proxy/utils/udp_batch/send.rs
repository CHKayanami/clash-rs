//! Reusable syscall descriptors. Payload owners are borrowed only while a send
//! is polled; no descriptor is submitted before its active prefix is rebuilt.
use super::*;
use std::{array::from_fn, mem::MaybeUninit};
#[cfg(all(target_os = "linux", any(feature = "tproxy", feature = "ebpf")))]
use std::cell::RefCell;
#[cfg(all(target_os = "linux", any(feature = "tproxy", feature = "ebpf")))]
use crate::{proxy::datagram::UdpPacket, session::SocksAddr};

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
    loop {
        match ready!(socket.poll_send_ready(cx)) {
            Ok(()) => {},
            Err(error) => return Poll::Ready(BatchResult::failed(error)),
        }
        let result = socket.try_io(Interest::WRITABLE, || {
            send(socket, ipv6, packets.iter().copied(), workspace)
        });
        if let Poll::Ready(result) = send_status(result) {
            return Poll::Ready(result);
        }
    }
}

#[cfg(all(target_os = "linux", any(feature = "tproxy", feature = "ebpf")))]
thread_local! {
    static REPLY_WORKSPACE: RefCell<SendWorkspace> = RefCell::new(SendWorkspace::default());
}

/// Shared sockets use independent writable() futures after this immediate
/// attempt. The thread-local borrow lasts only for the synchronous syscall.
#[cfg(all(target_os = "linux", any(feature = "tproxy", feature = "ebpf")))]
pub(crate) fn try_send_replies(socket: &UdpSocket, ipv6: bool, packets: &[UdpPacket])
    -> Poll<BatchResult>
{
    let send_replies = || REPLY_WORKSPACE.with_borrow_mut(|workspace| {
        let slices = packets.iter().map(|packet| {
            let SocksAddr::Ip(destination) = packet.dst_addr else {
                unreachable!("validated reply destination");
            };
            DatagramSlice { header: &[], payload: &packet.data, destination }
        });
        send(socket, ipv6, slices, workspace)
    });
    let mut attempted = false;
    let result = socket.try_io(Interest::WRITABLE, || {
        attempted = true;
        send_replies()
    });
    // A newly bound socket may be writable before Tokio has observed a
    // readiness event. Try the nonblocking syscall before staging a batch.
    if !attempted && result.as_ref().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock) {
        return send_status(send_replies());
    }
    send_status(result)
}

fn send_status(result: io::Result<BatchResult>) -> Poll<BatchResult> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(error) => Poll::Ready(BatchResult::failed(error)),
        Ok(result) => Poll::Ready(result),
    }
}

fn send<'a>(socket: &UdpSocket, ipv6: bool,
    packets: impl ExactSizeIterator<Item = DatagramSlice<'a>> + Clone,
    workspace: &mut SendWorkspace) -> io::Result<BatchResult> {
    let count = packets.len();
    assert!(count > 0 && count <= MAX_DIRECT_BATCH_PACKETS);
    for (i, packet) in packets.clone().enumerate() {
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
    let sent = loop {
        // SAFETY: active descriptors and their borrowed payload owners stay
        // stationary and live until this synchronous syscall returns.
        let sent = unsafe { libc::sendmmsg(socket.as_raw_fd(), workspace.messages.as_mut_ptr(), count as u32, libc::MSG_DONTWAIT as _) };
        if sent >= 0 { break sent as usize; }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted { return Err(error); }
    };
    if sent == 0 {
        return Ok(BatchResult::failed(io::Error::new(io::ErrorKind::WriteZero, "zero UDP batch send")));
    }
    for (i, packet) in packets.take(sent).enumerate() {
        if workspace.messages[i].msg_len as usize != packet.header.len() + packet.payload.len() {
            return Ok(BatchResult { sent: i, fatal: false,
                error: Some(io::Error::new(io::ErrorKind::WriteZero, "partial UDP datagram send")) });
        }
    }
    Ok(BatchResult::sent(sent))
}
