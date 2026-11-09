//! Logical completion remains packet-based for both sendmsg and sendmmsg.
use std::{io, mem::{size_of, zeroed}, os::fd::AsRawFd,
    ptr::copy_nonoverlapping, task::{Context, Poll}};
use socket2::SockAddr;
use tokio::{io::Interest, net::UdpSocket};
use crate::proxy::{datagram::batch::{BatchResult, MAX_DIRECT_BATCH_PACKETS},
    utils::udp_batch::{DatagramSlice, SendWorkspace, map_destination}, direct::segment_plan::{self, Group}};

pub(in crate::proxy::direct) fn poll_send(socket: &UdpSocket, ipv6: bool, cx: &mut Context<'_>,
    packets: &[DatagramSlice<'_>], enabled: &mut bool, workspace: &mut SendWorkspace) -> Option<Poll<BatchResult>> {
    if !*enabled || packets.iter().any(|packet| !packet.header.is_empty()) { return None; }
    let mut groups = [Group::default(); MAX_DIRECT_BATCH_PACKETS];
    let (count, segmented) = segment_plan::groups(packets, &mut groups);
    if !segmented { return None; }
    send(socket, ipv6, cx, packets, &groups[..count], enabled, workspace)
}
#[cfg(feature = "tun")]
pub(in crate::proxy::direct) fn poll_send_segments(socket: &UdpSocket, ipv6: bool, cx: &mut Context<'_>,
    packet: DatagramSlice<'_>, size: usize, enabled: &mut bool, workspace: &mut SendWorkspace) -> Option<Poll<BatchResult>> {
    if !*enabled || packet.payload.len() <= size || packet.payload.len() > 65507 { return None; }
    send(socket, ipv6, cx, &[packet], &[Group { start: 0, count: 1, size: Some(size) }], enabled, workspace)
}
fn control(header: &mut libc::msghdr, storage: &mut [usize; 4], size: Option<usize>) {
    if let Some(size) = size {
        header.msg_control = storage.as_mut_ptr().cast();
        header.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<u16>() as _) } as _;
        // SAFETY: aligned storage holds the complete cmsghdr and u16 value.
        unsafe {
            let cmsg = header.msg_control.cast::<libc::cmsghdr>();
            (*cmsg).cmsg_len = libc::CMSG_LEN(2) as _;
            (*cmsg).cmsg_level = libc::SOL_UDP; (*cmsg).cmsg_type = libc::UDP_SEGMENT;
            copy_nonoverlapping((size as u16).to_ne_bytes().as_ptr(), libc::CMSG_DATA(cmsg), 2);
        }
    }
}
fn poll_write(socket: &UdpSocket, cx: &mut Context<'_>, mut operation: impl FnMut() -> io::Result<usize>) -> Poll<io::Result<usize>> {
    loop {
        match socket.poll_send_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {},
        }
        match socket.try_io(Interest::WRITABLE, &mut operation) {
            Err(error) if matches!(error.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock) => {},
            result => return Poll::Ready(result),
        }
    }
}
fn fallback(error: &io::Error, enabled: &mut bool) -> bool {
    if matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOPROTOOPT | libc::EOPNOTSUPP | libc::EMSGSIZE | libc::EIO)) {
        if error.raw_os_error() != Some(libc::EMSGSIZE) { *enabled = false; }
        tracing::debug!("UDP GSO unavailable, using datagram batches: {error}"); true
    } else { false }
}
fn send(socket: &UdpSocket, ipv6: bool, cx: &mut Context<'_>, packets: &[DatagramSlice<'_>],
    groups: &[Group], enabled: &mut bool, workspace: &mut SendWorkspace) -> Option<Poll<BatchResult>> {
    for (slot, packet) in workspace.vectors.iter_mut().zip(packets) {
        *slot = libc::iovec { iov_base: packet.payload.as_ptr().cast_mut().cast(), iov_len: packet.payload.len() };
    }
    for (i, group) in groups.iter().enumerate() {
        let address = workspace.addresses[i].write(SockAddr::from(map_destination(packets[group.start].destination, ipv6)));
        let message = &mut workspace.messages[i];
        // SAFETY: reset stale ancillary pointers before rebuilding this prefix.
        *message = unsafe { zeroed() };
        let header = &mut message.msg_hdr;
        header.msg_name = address.as_ptr().cast_mut().cast(); header.msg_namelen = address.len();
        header.msg_iov = workspace.vectors[group.start..].as_mut_ptr();
        header.msg_iovlen = group.count as _;
        control(header, &mut workspace.controls[i], group.size);
    }
    // SAFETY: descriptors are rebuilt from live payloads for this call only;
    // neither workspace nor owners move until the synchronous syscall returns.
    let result = poll_write(socket, cx, || {
        if groups.len() == 1 {
            let length = unsafe { libc::sendmsg(socket.as_raw_fd(), &workspace.messages[0].msg_hdr, libc::MSG_DONTWAIT as _) };
            if length < 0 { return Err(io::Error::last_os_error()); }
            workspace.messages[0].msg_len = length as _;
            Ok(1)
        } else {
            let count = unsafe { libc::sendmmsg(socket.as_raw_fd(), workspace.messages.as_mut_ptr(), groups.len() as u32, libc::MSG_DONTWAIT as _) };
            if count < 0 { Err(io::Error::last_os_error()) } else { Ok(count as usize) }
        }
    });
    match result {
        Poll::Pending => Some(Poll::Pending),
        Poll::Ready(Err(error)) if fallback(&error, enabled) => None,
        Poll::Ready(Err(error)) => Some(Poll::Ready(BatchResult::failed(error))),
        Poll::Ready(Ok(0)) => Some(Poll::Ready(BatchResult::terminated(io::Error::new(io::ErrorKind::WriteZero, "zero UDP batch send")))),
        Poll::Ready(Ok(count)) => {
            let mut completed = 0;
            for (i, group) in groups[..count].iter().enumerate() {
                let expected: usize = packets[group.start..group.start + group.count].iter().map(|p| p.payload.len()).sum();
                if workspace.messages[i].msg_len as usize != expected {
                    return Some(Poll::Ready(BatchResult { sent: completed, fatal: true,
                        error: Some(io::Error::new(io::ErrorKind::WriteZero, "partial UDP GSO message")) }));
                }
                completed += group.count;
            }
            Some(Poll::Ready(BatchResult::sent(completed)))
        },
    }
}
