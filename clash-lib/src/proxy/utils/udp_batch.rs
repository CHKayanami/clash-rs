//! Packet boundaries and payload ownership stay intact across batched syscalls.
use std::{net::{SocketAddr, SocketAddrV6}, task::{Context, Poll}};
use futures::ready;
use tokio::net::UdpSocket;
#[cfg(target_os = "linux")]
use tokio::io::Interest;
use crate::proxy::datagram::batch::{BatchResult, MAX_BATCH_PACKETS};
#[cfg(target_os = "linux")]
use std::{io, mem::zeroed, os::fd::AsRawFd};
#[cfg(target_os = "linux")]
use socket2::SockAddr;
#[cfg(not(target_os = "linux"))]
use super::poll_send_to_vectored;

pub(crate) struct DatagramSlice<'a> {
    pub header: &'a [u8],
    pub payload: &'a [u8],
    pub destination: SocketAddr,
}

pub(crate) fn poll_send_batch(
    socket: &UdpSocket, local_is_ipv6: bool, cx: &mut Context<'_>, packets: &[DatagramSlice<'_>],
) -> Poll<BatchResult> {
    assert!(!packets.is_empty() && packets.len() <= MAX_BATCH_PACKETS);
    #[cfg(target_os = "linux")]
    {
        let addresses = std::array::from_fn::<_, MAX_BATCH_PACKETS, _>(|i| {
            let destination = packets.get(i).unwrap_or(&packets[0]).destination;
            SockAddr::from(map_destination(destination, local_is_ipv6))
        });
        // All arrays and payload owners remain live and stationary throughout
        // sendmmsg. The kernel only reads iovecs/payloads and writes msg_len.
        let mut iovecs = std::array::from_fn::<_, MAX_BATCH_PACKETS, _>(|i| {
            if let Some(packet) = packets.get(i) {
                [libc::iovec { iov_base: packet.header.as_ptr().cast_mut().cast(), iov_len: packet.header.len() },
                 libc::iovec { iov_base: packet.payload.as_ptr().cast_mut().cast(), iov_len: packet.payload.len() }]
            } else {
                // SAFETY: null pointers with zero lengths are valid unused iovecs.
                unsafe { zeroed() }
            }
        });
        let mut messages = std::array::from_fn::<_, MAX_BATCH_PACKETS, _>(|i| {
            // SAFETY: zero initializes scalar lengths and nullable pointers.
            let mut message: libc::mmsghdr = unsafe { zeroed() };
            if let Some(address) = addresses.get(i) {
                message.msg_hdr.msg_name = address.as_ptr().cast_mut().cast();
                message.msg_hdr.msg_namelen = address.len();
                message.msg_hdr.msg_iov = iovecs[i].as_mut_ptr();
                message.msg_hdr.msg_iovlen = 2;
            }
            message
        });
        loop {
            match ready!(socket.poll_send_ready(cx)) {
                Ok(()) => {},
                Err(error) => return Poll::Ready(BatchResult::failed(error)),
            }
            let result = socket.try_io(Interest::WRITABLE, || {
                // SAFETY: only the initialized prefix is submitted; every
                // address/iovec/payload is valid until this syscall returns.
                let sent = unsafe { libc::sendmmsg(socket.as_raw_fd(), messages.as_mut_ptr(), packets.len() as u32, libc::MSG_DONTWAIT as _) };
                if sent < 0 { Err(io::Error::last_os_error()) } else { Ok(sent as usize) }
            });
            match result {
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => continue,
                Err(error) => return Poll::Ready(BatchResult::failed(error)),
                Ok(0) => return Poll::Ready(BatchResult::failed(io::Error::new(io::ErrorKind::WriteZero, "zero UDP batch send"))),
                Ok(sent) => {
                    for i in 0..sent {
                        if messages[i].msg_len as usize != packets[i].header.len() + packets[i].payload.len() {
                            return Poll::Ready(BatchResult { sent: i, fatal: false, error: Some(io::Error::new(io::ErrorKind::WriteZero, "partial UDP datagram send")) });
                        }
                    }
                    return Poll::Ready(BatchResult::sent(sent));
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let packet = &packets[0];
        match ready!(poll_send_to_vectored(socket, cx, packet.header, packet.payload, map_destination(packet.destination, local_is_ipv6))) {
            Ok(()) => Poll::Ready(BatchResult::sent(1)),
            Err(error) => Poll::Ready(BatchResult::failed(error)),
        }
    }
}

fn map_destination(destination: SocketAddr, ipv6: bool) -> SocketAddr {
    if ipv6 && let SocketAddr::V4(address) = destination {
        SocketAddrV6::new(address.ip().to_ipv6_mapped(), address.port(), 0, 0).into()
    } else { destination }
}
