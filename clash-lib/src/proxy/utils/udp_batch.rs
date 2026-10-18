//! Packet boundaries and payload ownership stay intact across batched syscalls.
use std::{net::{SocketAddr, SocketAddrV6}, task::{Context, Poll}};
use futures::ready;
use tokio::net::UdpSocket;
#[cfg(target_os = "linux")]
use tokio::io::Interest;
use crate::proxy::datagram::batch::{BatchResult, MAX_BATCH_PACKETS};
#[cfg(target_os = "linux")]
use std::{io, mem::zeroed, os::fd::AsRawFd, sync::Arc};
#[cfg(target_os = "linux")]
use crate::{proxy::datagram::UdpPacket, session::SocksAddr};
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

/// Source-bound sockets may serve multiple clients. Group only within the
/// current bounded batch; preserve each socket's packet order and never wait
/// for another packet to fill it. Borrowed payloads remain owned by the caller.
#[cfg(target_os = "linux")]
pub(crate) async fn send_replies(
    packets: &[UdpPacket],
    mut get_socket: impl FnMut(SocketAddr) -> io::Result<Arc<UdpSocket>>,
) {
    use futures::future::poll_fn;
    assert!(packets.len() <= MAX_BATCH_PACKETS);
    let mut done = [false; MAX_BATCH_PACKETS];
    for first in 0..packets.len() {
        if done[first] { continue; }
        let SocksAddr::Ip(source) = &packets[first].src_addr else {
            tracing::warn!("transparent UDP reply contains a non-IP source");
            done[first] = true;
            continue;
        };
        let source = *source;
        let mut slices = std::array::from_fn::<_, MAX_BATCH_PACKETS, _>(|_| DatagramSlice {
            header: &[], payload: &[], destination: source,
        });
        let mut count = 0;
        for i in first..packets.len() {
            if done[i] || packets[i].src_addr != SocksAddr::Ip(source) { continue; }
            done[i] = true;
            let SocksAddr::Ip(destination) = &packets[i].dst_addr else {
                tracing::warn!("transparent UDP reply contains a non-IP destination");
                continue;
            };
            slices[count] = DatagramSlice { header: &[], payload: &packets[i].data, destination: *destination };
            count += 1;
        }
        if count == 0 { continue; }
        let socket = match get_socket(source) {
            Ok(socket) => socket,
            Err(error) => { tracing::warn!("failed to create UDP reply socket for {source}: {error}"); continue; }
        };
        let ipv6 = match socket.local_addr() {
            Ok(address) => address.is_ipv6(),
            Err(error) => { tracing::warn!("failed to inspect UDP reply socket: {error}"); continue; }
        };
        let mut offset = 0;
        while offset < count {
            let result = poll_fn(|cx| poll_send_batch(&socket, ipv6, cx, &slices[offset..count])).await;
            offset += result.sent;
            if let Some(error) = result.error {
                // A datagram error rejects the next packet, not its suffix.
                tracing::warn!("failed to send UDP reply from {source}: {error}");
                offset += 1;
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use bytes::Bytes;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn datagram_error_keeps_successful_prefix_and_valid_suffix() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let source = socket.local_addr().unwrap();
        let destination = client.local_addr().unwrap();
        let packets = [
            UdpPacket::new(Bytes::from_static(b"before"), source.into(), destination.into()),
            UdpPacket::new(Bytes::from(vec![0; 70000]), source.into(), destination.into()),
            UdpPacket::new(Bytes::from_static(b"after"), source.into(), destination.into()),
        ];
        send_replies(&packets, |_| Ok(socket.clone())).await;
        timeout(Duration::from_secs(2), async {
            let mut buffer = [0; 16];
            for expected in [&b"before"[..], &b"after"[..]] {
                let len = client.recv(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..len], expected);
            }
        }).await.unwrap();
    }

    #[tokio::test]
    async fn source_grouped_replies_preserve_clients_empty_packets_and_order() {
        let source_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let source_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a = source_a.local_addr().unwrap();
        let b = source_b.local_addr().unwrap();
        let client = client_a.local_addr().unwrap();
        let packets = [
            UdpPacket::new(Bytes::from_static(b"a1"), a.into(), client.into()),
            UdpPacket::new(Bytes::from_static(b"b1"), b.into(), client.into()),
            UdpPacket::new(Bytes::new(), a.into(), client_b.local_addr().unwrap().into()),
            UdpPacket::new(Bytes::from_static(b"a2"), a.into(), client.into()),
        ];
        let mut lookups = Vec::new();
        send_replies(&packets, |source| {
            lookups.push(source);
            Ok(if source == a { source_a.clone() } else { source_b.clone() })
        }).await;
        assert_eq!(lookups, vec![a, b]);
        timeout(Duration::from_secs(2), async {
            let mut buffer = [0; 16];
            for (payload, source) in [(&b"a1"[..], a), (&b"a2"[..], a), (&b"b1"[..], b)] {
                let (len, actual) = client_a.recv_from(&mut buffer).await.unwrap();
                assert_eq!((&buffer[..len], actual), (payload, source));
            }
            let (len, source) = client_b.recv_from(&mut buffer).await.unwrap();
            assert_eq!((len, source), (0, a));
        }).await.unwrap();
    }
}
