//! Packet boundaries and payload ownership stay intact across batched syscalls.
use std::{net::{SocketAddr, SocketAddrV6}, task::{Context, Poll}};
use futures::ready;
use tokio::net::UdpSocket;
#[cfg(any(target_os = "linux", target_os = "android"))]
use tokio::io::Interest;
use crate::proxy::datagram::batch::{BatchResult, MAX_DIRECT_BATCH_PACKETS};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{io, mem::zeroed, os::fd::AsRawFd};
#[cfg(any(target_os = "linux", target_os = "android"))]
use socket2::SockAddr;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use super::poll_send_to_vectored;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod send;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use send::SendWorkspace;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use send::poll_send as poll_send_with;
#[cfg(all(target_os = "linux", any(feature = "tproxy", feature = "ebpf")))]
pub(crate) use send::try_send_replies;

#[derive(Clone, Copy)]
pub(crate) struct DatagramSlice<'a> {
    pub header: &'a [u8],
    pub payload: &'a [u8],
    pub destination: SocketAddr,
}

pub(crate) fn poll_send_batch(
    socket: &UdpSocket, local_is_ipv6: bool, cx: &mut Context<'_>, packets: &[DatagramSlice<'_>],
) -> Poll<BatchResult> {
    assert!(!packets.is_empty() && packets.len() <= MAX_DIRECT_BATCH_PACKETS);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        poll_send_with(socket, local_is_ipv6, cx, packets, &mut SendWorkspace::default())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let packet = &packets[0];
        match ready!(poll_send_to_vectored(socket, cx, packet.header, packet.payload, map_destination(packet.destination, local_is_ipv6))) {
            Ok(()) => Poll::Ready(BatchResult::sent(1)),
            Err(error) => Poll::Ready(BatchResult::failed(error)),
        }
    }
}

pub(crate) fn map_destination(destination: SocketAddr, ipv6: bool) -> SocketAddr {
    if ipv6 && let SocketAddr::V4(address) = destination {
        SocketAddrV6::new(address.ip().to_ipv6_mapped(), address.port(), 0, 0).into()
    } else { destination }
}

#[cfg(test)]
#[path = "udp_batch_tests.rs"]
mod socket_tests;
