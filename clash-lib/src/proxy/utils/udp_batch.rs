//! Packet boundaries and payload ownership stay intact across batched syscalls.
use std::{net::{SocketAddr, SocketAddrV6}, task::{Context, Poll}};
use futures::ready;
use tokio::net::UdpSocket;
#[cfg(any(target_os = "linux", target_os = "android"))]
use tokio::io::Interest;
use crate::proxy::datagram::batch::{BatchResult, MAX_DIRECT_BATCH_PACKETS};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{io, mem::zeroed, os::fd::AsRawFd};
#[cfg(all(target_os = "linux", any(feature = "tproxy", feature = "ebpf", test)))]
use std::{array::from_fn, sync::Arc};
#[cfg(all(target_os = "linux", any(feature = "tproxy", feature = "ebpf", test)))]
use super::ToCanonical;
#[cfg(all(target_os = "linux", any(feature = "tproxy", feature = "ebpf", test)))]
use crate::{proxy::datagram::UdpPacket, session::SocksAddr};
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

/// Source-bound sockets may serve multiple clients. Group only within the
/// current bounded batch; preserve each socket's packet order and never wait
/// for another packet to fill it. Borrowed payloads remain owned by the caller.
#[cfg(all(target_os = "linux", any(feature = "tproxy", feature = "ebpf", test)))]
pub(crate) async fn send_replies(
    packets: &[UdpPacket],
    workspace: &mut SendWorkspace,
    mut get_socket: impl FnMut(SocketAddr) -> io::Result<Arc<UdpSocket>>,
) {
    use futures::future::poll_fn;
    use tracing::warn;
    use crate::proxy::datagram::batch::MAX_BATCH_PACKETS;

    for chunk in packets.chunks(MAX_BATCH_PACKETS) {
        let mut done = [false; MAX_BATCH_PACKETS];
        for first in 0..chunk.len() {
            if done[first] {
                continue;
            }
            let SocksAddr::Ip(source) = &chunk[first].src_addr else {
                warn!("transparent UDP reply contains a non-IP source");
                done[first] = true;
                continue;
            };
            let source = source.to_canonical();
            let mut slices = from_fn::<_, MAX_BATCH_PACKETS, _>(|_| DatagramSlice {
                header: &[],
                payload: &[],
                destination: source,
            });
            let mut count = 0;
            for i in first..chunk.len() {
                if done[i] {
                    continue;
                }
                let SocksAddr::Ip(pkt_source) = &chunk[i].src_addr else {
                    continue;
                };
                if pkt_source.to_canonical() != source {
                    continue;
                }
                done[i] = true;
                let SocksAddr::Ip(destination) = &chunk[i].dst_addr else {
                    warn!("transparent UDP reply contains a non-IP destination");
                    continue;
                };
                slices[count] = DatagramSlice {
                    header: &[],
                    payload: &chunk[i].data,
                    destination: destination.to_canonical(),
                };
                count += 1;
            }
            if count == 0 {
                continue;
            }
            let socket = match get_socket(source) {
                Ok(socket) => socket,
                Err(error) => {
                    warn!("failed to create UDP reply socket for {source}: {error}");
                    continue;
                }
            };
            let ipv6 = source.is_ipv6();
            let mut offset = 0;
            while offset < count {
                let result = poll_fn(|cx| {
                    poll_send_with(&socket, ipv6, cx, &slices[offset..count], workspace)
                })
                .await;
                offset += result.sent;
                if let Some(error) = result.error {
                    // A datagram error rejects the next packet, not its suffix.
                    warn!("failed to send UDP reply from {source}: {error}");
                    offset += 1;
                }
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
        let mut workspace = SendWorkspace::default();
        send_replies(&packets, &mut workspace, |_| Ok(socket.clone())).await;
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
        let mut workspace = SendWorkspace::default();
        send_replies(&packets, &mut workspace, |source| {
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

    #[tokio::test]
    async fn batches_over_max_batch_packets_and_canonicalizes_mapped_sources() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let source = socket.local_addr().unwrap();
        let mapped_source = match source {
            SocketAddr::V4(v4) => SocketAddr::from((v4.ip().to_ipv6_mapped(), v4.port())),
            SocketAddr::V6(_) => unreachable!(),
        };
        let destination = client.local_addr().unwrap();
        let packets: Vec<_> = (0..20usize)
            .map(|i| {
                let src = if i % 2 == 0 { source } else { mapped_source };
                UdpPacket::new(
                    Bytes::from(vec![i as u8; 8]),
                    src.into(),
                    destination.into(),
                )
            })
            .collect();
        let mut lookups = Vec::new();
        let mut workspace = SendWorkspace::default();
        send_replies(&packets, &mut workspace, |resolved_source| {
            lookups.push(resolved_source);
            Ok(socket.clone())
        })
        .await;
        assert_eq!(lookups, vec![source, source]);
        timeout(Duration::from_secs(2), async {
            let mut buffer = [0; 16];
            for i in 0..20usize {
                let (len, actual) = client.recv_from(&mut buffer).await.unwrap();
                assert_eq!((&buffer[..len], actual), (&[i as u8; 8][..], source));
            }
        })
        .await
        .unwrap();
    }
}

#[cfg(test)]
#[path = "udp_batch_tests.rs"]
mod socket_tests;
