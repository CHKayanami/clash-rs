use super::*;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use crate::proxy::utils::new_dual_stack_udp_socket;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn native_udp_rejects_domains_and_recovers_after_send_errors() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut datagram = NativeDatagram::new(new_dual_stack_udp_socket(None,
        #[cfg(target_os = "linux")] None).unwrap()).unwrap();
    let domain = SocksAddr::try_from(("example.test".to_owned(), 80)).unwrap();
    let err = datagram.send(UdpPacket::new(Bytes::from_static(b"a"), SocksAddr::any_ipv4(), domain)).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    let target: SocksAddr = server.local_addr().unwrap().into();
    assert!(datagram.send(UdpPacket::new(Bytes::from(vec![0; 70000]), SocksAddr::any_ipv4(), target.clone())).await.is_err());
    datagram.send(UdpPacket::new(Bytes::from_static(b"valid"), SocksAddr::any_ipv4(), target)).await.unwrap();
    let mut buf = [0; 32];
    let (length, source) = timeout(Duration::from_secs(2), server.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..length], b"valid");
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    peer.send_to(b"unknown", source).await.unwrap();
    let reply = timeout(Duration::from_secs(2), datagram.next()).await.unwrap().unwrap();
    assert_eq!(reply.src_addr, SocksAddr::Ip(peer.local_addr().unwrap()));
    assert_eq!(reply.data.as_ref(), b"unknown");
}

#[tokio::test]
async fn native_udp_preserves_ipv6_peers_and_empty_packets() {
    let server = UdpSocket::bind("[::1]:0").await.unwrap();
    let socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let mut datagram = NativeDatagram::new(socket).unwrap();
    let target: SocksAddr = server.local_addr().unwrap().into();
    datagram.send(UdpPacket::new(Bytes::new(), SocksAddr::any_ipv4(), target.clone())).await.unwrap();
    let mut buf = [0; 32];
    let (length, source) = timeout(Duration::from_secs(2), server.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(length, 0);
    server.send_to(b"", source).await.unwrap();
    let reply = timeout(Duration::from_secs(2), datagram.next()).await.unwrap().unwrap();
    assert_eq!(reply.src_addr, target);
    assert!(reply.data.is_empty());
}

#[tokio::test]
async fn raw_batch_surplus_is_mapped_once_when_stream_or_segment_api_reads_it() {
    use futures::{future::poll_fn, task::noop_waker};
    let mut native = NativeDatagram::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()).unwrap();
    let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let logical = SocksAddr::Domain("cached.test".into(), 1234);
    // A raw batch's GRO surplus has not passed through a source callback.
    native.recv_queue.push_back(Received::raw(UdpPacket { src_addr: peer.into(), ..Default::default() }));
    let packet = poll_fn(|cx| native.poll_recv_with(cx, |_| logical.clone())).await.unwrap();
    assert_eq!(packet.src_addr, logical);
    // An already mapped IP must also retain its receive-time identity. Merely
    // checking is_domain would map this packet for a second time.
    native.recv_queue.push_back(Received::mapped(UdpPacket { src_addr: peer.into(), ..Default::default() }));
    native.recv_queue.push_back(Received::raw(UdpPacket { src_addr: peer.into(), ..Default::default() }));
    let wake = noop_waker();
    let mut packets = Vec::new();
    assert!(native.poll_recv_segments_with(&mut Context::from_waker(&wake), |_| logical.clone(), &mut packets).is_ready());
    assert_eq!(packets[0].packet.src_addr, SocksAddr::Ip(peer));
    assert_eq!(packets[1].packet.src_addr, logical);
}

#[tokio::test]
async fn invalid_receive_budget_survives_pending_and_resets_only_on_usable_data() {
    use futures::task::noop_waker;
    let mut native = NativeDatagram::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()).unwrap();
    for _ in 0..16 { assert!(native.observe_receive(false)); }
    let wake = noop_waker();
    let mut packets = Vec::new();
    assert!(native.poll_recv_segments(&mut Context::from_waker(&wake), &mut packets).is_pending());
    assert_eq!(native.consecutive_recv_errors, 16);
    assert!(native.observe_receive(true));
    assert_eq!(native.consecutive_recv_errors, 0);
    for _ in 0..31 { assert!(native.observe_receive(false)); }
    assert!(!native.observe_receive(false));
}
