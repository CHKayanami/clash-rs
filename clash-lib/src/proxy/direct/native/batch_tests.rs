use super::*;
use bytes::Bytes;
use futures::future::poll_fn;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn batch_send_commits_prefix_and_recovers_after_bad_packet() {
    timeout(Duration::from_secs(3), async {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut native = NativeDatagram::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()).unwrap();
        let target: SocksAddr = server.local_addr().unwrap().into();
        let mut batch = PacketBatch::default();
        batch.push(UdpPacket::new(Bytes::from_static(b"first"), SocksAddr::any_ipv4(), target.clone())).unwrap();
        // Exceed the socket's UDP payload limit while remaining within the
        // batch byte budget, then retain the following valid datagram.
        batch.push(UdpPacket::new(Bytes::from(vec![0; 65508]), SocksAddr::any_ipv4(), target.clone())).unwrap();
        batch.push(UdpPacket::new(Bytes::from_static(b"last"), SocksAddr::any_ipv4(), target)).unwrap();
        let mut sent = 0;
        let mut errors = 0;
        while !batch.is_empty() {
            let result = poll_fn(|cx| native.poll_send_batch(cx, &mut batch)).await;
            for _ in 0..result.sent { batch.complete(); sent += 1; }
            if result.error.is_some() { batch.complete(); errors += 1; }
        }
        assert_eq!((sent, errors), (2, 1));
        let mut data = [0; 32];
        let first = server.recv(&mut data).await.unwrap();
        assert_eq!(&data[..first], b"first");
        let last = server.recv(&mut data).await.unwrap();
        assert_eq!(&data[..last], b"last");
    }).await.unwrap();
}

#[tokio::test]
async fn batch_send_and_receive_preserve_empty_packets_and_multiple_peers() {
    timeout(Duration::from_secs(3), async {
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let source = socket.local_addr().unwrap();
        let mut native = NativeDatagram::new(socket).unwrap();
        let mut batch = PacketBatch::default();
        for (peer, data) in [(&first, Bytes::new()), (&second, Bytes::from_static(b"second"))] {
            batch.push(UdpPacket::new(data, SocksAddr::any_ipv4(), peer.local_addr().unwrap().into())).unwrap();
        }
        let result = poll_fn(|cx| native.poll_send_batch(cx, &mut batch)).await;
        #[cfg(target_os = "linux")]
        assert_eq!(result.sent, 2, "one syscall must send both datagrams");
        assert!(result.error.is_none());
        for _ in 0..result.sent { batch.complete(); }
        while !batch.is_empty() {
            let result = poll_fn(|cx| native.poll_send_batch(cx, &mut batch)).await;
            assert!(result.error.is_none());
            for _ in 0..result.sent { batch.complete(); }
        }
        let mut data = [0; 32];
        assert_eq!(first.recv(&mut data).await.unwrap(), 0);
        assert_eq!(second.recv(&mut data).await.unwrap(), 6);
        first.send_to(b"", source).await.unwrap();
        second.send_to(b"reply", source).await.unwrap();
        let mut received = Vec::new();
        let mut all = Vec::new();
        while all.len() < 2 {
            assert!(poll_fn(|cx| native.poll_recv_batch(cx, &mut received)).await.is_some());
            all.append(&mut received);
        }
        assert_eq!(all[0].src_addr, first.local_addr().unwrap().into());
        assert!(all[0].data.is_empty());
        assert_eq!(all[1].data.as_ref(), b"reply");
    }).await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn udp_offload_preserves_datagram_counts_empty_packets_and_peer_boundaries() {
    use futures::StreamExt;
    let mut sender = NativeDatagram::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()).unwrap();
    let mut first = NativeDatagram::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()).unwrap();
    let mut second = NativeDatagram::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()).unwrap();
    sender.enable_udp_offload(); first.enable_udp_offload(); second.enable_udp_offload();
    let first_address = first.local_addr().unwrap();
    let second_address = second.local_addr().unwrap();
    let source = sender.local_addr().unwrap();
    let mut batch = PacketBatch::default();
    for index in 0..4 {
        batch.push(UdpPacket::new(Bytes::from(vec![index as u8; 1200]), source.into(), first_address.into())).unwrap();
    }
    batch.push(UdpPacket::new(Bytes::new(), source.into(), first_address.into())).unwrap();
    batch.push(UdpPacket::new(Bytes::from_static(b"other-peer"), source.into(), second_address.into())).unwrap();
    timeout(Duration::from_secs(3), async {
        while !batch.is_empty() {
            let result = poll_fn(|cx| sender.poll_send_batch(cx, &mut batch)).await;
            assert!(result.error.is_none()); assert!(result.sent > 0);
            for _ in 0..result.sent { batch.complete(); }
        }
        let mut received = Vec::new();
        while received.len() < 5 {
            let mut groups = Vec::new();
            assert!(poll_fn(|cx| first.poll_recv_segments(cx, &mut groups)).await.is_some());
            received.extend(groups.into_iter().flat_map(DatagramSegments::into_packets));
        }
        assert_eq!(received.len(), 5);
        for (index, packet) in received.iter().enumerate() {
            assert_eq!(packet.src_addr, SocksAddr::Ip(source));
            if index == 4 { assert!(packet.data.is_empty()); }
            else { assert_eq!(&packet.data[..], &vec![index as u8; 1200]); }
        }
        let packet = second.next().await.unwrap();
        assert_eq!(&packet.data[..], b"other-peer");
        assert_eq!(packet.src_addr, SocksAddr::Ip(source));
    }).await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn shared_send_workspace_rebuilds_gso_plain_empty_and_peer_descriptors() {
    timeout(Duration::from_secs(3), async {
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut sender = NativeDatagram::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()).unwrap();
        sender.enable_udp_offload();
        let mut workspace = SendWorkspace::default();
        let payloads = [vec![1; 1200], vec![2; 1200], vec![3; 1200]];
        let slices = payloads.each_ref().map(|payload| DatagramSlice {
            header: &[], payload, destination: first.local_addr().unwrap(),
        });
        let mut offset = 0;
        while offset < slices.len() {
            let result = poll_fn(|cx| sender.poll_send_slices_with(cx, &slices[offset..], &mut workspace)).await;
            assert!(result.error.is_none()); assert!(result.sent > 0);
            offset += result.sent;
        }
        let mut data = [0; 1500];
        for payload in &payloads {
            let length = first.recv(&mut data).await.unwrap();
            assert_eq!(&data[..length], payload);
        }
        // Reuse the same descriptors on another socket and the plain-send
        // path. A stale UDP_SEGMENT control or address would corrupt delivery.
        let mut plain = NativeDatagram::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()).unwrap();
        let slices = [DatagramSlice { header: &[], payload: b"", destination: second.local_addr().unwrap() },
            DatagramSlice { header: b"head", payload: b"tail", destination: first.local_addr().unwrap() }];
        let mut offset = 0;
        while offset < slices.len() {
            let result = poll_fn(|cx| plain.poll_send_slices_with(cx, &slices[offset..], &mut workspace)).await;
            assert!(result.error.is_none()); assert!(result.sent > 0);
            offset += result.sent;
        }
        assert_eq!(second.recv(&mut data).await.unwrap(), 0);
        let length = first.recv(&mut data).await.unwrap();
        assert_eq!(&data[..length], b"headtail");
    }).await.unwrap();
}
