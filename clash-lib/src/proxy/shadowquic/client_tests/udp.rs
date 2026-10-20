use super::*;

#[tokio::test]
async fn udp_datagrams_share_connection_and_preserve_reply_addresses() {
    timeout(DEADLINE, async {
        let server = server(true);
        let (_endpoint, client, peer) = connect(&server).await;
        let client = ClientConnection::new(client);
        let mut ids = Vec::new();
        for target in [
            SocksAddr::from((Ipv4Addr::LOCALHOST, 53)),
            SocksAddr::Domain("example.test".into(), 443),
            SocksAddr::Ip("[::1]:5353".parse().unwrap()),
        ] {
            let (sender, mut receiver) = client.associate(
                "0.0.0.0:0".parse().unwrap(), false,
            ).await.unwrap();
            sender.send(packet(Bytes::from_static(b"outgoing"), target.clone())).await.unwrap();
            let (mut control, mut recv) = peer.accept_bi().await.unwrap();
            assert_eq!(recv.read_u8().await.unwrap(), 0x03);
            assert_eq!(SocksAddr::read_from(&mut recv).await.unwrap(), "0.0.0.0:0".parse().unwrap());
            assert_eq!(SocksAddr::read_from(&mut recv).await.unwrap(), target);
            let id = recv.read_u16().await.unwrap();
            assert!(!ids.contains(&id));
            ids.push(id);
            let data = peer.read_datagram().await.unwrap();
            assert_eq!(&data[..2], &id.to_be_bytes());
            assert_eq!(&data[2..], b"outgoing");
            // Inbound and outbound IDs are independent; replies may precede registration.
            let reply_id = 60000u16;
            let mut reply = reply_id.to_be_bytes().to_vec();
            reply.extend_from_slice(b"incoming");
            peer.send_datagram(reply.into()).unwrap();
            control.write_all(&protocol::encode_addr(&target).unwrap()).await.unwrap();
            control.write_u16(reply_id).await.unwrap();
            assert_eq!(receiver.recv().await.unwrap(), (Bytes::from_static(b"incoming"), target));
            // Closing the control stream must terminate the association.
            control.finish().unwrap();
            assert!(receiver.recv().await.is_none());
            assert!(sender.send(packet(Bytes::new(), "0.0.0.0:0".parse().unwrap())).await.is_err());
        }
    }).await.unwrap();
}

#[tokio::test]
async fn udp_stream_reuses_context_and_supports_empty_packets() {
    timeout(DEADLINE, async {
        let server = server(true);
        let (_endpoint, client, peer) = connect(&server).await;
        let client = ClientConnection::new(client);
        let target = SocksAddr::Domain("example.test".into(), 53);
        let (sender, mut receiver) = client.associate(
            "[::]:0".parse().unwrap(), true,
        ).await.unwrap();
        sender.send(packet(Bytes::from_static(b"one"), target.clone())).await.unwrap();
        sender.send(packet(Bytes::new(), target.clone())).await.unwrap();
        let (mut control, mut recv) = peer.accept_bi().await.unwrap();
        assert_eq!(recv.read_u8().await.unwrap(), 0x04);
        assert_eq!(SocksAddr::read_from(&mut recv).await.unwrap(), "[::]:0".parse().unwrap());
        assert_eq!(SocksAddr::read_from(&mut recv).await.unwrap(), target);
        let id = recv.read_u16().await.unwrap();
        let mut stream = peer.accept_uni().await.unwrap();
        assert_eq!(stream.read_u16().await.unwrap(), id);
        assert_eq!(stream.read_u16().await.unwrap(), 3);
        let mut data = [0; 3];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"one");
        assert_eq!(stream.read_u16().await.unwrap(), 0);
        let mut reply = peer.open_uni().await.unwrap();
        reply.write_u16(42).await.unwrap();
        reply.write_u16(3).await.unwrap();
        reply.write_all(b"two").await.unwrap();
        control.write_all(&protocol::encode_addr(&target).unwrap()).await.unwrap();
        control.write_u16(42).await.unwrap();
        assert_eq!(receiver.recv().await.unwrap(), (Bytes::from_static(b"two"), target));
        drop(receiver);
        sender.closed().await;
        assert!(recv.read_u8().await.is_err());
    }).await.unwrap();
}

#[tokio::test]
async fn unregistered_uni_stream_does_not_block_datagrams_or_other_streams() {
    timeout(DEADLINE, async {
        let server = server(true);
        let (_endpoint, conn, peer) = connect(&server).await;
        let client = ClientConnection::new(conn);
        let (_sender, mut receiver) = client.associate(
            "0.0.0.0:0".parse().unwrap(), true,
        ).await.unwrap();
        let (mut control, mut recv) = peer.accept_bi().await.unwrap();
        assert_eq!(recv.read_u8().await.unwrap(), 0x04);
        let _ = SocksAddr::read_from(&mut recv).await.unwrap();
        let addr: SocksAddr = "127.0.0.1:53".parse().unwrap();
        control.write_all(&protocol::encode_addr(&addr).unwrap()).await.unwrap();
        control.write_u16(1).await.unwrap();
        // These streams cannot be dispatched until the later registrations.
        let mut delayed = Vec::new();
        for id in 100..108 {
            let mut stream = peer.open_uni().await.unwrap();
            stream.write_u16(id).await.unwrap();
            delayed.push((id, stream));
        }
        // Datagram dispatch must continue while uni streams await registration.
        peer.send_datagram(Bytes::from_static(b"\x00\x01datagram")).unwrap();
        assert_eq!(receiver.recv().await.unwrap().0, b"datagram"[..]);
        let mut ready = peer.open_uni().await.unwrap();
        ready.write_all(b"\x00\x01\x00\x05ready").await.unwrap();
        assert_eq!(receiver.recv().await.unwrap().0, b"ready"[..]);
        // Waiting streams must survive concurrent datagram reception.
        for (id, mut stream) in delayed {
            control.write_all(&protocol::encode_addr(&addr).unwrap()).await.unwrap();
            control.write_u16(id).await.unwrap();
            stream.write_all(b"\x00\x04late").await.unwrap();
            assert_eq!(receiver.recv().await.unwrap().0, b"late"[..]);
        }
    }).await.unwrap();
}

#[tokio::test]
async fn closing_one_udp_association_preserves_another() {
    timeout(DEADLINE, async {
        let server = server(true);
        let (_endpoint, conn, peer) = connect(&server).await;
        let client = ClientConnection::new(conn);
        let mut sessions = Vec::new();
        let addr: SocksAddr = "127.0.0.1:53".parse().unwrap();
        let mut last_id = None;
        for reply_id in [500u16, 501] {
            let (sender, receiver) = client.associate(
                "0.0.0.0:0".parse().unwrap(), false,
            ).await.unwrap();
            sender.send(packet(Bytes::new(), addr.clone())).await.unwrap();
            let (mut control, mut recv) = peer.accept_bi().await.unwrap();
            assert_eq!(recv.read_u8().await.unwrap(), 0x03);
            let _ = SocksAddr::read_from(&mut recv).await.unwrap();
            let _ = SocksAddr::read_from(&mut recv).await.unwrap();
            let id = recv.read_u16().await.unwrap();
            assert_ne!(last_id, Some(id));
            last_id = Some(id);
            assert_eq!(peer.read_datagram().await.unwrap().as_ref(), &id.to_be_bytes());
            control.write_all(&protocol::encode_addr(&addr).unwrap()).await.unwrap();
            control.write_u16(reply_id).await.unwrap();
            sessions.push((sender, receiver, control, recv));
        }
        let (sender, receiver, _control, mut recv) = sessions.remove(0);
        drop(receiver);
        sender.closed().await;
        assert!(recv.read_u8().await.is_err());
        let (sender, mut receiver, _control, _recv) = sessions.remove(0);
        sender.send(packet(Bytes::from_static(b"still alive"), addr.clone())).await.unwrap();
        assert_eq!(&peer.read_datagram().await.unwrap()[2..], b"still alive");
        peer.send_datagram(Bytes::from_static(b"\x01\xf5reply")).unwrap();
        assert_eq!(receiver.recv().await.unwrap(), (Bytes::from_static(b"reply"), addr));
    }).await.unwrap();
}

fn packet(data: Bytes, dst_addr: SocksAddr) -> UdpPacket {
    UdpPacket { data, dst_addr, ..Default::default() }
}

#[tokio::test]
async fn large_udp_stream_frames_preserve_payload_in_both_directions() {
    timeout(DEADLINE, async {
        let server = server(true);
        let (_endpoint, conn, peer) = connect(&server).await;
        let client = ClientConnection::new(conn);
        let target: SocksAddr = "127.0.0.1:53".parse().unwrap();
        let (sender, mut receiver) = client.associate(
            "0.0.0.0:0".parse().unwrap(), true,
        ).await.unwrap();
        let data = Bytes::from(vec![0x5a; 60000]);
        sender.send(packet(data.clone(), target.clone())).await.unwrap();
        let (mut control, mut recv) = peer.accept_bi().await.unwrap();
        assert_eq!(recv.read_u8().await.unwrap(), 0x04);
        let _ = SocksAddr::read_from(&mut recv).await.unwrap();
        assert_eq!(SocksAddr::read_from(&mut recv).await.unwrap(), target);
        let id = recv.read_u16().await.unwrap();
        let mut stream = peer.accept_uni().await.unwrap();
        assert_eq!(stream.read_u16().await.unwrap(), id);
        assert_eq!(stream.read_u16().await.unwrap(), 60000);
        let mut outgoing = vec![0; 60000];
        stream.read_exact(&mut outgoing).await.unwrap();
        assert_eq!(outgoing, data);
        control.write_all(&protocol::encode_addr(&target).unwrap()).await.unwrap();
        control.write_u16(42).await.unwrap();
        let mut reply = peer.open_uni().await.unwrap();
        reply.write_u16(42).await.unwrap();
        reply.write_u16(60000).await.unwrap();
        reply.write_all(&data).await.unwrap();
        assert_eq!(receiver.recv().await.unwrap(), (data, target));
    }).await.unwrap();
}
