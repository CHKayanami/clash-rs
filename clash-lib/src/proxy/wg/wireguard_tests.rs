use super::*;
use crate::proxy::datagram::ChannelDatagram;
use tokio::sync::mpsc;

fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut packet = vec![0; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
    packet
}

#[tokio::test]
async fn handshake_drains_queued_packets_and_backpressure_releases_peer() {
    let local_key = StaticSecret::from([1; 32]);
    let remote_key = StaticSecret::from([2; 32]);
    let local_public = PublicKey::from(&local_key);
    let remote_public = PublicKey::from(&remote_key);
    let peer = Tunn::new(local_key, remote_public, None, None, 0, None);
    let mut remote = Tunn::new(remote_key, local_public, None, None, 1, None);
    let (outbound, mut sent) = mpsc::channel(4);
    let (incoming, received) = mpsc::channel(1);
    let udp = AnyOutboundDatagram::dynamic(ChannelDatagram::new(outbound, received));
    let (tx, rx) = udp.split();
    let (packet_writer, mut stack) = mpsc::channel(1);
    let (packet_sender, packet_reader) = mpsc::channel(1);
    let tunnel = Arc::new(WireguardTunnel {
        source_peer_ip: Ipv4Addr::new(10, 0, 0, 1),
        source_peer_ipv6: None,
        peer: Mutex::new(peer),
        endpoint: "127.0.0.1:51820".parse().unwrap(),
        allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
        reserved_bits: [0; 3],
        tx: AsyncMutex::new(tx),
        packet_writer,
        receivers: Mutex::new(Some(TunnelReceivers { rx, packet_reader })),
    });
    let TunnelReceivers { rx, packet_reader } = tunnel.receivers.lock().take().unwrap();
    let forwarding = tokio::spawn({
        let tunnel = tunnel.clone();
        async move { tunnel.start_forwarding(packet_reader).await }
    });
    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]);
    let mut buffer = vec![0; 65535];
    packet_sender.send(Bytes::copy_from_slice(&packet)).await.unwrap();
    let initiation = sent.recv().await.unwrap();
    let TunnResult::WriteToNetwork(response) =
        remote.decapsulate(None, &initiation.data, &mut buffer)
    else {
        panic!("missing handshake response");
    };
    incoming.send(UdpPacket {
        data: Bytes::copy_from_slice(response),
        src_addr: tunnel.endpoint.into(),
        dst_addr: SocksAddr::any_ipv4(),
        inbound_user: None,
    }).await.unwrap();
    let receiving = tokio::spawn({
        let tunnel = tunnel.clone();
        async move { tunnel.start_receiving(rx).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let output = sent.recv().await.unwrap();
            if let TunnResult::WriteToTunnelV4(decoded, _) =
                remote.decapsulate(None, &output.data, &mut buffer)
            {
                assert_eq!(decoded, packet);
                break;
            }
        }
    }).await.unwrap();

    // Reuse the forwarding scratch after the handshake for different payloads.
    for destination in [[10, 0, 0, 3], [10, 0, 0, 4]] {
        let packet = ipv4_packet([10, 0, 0, 1], destination);
        packet_sender.send(Bytes::copy_from_slice(&packet)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let output = sent.recv().await.unwrap();
                if let TunnResult::WriteToTunnelV4(decoded, _) =
                    remote.decapsulate(None, &output.data, &mut buffer)
                {
                    assert_eq!(decoded, packet);
                    break;
                }
            }
        }).await.unwrap();
    }
    drop(packet_sender);
    tokio::time::timeout(Duration::from_secs(1), forwarding).await.unwrap().unwrap();

    // Fill the virtual-device queue before delivering an authenticated packet.
    tunnel.packet_writer.send((PortProtocol::Udp, Bytes::new())).await.unwrap();
    let reply = ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1]);
    let TunnResult::WriteToNetwork(encrypted) = remote.encapsulate(&reply, &mut buffer)
    else {
        panic!("missing encrypted reply");
    };
    incoming.send(UdpPacket {
        data: Bytes::copy_from_slice(encrypted),
        src_addr: tunnel.endpoint.into(),
        dst_addr: SocksAddr::any_ipv4(),
        inbound_user: None,
    }).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while incoming.capacity() == 0 {
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    assert!(tunnel.peer.try_lock().is_some());
    assert!(!receiving.is_finished());
    assert!(stack.recv().await.unwrap().1.is_empty());
    let (_, delivered) = tokio::time::timeout(Duration::from_secs(1), stack.recv())
        .await.unwrap().unwrap();
    assert_eq!(delivered.as_ref(), reply);
    drop(incoming);
    tokio::time::timeout(Duration::from_secs(1), receiving).await.unwrap().unwrap();
}
