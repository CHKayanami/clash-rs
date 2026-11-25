use super::*;
use std::sync::Arc;

use crate::proxy::utils::test_utils::noop::NoopResolver;
use smoltcp::wire::{Ipv4Packet, UdpPacket as WireUdpPacket};
use tokio::sync::mpsc;

#[tokio::test]
async fn task_owned_socket_set_routes_udp_and_accepts_new_sockets() {
    let (notifier, notified) = mpsc::channel(4);
    let manager = Arc::new(DeviceManager::new(
        Ipv4Addr::new(10, 0, 0, 1), None, Arc::new(NoopResolver), Vec::new(), notified,
    ));
    let (outgoing, mut packets) = mpsc::channel(4);
    let (incoming, received) = mpsc::channel(4);
    let device = VirtualIpDevice::new(outgoing, received, notifier, 1500);
    let polling = tokio::spawn({
        let manager = manager.clone();
        async move { manager.poll_sockets(device).await }
    });

    for port in [5353, 5354] {
        let mut socket = manager.new_udp_socket().await;
        socket.send(UdpPacket {
            data: Bytes::from_static(b"hello"),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: SocketAddr::from(([10, 0, 0, 2], port)).into(),
            inbound_user: None,
        }).await.unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(1), packets.recv())
            .await.unwrap().unwrap();
        let ipv4 = Ipv4Packet::new_checked(packet.as_ref()).unwrap();
        assert_eq!(ipv4.src_addr(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ipv4.dst_addr(), Ipv4Addr::new(10, 0, 0, 2));
        let header_len = ipv4.header_len() as usize;
        let udp = WireUdpPacket::new_checked(ipv4.payload()).unwrap();
        let local_port = udp.src_port();
        assert_eq!(udp.dst_port(), port);
        assert_eq!(udp.payload(), b"hello");

        let mut reply = packet.to_vec();
        {
            let mut ipv4 = Ipv4Packet::new_unchecked(&mut reply[..]);
            ipv4.set_src_addr(Ipv4Addr::new(10, 0, 0, 2));
            ipv4.set_dst_addr(Ipv4Addr::new(10, 0, 0, 1));
            ipv4.fill_checksum();
        }
        {
            let mut udp = WireUdpPacket::new_unchecked(&mut reply[header_len..]);
            udp.set_src_port(port);
            udp.set_dst_port(local_port);
            udp.payload_mut().copy_from_slice(b"world");
        }
        incoming.send((PortProtocol::Udp, Bytes::from(reply))).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(1), socket.next())
            .await.unwrap().unwrap();
        assert_eq!(reply.data.as_ref(), b"world");
        assert_eq!(reply.src_addr, SocketAddr::from(([10, 0, 0, 2], port)).into());
    }
    assert!(manager.receivers.lock().is_none());
    polling.abort();
    let _ = polling.await;
    drop(incoming);
}

#[tokio::test]
async fn upstream_tcp_socket_completes_handshake_and_bidirectional_transfer() {
    use smoltcp::{phy::ChecksumCapabilities, wire::{IpAddress, IpProtocol, Ipv4Repr,
        TcpControl, TcpPacket, TcpRepr, TcpSeqNumber}};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (notifier, notified) = mpsc::channel(4);
    let manager = Arc::new(DeviceManager::new(
        Ipv4Addr::new(10, 0, 0, 1), None, Arc::new(NoopResolver), Vec::new(), notified,
    ));
    let (outgoing, mut packets) = mpsc::channel(8);
    let (incoming, received) = mpsc::channel(8);
    let device = VirtualIpDevice::new(outgoing, received, notifier, 1500);
    let polling = tokio::spawn({
        let manager = manager.clone();
        async move { manager.poll_sockets(device).await }
    });
    let mut stream = manager.new_tcp_socket(SocketAddr::from(([10, 0, 0, 2], 443))).await;
    let syn = tokio::time::timeout(Duration::from_secs(1), packets.recv()).await.unwrap().unwrap();
    let ip = Ipv4Packet::new_checked(&syn[..]).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.syn());
    let local_port = tcp.src_port();
    let client_sequence = tcp.seq_number() + 1;
    let reply = |control, sequence, ack, payload: &[u8]| {
        let tcp = TcpRepr {
            src_port: 443, dst_port: local_port, control, seq_number: sequence,
            ack_number: Some(ack), window_len: 65535, window_scale: None,
            max_seg_size: if control == TcpControl::Syn { Some(1460) } else { None },
            sack_permitted: false, sack_ranges: [None; 3], timestamp: None, payload,
        };
        let ip = Ipv4Repr {
            src_addr: Ipv4Addr::new(10, 0, 0, 2), dst_addr: Ipv4Addr::new(10, 0, 0, 1),
            next_header: IpProtocol::Tcp, payload_len: tcp.buffer_len(), hop_limit: 64,
        };
        let checksums = ChecksumCapabilities::default();
        let mut bytes = vec![0; 20 + tcp.buffer_len()];
        ip.emit(&mut Ipv4Packet::new_unchecked(&mut bytes[..20]), &checksums);
        tcp.emit(&mut TcpPacket::new_unchecked(&mut bytes[20..]),
            &IpAddress::from(ip.src_addr), &IpAddress::from(ip.dst_addr), &checksums);
        Bytes::from(bytes)
    };
    incoming.send((PortProtocol::Tcp,
        reply(TcpControl::Syn, TcpSeqNumber(900), client_sequence, &[]))).await.unwrap();
    stream.write_all(b"hello").await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let packet = packets.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            assert!(tcp.verify_checksum(&IpAddress::from(ip.src_addr()), &IpAddress::from(ip.dst_addr())));
            if !tcp.payload().is_empty() {
                assert_eq!(tcp.payload(), b"hello");
                assert_eq!(tcp.seq_number(), client_sequence);
                break;
            }
        }
    }).await.unwrap();
    incoming.send((PortProtocol::Tcp,
        reply(TcpControl::Psh, TcpSeqNumber(901), client_sequence + 5, b"world"))).await.unwrap();
    let mut bytes = [0; 5];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut bytes)).await.unwrap().unwrap();
    assert_eq!(&bytes, b"world");
    polling.abort();
    let _ = polling.await;
}

#[tokio::test]
async fn dropped_tcp_stream_drains_writes_and_fin_before_releasing_lease() {
    use crate::proxy::wg::Inner;
    use arc_swap::ArcSwapOption;
    use smoltcp::{
        phy::ChecksumCapabilities,
        wire::{
            IpAddress, IpProtocol, Ipv4Repr, TcpControl, TcpPacket, TcpRepr,
            TcpSeqNumber,
        },
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::AsyncWriteExt;

    let (notifier, notified) = mpsc::channel(16);
    let manager = Arc::new(
        DeviceManager::new(
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            Arc::new(NoopResolver),
            Vec::new(),
            notified,
        )
        .with_tcp_drain_timeouts(Duration::from_secs(5), Duration::from_secs(1)),
    );
    let (outgoing, mut packets) = mpsc::channel(32);
    let (incoming, received) = mpsc::channel(32);
    let device = VirtualIpDevice::new(outgoing, received, notifier, 1500);
    let polling = tokio::spawn({
        let manager = manager.clone();
        async move { manager.poll_sockets(device).await }
    });
    let wg_dummy = tokio::spawn(std::future::pending::<()>());

    let keep_idle = Arc::new(AtomicBool::new(true));
    let cache_slot = Arc::new(ArcSwapOption::empty());
    let inner = Inner::new_for_test(
        manager.clone(),
        wg_dummy,
        polling,
        keep_idle.clone(),
        Arc::downgrade(&cache_slot),
    );
    cache_slot.store(Some(inner.clone()));

    let lease = inner.try_acquire_lease().unwrap();
    keep_idle.store(false, Ordering::SeqCst);

    let mut stream = manager
        .new_tcp_socket_with_lease(SocketAddr::from(([10, 0, 0, 2], 443)), lease)
        .await;

    let syn = tokio::time::timeout(Duration::from_secs(1), packets.recv())
        .await
        .unwrap()
        .unwrap();
    let ip = Ipv4Packet::new_checked(&syn[..]).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.syn());
    let local_port = tcp.src_port();
    let client_seq = tcp.seq_number() + 1;

    let make_reply = |control, seq, ack, payload: &[u8]| {
        let tcp = TcpRepr {
            src_port: 443,
            dst_port: local_port,
            control,
            seq_number: seq,
            ack_number: Some(ack),
            window_len: 65535,
            window_scale: None,
            max_seg_size: if control == TcpControl::Syn { Some(1460) } else { None },
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload,
        };
        let ip = Ipv4Repr {
            src_addr: Ipv4Addr::new(10, 0, 0, 2),
            dst_addr: Ipv4Addr::new(10, 0, 0, 1),
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        let checksums = ChecksumCapabilities::default();
        let mut bytes = vec![0; 20 + tcp.buffer_len()];
        ip.emit(&mut Ipv4Packet::new_unchecked(&mut bytes[..20]), &checksums);
        tcp.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[20..]),
            &IpAddress::from(ip.src_addr),
            &IpAddress::from(ip.dst_addr),
            &checksums,
        );
        Bytes::from(bytes)
    };

    // Complete 3-way handshake.
    incoming
        .send((
            PortProtocol::Tcp,
            make_reply(TcpControl::Syn, TcpSeqNumber(900), client_seq, &[]),
        ))
        .await
        .unwrap();

    // Write payload, call shutdown, and immediately drop the stream while
    // keep_idle == false: the tunnel lease must remain held until smoltcp
    // transmits both the payload and FIN and completes TCP close.
    let payload = b"tail-payload-must-survive-drop";
    stream.write_all(payload).await.unwrap();
    stream.shutdown().await.unwrap();
    drop(stream);

    assert!(
        !inner.is_closing(),
        "tunnel must not close before accepted TCP writes and FIN drain"
    );

    let mut received_payload = Vec::new();
    let mut saw_fin = false;
    tokio::time::timeout(Duration::from_secs(2), async {
        while !saw_fin {
            let packet = packets.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            if !tcp.payload().is_empty() {
                received_payload.extend_from_slice(tcp.payload());
            }
            if tcp.fin() {
                saw_fin = true;
            }
        }
    })
    .await
    .expect("must transmit accepted payload and graceful TCP FIN");
    assert_eq!(received_payload, payload);
    assert!(
        !inner.is_closing(),
        "tunnel must stay alive until peer ACKs our payload and FIN"
    );

    // Peer ACKs our payload + FIN and sends its own FIN -> client enters
    // TimeWait and immediately releases the lease.
    let fin_ack = client_seq + payload.len() + 1;
    incoming
        .send((
            PortProtocol::Tcp,
            make_reply(TcpControl::Fin, TcpSeqNumber(901), fin_ack, &[]),
        ))
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(2), async {
        while !inner.is_closing() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("tunnel lease must release promptly after peer ACKs payload and FIN");
    assert!(cache_slot.load().is_none());
    drop(inner);
    drop(incoming);
}

#[tokio::test]
async fn dropped_tcp_stream_with_silent_peer_releases_lease_on_drain_timeout() {
    use crate::proxy::wg::Inner;
    use arc_swap::ArcSwapOption;
    use smoltcp::{
        phy::ChecksumCapabilities,
        wire::{
            IpAddress, IpProtocol, Ipv4Repr, TcpControl, TcpPacket, TcpRepr,
            TcpSeqNumber,
        },
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::AsyncWriteExt;

    let (notifier, notified) = mpsc::channel(16);
    let manager = Arc::new(
        DeviceManager::new(
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            Arc::new(NoopResolver),
            Vec::new(),
            notified,
        )
        .with_tcp_drain_timeouts(
            Duration::from_millis(200),
            Duration::from_millis(100),
        ),
    );
    let (outgoing, mut packets) = mpsc::channel(32);
    let (incoming, received) = mpsc::channel(32);
    let device = VirtualIpDevice::new(outgoing, received, notifier, 1500);
    let polling = tokio::spawn({
        let manager = manager.clone();
        async move { manager.poll_sockets(device).await }
    });
    let wg_dummy = tokio::spawn(std::future::pending::<()>());

    let keep_idle = Arc::new(AtomicBool::new(true));
    let cache_slot = Arc::new(ArcSwapOption::empty());
    let inner = Inner::new_for_test(
        manager.clone(),
        wg_dummy,
        polling,
        keep_idle.clone(),
        Arc::downgrade(&cache_slot),
    );
    cache_slot.store(Some(inner.clone()));

    let lease = inner.try_acquire_lease().unwrap();
    keep_idle.store(false, Ordering::SeqCst);

    let mut stream = manager
        .new_tcp_socket_with_lease(SocketAddr::from(([10, 0, 0, 2], 443)), lease)
        .await;

    let syn = tokio::time::timeout(Duration::from_secs(1), packets.recv())
        .await
        .unwrap()
        .unwrap();
    let ip = Ipv4Packet::new_checked(&syn[..]).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    let local_port = tcp.src_port();
    let client_seq = tcp.seq_number() + 1;

    let tcp_repr = TcpRepr {
        src_port: 443,
        dst_port: local_port,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(900),
        ack_number: Some(client_seq),
        window_len: 65535,
        window_scale: None,
        max_seg_size: Some(1460),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    let ip_repr = Ipv4Repr {
        src_addr: Ipv4Addr::new(10, 0, 0, 2),
        dst_addr: Ipv4Addr::new(10, 0, 0, 1),
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.buffer_len(),
        hop_limit: 64,
    };
    let checksums = ChecksumCapabilities::default();
    let mut syn_ack = vec![0; 20 + tcp_repr.buffer_len()];
    ip_repr.emit(&mut Ipv4Packet::new_unchecked(&mut syn_ack[..20]), &checksums);
    tcp_repr.emit(
        &mut TcpPacket::new_unchecked(&mut syn_ack[20..]),
        &IpAddress::from(ip_repr.src_addr),
        &IpAddress::from(ip_repr.dst_addr),
        &checksums,
    );
    incoming
        .send((PortProtocol::Tcp, Bytes::from(syn_ack)))
        .await
        .unwrap();

    stream.write_all(b"silent-peer-payload").await.unwrap();
    drop(stream);

    // Peer never ACKs anything; bounded drain timeout must still release lease.
    tokio::time::timeout(Duration::from_secs(2), async {
        while !inner.is_closing() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("bounded drain timeout must reclaim tunnel even if peer is silent");
    assert!(cache_slot.load().is_none());
    drop(inner);
    drop(incoming);
}

#[tokio::test]
async fn dropped_tcp_stream_during_syn_sent_waits_for_handshake_and_drains_writes() {
    use crate::proxy::wg::Inner;
    use arc_swap::ArcSwapOption;
    use smoltcp::{
        phy::ChecksumCapabilities,
        wire::{
            IpAddress, IpProtocol, Ipv4Repr, TcpControl, TcpPacket, TcpRepr,
            TcpSeqNumber,
        },
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::AsyncWriteExt;

    let (notifier, notified) = mpsc::channel(16);
    let manager = Arc::new(
        DeviceManager::new(
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            Arc::new(NoopResolver),
            Vec::new(),
            notified,
        )
        .with_tcp_drain_timeouts(Duration::from_secs(5), Duration::from_secs(1)),
    );
    let (outgoing, mut packets) = mpsc::channel(32);
    let (incoming, received) = mpsc::channel(32);
    let device = VirtualIpDevice::new(outgoing, received, notifier, 1500);
    let polling = tokio::spawn({
        let manager = manager.clone();
        async move { manager.poll_sockets(device).await }
    });
    let wg_dummy = tokio::spawn(std::future::pending::<()>());

    let keep_idle = Arc::new(AtomicBool::new(true));
    let cache_slot = Arc::new(ArcSwapOption::empty());
    let inner = Inner::new_for_test(
        manager.clone(),
        wg_dummy,
        polling,
        keep_idle.clone(),
        Arc::downgrade(&cache_slot),
    );
    cache_slot.store(Some(inner.clone()));

    let lease = inner.try_acquire_lease().unwrap();
    keep_idle.store(false, Ordering::SeqCst);

    let mut stream = manager
        .new_tcp_socket_with_lease(SocketAddr::from(([10, 0, 0, 2], 443)), lease)
        .await;

    // Wait for initial SYN (peer has NOT replied SYN-ACK yet -> socket is in SynSent).
    let syn = tokio::time::timeout(Duration::from_secs(1), packets.recv())
        .await
        .unwrap()
        .unwrap();
    let ip = Ipv4Packet::new_checked(&syn[..]).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.syn());
    let local_port = tcp.src_port();
    let client_seq = tcp.seq_number() + 1;

    // Write payload and immediately drop stream BEFORE SYN-ACK arrives.
    let payload = b"written-during-syn-sent";
    stream.write_all(payload).await.unwrap();
    stream.shutdown().await.unwrap();
    drop(stream);

    // Give the forwarding and poll tasks time to observe channel closure;
    // the socket must NOT abort because accepted writes are still pending.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !inner.is_closing(),
        "SynSent socket with accepted writes must not abort before handshake completes"
    );

    let make_reply = |control, seq, ack, data: &[u8]| {
        let tcp = TcpRepr {
            src_port: 443,
            dst_port: local_port,
            control,
            seq_number: seq,
            ack_number: Some(ack),
            window_len: 65535,
            window_scale: None,
            max_seg_size: if control == TcpControl::Syn { Some(1460) } else { None },
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: data,
        };
        let ip = Ipv4Repr {
            src_addr: Ipv4Addr::new(10, 0, 0, 2),
            dst_addr: Ipv4Addr::new(10, 0, 0, 1),
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        let checksums = ChecksumCapabilities::default();
        let mut bytes = vec![0; 20 + tcp.buffer_len()];
        ip.emit(&mut Ipv4Packet::new_unchecked(&mut bytes[..20]), &checksums);
        tcp.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[20..]),
            &IpAddress::from(ip.src_addr),
            &IpAddress::from(ip.dst_addr),
            &checksums,
        );
        Bytes::from(bytes)
    };

    // Now peer replies with SYN-ACK: handshake completes and buffered payload + FIN must flush.
    incoming
        .send((
            PortProtocol::Tcp,
            make_reply(TcpControl::Syn, TcpSeqNumber(900), client_seq, &[]),
        ))
        .await
        .unwrap();

    let mut received_payload = Vec::new();
    let mut saw_fin = false;
    tokio::time::timeout(Duration::from_secs(2), async {
        while !saw_fin {
            let packet = packets.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            if !tcp.payload().is_empty() {
                received_payload.extend_from_slice(tcp.payload());
            }
            if tcp.fin() {
                saw_fin = true;
            }
        }
    })
    .await
    .expect("accepted writes during SynSent must be transmitted once handshake completes");
    assert_eq!(received_payload, payload);

    // Peer ACKs payload + FIN and sends its own FIN -> lease releases promptly.
    let fin_ack = client_seq + payload.len() + 1;
    incoming
        .send((
            PortProtocol::Tcp,
            make_reply(TcpControl::Fin, TcpSeqNumber(901), fin_ack, &[]),
        ))
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(2), async {
        while !inner.is_closing() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("tunnel lease must release once peer acknowledges SynSent writes and FIN");
    assert!(cache_slot.load().is_none());
    drop(inner);
    drop(incoming);
}

#[tokio::test]
async fn dropped_unwritten_tcp_stream_during_syn_sent_aborts_after_eof() {
    use crate::proxy::wg::Inner;
    use arc_swap::ArcSwapOption;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (notifier, notified) = mpsc::channel(16);
    let manager = Arc::new(
        DeviceManager::new(
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            Arc::new(NoopResolver),
            Vec::new(),
            notified,
        )
        .with_tcp_drain_timeouts(Duration::from_secs(10), Duration::from_secs(5)),
    );
    let (outgoing, mut packets) = mpsc::channel(32);
    let (incoming, received) = mpsc::channel(32);
    let device = VirtualIpDevice::new(outgoing, received, notifier, 1500);
    let polling = tokio::spawn({
        let manager = manager.clone();
        async move { manager.poll_sockets(device).await }
    });
    let wg_dummy = tokio::spawn(std::future::pending::<()>());

    let keep_idle = Arc::new(AtomicBool::new(true));
    let cache_slot = Arc::new(ArcSwapOption::empty());
    let inner = Inner::new_for_test(
        manager.clone(),
        wg_dummy,
        polling,
        keep_idle.clone(),
        Arc::downgrade(&cache_slot),
    );
    cache_slot.store(Some(inner.clone()));

    let lease = inner.try_acquire_lease().unwrap();
    keep_idle.store(false, Ordering::SeqCst);

    let stream = manager
        .new_tcp_socket_with_lease(SocketAddr::from(([10, 0, 0, 2], 443)), lease)
        .await;
    let _syn = tokio::time::timeout(Duration::from_secs(1), packets.recv())
        .await
        .unwrap()
        .unwrap();

    // Drop without writing any data: once ordered EOF reaches the device,
    // SynSent aborts promptly without waiting for the 10s drain timeout.
    drop(stream);

    tokio::time::timeout(Duration::from_secs(1), async {
        while !inner.is_closing() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("unwritten SynSent stream must abort promptly after ordered EOF");
    assert!(cache_slot.load().is_none());
    drop(inner);
    drop(incoming);
}
