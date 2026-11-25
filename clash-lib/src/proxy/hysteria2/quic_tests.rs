use std::{
    collections::HashMap,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicUsize},
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt, future::poll_fn};
use parking_lot::Mutex;
use quinn::{Connection, Endpoint};
use tokio::time::timeout;

use crate::proxy::datagram::{UdpPacket, batch::{DatagramBatch, PacketBatch, MAX_BATCH_PACKETS}};
use crate::{
    app::dns::transport::quic_test_support,
    proxy::hysteria2::{
        HysteriaConnection,
        codec::{Defragger, HysUdpPacket},
        datagram::HysteriaDatagramOutbound,
    },
    session::SocksAddr,
};

async fn pair() -> (Endpoint, Endpoint, Connection, Connection) {
    let (server, config) = quic_test_support::server(b"udp-batch-test");
    let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(config);
    let connecting = client.connect(server.local_addr().unwrap(), "localhost").unwrap();
    let (conn, peer) = timeout(Duration::from_secs(5), async {
        tokio::join!(connecting, async { server.accept().await.unwrap().await.unwrap() })
    }).await.unwrap();
    (client, server, conn.unwrap(), peer)
}

fn batch() -> PacketBatch {
    let mut batch = PacketBatch::default();
    for i in 0..MAX_BATCH_PACKETS {
        batch.push(UdpPacket {
            // Include an empty datagram and a fragmented datagram.
            data: Bytes::from(vec![i as u8; if i == 15 { 4096 } else { i * 8 }]),
            dst_addr: SocksAddr::Domain("batch.test".into(), 1000 + i as u16),
            ..UdpPacket::default()
        }).unwrap();
    }
    batch
}

#[tokio::test]
async fn hysteria_native_batch_roundtrip_and_close() {
    let (_client, _server, conn, peer) = pair().await;
    let conn = HysteriaConnection::new_with_task_loop(Arc::new(conn), Some(1200));
    let mut udp = HysteriaDatagramOutbound::new(7, conn.clone(), SocksAddr::any_ipv4());
    let mut batch = batch();
    // Direct submission completes without polling a background sender.
    let result = poll_fn(|cx| udp.poll_send_batch(cx, &mut batch)).await;
    assert_eq!(result.sent, MAX_BATCH_PACKETS);
    assert!(result.error.is_none());
    let mut defragger = Defragger::default();
    let mut received = HashMap::new();
    timeout(Duration::from_secs(5), async {
        while received.len() < MAX_BATCH_PACKETS {
            let wire = peer.read_datagram().await.unwrap();
            peer.send_datagram(wire.clone()).unwrap();
            let packet = HysUdpPacket::decode(&mut BytesMut::from(wire.as_ref())).unwrap();
            assert_eq!(packet.session_id, 7);
            if let Some(packet) = defragger.feed(packet) {
                received.insert(packet.pkt_id, packet);
            }
        }
        for (i, expected) in batch.packets().enumerate() {
            let actual = &received[&(i as u16)];
            assert_eq!(actual.data, expected.data);
            assert_eq!(actual.addr, expected.dst_addr);
        }
        let mut replies = HashMap::new();
        for _ in 0..MAX_BATCH_PACKETS {
            let reply = udp.next().await.unwrap();
            replies.insert(reply.src_addr, reply.data);
        }
        for expected in batch.packets() {
            assert_eq!(replies[&expected.dst_addr], expected.data);
        }
    }).await.unwrap();
    udp.close().await.unwrap();
    assert!(!conn.udp_sessions.lock().contains_key(&7));
    let result = poll_fn(|cx| udp.poll_send_batch(cx, &mut batch)).await;
    assert_eq!(result.sent, 0);
    assert!(result.fatal && result.error.is_some());
}

#[tokio::test]
async fn hysteria_native_batch_validation_preserves_prefix_and_suffix() {
    let (_client, _server, raw, peer) = pair().await;
    let conn = Arc::new(HysteriaConnection {
        conn: Arc::new(raw),
        _preface: None,
        udp_sessions: Arc::new(Mutex::new(HashMap::new())),
        active_streams: AtomicUsize::new(0),
        keep_idle: Arc::new(AtomicBool::new(true)),
        evicted: AtomicBool::new(false),
        cache_slot: Weak::new(),
        udp_mtu: Some(40),
    });
    let mut udp = HysteriaDatagramOutbound::new(10, conn.clone(), SocksAddr::any_ipv4());
    let mut batch = PacketBatch::default();
    let packet = UdpPacket {
        dst_addr: SocksAddr::Domain("batch.test".into(), 1000),
        ..UdpPacket::default()
    };
    batch.push(packet.clone()).unwrap();
    batch.push(UdpPacket {
        // Its header alone exceeds the configured fragment limit.
        dst_addr: SocksAddr::Domain("x".repeat(64).into(), 1000),
        ..packet.clone()
    }).unwrap();
    batch.push(packet.clone()).unwrap();
    let result = poll_fn(|cx| udp.poll_send_batch(cx, &mut batch)).await;
    assert_eq!(result.sent, 1);
    assert!(!result.fatal && result.error.is_some());
    assert_eq!(batch.len(), 3);
    assert!(conn.udp_sessions.lock().contains_key(&10));
    let wire = timeout(Duration::from_secs(5), peer.read_datagram()).await.unwrap().unwrap();
    let sent = HysUdpPacket::decode(&mut BytesMut::from(wire.as_ref())).unwrap();
    assert_eq!(sent.addr, packet.dst_addr);
    assert!(sent.data.is_empty());
    batch.complete(); // Successful prefix.
    batch.complete(); // Rejected packet.
    let result = poll_fn(|cx| udp.poll_send_batch(cx, &mut batch)).await;
    assert_eq!(result.sent, 1);
    assert!(!result.fatal && result.error.is_none());
    let wire = timeout(Duration::from_secs(5), peer.read_datagram()).await.unwrap().unwrap();
    let sent = HysUdpPacket::decode(&mut BytesMut::from(wire.as_ref())).unwrap();
    assert_eq!(sent.addr, packet.dst_addr);
}

#[tokio::test]
async fn hysteria_native_send_failure_removes_session() {
    let (_client, _server, raw, _peer) = pair().await;
    let conn = Arc::new(HysteriaConnection {
        conn: Arc::new(raw),
        _preface: None,
        udp_sessions: Arc::new(Mutex::new(HashMap::new())),
        active_streams: AtomicUsize::new(0),
        keep_idle: Arc::new(AtomicBool::new(true)),
        evicted: AtomicBool::new(false),
        cache_slot: Weak::new(),
        udp_mtu: None,
    });
    let mut udp = HysteriaDatagramOutbound::new(9, conn.clone(), SocksAddr::any_ipv4());
    conn.conn.close(0u32.into(), b"test closed");
    let mut batch = batch();
    let result = poll_fn(|cx| udp.poll_send_batch(cx, &mut batch)).await;
    assert_eq!(result.sent, 0);
    assert!(result.fatal && result.error.is_some());
    assert!(!conn.udp_sessions.lock().contains_key(&9));
    assert_eq!(batch.len(), MAX_BATCH_PACKETS);
}

#[cfg(feature = "tuic")]
mod tuic {
    use super::*;
    use futures::FutureExt;
    use std::io::ErrorKind;
    use std::thread;
    use crate::proxy::tuic::{
        TuicDatagramOutbound,
        proto::{decode_packet_frame, encode_dissociate, fragment::FragmentReassembler},
        types::{SocketAdderTrans, TuicConnection, UdpRelayMode},
    };

    fn connection(raw: Connection, mode: UdpRelayMode) -> Arc<TuicConnection> {
        TuicConnection::new_for_test(raw, mode, u16::MAX)
    }

    #[tokio::test]
    async fn native_batch_fragments_wrap_and_dissociate() {
        let (_client, _server, raw, peer) = pair().await;
        let conn = connection(raw, UdpRelayMode::Native);
        let mut udp = TuicDatagramOutbound::new(5, conn.clone(), SocksAddr::any_ipv4());
        let mut batch = batch();
        let result = poll_fn(|cx| udp.poll_send_batch(cx, &mut batch)).await;
        assert_eq!(result.sent, MAX_BATCH_PACKETS);
        assert!(result.error.is_none());
        let mut fragments = FragmentReassembler::default();
        let mut received = HashMap::new();
        timeout(Duration::from_secs(5), async {
            while received.len() < MAX_BATCH_PACKETS {
                let wire = peer.read_datagram().await.unwrap();
                let packet = decode_packet_frame(wire.clone()).unwrap();
                assert_eq!(packet.assoc_id, 5);
                let id = packet.pkt_id;
                if let Some(complete) = fragments.accept(packet) {
                    received.insert(id, complete);
                }
                conn.handle_datagram(wire).await;
            }
            for (i, expected) in batch.packets().enumerate() {
                let (addr, data) = &received[&u16::MAX.wrapping_add(i as u16)];
                assert_eq!(*data, expected.data);
                assert_eq!(*addr, expected.dst_addr.clone().into_tuic());
            }
            let mut replies = HashMap::new();
            for _ in 0..MAX_BATCH_PACKETS {
                let reply = udp.next().await.unwrap();
                replies.insert(reply.src_addr, reply.data);
            }
            for expected in batch.packets() {
                assert_eq!(replies[&expected.dst_addr], expected.data);
            }
            udp.close().await.unwrap();
            assert!(!conn.udp_sessions.read().contains_key(&5));
            let mut stream = peer.accept_uni().await.unwrap();
            assert_eq!(stream.read_to_end(32).await.unwrap(), encode_dissociate(5));
        }).await.unwrap();
        let result = poll_fn(|cx| udp.poll_send_batch(cx, &mut batch)).await;
        assert_eq!(result.sent, 0);
        assert!(result.fatal && result.error.is_some());
    }

    #[tokio::test]
    async fn native_validation_keeps_session_usable() {
        let (_client, _server, raw, peer) = pair().await;
        let conn = connection(raw, UdpRelayMode::Native);
        let mut udp = TuicDatagramOutbound::new(12, conn.clone(), SocksAddr::any_ipv4());
        let mut invalid = PacketBatch::default();
        invalid.push(UdpPacket {
            data: Bytes::from(vec![0; 65536]),
            dst_addr: "127.0.0.1:1000".parse().unwrap(),
            ..UdpPacket::default()
        }).unwrap();
        let result = poll_fn(|cx| udp.poll_send_batch(cx, &mut invalid)).await;
        assert_eq!(result.sent, 0);
        assert!(!result.fatal);
        assert_eq!(result.error.unwrap().kind(), ErrorKind::InvalidInput);
        assert!(conn.udp_sessions.read().contains_key(&12));
        let mut valid = batch();
        let result = poll_fn(|cx| udp.poll_send_batch(cx, &mut valid)).await;
        assert_eq!(result.sent, MAX_BATCH_PACKETS);
        assert!(result.error.is_none());
        timeout(Duration::from_secs(5), peer.read_datagram()).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn native_drop_outside_runtime_cleans_session() {
        let (_client, _server, raw, peer) = pair().await;
        let conn = connection(raw, UdpRelayMode::Native);
        let udp = TuicDatagramOutbound::new(8, conn.clone(), SocksAddr::any_ipv4());
        // Destructors may run on a thread that has not entered the runtime.
        thread::spawn(move || drop(udp)).join().unwrap();
        assert!(!conn.udp_sessions.read().contains_key(&8));
        timeout(Duration::from_secs(5), async {
            let mut stream = peer.accept_uni().await.unwrap();
            assert_eq!(stream.read_to_end(32).await.unwrap(), encode_dissociate(8));
        }).await.unwrap();
    }

    #[tokio::test]
    async fn stream_close_removes_session_before_blocked_dissociate() {
        let (_client, _server, raw, _peer) = pair().await;
        let conn = connection(raw, UdpRelayMode::Quic);
        let mut udp = TuicDatagramOutbound::new(11, conn.clone(), SocksAddr::any_ipv4());
        // Hold all available uni-stream credit so dissociate cannot open one.
        let mut streams = Vec::new();
        for _ in 0..256 {
            match conn.conn.open_uni().now_or_never() {
                Some(stream) => streams.push(stream.unwrap()),
                None => break,
            }
        }
        assert!(!streams.is_empty());
        assert!(conn.conn.open_uni().now_or_never().is_none());
        udp.close().await.unwrap();
        timeout(Duration::from_secs(1), async {
            while conn.udp_sessions.read().contains_key(&11) {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        // Release the background notification without waiting for stream credit.
        conn.conn.close(0u32.into(), b"test complete");
    }

    #[tokio::test]
    async fn stream_mode_preserves_one_stream_per_packet() {
        let (_client, _server, raw, peer) = pair().await;
        let conn = connection(raw, UdpRelayMode::Quic);
        let mut udp = TuicDatagramOutbound::new(6, conn.clone(), SocksAddr::any_ipv4());
        let mut batch = batch();
        timeout(Duration::from_secs(5), async {
            // The queued mode retains its packet-based completion semantics.
            for i in 0..MAX_BATCH_PACKETS {
                let expected = batch.packets().next().unwrap().clone();
                let result = poll_fn(|cx| udp.poll_send_batch(cx, &mut batch)).await;
                assert_eq!(result.sent, 1);
                assert!(result.error.is_none());
                batch.complete();
                let mut stream = peer.accept_uni().await.unwrap();
                let wire = stream.read_to_end(65536).await.unwrap();
                let packet = decode_packet_frame(Bytes::from(wire)).unwrap();
                assert_eq!(packet.assoc_id, 6);
                assert_eq!(packet.pkt_id, u16::MAX.wrapping_add(i as u16));
                assert_eq!(packet.payload, expected.data);
                assert_eq!(packet.frag_total, 1);
            }
            udp.close().await.unwrap();
            let mut stream = peer.accept_uni().await.unwrap();
            assert_eq!(stream.read_to_end(32).await.unwrap(), encode_dissociate(6));
        }).await.unwrap();
        assert!(!conn.udp_sessions.read().contains_key(&6));
    }

    #[tokio::test]
    async fn quic_udp_mode_drains_queued_packets_before_idle_close() {
        let (_client, _server, raw, peer) = pair().await;
        let conn = connection(raw, UdpRelayMode::Quic);
        let mut udp = TuicDatagramOutbound::new(15, conn.clone(), SocksAddr::any_ipv4());
        conn.set_keep_idle_for_test(false);

        let dst: SocksAddr = "127.0.0.1:5353".parse().unwrap();
        let payloads: Vec<Bytes> = (0u8..4)
            .map(|i| Bytes::from(format!("tuic-quic-udp-queued-packet-{i}")))
            .collect();
        for payload in &payloads {
            udp.send(UdpPacket {
                data: payload.clone(),
                dst_addr: dst.clone(),
                ..UdpPacket::default()
            })
            .await
            .unwrap();
        }
        // Drop immediately after queueing multiple packets; the background
        // sender task owns the lease and must drain all uni-streams and
        // dissociate before closing the idle QUIC connection.
        drop(udp);

        timeout(Duration::from_secs(5), async {
            let mut received_payloads = Vec::new();
            let mut saw_dissociate = false;
            for _ in 0..(payloads.len() + 1) {
                let mut stream = peer.accept_uni().await.unwrap();
                let wire = stream.read_to_end(65536).await.unwrap();
                if wire == encode_dissociate(15) {
                    saw_dissociate = true;
                } else {
                    let packet = decode_packet_frame(Bytes::from(wire)).unwrap();
                    assert_eq!(packet.assoc_id, 15);
                    received_payloads.push(packet.payload);
                }
            }
            assert!(saw_dissociate, "expected dissociate frame");
            received_payloads.sort();
            let mut expected = payloads.clone();
            expected.sort();
            assert_eq!(received_payloads, expected);
            conn.conn.closed().await;
        })
        .await
        .expect("all queued UDP packets and dissociate must drain before idle close");
        assert!(conn.conn.close_reason().is_some());
    }

    #[tokio::test]
    async fn quic_udp_blocked_dissociate_times_out_and_closes_idle_conn() {
        let (_client, _server, raw, _peer) = pair().await;
        let conn = connection(raw, UdpRelayMode::Quic);
        conn.set_drain_timeout_for_test(Duration::from_millis(120));
        let udp = TuicDatagramOutbound::new(16, conn.clone(), SocksAddr::any_ipv4());
        conn.set_keep_idle_for_test(false);

        // Exhaust uni-stream credit so `send_dissociate`'s `open_uni().await`
        // blocks; the cleanup timeout must still release the lease and close
        // the idle connection without manual intervention.
        let mut streams = Vec::new();
        for _ in 0..256 {
            match conn.conn.open_uni().now_or_never() {
                Some(stream) => streams.push(stream.unwrap()),
                None => break,
            }
        }
        assert!(conn.conn.open_uni().now_or_never().is_none());

        drop(udp);

        timeout(Duration::from_secs(2), conn.conn.closed())
            .await
            .expect("blocked dissociate must time out and release the last lease");
        assert!(!conn.udp_sessions.read().contains_key(&16));
        assert!(conn.conn.close_reason().is_some());
    }

    #[tokio::test]
    async fn quic_udp_blocked_send_packet_times_out_and_closes_idle_conn() {
        let (_client, _server, raw, _peer) = pair().await;
        let conn = connection(raw, UdpRelayMode::Quic);
        conn.set_drain_timeout_for_test(Duration::from_millis(120));
        let mut udp = TuicDatagramOutbound::new(17, conn.clone(), SocksAddr::any_ipv4());
        conn.set_keep_idle_for_test(false);

        // Exhaust uni-stream credit BEFORE queueing a packet so the background
        // task blocks inside `send_stream_packet().await` (`open_uni().await`).
        let mut streams = Vec::new();
        for _ in 0..256 {
            match conn.conn.open_uni().now_or_never() {
                Some(stream) => streams.push(stream.unwrap()),
                None => break,
            }
        }
        assert!(conn.conn.open_uni().now_or_never().is_none());

        udp.send(UdpPacket {
            data: Bytes::from_static(b"blocked-on-open-uni"),
            dst_addr: "127.0.0.1:5353".parse().unwrap(),
            ..UdpPacket::default()
        })
        .await
        .unwrap();
        // Give the background task a turn to pull the packet and block in send_stream_packet.
        tokio::time::sleep(Duration::from_millis(20)).await;

        drop(udp);

        timeout(Duration::from_secs(2), conn.conn.closed())
            .await
            .expect("blocked send_stream_packet must time out after UDP drop");
        assert!(!conn.udp_sessions.read().contains_key(&17));
        assert!(conn.conn.close_reason().is_some());
    }

    #[tokio::test]
    async fn udp_keep_idle_switch_during_teardown_still_drains_packets() {
        let (_client, _server, raw, peer) = pair().await;
        let conn = connection(raw, UdpRelayMode::Quic);
        let mut udp = TuicDatagramOutbound::new(18, conn.clone(), SocksAddr::any_ipv4());
        // Keep `keep_idle == true` when dropping UDP, then immediately switch
        // policy to `false`. The teardown task must still await ACKs and grace
        // before releasing the last lease.
        let payload = Bytes::from_static(b"packet-during-policy-switch");
        udp.send(UdpPacket {
            data: payload.clone(),
            dst_addr: "127.0.0.1:5353".parse().unwrap(),
            ..UdpPacket::default()
        })
        .await
        .unwrap();
        drop(udp);
        conn.set_keep_idle_for_test(false);

        // Delay peer reads to prove the grace window stays active even though
        // `keep_idle` was `true` when teardown began.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            conn.conn.close_reason().is_none(),
            "connection must not close before peer reads packet and dissociate"
        );

        timeout(Duration::from_secs(5), async {
            let mut got_packet = false;
            let mut got_dissociate = false;
            for _ in 0..2 {
                let mut stream = peer.accept_uni().await.unwrap();
                let wire = stream.read_to_end(65536).await.unwrap();
                if wire == encode_dissociate(18) {
                    got_dissociate = true;
                } else {
                    let pkt = decode_packet_frame(Bytes::from(wire)).unwrap();
                    assert_eq!(pkt.assoc_id, 18);
                    assert_eq!(pkt.payload, payload);
                    got_packet = true;
                }
            }
            assert!(got_packet && got_dissociate);
            conn.conn.closed().await;
        })
        .await
        .expect("teardown must drain even when keep_idle flips during cleanup");
    }
}
