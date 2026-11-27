use std::{
    collections::HashMap,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicUsize},
    },
    time::Duration,
};

use bytes::Bytes;
use futures::{SinkExt, StreamExt, future::poll_fn};
use parking_lot::Mutex;
use quinn::{Connection, Endpoint};
use tokio::{runtime::Handle, time::timeout};

use crate::proxy::datagram::{UdpPacket, batch::{DatagramBatch, PacketBatch, MAX_BATCH_PACKETS}};
use crate::{
    app::dns::transport::quic_test_support,
    proxy::{
        hysteria2::{
            HysteriaConnection,
            codec::{Defragger, HysUdpPacket},
            datagram::HysteriaDatagramOutbound,
        },
        utils::quic_stream::{QuicUploadGrace, UdpSessionTable},
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
            let packet = HysUdpPacket::decode(wire).unwrap();
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
        udp_sessions: Arc::new(Mutex::new(UdpSessionTable::default())),
        active_streams: AtomicUsize::new(0),
        keep_idle: Arc::new(AtomicBool::new(true)),
        evicted: AtomicBool::new(false),
        upload_grace: QuicUploadGrace::default(),
        runtime: Handle::current(),
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
    let sent = HysUdpPacket::decode(wire).unwrap();
    assert_eq!(sent.addr, packet.dst_addr);
    assert!(sent.data.is_empty());
    batch.complete(); // Successful prefix.
    batch.complete(); // Rejected packet.
    let result = poll_fn(|cx| udp.poll_send_batch(cx, &mut batch)).await;
    assert_eq!(result.sent, 1);
    assert!(!result.fatal && result.error.is_none());
    let wire = timeout(Duration::from_secs(5), peer.read_datagram()).await.unwrap().unwrap();
    let sent = HysUdpPacket::decode(wire).unwrap();
    assert_eq!(sent.addr, packet.dst_addr);
}

#[tokio::test]
async fn hysteria_native_send_failure_removes_session() {
    let (_client, _server, raw, _peer) = pair().await;
    let conn = Arc::new(HysteriaConnection {
        conn: Arc::new(raw),
        _preface: None,
        udp_sessions: Arc::new(Mutex::new(UdpSessionTable::default())),
        active_streams: AtomicUsize::new(0),
        keep_idle: Arc::new(AtomicBool::new(true)),
        evicted: AtomicBool::new(false),
        upload_grace: QuicUploadGrace::default(),
        runtime: Handle::current(),
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

#[tokio::test]
async fn hysteria_connection_close_clears_udp_sessions_and_wakes_receiver() {
    let (_client, _server, raw, peer) = pair().await;
    let conn = HysteriaConnection::new_with_task_loop(Arc::new(raw), Some(1200));
    let mut udp = HysteriaDatagramOutbound::new(21, conn.clone(), SocksAddr::any_ipv4());
    assert!(conn.udp_sessions.lock().contains_key(&21));

    // Closing the peer terminates `spawn_tasks`, which must clear `udp_sessions`
    // so an idle receiver wakes immediately with `None` instead of hanging.
    peer.close(0u32.into(), b"peer gone");
    let next = timeout(Duration::from_secs(2), udp.next())
        .await
        .expect("UDP receiver must wake promptly when QUIC connection closes");
    assert!(next.is_none());
    assert!(conn.udp_sessions.lock().is_empty());
}

#[tokio::test]
async fn hysteria_register_udp_after_connection_close_wakes_with_none() {
    let (_client, _server, raw, peer) = pair().await;
    let conn = HysteriaConnection::new_with_task_loop(Arc::new(raw), Some(1200));
    let lease = conn.try_acquire_lease().unwrap();

    // Connection closes and receive loop exits BEFORE the UDP session registers.
    peer.close(0u32.into(), b"peer gone");
    timeout(Duration::from_secs(2), async {
        while !conn.udp_sessions.lock().is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("spawn_tasks must mark udp_sessions closed after peer close");

    let mut udp = HysteriaDatagramOutbound::new_with_lease(
        22,
        conn.clone(),
        SocksAddr::any_ipv4(),
        Some(lease),
    );
    let next = timeout(Duration::from_secs(2), udp.next())
        .await
        .expect("UDP registered after connection close must return None immediately");
    assert!(next.is_none());
    assert!(conn.udp_sessions.lock().is_empty());
}

#[tokio::test]
async fn hysteria_defragger_evicts_oldest_partial_packet_after_queue_drain() {
    use futures::FutureExt;
    use crate::proxy::hysteria2::codec::Fragments;

    let (_client, _server, raw, _peer) = pair().await;
    let conn = Arc::new(HysteriaConnection {
        conn: Arc::new(raw),
        _preface: None,
        udp_sessions: Arc::new(Mutex::new(UdpSessionTable::default())),
        active_streams: AtomicUsize::new(0),
        keep_idle: Arc::new(AtomicBool::new(true)),
        evicted: AtomicBool::new(false),
        upload_grace: QuicUploadGrace::default(),
        runtime: Handle::current(),
        cache_slot: Weak::new(),
        udp_mtu: Some(1200),
    });
    let mut udp = HysteriaDatagramOutbound::new(25, conn.clone(), SocksAddr::any_ipv4());
    let addr = SocksAddr::Domain("frag.test".into(), 443);
    let partial_payload = vec![0x11u8; 1500];

    // Enqueue 64 distinct first fragments whose trailing fragments were lost
    // (e.g. during a queue overflow), then drain the receive queue so all 64
    // defrag slots are occupied by incomplete packets.
    for pkt_id in 0u16..64 {
        let mut frags =
            Fragments::new(25, pkt_id, &addr, 1200, &partial_payload).unwrap();
        assert_eq!(frags.len(), 2);
        conn.recv_packet(frags.next().unwrap());
    }
    assert!(udp.next().now_or_never().is_none());

    // Immediately deliver a fresh 2-fragment packet whose fragments all arrive:
    // the defragger must evict the oldest partial entry and reassemble at once
    // without waiting 5s for DEFRAG_MAX_AGE.
    let fresh_payload = vec![0x7au8; 1500];
    let fresh_frags: Vec<Bytes> =
        Fragments::new(25, 100, &addr, 1200, &fresh_payload)
            .unwrap()
            .collect();
    assert_eq!(fresh_frags.len(), 2);
    for frame in fresh_frags {
        conn.recv_packet(frame);
    }

    let packet = timeout(Duration::from_secs(1), udp.next())
        .await
        .expect("fresh fragmented packet must reassemble immediately after drain")
        .unwrap();
    assert_eq!(packet.data.as_ref(), fresh_payload.as_slice());
    assert_eq!(packet.src_addr, addr);
}

#[tokio::test]
async fn hysteria_recv_packet_detaches_payload_from_shared_slab() {
    use crate::proxy::hysteria2::codec::Fragments;
    use tokio::sync::mpsc;

    let (_client, _server, raw, _peer) = pair().await;
    let conn = Arc::new(HysteriaConnection {
        conn: Arc::new(raw),
        _preface: None,
        udp_sessions: Arc::new(Mutex::new(UdpSessionTable::default())),
        active_streams: AtomicUsize::new(0),
        keep_idle: Arc::new(AtomicBool::new(true)),
        evicted: AtomicBool::new(false),
        upload_grace: QuicUploadGrace::default(),
        runtime: Handle::current(),
        cache_slot: Weak::new(),
        udp_mtu: None,
    });

    let (tx, mut rx) = mpsc::channel(1);
    assert!(conn.udp_sessions.lock().insert(31, tx));

    let addr = SocksAddr::Ip("127.0.0.1:5353".parse().unwrap());
    let payload = b"gro-detached-payload-1";
    let encoded = Fragments::new(31, 1, &addr, 1200, payload.as_slice())
        .unwrap()
        .next()
        .unwrap();

    // Simulate a Quinn GRO datagram sliced out of a larger shared receive slab.
    let mut backing = Vec::with_capacity(encoded.len() + 4096);
    backing.extend_from_slice(&encoded);
    backing.resize(encoded.len() + 4096, 0xaa);
    let slab = Bytes::from(backing);
    let wire = slab.slice(..encoded.len());
    assert!(!slab.is_unique());

    conn.recv_packet(wire);
    assert!(
        slab.is_unique(),
        "queued packet must not retain a reference to the shared receive slab"
    );

    // When the session queue is full, `recv_packet` drops the second packet
    // while keeping the first queued packet and releasing the shared slab.
    let payload2 = b"gro-dropped-payload-2";
    let encoded2 = Fragments::new(31, 2, &addr, 1200, payload2.as_slice())
        .unwrap()
        .next()
        .unwrap();
    let mut backing2 = Vec::with_capacity(encoded2.len() + 4096);
    backing2.extend_from_slice(&encoded2);
    backing2.resize(encoded2.len() + 4096, 0xbb);
    let slab2 = Bytes::from(backing2);
    let wire2 = slab2.slice(..encoded2.len());
    assert!(!slab2.is_unique());

    conn.recv_packet(wire2);
    assert!(slab2.is_unique());

    let queued = rx.try_recv().unwrap();
    assert_eq!(queued.session_id, 31);
    assert_eq!(queued.pkt_id, 1);
    assert_eq!(queued.addr, addr);
    assert_eq!(queued.data.as_ref(), payload);
    assert!(rx.try_recv().is_err());
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
                conn.handle_datagram(wire);
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

    #[tokio::test]
    async fn native_handle_datagram_drops_when_full_without_blocking() {
        use crate::proxy::tuic::proto::{Address, encode_single_packet};
        use std::net::Ipv4Addr;

        let (_client, _server, raw, _peer) = pair().await;
        let conn = connection(raw, UdpRelayMode::Native);
        let mut udp =
            TuicDatagramOutbound::new(22, conn.clone(), SocksAddr::any_ipv4());

        let addr = Address::IPv4(Ipv4Addr::LOCALHOST, 5353);
        // Push more datagrams than the 256-slot session queue without reading;
        // synchronous `handle_datagram` must never block and must preserve the
        // first 256 queued packets.
        for pkt_id in 0u16..300 {
            let wire = encode_single_packet(
                22,
                pkt_id,
                &addr,
                &pkt_id.to_be_bytes(),
            )
            .unwrap();
            conn.handle_datagram(wire);
        }

        for pkt_id in 0u16..256 {
            let pkt = timeout(Duration::from_secs(2), udp.next())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(pkt.data.as_ref(), &pkt_id.to_be_bytes());
        }
        assert!(udp.next().now_or_never().is_none());
    }

    #[tokio::test]
    async fn native_gc_interval_expires_stale_fragments_while_idle_and_stops_timer() {
        use crate::proxy::tuic::proto::{
            Address, encode_single_packet, packet_fragments,
        };
        use std::net::Ipv4Addr;

        let (_client, _server, raw, _peer) = pair().await;
        let conn = TuicConnection::new_for_test_with_gc(
            raw,
            UdpRelayMode::Native,
            0,
            Duration::from_millis(30),
            Duration::from_millis(60),
        );
        let mut udp =
            TuicDatagramOutbound::new(23, conn.clone(), SocksAddr::any_ipv4());
        assert!(!udp.has_gc_timer_for_test());

        // Single-fragment packets never start the GC timer.
        let addr = Address::IPv4(Ipv4Addr::LOCALHOST, 5353);
        let small = encode_single_packet(23, 1, &addr, b"small").unwrap();
        conn.handle_datagram(small);
        let got = timeout(Duration::from_secs(2), udp.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.data.as_ref(), b"small");
        assert!(!udp.has_pending_fragments_for_test());
        assert!(!udp.has_gc_timer_for_test());
        assert_eq!(udp.gc_timer_allocs_for_test(), 0);

        // When all fragments of a packet are already queued together,
        // `poll_next` completes reassembly without allocating a GC timer.
        let big_payload = vec![0x5a; 1500];
        let ready_frames: Vec<_> =
            packet_fragments(23, 2, &addr, &big_payload, 1200)
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
        assert_eq!(ready_frames.len(), 2);
        conn.handle_datagram(ready_frames[0].clone());
        conn.handle_datagram(ready_frames[1].clone());
        let reassembled = timeout(Duration::from_secs(2), udp.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reassembled.data.as_ref(), big_payload.as_slice());
        assert!(!udp.has_pending_fragments_for_test());
        assert!(!udp.has_gc_timer_for_test());
        assert_eq!(
            udp.gc_timer_allocs_for_test(),
            0,
            "already-complete queued fragments must not allocate a GC timer"
        );

        // Feed only fragment 0 of a 2-fragment packet: timer arms on demand.
        let frames: Vec<_> =
            packet_fragments(23, 10, &addr, &big_payload, 1200)
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
        assert_eq!(frames.len(), 2);
        conn.handle_datagram(frames[0].clone());
        assert!(udp.next().now_or_never().is_none());
        assert!(udp.has_pending_fragments_for_test());
        assert!(udp.has_gc_timer_for_test());
        assert_eq!(udp.gc_timer_allocs_for_test(), 1);

        // While idle waiting for the next packet, the on-demand GC timer fires
        // on `gc_interval`, expires the stale fragment after `gc_lifetime`, and
        // disarms itself once the table becomes empty.
        let _ = timeout(Duration::from_millis(200), udp.next()).await;
        assert!(
            !udp.has_pending_fragments_for_test(),
            "stale fragment must expire while idle receiver waits"
        );
        assert!(
            !udp.has_gc_timer_for_test(),
            "GC timer must stop once pending fragment table becomes empty"
        );

        // Sending fragment 1 afterwards must not complete with the expired
        // fragment 0.
        conn.handle_datagram(frames[1].clone());
        assert!(udp.next().now_or_never().is_none());

        // Also verify expiry during continuous small-packet traffic (where the
        // receiver keeps returning `Poll::Ready(Some(_))` without idling).
        let frames2: Vec<_> =
            packet_fragments(23, 11, &addr, &big_payload, 1200)
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
        conn.handle_datagram(frames2[0].clone());
        assert!(udp.next().now_or_never().is_none());
        assert!(udp.has_pending_fragments_for_test());

        tokio::time::sleep(Duration::from_millis(100)).await;
        let small2 = encode_single_packet(23, 12, &addr, b"small-2").unwrap();
        conn.handle_datagram(small2);
        let got2 = timeout(Duration::from_secs(2), udp.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got2.data.as_ref(), b"small-2");
        assert!(
            !udp.has_pending_fragments_for_test(),
            "stale fragment must also expire during continuous small-packet traffic"
        );
        assert!(!udp.has_gc_timer_for_test());
    }
}
