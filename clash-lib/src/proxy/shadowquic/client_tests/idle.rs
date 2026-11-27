use std::net::{SocketAddr, UdpSocket};
use futures::{SinkExt, StreamExt};
use tokio_util::sync::CancellationToken;
use super::*;
use crate::proxy::{
    shadowquic::client_config,
    utils::test_utils::noop::NoopResolver,
};

async fn assert_udp_port_rebindable(addr: SocketAddr) {
    // When a QUIC handshake to a silent peer is aborted, RFC 9000 closing/draining
    // lasts 3 * initial_PTO (~3.1s) before the ConnectionDriver drains and releases
    // the endpoint's UDP socket.
    timeout(Duration::from_secs(5), async {
        loop {
            match UdpSocket::bind(addr) {
                Ok(sock) => {
                    drop(sock);
                    return;
                }
                Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(err) => panic!("unexpected UDP bind error on {addr}: {err}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("UDP port {addr} remained bound (FD leaked)"));
}

#[tokio::test]
async fn health_check_only_reclaims_tcp_and_both_udp_modes_and_failures() {
    timeout(Duration::from_secs(10), async {
        let server_ep = server(true);
        let handler = Handler::new("sq".into(), options(&server_ep));
        handler.set_keep_idle(false);
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let session = Session {
            destination: SocksAddr::from((Ipv4Addr::LOCALHOST, 8080)),
            ..Default::default()
        };

        // 1. TCP health check with keep_idle = false: overlapping request shares
        // the leased connection without a second handshake, and once the last
        // lease drops the cache is evicted immediately and the connection closes.
        let (stream_res, peer_tcp) = tokio::join!(
            handler.connect_stream(&session, resolver.clone()),
            async { server_ep.accept().await.unwrap().await.unwrap() },
        );
        let stream = stream_res.unwrap();
        let cached = handler.cached_conn_for_test().expect("leased conn cached");
        assert!(handler.cached_endpoint_for_test().is_some());
        assert!(handler.has_client_config_for_test());
        let (overlap_conn, overlap_lease) = handler
            .prepare_conn(&session, resolver.clone())
            .await
            .unwrap();
        assert_eq!(
            cached.connection().stable_id(),
            overlap_conn.connection().stable_id(),
        );
        drop((overlap_lease, overlap_conn, cached));
        drop(stream);
        assert!(handler.cached_conn_for_test().is_none());
        assert!(handler.cached_endpoint_for_test().is_none());
        peer_tcp.closed().await;
        peer_tcp.close(0u8.into(), b"done");

        // 2. UDP datagram & over-stream probes with keep_idle = false
        for over_stream in [false, true] {
            let mut opts = options(&server_ep);
            opts.over_stream = over_stream;
            let udp_handler = Handler::new("sq-udp".into(), opts);
            udp_handler.set_keep_idle(false);
            let (dgram_res, peer_udp) = tokio::join!(
                udp_handler.connect_datagram(&session, resolver.clone()),
                async { server_ep.accept().await.unwrap().await.unwrap() },
            );
            let dgram = dgram_res.unwrap();
            assert!(udp_handler.cached_conn_for_test().is_some());
            assert!(udp_handler.cached_endpoint_for_test().is_some());
            drop(dgram);
            peer_udp.closed().await;
            assert!(udp_handler.cached_conn_for_test().is_none());
            assert!(udp_handler.cached_endpoint_for_test().is_none());
            peer_udp.close(0u8.into(), b"done");
        }
        server_ep.close(0u8.into(), b"done");

        // 3. Handshake failure (wrong password)
        let auth_server = server(true);
        let mut bad_opts = options(&auth_server);
        bad_opts.password = "wrong".into();
        let bad_handler = Handler::new("sq-bad".into(), bad_opts);
        bad_handler.set_keep_idle(false);
        let accepting = auth_server.clone();
        let accept_task = tokio::spawn(async move {
            if let Some(inc) = accepting.accept().await {
                let _ = inc.await;
            }
        });
        // `connect_with_timeout` uses 10s, bound the test with short timeout to cover cancellation too.
        let _ = timeout(
            Duration::from_millis(200),
            bad_handler.prepare_conn(&session, resolver.clone()),
        )
        .await;
        assert!(bad_handler.cached_conn_for_test().is_none());
        assert!(bad_handler.cached_endpoint_for_test().is_none());
        accept_task.abort();
        auth_server.close(0u8.into(), b"done");

        // 4. Handshake cancelled mid-flight while UDP socket is bound
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut silent_opts = options(&server(true));
        silent_opts.addr = silent.local_addr().unwrap().to_string();
        let cancel_handler = Handler::new("sq-cancel".into(), silent_opts);
        cancel_handler.set_keep_idle(false);
        assert!(
            timeout(
                Duration::from_millis(50),
                cancel_handler.prepare_conn(&session, resolver),
            )
            .await
            .is_err()
        );
        assert!(cancel_handler.cached_conn_for_test().is_none());
        assert!(cancel_handler.cached_endpoint_for_test().is_none());
        if let Some(addr) = cancel_handler.last_dial_local_addr_for_test() {
            assert_udp_port_rebindable(addr).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dial_failure_before_connection_releases_udp_port_for_rebind() {
    timeout(DEADLINE, async {
        let server_ep = server(true);
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let session = Session::default();

        // 1. Direct ClientEndpoint failure before any connection exists (invalid SNI)
        // after the endpoint driver has polled and parked on `poll_recv`.
        let mut bad_sni_opts = options(&server_ep);
        bad_sni_opts.server_name = "invalid sni".into();
        let config = client_config(&bad_sni_opts).unwrap();
        let server_addr = server_ep.local_addr().unwrap();
        let ep = ClientEndpoint::new_with_config(config, server_addr, &session)
            .await
            .unwrap();
        let local_addr = ep.local_addr().unwrap();
        // Let the quinn-jls EndpointDriver run and park before dropping the endpoint.
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert!(ep.connect(&bad_sni_opts, server_addr).await.is_err());
        ep.close(b"dial aborted");
        drop(ep);
        assert_udp_port_rebindable(local_addr).await;

        // 2. Full Handler::prepare_conn path with invalid SNI (fails inside
        // `Endpoint::connect` before creating any QUIC connection).
        let handler = Handler::new("sq-bad-sni".into(), bad_sni_opts);
        handler.set_keep_idle(false);
        assert!(handler.prepare_conn(&session, resolver).await.is_err());
        assert!(handler.cached_conn_for_test().is_none());
        assert!(handler.cached_endpoint_for_test().is_none());
        let bound_addr = handler
            .last_dial_local_addr_for_test()
            .expect("dial must have bound a local UDP socket");
        assert_udp_port_rebindable(bound_addr).await;

        server_ep.close(0u8.into(), b"done");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn last_udp_association_drains_tail_packets_on_exit_for_both_modes() {
    timeout(DEADLINE, async {
        for over_stream in [false, true] {
            let server_ep = server(true);
            let mut opts = options(&server_ep);
            opts.over_stream = over_stream;
            let handler = Handler::new("sq-udp-tail".into(), opts);
            let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
            let session = Session::default();

            let (dgram_res, peer) = tokio::join!(
                handler.connect_datagram(&session, resolver.clone()),
                async { server_ep.accept().await.unwrap().await.unwrap() },
            );
            let mut dgram = dgram_res.unwrap();
            let ep = handler.cached_endpoint_for_test().unwrap();
            let local_addr = ep.local_addr().unwrap();
            let weak_ep = Arc::downgrade(&ep);
            drop(ep);

            // Switch away while this UDP association is the sole active user.
            handler.set_keep_idle(false);

            let target = SocksAddr::from((Ipv4Addr::LOCALHOST, 5353));
            let payloads: [&[u8]; 3] = [b"tail-1", b"tail-2", b"tail-last"];
            for payload in payloads {
                dgram
                    .send(UdpPacket {
                        data: Bytes::from_static(payload),
                        src_addr: SocksAddr::any_ipv4(),
                        dst_addr: target.clone(),
                        inbound_user: None,
                    })
                    .await
                    .unwrap();
            }
            // Drop the sole UDP session immediately after enqueuing tail packets:
            // this triggers `output.closed()` right away, yet all queued packets
            // and uni-streams must finish bounded drain before closing the QUIC conn.
            drop(dgram);

            let (_ctrl_tx, mut ctrl_rx) = peer.accept_bi().await.unwrap();
            let expected_cmd = if over_stream { 0x04 } else { 0x03 };
            assert_eq!(ctrl_rx.read_u8().await.unwrap(), expected_cmd);
            let _ = SocksAddr::read_from(&mut ctrl_rx).await.unwrap();
            assert_eq!(SocksAddr::read_from(&mut ctrl_rx).await.unwrap(), target);
            let id = ctrl_rx.read_u16().await.unwrap();

            if over_stream {
                let mut uni = peer.accept_uni().await.unwrap();
                assert_eq!(uni.read_u16().await.unwrap(), id);
                for expected in payloads {
                    let len = uni.read_u16().await.unwrap() as usize;
                    let mut buf = vec![0u8; len];
                    uni.read_exact(&mut buf).await.unwrap();
                    assert_eq!(buf.as_slice(), expected);
                }
                assert!(uni.read_u8().await.is_err());
            } else {
                for expected in payloads {
                    let dg = peer.read_datagram().await.unwrap();
                    assert_eq!(&dg[..2], &id.to_be_bytes());
                    assert_eq!(&dg[2..], expected);
                }
            }

            // Connection closes cleanly after drain + grace, releasing endpoint & UDP FD.
            peer.closed().await;
            while weak_ep.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
            assert!(handler.cached_conn_for_test().is_none());
            assert!(handler.cached_endpoint_for_test().is_none());
            assert_udp_port_rebindable(local_addr).await;
            peer.close(0u8.into(), b"done");
            server_ep.close(0u8.into(), b"done");
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn closed_connection_before_publish_is_not_cached_and_eviction_is_instance_scoped() {
    timeout(DEADLINE, async {
        let server_ep = server(true);
        let opts = options(&server_ep);
        let handler = Handler::new("sq-race".into(), opts.clone());
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let session = Session::default();

        // 1. Dial a connection and let the peer close it BEFORE `publish_conn`,
        // simulating the close-watcher running while the cache is still empty.
        let config = client_config(&opts).unwrap();
        let server_addr = server_ep.local_addr().unwrap();
        let ep1 = Arc::new(
            ClientEndpoint::new_with_config(config, server_addr, &session)
                .await
                .unwrap(),
        );
        let local_addr1 = ep1.local_addr().unwrap();
        let weak_ep1 = Arc::downgrade(&ep1);
        let (quic_res, peer1) = tokio::join!(
            ep1.connect(&opts, server_addr),
            async { server_ep.accept().await.unwrap().await.unwrap() },
        );
        let conn1 = ClientConnection::new_managed(
            quic_res.unwrap(),
            Some(ep1),
            handler.keep_idle.clone(),
            Arc::downgrade(&handler.conn),
        );
        peer1.close(0u8.into(), b"immediate peer close");
        conn1.connection().closed().await;
        while conn1.is_alive() {
            tokio::task::yield_now().await;
        }

        // Handler is still selected (keep_idle = true), yet publishing a dead
        // connection must not leave either connection or endpoint in cache.
        handler.publish_conn(&conn1);
        assert!(handler.cached_conn_for_test().is_none());
        assert!(handler.cached_endpoint_for_test().is_none());
        drop(conn1);
        while weak_ep1.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
        assert_udp_port_rebindable(local_addr1).await;

        // 2. Evicting an older instance must never clear a newer cached connection/endpoint.
        let (res2, peer2) = tokio::join!(
            handler.prepare_conn(&session, resolver),
            async { server_ep.accept().await.unwrap().await.unwrap() },
        );
        let (conn2, lease2) = res2.unwrap();
        let ep2 = handler.cached_endpoint_for_test().unwrap();

        let (quic3_res, peer3) = tokio::join!(
            ep2.connect(&opts, server_addr),
            async { server_ep.accept().await.unwrap().await.unwrap() },
        );
        let unrelated = ClientConnection::new_managed(
            quic3_res.unwrap(),
            None,
            handler.keep_idle.clone(),
            Arc::downgrade(&handler.conn),
        );
        unrelated.evict_from_cache();
        assert_eq!(
            handler.cached_conn_for_test().unwrap().connection().stable_id(),
            conn2.connection().stable_id()
        );
        assert!(Arc::ptr_eq(&handler.cached_endpoint_for_test().unwrap(), &ep2));

        drop((ep2, lease2, conn2, unrelated));
        peer2.close(0u8.into(), b"done");
        peer3.close(0u8.into(), b"done");
        server_ep.close(0u8.into(), b"done");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn switch_away_keeps_active_tcp_and_udp_and_reclaims_after_last_exit() {
    timeout(DEADLINE, async {
        let server_ep = server(true);
        let handler = Handler::new("sq".into(), options(&server_ep));
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let session = Session {
            destination: SocksAddr::from((Ipv4Addr::LOCALHOST, 8080)),
            ..Default::default()
        };

        let (tcp_res, peer) = tokio::join!(
            handler.connect_stream(&session, resolver.clone()),
            async { server_ep.accept().await.unwrap().await.unwrap() },
        );
        let mut tcp = tcp_res.unwrap();
        let conn = handler.cached_conn_for_test().unwrap();
        let ep = handler.cached_endpoint_for_test().unwrap();
        let weak_ep = Arc::downgrade(&ep);
        drop(ep);

        let dgram_dg = handler
            .connect_datagram(&session, resolver.clone())
            .await
            .unwrap();
        let dgram_stream = conn
            .associate_with_lease(
                "0.0.0.0:0".parse::<SocketAddr>().unwrap().into(),
                true,
                conn.try_acquire_lease(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(conn.active_streams_for_test(), 3);

        // Switch away while TCP stream + both UDP associations are active.
        handler.set_keep_idle(false);
        assert!(conn.connection().close_reason().is_none());
        assert!(weak_ep.upgrade().is_some());

        // Existing TCP stream continues operating.
        tcp.write_all(b"ping").await.unwrap();
        let (_send, mut recv) = peer.accept_bi().await.unwrap();
        assert_eq!(recv.read_u8().await.unwrap(), 0x01);
        let _ = SocksAddr::read_from(&mut recv).await.unwrap();
        let mut buf = [0; 4];
        recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // Dropping first two users leaves connection alive for the third.
        drop(dgram_dg);
        drop(dgram_stream);
        tokio::task::yield_now().await;
        assert!(conn.connection().close_reason().is_none());

        // Dropping final TCP stream waits for upload FIN ACK + grace, then closes.
        drop(tcp);
        drop(conn);
        peer.closed().await;
        while weak_ep.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
        assert!(handler.cached_conn_for_test().is_none());
        assert!(handler.cached_endpoint_for_test().is_none());
        server_ep.close(0u8.into(), b"done");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn deselect_reselect_concurrent_dial_and_drop_handler() {
    timeout(DEADLINE, async {
        let server_ep = server(true);
        let handler = Arc::new(Handler::new("sq".into(), options(&server_ep)));
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let session = Session::default();

        // 1. Active stream survives brief deselect -> reselect and reuses conn.
        let (first_res, peer1) = tokio::join!(
            handler.prepare_conn(&session, resolver.clone()),
            async { server_ep.accept().await.unwrap().await.unwrap() },
        );
        let (conn1, lease1) = first_res.unwrap();
        let ep1 = handler.cached_endpoint_for_test().unwrap();
        let weak_ep1 = Arc::downgrade(&ep1);
        drop(ep1);

        handler.set_keep_idle(false);
        handler.set_keep_idle(true);
        let (conn1_reused, lease1_reused) =
            handler.prepare_conn(&session, resolver.clone()).await.unwrap();
        assert_eq!(
            conn1.connection().stable_id(),
            conn1_reused.connection().stable_id()
        );
        drop((lease1, lease1_reused, conn1_reused));

        // 2. Deselect while idle closes conn1 & releases ep1; reselect rebuilds.
        handler.set_keep_idle(false);
        conn1.connection().closed().await;
        drop(conn1);
        while weak_ep1.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
        assert!(handler.has_client_config_for_test());

        handler.set_keep_idle(true);
        let (second_res, peer2) = tokio::join!(
            handler.prepare_conn(&session, resolver.clone()),
            async { server_ep.accept().await.unwrap().await.unwrap() },
        );
        let (conn2, lease2) = second_res.unwrap();
        let ep2 = handler.cached_endpoint_for_test().unwrap();
        assert_ne!(Arc::as_ptr(&ep2), weak_ep1.as_ptr());
        drop((ep2, lease2, conn2));

        // 3. Concurrent dial loses route reference mid-handshake.
        handler.set_keep_idle(false);
        handler.set_keep_idle(true);
        let accept = async { server_ep.accept().await.unwrap() };
        let dial = {
            let handler = handler.clone();
            let resolver = resolver.clone();
            let session = session.clone();
            tokio::spawn(async move { handler.prepare_conn(&session, resolver).await })
        };
        let incoming = accept.await;
        handler.set_keep_idle(false);
        let (peer3, dial_res) = tokio::join!(async { incoming.await.unwrap() }, dial);
        let (conn3, lease3) = dial_res.unwrap().unwrap();
        drop(lease3);
        conn3.connection().closed().await;
        drop(conn3);
        assert!(handler.cached_conn_for_test().is_none());
        assert!(handler.cached_endpoint_for_test().is_none());

        // 4. Dropping handler retires active connection and releases on last exit.
        let handler2 = Handler::new("sq-drop".into(), options(&server_ep));
        let (fourth_res, peer4) = tokio::join!(
            handler2.prepare_conn(&session, resolver),
            async { server_ep.accept().await.unwrap().await.unwrap() },
        );
        let (conn4, lease4) = fourth_res.unwrap();
        let quic_conn4 = conn4.connection().clone();
        let ep4 = handler2.cached_endpoint_for_test().unwrap();
        let weak_ep4 = Arc::downgrade(&ep4);
        drop(ep4);
        drop(handler2);
        assert!(quic_conn4.close_reason().is_none());
        drop((lease4, conn4));
        quic_conn4.closed().await;
        while weak_ep4.upgrade().is_some() {
            tokio::task::yield_now().await;
        }

        peer1.close(0u8.into(), b"done");
        peer2.close(0u8.into(), b"done");
        peer3.close(0u8.into(), b"done");
        peer4.close(0u8.into(), b"done");
        server_ep.close(0u8.into(), b"done");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stalled_udp_send_bounded_by_drain_timeout_and_releases_lease() {
    timeout(Duration::from_secs(10), async {
        // Advertise 0 uni streams so `conn.open_uni().await` inside `send_packet`
        // stalls indefinitely until the association's drain deadline fires.
        let server_ep = server_with_uni_limit(true, 0);
        let mut opts = options(&server_ep);
        opts.over_stream = true;
        let handler = Handler::new("sq-stalled-udp".into(), opts);
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let session = Session {
            destination: SocksAddr::from((Ipv4Addr::LOCALHOST, 8080)),
            ..Default::default()
        };

        // Keep an active TCP stream on the same QUIC connection so the connection
        // remains alive while the stalled UDP association exits.
        let (tcp_res, peer) = tokio::join!(
            handler.connect_stream(&session, resolver.clone()),
            async { server_ep.accept().await.unwrap().await.unwrap() },
        );
        let tcp = tcp_res.unwrap();
        let (_tcp_tx, mut tcp_rx) = peer.accept_bi().await.unwrap();
        assert_eq!(tcp_rx.read_u8().await.unwrap(), 0x01);
        let _ = SocksAddr::read_from(&mut tcp_rx).await.unwrap();

        let conn = handler.cached_conn_for_test().unwrap();
        let ep = handler.cached_endpoint_for_test().unwrap();
        let local_addr = ep.local_addr().unwrap();
        let weak_ep = Arc::downgrade(&ep);
        drop(ep);
        conn.set_udp_drain_timeout_for_test(Duration::from_millis(120));

        let mut dgram = handler
            .connect_datagram(&session, resolver.clone())
            .await
            .unwrap();
        assert_eq!(conn.active_streams_for_test(), 2);

        let target = SocksAddr::from((Ipv4Addr::LOCALHOST, 5353));
        dgram
            .send(UdpPacket {
                data: Bytes::from_static(b"stalled-packet"),
                src_addr: SocksAddr::any_ipv4(),
                dst_addr: target.clone(),
                inbound_user: None,
            })
            .await
            .unwrap();

        // Wait until the association has registered the destination on the control
        // stream and is therefore parked inside `conn.open_uni().await`.
        let (_ctrl_tx, mut ctrl_rx) = peer.accept_bi().await.unwrap();
        assert_eq!(ctrl_rx.read_u8().await.unwrap(), 0x04);
        let _ = SocksAddr::read_from(&mut ctrl_rx).await.unwrap();
        assert_eq!(SocksAddr::read_from(&mut ctrl_rx).await.unwrap(), target);
        let _id = ctrl_rx.read_u16().await.unwrap();

        // 1. Dropping the UDP session must interrupt the stalled `send_packet` within
        // the association drain timeout and release its lease while TCP stays open.
        drop(dgram);
        timeout(Duration::from_secs(2), async {
            while conn.active_streams_for_test() != 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stalled UDP association must release lease within drain timeout");
        assert!(conn.connection().close_reason().is_none());

        // 2. Closing only the upload side via `Sink::close().await` while keeping
        // the receiver alive must also start the same drain deadline so a deselected
        // node is reclaimed once the stalled send times out.
        let mut dgram_half = handler
            .connect_datagram(&session, resolver)
            .await
            .unwrap();
        assert_eq!(conn.active_streams_for_test(), 2);
        dgram_half
            .send(UdpPacket {
                data: Bytes::from_static(b"stalled-half-close"),
                src_addr: SocksAddr::any_ipv4(),
                dst_addr: target.clone(),
                inbound_user: None,
            })
            .await
            .unwrap();

        let (_ctrl_tx2, mut ctrl_rx2) = peer.accept_bi().await.unwrap();
        assert_eq!(ctrl_rx2.read_u8().await.unwrap(), 0x04);
        let _ = SocksAddr::read_from(&mut ctrl_rx2).await.unwrap();
        assert_eq!(SocksAddr::read_from(&mut ctrl_rx2).await.unwrap(), target);
        let _id2 = ctrl_rx2.read_u16().await.unwrap();

        // Deselect the node and drop the TCP stream so `dgram_half` is the sole user.
        handler.set_keep_idle(false);
        drop(tcp);
        assert_eq!(conn.active_streams_for_test(), 1);
        assert!(conn.connection().close_reason().is_none());

        // Close upload only, keeping `dgram_half` (receiver) alive.
        dgram_half.close().await.unwrap();
        timeout(Duration::from_secs(2), async {
            while conn.active_streams_for_test() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("upload-only close must bound stalled send and release lease");
        assert!(timeout(Duration::from_secs(2), dgram_half.next()).await.unwrap().is_none());
        drop(conn);
        peer.closed().await;
        while weak_ep.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
        drop(dgram_half);
        assert_udp_port_rebindable(local_addr).await;
        peer.close(0u8.into(), b"done");
        server_ep.close(0u8.into(), b"done");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_handshake_releases_udp_port_for_rebind() {
    timeout(Duration::from_secs(10), async {
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let silent_addr = silent.local_addr().unwrap();
        let server_ep = server(true);
        let mut opts = options(&server_ep);
        opts.addr = silent_addr.to_string();
        let config = client_config(&opts).unwrap();
        let session = Session::default();

        let ep = ClientEndpoint::new_with_config(config, silent_addr, &session)
            .await
            .unwrap();
        let local_addr = ep.local_addr().unwrap();

        // Start a handshake to a silent peer and cancel it mid-flight so the
        // QUIC connection enters RFC 9000 closing/draining.
        assert!(
            timeout(Duration::from_millis(30), ep.connect(&opts, silent_addr))
                .await
                .is_err()
        );
        ep.close(b"dial aborted");
        drop(ep);

        // Socket must be released cleanly once QUIC draining completes.
        assert_udp_port_rebindable(local_addr).await;
        server_ep.close(0u8.into(), b"done");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn peer_close_after_udp_receive_task_started_evicts_cached_conn_and_endpoint() {
    timeout(Duration::from_secs(10), async {
        let server_ep = server(true);
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let session = Session::default();

        // Repeat multiple rounds to catch races where `receive_packets` cancels
        // the shared token before the close watcher observes `conn.closed()`.
        for _ in 0..8 {
            let handler = Handler::new("sq-udp-peer-close".into(), options(&server_ep));
            let (dgram_res, peer) = tokio::join!(
                handler.connect_datagram(&session, resolver.clone()),
                async { server_ep.accept().await.unwrap().await.unwrap() },
            );
            let dgram = dgram_res.unwrap();
            let ep = handler.cached_endpoint_for_test().unwrap();
            let local_addr = ep.local_addr().unwrap();
            let weak_ep = Arc::downgrade(&ep);
            drop(ep);

            // Drop the UDP session so the connection sits idle while `receive_packets`
            // is running and `keep_idle` remains true.
            drop(dgram);
            tokio::task::yield_now().await;
            assert!(handler.cached_conn_for_test().is_some());
            assert!(handler.cached_endpoint_for_test().is_some());

            // Peer closes the connection: cache & endpoint must be evicted without
            // needing another dial.
            peer.close(0u8.into(), b"peer closed");
            timeout(Duration::from_secs(2), async {
                while handler.cached_conn_for_test().is_some()
                    || handler.cached_endpoint_for_test().is_some()
                    || weak_ep.upgrade().is_some()
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("peer close must evict cached conn and endpoint even after UDP receive_packets started");
            assert_udp_port_rebindable(local_addr).await;
        }
        server_ep.close(0u8.into(), b"done");
    })
    .await
    .unwrap();
}
