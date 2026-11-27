use super::*;
use crate::app::dns::transport::quic_test_support;
use crate::proxy::utils::test_utils::noop::NoopResolver;

fn options(port: u16) -> HandlerOptions {
    HandlerOptions {
        name: "local-tuic".to_owned(),
        server: "127.0.0.1".to_owned(),
        port,
        uuid: Uuid::nil(),
        password: "test-password".to_owned(),
        udp_relay_mode: UdpRelayMode::Native,
        disable_sni: false,
        alpn: vec![b"tuic".to_vec()],
        heartbeat_interval: Duration::from_secs(60),
        reduce_rtt: false,
        request_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(60),
        congestion_controller: CongestionControl::Cubic,
        max_open_stream: VarInt::from_u32(16),
        gc_interval: Duration::from_secs(60),
        gc_lifetime: Duration::from_secs(60),
        send_window: 1024 * 1024,
        receive_window: VarInt::from_u32(1024 * 1024),
        skip_cert_verify: true,
        fingerprint: None,
        common_opts: HandlerCommonOptions::default(),
        max_udp_relay_packet_size: 1200,
        ip: None,
        sni: Some("localhost".to_owned()),
        tls_cert: None,
        tls_key: None,
    }
}

#[tokio::test]
async fn concurrent_connects_share_cache_and_cached_reads_skip_reconnect_lock() {
    let (server, _) = quic_test_support::server(b"tuic");
    let handler = Handler::new(options(server.local_addr().unwrap().port()));
    let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
    let session = Session::default();
    let (connections, remote) = tokio::join!(
        futures::future::join_all((0..16).map(|_| handler.get_conn(&resolver, &session))),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let connections: Vec<_> = connections.into_iter().map(Result::unwrap).collect();
    let first = &connections[0].0;
    assert!(connections.iter().all(|(conn, _)| Arc::ptr_eq(conn, first)));

    let reconnect = handler.reconnect.lock().await;
    let (cached, _cached_lease) = tokio::time::timeout(
        Duration::from_millis(100), handler.get_conn(&resolver, &session),
    ).await.unwrap().unwrap();
    assert!(Arc::ptr_eq(&cached, first));

    first.conn.close(0_u32.into(), b"reconnect test");
    assert!(first.check_open().is_err());
    let error = handler.get_conn(&resolver, &session).await.err().unwrap();
    assert!(error.is::<tokio::time::error::Elapsed>());
    drop(reconnect);
    let (replacement, next_remote) = tokio::join!(
        handler.get_conn(&resolver, &session),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let (replacement, _replacement_lease) = replacement.unwrap();
    assert!(!Arc::ptr_eq(first, &replacement));
    assert!(replacement.check_open().is_ok());
    replacement.conn.close(0_u32.into(), b"done");
    remote.close(0_u32.into(), b"done");
    next_remote.close(0_u32.into(), b"done");
    server.close(0_u32.into(), b"done");
}

#[tokio::test]
async fn dropping_handler_retires_connection_and_stops_heartbeat() {
    let (server, _) = quic_test_support::server(b"tuic");
    let handler = Handler::new(options(server.local_addr().unwrap().port()));
    let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
    let session = Session::default();

    let (conn_res, remote) = tokio::join!(
        handler.get_conn(&resolver, &session),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let (conn, lease) = conn_res.unwrap();
    let weak_conn = Arc::downgrade(&conn);
    let quic_conn = conn.conn.clone();

    // Handler stays in keep_idle=true (default) and is dropped as if replaced
    // by a provider refresh or config reload while a stream is still active.
    drop(handler);
    assert!(
        quic_conn.close_reason().is_none(),
        "dropping handler must not cut active stream"
    );

    // Once the final stream finishes, the retired connection must close
    // immediately and all background tasks (including the 60s heartbeat loop)
    // must exit so the Arc<TuicConnection> is released.
    drop(lease);
    drop(conn);

    tokio::time::timeout(Duration::from_secs(2), quic_conn.closed())
        .await
        .expect("retired TUIC connection must close once active streams finish");
    tokio::time::timeout(Duration::from_secs(2), async {
        while weak_conn.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("TUIC background tasks including heartbeat must exit promptly");

    remote.close(0_u32.into(), b"done");
    server.close(0_u32.into(), b"done");
}

#[tokio::test]
async fn keep_idle_switch_after_upload_ack_respects_grace_window() {
    use tokio::io::AsyncWriteExt;
    use super::stream::TuicStream;

    let (server, _) = quic_test_support::server(b"tuic");
    let handler = Handler::new(options(server.local_addr().unwrap().port()));
    let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
    let session = Session::default();

    let (conn_res, remote) = tokio::join!(
        handler.get_conn(&resolver, &session),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let (conn, lease) = conn_res.unwrap();
    let quic_conn = conn.conn.clone();

    // keep_idle is enabled while client uploads and drops the stream.
    let (tx, rx) = quic_conn.open_bi().await.unwrap();
    let mut stream = TuicStream::new(tx, rx, lease);
    let payload = b"tuic-acked-upload-before-switch";
    stream.write_all(payload).await.unwrap();
    drop(stream);

    // Wait until QUIC ACKs the FIN and the stream lease is released.
    tokio::time::timeout(Duration::from_secs(2), async {
        while conn.active_streams_for_test() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("upload ACK must release kept-idle stream lease");

    // Immediately switch away (disable keep_idle): connection must stay open
    // for the remaining grace period computed from the ACK.
    handler.set_keep_idle(false);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        quic_conn.close_reason().is_none(),
        "switching TUIC node right after upload ACK must honor grace window"
    );

    let (_peer_tx, mut peer_rx) =
        tokio::time::timeout(Duration::from_secs(2), remote.accept_bi())
            .await
            .unwrap()
            .unwrap();
    let received = tokio::time::timeout(
        Duration::from_secs(2),
        peer_rx.read_to_end(1024),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(received, payload);

    tokio::time::timeout(Duration::from_secs(3), quic_conn.closed())
        .await
        .expect("TUIC connection must close after upload ACK grace expires");

    remote.close(0_u32.into(), b"done");
    server.close(0_u32.into(), b"done");
}

#[tokio::test]
async fn connection_close_clears_udp_sessions_and_wakes_receiver() {
    use futures::StreamExt;
    use crate::session::SocksAddr;
    use super::TuicDatagramOutbound;

    let (server, _) = quic_test_support::server(b"tuic");
    let handler = Handler::new(options(server.local_addr().unwrap().port()));
    let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
    let session = Session::default();

    let (conn_res, remote) = tokio::join!(
        handler.get_conn(&resolver, &session),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let (conn, lease) = conn_res.unwrap();
    let mut udp = TuicDatagramOutbound::new_with_lease(
        42,
        conn.clone(),
        SocksAddr::any_ipv4(),
        Some(lease),
    );
    assert!(conn.udp_sessions.read().contains_key(&42));

    // Closing the peer ends `TuicConnection::init`, which must clear
    // `udp_sessions` so waiting receivers observe `None` immediately.
    remote.close(0_u32.into(), b"peer closed");
    let next = tokio::time::timeout(Duration::from_secs(2), udp.next())
        .await
        .expect("TUIC UDP receiver must wake promptly when connection closes");
    assert!(next.is_none());
    assert!(conn.udp_sessions.read().is_empty());

    server.close(0_u32.into(), b"done");
}

#[tokio::test]
async fn register_udp_after_connection_close_wakes_with_none() {
    use futures::StreamExt;
    use crate::session::SocksAddr;
    use super::TuicDatagramOutbound;

    let (server, _) = quic_test_support::server(b"tuic");
    let handler = Handler::new(options(server.local_addr().unwrap().port()));
    let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
    let session = Session::default();

    let (conn_res, remote) = tokio::join!(
        handler.get_conn(&resolver, &session),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let (conn, lease) = conn_res.unwrap();

    // Connection closes and `TuicConnection::init` exits BEFORE registering UDP.
    remote.close(0_u32.into(), b"peer closed");
    tokio::time::timeout(Duration::from_secs(2), async {
        while !conn.udp_sessions.read().is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("TuicConnection::init must close udp_sessions after peer close");

    let mut udp = TuicDatagramOutbound::new_with_lease(
        43,
        conn.clone(),
        SocksAddr::any_ipv4(),
        Some(lease),
    );
    let next = tokio::time::timeout(Duration::from_secs(2), udp.next())
        .await
        .expect("TUIC UDP registered after close must return None immediately");
    assert!(next.is_none());
    assert!(conn.udp_sessions.read().is_empty());

    server.close(0_u32.into(), b"done");
}

#[tokio::test]
async fn health_check_only_reclaims_conn_and_endpoint_on_success_failure_timeout_and_cancel() {
    let (server, _) = quic_test_support::server(b"tuic");
    let handler = Handler::new(options(server.local_addr().unwrap().port()));
    handler.set_keep_idle(false);
    let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
    let session = Session::default();

    // 1. Successful probe with keep_idle=false: active connection stays cached
    // while leased so overlapping requests share it without a second handshake,
    // and is evicted & reclaimed immediately once the last lease drops, while
    // TLS client_config stays cached.
    let (conn_res, remote) = tokio::join!(
        handler.get_conn(&resolver, &session),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let (conn, lease) = conn_res.unwrap();
    let quic_conn = conn.conn.clone();
    let weak_conn = Arc::downgrade(&conn);
    assert!(Arc::ptr_eq(&handler.cached_conn_for_test().unwrap(), &conn));
    assert!(handler.cached_endpoint_for_test().is_some());
    assert!(handler.has_client_config_for_test());

    // Overlapping request on keep_idle=false reuses the active connection.
    let (conn_overlap, lease_overlap) =
        handler.get_conn(&resolver, &session).await.unwrap();
    assert!(Arc::ptr_eq(&conn, &conn_overlap));
    drop((lease_overlap, conn_overlap));
    assert!(quic_conn.close_reason().is_none());

    drop(lease);
    drop(conn);
    assert!(handler.cached_conn_for_test().is_none());
    assert!(handler.cached_endpoint_for_test().is_none());
    tokio::time::timeout(Duration::from_secs(2), quic_conn.closed())
        .await
        .expect("probe connection must close after lease drops");
    tokio::time::timeout(Duration::from_secs(2), async {
        while weak_conn.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("probe connection and endpoint must be released");
    remote.close(0_u32.into(), b"done");
    server.close(0_u32.into(), b"done");

    // 2. Handshake failure (ALPN mismatch): no endpoint or connection cached.
    let (bad_server, _) = quic_test_support::server(b"wrong-alpn");
    let bad_handler = Handler::new(options(bad_server.local_addr().unwrap().port()));
    bad_handler.set_keep_idle(false);
    let (res, _) = tokio::join!(
        bad_handler.get_conn(&resolver, &session),
        async {
            if let Some(inc) = bad_server.accept().await {
                let _ = inc.await;
            }
        },
    );
    assert!(res.is_err());
    assert!(bad_handler.cached_conn_for_test().is_none());
    assert!(bad_handler.cached_endpoint_for_test().is_none());
    bad_server.close(0_u32.into(), b"done");

    // 3. Handshake timeout against unresponsive UDP socket.
    use std::net::UdpSocket;
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut timeout_opts = options(silent.local_addr().unwrap().port());
    timeout_opts.request_timeout = Duration::from_millis(100);
    let timeout_handler = Handler::new(timeout_opts);
    timeout_handler.set_keep_idle(false);
    assert!(timeout_handler.get_conn(&resolver, &session).await.is_err());
    assert!(timeout_handler.cached_conn_for_test().is_none());
    assert!(timeout_handler.cached_endpoint_for_test().is_none());

    // 4. Handshake cancelled mid-flight while UDP socket is bound.
    let mut cancel_opts = options(silent.local_addr().unwrap().port());
    cancel_opts.request_timeout = Duration::from_secs(10);
    let cancel_handler = Handler::new(cancel_opts);
    cancel_handler.set_keep_idle(false);
    let fut = cancel_handler.get_conn(&resolver, &session);
    assert!(tokio::time::timeout(Duration::from_millis(50), fut).await.is_err());
    assert!(cancel_handler.cached_conn_for_test().is_none());
    assert!(cancel_handler.cached_endpoint_for_test().is_none());
}

#[tokio::test]
async fn switch_away_keeps_active_stream_and_reclaims_endpoint_after_last_exit() {
    let (server, _) = quic_test_support::server(b"tuic");
    let handler = Handler::new(options(server.local_addr().unwrap().port()));
    let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
    let session = Session::default();

    let (conn_res, remote) = tokio::join!(
        handler.get_conn(&resolver, &session),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let (conn, lease) = conn_res.unwrap();
    let quic_conn = conn.conn.clone();
    let weak_conn = Arc::downgrade(&conn);
    let ep = handler.cached_endpoint_for_test().expect("endpoint cached");
    let weak_ep = Arc::downgrade(&ep);
    drop(ep);

    // Switch node away while stream lease is still held.
    handler.set_keep_idle(false);
    assert!(quic_conn.close_reason().is_none());
    assert!(weak_ep.upgrade().is_some());

    drop(lease);
    drop(conn);

    tokio::time::timeout(Duration::from_secs(2), quic_conn.closed())
        .await
        .expect("TUIC connection must close once active stream finishes");
    tokio::time::timeout(Duration::from_secs(2), async {
        while weak_conn.upgrade().is_some() || weak_ep.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("TUIC endpoint and socket must be released after last user exits");
    assert!(handler.cached_conn_for_test().is_none());
    assert!(handler.cached_endpoint_for_test().is_none());

    remote.close(0_u32.into(), b"done");
    server.close(0_u32.into(), b"done");
}

#[tokio::test]
async fn deselect_then_reselect_and_concurrent_dial_keep_idle_check() {
    let (server, _) = quic_test_support::server(b"tuic");
    let handler = Arc::new(Handler::new(options(server.local_addr().unwrap().port())));
    let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
    let session = Session::default();

    // 1. Active stream survives brief deselect -> reselect and is reused.
    let (conn_res, remote1) = tokio::join!(
        handler.get_conn(&resolver, &session),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let (conn1, lease1) = conn_res.unwrap();
    let ep1 = handler.cached_endpoint_for_test().unwrap();
    let weak_ep1 = Arc::downgrade(&ep1);
    drop(ep1);

    handler.set_keep_idle(false);
    handler.set_keep_idle(true);
    let (conn1_again, lease1_again) = handler.get_conn(&resolver, &session).await.unwrap();
    assert!(Arc::ptr_eq(&conn1, &conn1_again));
    drop((lease1, lease1_again, conn1_again));

    // 2. Deselect while idle closes conn1 & releases ep1; reselect rebuilds ep2
    // while reusing cached client_config.
    handler.set_keep_idle(false);
    tokio::time::timeout(Duration::from_secs(2), conn1.conn.closed())
        .await
        .unwrap();
    drop(conn1);
    tokio::time::timeout(Duration::from_secs(2), async {
        while weak_ep1.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(handler.has_client_config_for_test());

    handler.set_keep_idle(true);
    let (conn2_res, remote2) = tokio::join!(
        handler.get_conn(&resolver, &session),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let (conn2, lease2) = conn2_res.unwrap();
    let ep2 = handler.cached_endpoint_for_test().unwrap();
    assert_ne!(Arc::as_ptr(&ep2), weak_ep1.as_ptr());
    drop((ep2, lease2, conn2));

    // 3. Concurrent dial loses route reference before caching: must not retain
    // idle carrier after completion.
    handler.set_keep_idle(false);
    let _ = handler.cached_conn_for_test();
    handler.set_keep_idle(true);

    let (incoming, dial_fut) = {
        let handler = handler.clone();
        let resolver = resolver.clone();
        let session = session.clone();
        let accept = async { server.accept().await.unwrap() };
        let dial = tokio::spawn(async move { handler.get_conn(&resolver, &session).await });
        let incoming = accept.await;
        (incoming, dial)
    };
    // Flip keep_idle to false before the handshake finishes.
    handler.set_keep_idle(false);
    let (remote3, dial_res) = tokio::join!(async { incoming.await.unwrap() }, dial_fut);
    let (conn3, lease3) = dial_res.unwrap().unwrap();
    let quic_conn3 = conn3.conn.clone();
    drop((lease3, conn3));
    tokio::time::timeout(Duration::from_secs(2), quic_conn3.closed())
        .await
        .expect("conn dialed across keep_idle=false flip must close once released");
    assert!(handler.cached_conn_for_test().is_none());
    assert!(handler.cached_endpoint_for_test().is_none());

    remote1.close(0_u32.into(), b"done");
    remote2.close(0_u32.into(), b"done");
    remote3.close(0_u32.into(), b"done");
    server.close(0_u32.into(), b"done");
}

#[tokio::test]
async fn closed_connection_before_publish_is_not_cached_and_eviction_is_instance_scoped() {
    let (server, _) = quic_test_support::server(b"tuic");
    let handler = Handler::new(options(server.local_addr().unwrap().port()));
    let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
    let session = Session::default();

    // 1. Handshake completes and peer closes immediately BEFORE `publish_conn` runs,
    // so `TuicConnection::init` executes its eviction while the cache is still empty.
    let quinn_config = Handler::build_client_config(&handler.opts).unwrap();
    let ep1 = handler
        .init_endpoint(quinn_config, &resolver, &session)
        .await
        .unwrap();
    let weak_ep1 = Arc::downgrade(&ep1);
    let (conn1_res, remote1) = tokio::join!(
        ep1.connect(
            &resolver,
            handler.keep_idle.clone(),
            Arc::downgrade(&handler.conn),
        ),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let conn1 = conn1_res.unwrap();
    drop(ep1);
    remote1.close(0_u32.into(), b"immediate peer close");
    tokio::time::timeout(Duration::from_secs(2), async {
        while conn1.is_alive() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("TuicConnection::init must observe close before publish");

    // Handler remains selected (keep_idle = true), yet publishing the dead
    // connection must not retain either connection or endpoint in cache.
    handler.publish_conn(&conn1);
    assert!(handler.cached_conn_for_test().is_none());
    assert!(handler.cached_endpoint_for_test().is_none());
    drop(conn1);
    tokio::time::timeout(Duration::from_secs(2), async {
        while weak_ep1.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dead TUIC endpoint must be released");

    // 2. Evicting an older instance must not clobber a newer cached connection/endpoint.
    let (conn2_res, remote2) = tokio::join!(
        handler.get_conn(&resolver, &session),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let (conn2, lease2) = conn2_res.unwrap();
    let ep2 = handler.cached_endpoint_for_test().unwrap();

    let ep3 = handler
        .init_endpoint(
            Handler::build_client_config(&handler.opts).unwrap(),
            &resolver,
            &session,
        )
        .await
        .unwrap();
    let (conn3_res, remote3) = tokio::join!(
        ep3.connect(
            &resolver,
            handler.keep_idle.clone(),
            Arc::downgrade(&handler.conn),
        ),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let unrelated = conn3_res.unwrap();
    unrelated.evict_from_cache();
    assert!(Arc::ptr_eq(&handler.cached_conn_for_test().unwrap(), &conn2));
    assert!(Arc::ptr_eq(&handler.cached_endpoint_for_test().unwrap(), &ep2));

    drop((ep2, ep3, lease2, conn2, unrelated));
    remote2.close(0_u32.into(), b"done");
    remote3.close(0_u32.into(), b"done");
    server.close(0_u32.into(), b"done");
}
