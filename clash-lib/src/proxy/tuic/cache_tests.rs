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
