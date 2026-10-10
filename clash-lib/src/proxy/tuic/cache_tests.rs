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
    let first = &connections[0];
    assert!(connections.iter().all(|conn| Arc::ptr_eq(conn, first)));

    let reconnect = handler.reconnect.lock().await;
    let cached = tokio::time::timeout(
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
    let replacement = replacement.unwrap();
    assert!(!Arc::ptr_eq(first, &replacement));
    assert!(replacement.check_open().is_ok());
    replacement.conn.close(0_u32.into(), b"done");
    remote.close(0_u32.into(), b"done");
    next_remote.close(0_u32.into(), b"done");
    server.close(0_u32.into(), b"done");
}
