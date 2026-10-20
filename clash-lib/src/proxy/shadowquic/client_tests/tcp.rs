use super::*;

#[tokio::test]
async fn tcp_dns_and_concurrent_connection_reuse() {
    timeout(DEADLINE, async {
        let server = server(true);
        let mut opts = options(&server);
        opts.addr = format!("sq.invalid:{}", server.local_addr().unwrap().port());
        let handler = Handler::new("sq".into(), opts);
        let mut dns = MockClashResolver::new();
        dns.expect_resolve().withf(|host, enhanced| host == "sq.invalid" && !enhanced)
            .times(1).returning(|_, _| Ok(Some(Ipv4Addr::LOCALHOST.into())));
        let dns: ThreadSafeDNSResolver = Arc::new(dns);
        let session = Session { destination: SocksAddr::from((Ipv4Addr::LOCALHOST, 8080)),
            ..Default::default() };
        let (connections, peer) = tokio::join!(async {
            tokio::join!(
                handler.prepare_conn(&session, dns.clone()),
                handler.prepare_conn(&session, dns.clone()),
            )
        }, async { server.accept().await.unwrap().await.unwrap() });
        let (first, second) = connections;
        assert_eq!(first.unwrap().connection().stable_id(), second.unwrap().connection().stable_id());
        assert_eq!(server.open_connections(), 1);
        let mut stream = handler.connect_stream(&session, dns).await.unwrap();
        stream.write_all(b"request").await.unwrap();
        stream.shutdown().await.unwrap();
        let (mut send, mut recv) = peer.accept_bi().await.unwrap();
        assert_eq!(recv.read_u8().await.unwrap(), 0x01);
        assert_eq!(SocksAddr::read_from(&mut recv).await.unwrap(), session.destination);
        let mut body = [0; 7];
        recv.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"request");
        assert_eq!(recv.read(&mut [0; 1]).await.unwrap(), None);
        send.write_all(b"response").await.unwrap();
        send.finish().unwrap();
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"response");
    }).await.unwrap();
}

#[tokio::test]
async fn closed_connection_is_replaced_and_server_dns_is_refreshed() {
    timeout(DEADLINE, async {
        let server = server(true);
        let mut opts = options(&server);
        opts.addr = format!("sq.invalid:{}", server.local_addr().unwrap().port());
        let handler = Handler::new("sq".into(), opts);
        let mut dns = MockClashResolver::new();
        dns.expect_resolve().times(2)
            .returning(|_, _| Ok(Some(Ipv4Addr::LOCALHOST.into())));
        let dns: ThreadSafeDNSResolver = Arc::new(dns);
        let session = Session::default();
        let (first, peer) = tokio::join!(handler.prepare_conn(&session, dns.clone()), async {
            server.accept().await.unwrap().await.unwrap()
        });
        let first = first.unwrap();
        peer.close(0u8.into(), b"test reconnect");
        first.connection().closed().await;
        let (second, _peer) = tokio::join!(handler.prepare_conn(&session, dns.clone()), async {
            server.accept().await.unwrap().await.unwrap()
        });
        assert_ne!(first.connection().stable_id(), second.unwrap().connection().stable_id());
    }).await.unwrap();
}

#[tokio::test]
async fn wrong_credentials_and_plain_tls_are_rejected() {
    timeout(DEADLINE, async {
        for jls in [true, false] {
            let server = server(jls);
            let mut opts = options(&server);
            if jls { opts.password = "wrong-password".into(); }
            let endpoint = ClientEndpoint::new(
                &opts, server.local_addr().unwrap(), &Session::default(),
            ).await.unwrap();
            let accepting = server.clone();
            let task = tokio::spawn(async move {
                let _ = accepting.accept().await.unwrap().await;
            });
            let result = endpoint.connect_with_timeout(
                &opts, server.local_addr().unwrap(), Duration::from_millis(300),
            ).await;
            assert!(result.is_err());
            task.abort();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn zero_rtt_configuration_reconnects_with_jls() {
    timeout(DEADLINE, async {
        let server = server(true);
        let mut opts = options(&server);
        opts.zero_rtt = true;
        let endpoint = ClientEndpoint::new(
            &opts, server.local_addr().unwrap(), &Session::default(),
        ).await.unwrap();
        for _ in 0..2 {
            let (client, peer) = tokio::join!(endpoint.connect(&opts, server.local_addr().unwrap()), async {
                server.accept().await.unwrap().await.unwrap()
            });
            let client = client.unwrap();
            let (mut send, mut recv) = client.open_bi().await.unwrap();
            protocol::write_request(&mut send, protocol::CONNECT,
                &"127.0.0.1:80".parse().unwrap()).await.unwrap();
            let (mut reply, mut request) = peer.accept_bi().await.unwrap();
            assert_eq!(request.read_u8().await.unwrap(), 0x01);
            let _ = SocksAddr::read_from(&mut request).await.unwrap();
            reply.write_u8(1).await.unwrap();
            assert_eq!(recv.read_u8().await.unwrap(), 1);
            assert_eq!(client.is_jls(), Some(true));
            client.close(0u8.into(), b"test reconnect");
            peer.closed().await;
        }
    }).await.unwrap();
}
