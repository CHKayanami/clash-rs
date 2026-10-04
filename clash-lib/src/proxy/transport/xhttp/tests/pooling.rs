use std::{sync::{Arc, atomic::Ordering}, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, time::{sleep, timeout}};
use crate::config::internal::proxy::XHttpReuseSettings;
use super::{Client, options, server::Server};

fn configured(settings: XHttpReuseSettings) -> Client {
    let mut opts = options("packet-up"); opts.reuse_settings = Some(settings);
    Client::new(&opts, "example.test", false, false, Some(&["h2".into()])).unwrap()
}

#[tokio::test]
async fn xhttp_delayed_h2_settings_wake_capacity_waiter() {
    timeout(Duration::from_secs(5), async {
        for mode in ["packet-up", "stream-up", "stream-one"] {
            let opts = options(mode);
            let mut state = Server::new(1);
            state.options = opts.clone();
            state.h2_streams = 1;
            state.h2_settings_delay = Duration::from_millis(50);
            let server = Arc::new(state);
            let client = Client::new(&opts, "example.test", false, false, Some(&["h2".into()])).unwrap();
            round_trip(&client, &server, None).await;
        }
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_h2_peer_stream_limits_leave_room_for_uploads() {
    timeout(Duration::from_secs(10), async {
        for limit in [1, 2, 4] {
            for mode in ["packet-up", "stream-up", "stream-one"] {
                let mut opts = options(mode);
                opts.reuse_settings = Some(XHttpReuseSettings::default());
                let mut state = Server::new(1);
                state.h2_streams = limit;
                state.options = opts.clone();
                let server = Arc::new(state);
                let client = Client::new(&opts, "example.test", false, false, Some(&["h2".into()])).unwrap();
                let mut streams = Vec::new();
                for _ in 0..8 {
                    streams.push(client.connect_with_factories(server.factory(true), None).await.unwrap());
                }
                for stream in &mut streams {
                    stream.write_all(b"x").await.unwrap();
                    stream.flush().await.unwrap();
                    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 1);
                }
                assert!(server.connections.load(Ordering::Acquire) > 1);
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_explicit_connection_count_expands_then_reuses() {
    timeout(Duration::from_secs(5), async {
        let server = Arc::new(Server::new(1));
        let client = configured(XHttpReuseSettings { max_connections: Some("3".into()), ..Default::default() });
        for expected in [1, 2, 3, 3, 3] {
            round_trip(&client, &server, None).await;
            assert_eq!(server.connections.load(Ordering::Acquire), expected);
        }
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_long_lived_downloads_do_not_starve_uploads() {
    timeout(Duration::from_secs(5), async {
        for h2 in [false, true] {
            let server = Arc::new(Server::new(1));
            let mut opts = options("packet-up");
            opts.reuse_settings = Some(XHttpReuseSettings::default());
            let client = Client::new(&opts, "example.test", false, false,
                Some(&[if h2 { "h2" } else { "http/1.1" }.into()])).unwrap();
            let mut streams = Vec::new();
            for _ in 0..32 {
                streams.push(client.connect_with_factories(server.factory(h2), None).await.unwrap());
            }
            streams[0].write_all(b"x").await.unwrap();
            streams[0].flush().await.unwrap();
            assert_eq!(streams[0].read(&mut [0; 1]).await.unwrap(), 1);
        }
    }).await.unwrap();
}

async fn round_trip(client: &Client, server: &Arc<Server>, key: Option<&str>) {
    let mut factory = server.factory(true);
    if let Some(key) = key { factory.key = key.into(); }
    let mut stream = client.connect_with_factories(factory, None).await.unwrap();
    let mut received = Vec::new();
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let (read, write) = tokio::join!(reader.read_to_end(&mut received), async {
        writer.write_all(b"x").await?; writer.shutdown().await
    });
    read.unwrap(); write.unwrap(); assert_eq!(received, b"x");
}

#[tokio::test]
async fn xhttp_pool_reuses_connections_and_isolates_dial_contexts() {
    timeout(Duration::from_secs(5), async {
        let server = Arc::new(Server::new(1));
        let client = configured(XHttpReuseSettings { h_keep_alive_period: Some(-1), ..Default::default() });
        round_trip(&client, &server, None).await;
        round_trip(&client, &server, None).await;
        assert_eq!(server.connections.load(Ordering::Acquire), 1);
        round_trip(&client, &server, Some("other-route")).await;
        assert_eq!(server.connections.load(Ordering::Acquire), 2);
        round_trip(&client, &server, None).await;
        assert_eq!(server.connections.load(Ordering::Acquire), 2);
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_pool_retires_by_reuse_count_request_count_and_lifetime() {
    timeout(Duration::from_secs(10), async {
        let server = Arc::new(Server::new(1));
        let client = configured(XHttpReuseSettings { c_max_reuse_times: Some("1".into()), ..Default::default() });
        round_trip(&client, &server, None).await; round_trip(&client, &server, None).await;
        assert_eq!(server.connections.load(Ordering::Acquire), 1);
        round_trip(&client, &server, None).await;
        assert_eq!(server.connections.load(Ordering::Acquire), 2);
        let server = Arc::new(Server::new(1));
        let client = configured(XHttpReuseSettings { h_max_request_times: Some("1".into()), ..Default::default() });
        round_trip(&client, &server, None).await; round_trip(&client, &server, None).await;
        assert_eq!(server.connections.load(Ordering::Acquire), 2);
        let server = Arc::new(Server::new(1));
        let client = configured(XHttpReuseSettings { h_max_reusable_secs: Some("1".into()), ..Default::default() });
        round_trip(&client, &server, None).await;
        sleep(Duration::from_millis(1100)).await;
        round_trip(&client, &server, None).await;
        assert_eq!(server.connections.load(Ordering::Acquire), 2);
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_pool_concurrency_limit_waits_and_releases_on_drop() {
    timeout(Duration::from_secs(5), async {
        let server = Arc::new(Server::new(1));
        let client = configured(XHttpReuseSettings { max_concurrency: Some("1".into()), max_connections: Some("1".into()), ..Default::default() });
        let stream = client.connect_with_factories(server.factory(true), None).await.unwrap();
        assert!(timeout(Duration::from_millis(100), client.connect_with_factories(server.factory(true), None)).await.is_err());
        drop(stream);
        round_trip(&client, &server, None).await;
        assert_eq!(server.connections.load(Ordering::Acquire), 1);
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_pool_expiration_wakes_waiters_without_killing_live_streams() {
    timeout(Duration::from_secs(5), async {
        let server = Arc::new(Server::new(1));
        let client = configured(XHttpReuseSettings { max_concurrency: Some("1".into()), max_connections: Some("1".into()),
            h_max_reusable_secs: Some("1".into()), ..Default::default() });
        let mut stream = client.connect_with_factories(server.factory(true), None).await.unwrap();
        round_trip(&client, &server, None).await;
        stream.write_all(b"x").await.unwrap(); stream.flush().await.unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 1);
        assert_eq!(server.connections.load(Ordering::Acquire), 2);
    }).await.unwrap();
}
