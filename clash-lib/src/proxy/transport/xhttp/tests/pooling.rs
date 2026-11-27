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

async fn wait_active_connections(server: &Server, expected: usize) {
    timeout(Duration::from_secs(2), async {
        while server.active_connections.load(Ordering::Acquire) != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timed out waiting for expected active HTTP connections");
}

#[tokio::test]
async fn xhttp_keep_idle_false_evicts_idle_upload_and_download_pools_and_drains_active() {
    timeout(Duration::from_secs(5), async {
        for mode in ["packet-up", "stream-up", "stream-one"] {
            let mut opts = options(mode);
            opts.reuse_settings = Some(XHttpReuseSettings {
                h_keep_alive_period: Some(-1),
                c_max_reuse_times: Some("4".into()),
                ..Default::default()
            });
            let mut upload_state = Server::new(1);
            upload_state.options = opts.clone();
            upload_state.post_delay = Duration::from_millis(80);
            let mut download_state = Server::new(1);
            download_state.options = opts.clone();
            if mode != "stream-one" {
                download_state.share_sessions(&upload_state);
            }
            let upload_server = Arc::new(upload_state);
            let download_server = Arc::new(download_state);

            let mut client = Client::new(&opts, "example.test", false, false, Some(&["h2".into()])).unwrap();
            if mode != "stream-one" {
                client.configure_download(&opts, "download.test".into(), 443, None, Some(&["h2".into()])).unwrap();
            }

            let download_factory = (mode != "stream-one").then(|| download_server.factory(true));

            // 1. Active stream runs, then keep_idle is disabled: active stream stays alive.
            let mut stream = client
                .connect_with_factories(upload_server.factory(true), download_factory.clone())
                .await
                .unwrap();
            stream.write_all(b"x").await.unwrap();
            stream.flush().await.unwrap();
            wait_active_connections(&upload_server, 1).await;
            if mode != "stream-one" {
                wait_active_connections(&download_server, 1).await;
            }
            client.set_keep_idle(false);
            assert_eq!(upload_server.active_connections.load(Ordering::Acquire), 1);
            if mode != "stream-one" {
                assert_eq!(download_server.active_connections.load(Ordering::Acquire), 1);
            }

            stream.shutdown().await.unwrap();
            let mut out = Vec::new();
            stream.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, b"x");

            // Drop stream: all background upload/download tasks exit and release HTTP connections.
            drop(stream);
            wait_active_connections(&upload_server, 0).await;
            if mode != "stream-one" {
                wait_active_connections(&download_server, 0).await;
            }

            // 2. Reselect keep_idle=true rebuilds and caches idle connection; disabling
            // keep_idle while idle immediately evicts and closes underlying sockets.
            client.set_keep_idle(true);
            let mut s2 = client
                .connect_with_factories(upload_server.factory(true), download_factory.clone())
                .await
                .unwrap();
            s2.write_all(b"x").await.unwrap();
            s2.shutdown().await.unwrap();
            let mut out2 = Vec::new();
            s2.read_to_end(&mut out2).await.unwrap();
            assert_eq!(out2, b"x");
            assert_eq!(upload_server.active_connections.load(Ordering::Acquire), 1);
            drop(s2);
            client.set_keep_idle(false);
            wait_active_connections(&upload_server, 0).await;
            if mode != "stream-one" {
                wait_active_connections(&download_server, 0).await;
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_health_check_and_reselect_preserve_reuse_limits() {
    timeout(Duration::from_secs(5), async {
        let server = Arc::new(Server::new(1));
        let client = configured(XHttpReuseSettings {
            h_keep_alive_period: Some(-1),
            c_max_reuse_times: Some("1".into()),
            ..Default::default()
        });

        // Probe with keep_idle = false: connection closes immediately after probe finishes.
        client.set_keep_idle(false);
        round_trip(&client, &server, None).await;
        wait_active_connections(&server, 0).await;

        // Failed probe (dial error) leaves no connection cached.
        let failing = super::super::connection::ConnectionFactory {
            key: "fail".into(),
            dial: Arc::new(|| Box::pin(async { Err(std::io::Error::other("dial failed")) })),
        };
        assert!(client.connect_with_factories(failing, None).await.is_err());
        wait_active_connections(&server, 0).await;

        // Brief deselect -> reselect while stream is active keeps reusing the entry
        // and still enforces c_max_reuse_times = 1 (1 initial + 1 reuse = 2 requests).
        client.set_keep_idle(true);
        let before = server.connections.load(Ordering::Acquire);
        let active = client.connect_with_factories(server.factory(true), None).await.unwrap();
        client.set_keep_idle(false);
        client.set_keep_idle(true);
        round_trip(&client, &server, None).await;
        assert_eq!(server.connections.load(Ordering::Acquire), before + 1);
        drop(active);

        // Next request exceeds c_max_reuse_times=1 and opens a fresh connection.
        round_trip(&client, &server, None).await;
        assert_eq!(server.connections.load(Ordering::Acquire), before + 2);
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_keep_idle_false_respects_connection_and_concurrency_limits() {
    timeout(Duration::from_secs(5), async {
        // 1. max_connections=1, max_concurrency=1 with keep_idle=false:
        // second overlapping request waits for the active lease instead of bypassing limits.
        let server = Arc::new(Server::new(1));
        let client = Arc::new(configured(XHttpReuseSettings {
            h_keep_alive_period: Some(-1),
            max_connections: Some("1".into()),
            max_concurrency: Some("1".into()),
            ..Default::default()
        }));
        client.set_keep_idle(false);

        let mut s1 = client
            .connect_with_factories(server.factory(true), None)
            .await
            .unwrap();
        s1.write_all(b"x").await.unwrap();
        s1.flush().await.unwrap();
        wait_active_connections(&server, 1).await;

        let client2 = client.clone();
        let server2 = server.clone();
        let mut second = tokio::spawn(async move {
            client2
                .connect_with_factories(server2.factory(true), None)
                .await
                .unwrap()
        });
        assert!(timeout(Duration::from_millis(80), &mut second).await.is_err());
        assert_eq!(server.connections.load(Ordering::Acquire), 1);

        // Finishing and dropping s1 releases the concurrency slot so s2 proceeds,
        // and once s2 finishes the entry is evicted immediately.
        s1.shutdown().await.unwrap();
        let mut out1 = Vec::new();
        s1.read_to_end(&mut out1).await.unwrap();
        assert_eq!(out1, b"x");
        drop(s1);

        let mut s2 = second.await.unwrap();
        s2.write_all(b"x").await.unwrap();
        s2.shutdown().await.unwrap();
        let mut out2 = Vec::new();
        s2.read_to_end(&mut out2).await.unwrap();
        assert_eq!(out2, b"x");
        drop(s2);
        wait_active_connections(&server, 0).await;

        // 2. max_connections=1, max_concurrency=2 with keep_idle=false:
        // two overlapping requests share the single active connection, then reclaim it.
        let server_shared = Arc::new(Server::new(1));
        let client_shared = configured(XHttpReuseSettings {
            h_keep_alive_period: Some(-1),
            max_connections: Some("1".into()),
            max_concurrency: Some("2".into()),
            ..Default::default()
        });
        client_shared.set_keep_idle(false);

        let mut a = client_shared
            .connect_with_factories(server_shared.factory(true), None)
            .await
            .unwrap();
        let mut b = client_shared
            .connect_with_factories(server_shared.factory(true), None)
            .await
            .unwrap();
        a.write_all(b"x").await.unwrap();
        a.shutdown().await.unwrap();
        b.write_all(b"x").await.unwrap();
        b.shutdown().await.unwrap();
        let mut out_a = Vec::new();
        let mut out_b = Vec::new();
        a.read_to_end(&mut out_a).await.unwrap();
        b.read_to_end(&mut out_b).await.unwrap();
        assert_eq!(out_a, b"x");
        assert_eq!(out_b, b"x");
        assert_eq!(server_shared.connections.load(Ordering::Acquire), 1);
        drop(a);
        drop(b);
        wait_active_connections(&server_shared, 0).await;
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_packet_up_multi_post_task_lease_reclaims_only_on_last_exit() {
    timeout(Duration::from_secs(5), async {
        let mut opts = options("packet-up");
        opts.sc_max_each_post_bytes = Some("1".into());
        opts.reuse_settings = Some(XHttpReuseSettings {
            h_keep_alive_period: Some(-1),
            ..Default::default()
        });
        let mut state = Server::new(4);
        state.options = opts.clone();
        state.post_delay = Duration::from_millis(40);
        let server = Arc::new(state);
        let client = Client::new(&opts, "example.test", false, false, Some(&["h2".into()])).unwrap();
        client.set_keep_idle(false);

        let mut stream = client
            .connect_with_factories(server.factory(true), None)
            .await
            .unwrap();
        stream.write_all(b"abcd").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"abcd");
        drop(stream);

        wait_active_connections(&server, 0).await;
    }).await.unwrap();
}
