use std::{future::pending, time::Duration};
use bytes::Bytes;
use h2::server::{Builder as ServerBuilder, handshake};
use http::Request;
use tokio::{io::duplex, spawn, sync::oneshot, task::yield_now, time::{advance, timeout}};
use super::{ConnectionDriver, MAX_WRITE_SIZE, client_builder, release_receive_capacity, send_bytes};

#[tokio::test]
async fn final_data_ends_stream_without_an_extra_empty_frame() {
    for (length, window) in [(32, 65535), (MAX_WRITE_SIZE * 2 + 3, 1024), (0, 0)] {
        let (client, peer) = duplex(4096);
        let (request_tx, request_rx) = oneshot::channel();
        let server = spawn(async move {
            let mut builder = ServerBuilder::new();
            builder.initial_window_size(window);
            let mut connection = builder.handshake::<_, Bytes>(peer).await.unwrap();
            let (request, response) = connection.accept().await.unwrap().unwrap();
            request_tx.send((request.into_body(), response)).unwrap();
            while connection.accept().await.is_some() {}
        });
        let (mut sender, connection) = client_builder().handshake(client).await.unwrap();
        let driver = ConnectionDriver::spawn(connection, None);
        let (response, mut send) = sender.send_request(
            Request::builder().uri("https://example.test/").body(()).unwrap(), false,
        ).unwrap();
        let (mut recv, respond) = request_rx.await.unwrap();
        let payload = Bytes::from(vec![0x5a; length]);
        let reading = async {
            let mut received = Vec::new();
            let mut frames = 0;
            while let Some(data) = recv.data().await {
                let data = data.unwrap();
                if length != 0 { assert!(!data.is_empty()); }
                frames += 1;
                received.extend_from_slice(&data);
                release_receive_capacity(&mut recv, data.len()).unwrap();
            }
            assert_eq!(received.as_slice(), payload.as_ref());
            if length == 32 { assert_eq!(frames, 1); }
        };
        timeout(Duration::from_secs(2), async {
            let (sent, ()) = tokio::join!(send_bytes(&mut send, payload.clone(), true), reading);
            sent.unwrap();
        }).await.unwrap();
        drop((recv, respond, response, send, sender, driver));
        timeout(Duration::from_secs(1), server).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn dropping_driver_closes_idle_connection() {
    let (client, peer) = duplex(4096);
    let server = spawn(async move {
        let mut connection = handshake(peer).await.unwrap();
        assert!(connection.accept().await.is_none());
    });
    let (sender, connection) = client_builder().handshake(client).await.unwrap();
    let driver = ConnectionDriver::spawn(connection, None);
    let state = driver.state();
    state.initialized().await.unwrap();
    drop(driver);
    assert!(state.closed());
    timeout(Duration::from_secs(1), server).await.unwrap().unwrap();
    drop(sender);
}

#[tokio::test(start_paused = true)]
async fn idle_keepalive_timeout_closes_connection() {
    let (client, peer) = duplex(4096);
    let (stop, stopped) = oneshot::channel();
    let (parked, parked_rx) = oneshot::channel();
    let server = spawn(async move {
        let mut connection = handshake(peer).await.unwrap();
        tokio::select! {
            _ = stopped => {},
            _ = connection.accept() => panic!("unexpected request"),
        }
        let _ = parked.send(());
        pending::<()>().await;
        drop(connection);
    });
    let mut builder = client_builder();
    builder.initial_max_send_streams(0);
    let (sender, connection) = builder.handshake(client).await.unwrap();
    let driver = ConnectionDriver::spawn(connection, Some(Duration::from_secs(1)));
    driver.state().initialized().await.unwrap();
    stop.send(()).unwrap();
    parked_rx.await.unwrap();
    advance(Duration::from_secs(1)).await;
    yield_now().await;
    advance(Duration::from_secs(11)).await;
    yield_now().await;
    assert!(driver.closed());
    drop((sender, driver));
    server.abort();
}
