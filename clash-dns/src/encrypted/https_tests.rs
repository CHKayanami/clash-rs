use std::{net::SocketAddr, sync::Arc, time::Duration};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2::Builder;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{io::{AsyncReadExt, AsyncWriteExt, duplex}, sync::Semaphore, time::timeout};
use super::http::Service;
use super::https::serve_connection;
use super::tests::Echo;

fn query() -> Bytes { Bytes::from_static(&[0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) }
fn peer() -> SocketAddr { "127.0.0.1:12345".parse().unwrap() }

#[tokio::test]
async fn http2_flow_control_stall_closes_connection_and_releases_admission() {
    for window in [0, 1] {
        let (server, client) = duplex(65536);
        let permits = Arc::new(Semaphore::new(1));
        let service = Arc::new(Service { exchanger: Echo::default(), hostname: None, permits: permits.clone() });
        let server = tokio::spawn(serve_connection(server, peer(), service, true, Duration::from_millis(100)));
        let (mut sender, connection) = Builder::new(TokioExecutor::new())
            .initial_stream_window_size(window).handshake(TokioIo::new(client)).await.unwrap();
        let driver = tokio::spawn(connection);
        let request = Request::builder().method("POST").uri("https://localhost/dns-query")
            .header("content-type", "application/dns-message").body(Full::new(query())).unwrap();
        let response = timeout(Duration::from_secs(1), sender.send_request(request)).await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // Keep the response unread. Even a nonzero window must not release
        // admission when only part of the DATA has been sent.
        assert_eq!(permits.available_permits(), 0);
        timeout(Duration::from_secs(1), server).await.unwrap().unwrap();
        timeout(Duration::from_secs(1), driver).await.unwrap().unwrap().unwrap_err();
        assert_eq!(permits.available_permits(), 1);
        drop(response);
    }
}

#[tokio::test]
async fn http1_client_that_stops_reading_cannot_pin_connection() {
    let (server, mut client) = duplex(1);
    let permits = Arc::new(Semaphore::new(1));
    let service = Arc::new(Service { exchanger: Echo::default(), hostname: None, permits: permits.clone() });
    let server = tokio::spawn(serve_connection(server, peer(), service, false, Duration::from_millis(50)));
    let request = format!("GET /dns-query?dns={} HTTP/1.1\r\nHost: localhost\r\n\r\n", URL_SAFE_NO_PAD.encode(query()));
    client.write_all(request.as_bytes()).await.unwrap();
    timeout(Duration::from_secs(1), server).await.unwrap().unwrap();
    assert_eq!(permits.available_permits(), 1);
}

#[tokio::test]
async fn get_body_is_rejected_before_client_finishes_uploading() {
    let (server, mut client) = duplex(65536);
    let service = Arc::new(Service { exchanger: Echo::default(), hostname: None, permits: Arc::new(Semaphore::new(1)) });
    let server = tokio::spawn(serve_connection(server, peer(), service, false, Duration::from_secs(1)));
    let request = format!("GET /dns-query?dns={} HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n", URL_SAFE_NO_PAD.encode(query()));
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = [0; 256];
    let length = timeout(Duration::from_secs(1), client.read(&mut response)).await.unwrap().unwrap();
    assert!(response[..length].starts_with(b"HTTP/1.1 400 Bad Request"));
    server.abort();
}

#[tokio::test]
async fn http2_successful_response_releases_admission_and_keeps_connection() {
    let (server, client) = duplex(65536);
    let permits = Arc::new(Semaphore::new(1));
    let service = Arc::new(Service { exchanger: Echo::default(), hostname: None, permits: permits.clone() });
    let server = tokio::spawn(serve_connection(server, peer(), service, true, Duration::from_millis(100)));
    let (mut sender, connection) = Builder::new(TokioExecutor::new()).handshake(TokioIo::new(client)).await.unwrap();
    let driver = tokio::spawn(connection);
    for _ in 0..2 {
        let request = Request::builder().method("POST").uri("https://localhost/dns-query")
            .header("content-type", "application/dns-message").body(Full::new(query())).unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await.unwrap();
        assert_eq!(permits.available_permits(), 1);
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!server.is_finished());
    driver.abort();
    server.abort();
}
