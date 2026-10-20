use std::{future::poll_fn, net::{IpAddr, SocketAddr}, sync::{Arc, Mutex}};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Buf, Bytes};
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use quinn::{ClientConfig as QuicClientConfig, Endpoint, crypto::rustls::QuicClientConfig as QuicCryptoConfig};
use rcgen::generate_simple_self_signed;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream, UdpSocket}};
use tokio_rustls::TlsConnector;
use crate::{DNSListenAddr, DNSError, DnsIngress, DnsMessageExchanger, DoHConfig, DoH3Config, DoTConfig, get_dns_listener};

#[derive(Clone, Default)]
pub(super) struct Echo(Arc<Mutex<Vec<DnsIngress>>>);
impl DnsMessageExchanger for Echo {
    fn ipv6(&self) -> bool { true }
    async fn exchange(&self, message: Bytes, source: Option<IpAddr>, ingress: DnsIngress) -> Result<Vec<u8>, DNSError> {
        assert_eq!(source, Some("127.0.0.1".parse().unwrap()));
        self.0.lock().unwrap().push(ingress);
        let mut response = message.to_vec();
        response[2] |= 0x80;
        Ok(response)
    }
}

fn credentials() -> (String, String, ClientConfig) {
    crate::tests::setup_default_crypto_provider();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let client = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    (cert.cert.pem(), cert.signing_key.serialize_pem(), client)
}

async fn tcp_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap()
}
async fn udp_address() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap()
}
fn query() -> Bytes { Bytes::from_static(&[0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) }
fn assert_answer(answer: &[u8]) {
    let mut expected = query().to_vec(); expected[2] = 0x80;
    assert_eq!(answer, expected);
}

#[tokio::test]
async fn dot_frames_and_shutdown_release_active_connections() {
    let (cert, key, mut client) = credentials();
    client.alpn_protocols = vec![b"dot".to_vec()];
    let addr = tcp_address().await;
    let echo = Echo::default();
    let mut listener = get_dns_listener(DNSListenAddr {
        dot: Some(DoTConfig { addr, ca_cert: Some(cert), ca_key: Some(key) }),
        ..Default::default()
    }, echo.clone()).await.unwrap();
    let mut stream = TlsConnector::from(Arc::new(client)).connect(
        ServerName::try_from("localhost").unwrap(), TcpStream::connect(addr).await.unwrap(),
    ).await.unwrap();
    let mut large = vec![0; 4096];
    large[..12].copy_from_slice(&query());
    for message in [query(), Bytes::from(large)] {
        stream.write_u16(message.len() as u16).await.unwrap();
        stream.write_all(&message).await.unwrap();
        let length = stream.read_u16().await.unwrap();
        let mut answer = vec![0; length as usize];
        stream.read_exact(&mut answer).await.unwrap();
        let mut expected = message.to_vec();
        expected[2] |= 0x80;
        assert_eq!(answer, expected);
    }
    listener.shutdown().await;
    let _rebound = TcpListener::bind(addr).await.unwrap();
    assert_eq!(*echo.0.lock().unwrap(), vec![DnsIngress::Dot; 2]);
}

#[tokio::test]
async fn doh_http2_get_post_validation_and_shutdown() {
    let (cert, key, mut client) = credentials();
    client.alpn_protocols = vec![b"h2".to_vec()];
    let addr = tcp_address().await;
    let echo = Echo::default();
    let mut listener = get_dns_listener(DNSListenAddr {
        doh: Some(DoHConfig { addr, ca_cert: Some(cert), ca_key: Some(key), hostname: Some("localhost".into()) }),
        ..Default::default()
    }, echo.clone()).await.unwrap();
    let stream = TlsConnector::from(Arc::new(client)).connect(
        ServerName::try_from("localhost").unwrap(), TcpStream::connect(addr).await.unwrap(),
    ).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await.unwrap();
    let driver = tokio::spawn(connection);
    for method in ["GET", "POST"] {
        let uri = if method == "GET" { format!("https://localhost/dns-query?dns={}", URL_SAFE_NO_PAD.encode(query())) }
            else { "https://localhost/dns-query".into() };
        let request = Request::builder().method(method).uri(uri)
            .header("content-type", "application/dns-message")
            .body(Full::new(if method == "POST" { query() } else { Bytes::new() })).unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/dns-message");
        assert_answer(&response.into_body().collect().await.unwrap().to_bytes());
    }
    for (method, uri, media, status) in [
        ("GET", "https://localhost/invalid", "application/dns-message", StatusCode::NOT_FOUND),
        ("PUT", "https://localhost/dns-query", "application/dns-message", StatusCode::METHOD_NOT_ALLOWED),
        ("POST", "https://localhost/dns-query", "text/plain", StatusCode::UNSUPPORTED_MEDIA_TYPE),
        ("GET", "https://localhost/dns-query?dns=***", "application/dns-message", StatusCode::BAD_REQUEST),
        ("GET", "https://other/dns-query", "application/dns-message", StatusCode::MISDIRECTED_REQUEST),
    ] {
        let response = sender.send_request(Request::builder().method(method).uri(uri)
            .header("content-type", media).body(Full::new(Bytes::new())).unwrap()).await.unwrap();
        assert_eq!(response.status(), status);
    }
    listener.shutdown().await;
    let _rebound = TcpListener::bind(addr).await.unwrap();
    driver.abort();
    assert_eq!(*echo.0.lock().unwrap(), vec![DnsIngress::Doh; 2]);
}

#[tokio::test]
async fn doh3_get_post_and_shutdown_release_quic_socket() {
    let (cert, key, mut client) = credentials();
    client.alpn_protocols = vec![b"h3".to_vec()];
    let addr = udp_address().await;
    let echo = Echo::default();
    let mut listener = get_dns_listener(DNSListenAddr {
        doh3: Some(DoH3Config { addr, ca_cert: Some(cert), ca_key: Some(key), hostname: Some("localhost".into()) }),
        ..Default::default()
    }, echo.clone()).await.unwrap();
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(QuicClientConfig::new(Arc::new(QuicCryptoConfig::try_from(client).unwrap())));
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection)).await.unwrap();
    let task = tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });
    for method in ["GET", "POST"] {
        let uri = if method == "GET" { format!("https://localhost/dns-query?dns={}", URL_SAFE_NO_PAD.encode(query())) }
            else { "https://localhost/dns-query".into() };
        let mut stream = sender.send_request(Request::builder().method(method).uri(uri)
            .header("content-type", "application/dns-message").body(()).unwrap()).await.unwrap();
        if method == "POST" { stream.send_data(query()).await.unwrap(); }
        stream.finish().await.unwrap();
        let response = stream.recv_response().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut answer = Vec::new();
        while let Some(mut data) = stream.recv_data().await.unwrap() {
            let remaining = data.remaining();
            answer.extend_from_slice(&data.copy_to_bytes(remaining));
        }
        assert_answer(&answer);
    }
    listener.shutdown().await;
    let _rebound = UdpSocket::bind(addr).await.unwrap();
    endpoint.close(0_u32.into(), b"done");
    task.abort();
    assert_eq!(*echo.0.lock().unwrap(), vec![DnsIngress::Doh3; 2]);
}

#[tokio::test]
async fn failed_encrypted_startup_releases_other_listeners() {
    let (cert, key, _) = credentials();
    let udp = udp_address().await;
    let dot = tcp_address().await;
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let result = get_dns_listener(DNSListenAddr {
        udp: Some(udp),
        dot: Some(DoTConfig { addr: dot, ca_cert: Some(cert.clone()), ca_key: Some(key.clone()) }),
        doh: Some(DoHConfig { addr: occupied.local_addr().unwrap(), ca_cert: Some(cert), ca_key: Some(key), hostname: None }),
        ..Default::default()
    }, Echo::default()).await;
    assert!(result.is_err());
    let _udp = UdpSocket::bind(udp).await.unwrap();
    let _dot = TcpListener::bind(dot).await.unwrap();
}

#[test]
fn encrypted_configuration_rejects_invalid_or_mismatched_credentials() {
    let (cert, key, _) = credentials();
    let (_, other_key, _) = credentials();
    assert!(super::tls::config(Some(&cert), Some(&other_key), &[b"dot"]).is_err());
    assert!(super::tls::config(Some("-----BEGIN invalid"), Some(&key), &[b"dot"]).is_err());
    assert!(super::tls::config(Some(&cert), None, &[b"dot"]).is_err());
}

#[test]
fn doh_validation_bounds_requests_and_honors_accept() {
    use super::http::prepare;
    let url = format!("https://localhost/dns-query?dns={}", URL_SAFE_NO_PAD.encode(query()));
    for (accept, allowed) in [
        ("application/dns-message", true), ("*/*", true), ("application/*", true),
        ("text/html", false), ("application/dns-message;q=0, */*;q=1", false),
    ] {
        let request = Request::builder().uri(&url).header("accept", accept).body(()).unwrap();
        assert_eq!(prepare(&request, None).is_ok(), allowed);
    }
    let request = Request::builder().method("POST").uri("/dns-query")
        .header("content-type", "application/dns-message").header("content-length", "65536")
        .body(()).unwrap();
    assert_eq!(prepare(&request, None).err(), Some(StatusCode::PAYLOAD_TOO_LARGE));
    let request = Request::builder().uri(format!("{url}&dns=AAAA")).body(()).unwrap();
    assert_eq!(prepare(&request, None).err(), Some(StatusCode::BAD_REQUEST));
}

#[tokio::test]
async fn doh_http1_serves_dns_messages() {
    let (cert, key, mut client) = credentials();
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    let addr = tcp_address().await;
    let echo = Echo::default();
    let mut listener = get_dns_listener(DNSListenAddr {
        doh: Some(DoHConfig { addr, ca_cert: Some(cert), ca_key: Some(key), hostname: None }),
        ..Default::default()
    }, echo.clone()).await.unwrap();
    let mut stream = TlsConnector::from(Arc::new(client)).connect(
        ServerName::try_from("localhost").unwrap(), TcpStream::connect(addr).await.unwrap(),
    ).await.unwrap();
    let request = format!("POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", query().len());
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(&query()).await.unwrap();
    let mut response = Vec::new();
    // TLS close_notify is optional on connection close; the HTTP body has its
    // own length, so an EOF after the complete body is sufficient here.
    let _ = stream.read_to_end(&mut response).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let body = response.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap() + 4;
    assert_answer(&response[body..]);
    listener.shutdown().await;
    assert_eq!(*echo.0.lock().unwrap(), vec![DnsIngress::Doh]);
}
