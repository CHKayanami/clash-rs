use super::*;
use super::super::TransportLayer;
use boring::{pkey::PKey, ssl::{SslAcceptor, SslMethod, SslStream}, x509::X509};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::net::TcpListener;
use std::{thread, time::Duration};
use tokio::{io::{duplex, AsyncReadExt, AsyncWriteExt}, net::TcpStream, time::timeout};
use tokio_boring::accept;
use std::sync::atomic::Ordering;
use crate::setup_default_crypto_provider;

#[test]
fn invalid_certificate_pins_are_rejected_for_both_backends() {
    setup_default_crypto_provider();
    for fingerprint in [Some("chrome"), None] {
        let result = Client::new_advanced(
            true, "localhost".into(), None, None, Some("invalid"),
            fingerprint, None, None,
        );
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidInput));
    }
}

#[tokio::test]
async fn expected_alpn_is_enforced_on_all_tls_paths() {
    setup_default_crypto_provider();
    for (fingerprint, spliced) in [(None, false), (Some("chrome"), false), (None, true), (Some("chrome"), true)] {
        let (cert, key) = generate_test_cert();
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_certificate(&X509::from_pem(cert.as_bytes()).unwrap()).unwrap();
        let key = PKey::private_key_from_pem(key.as_bytes()).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_alpn_select_callback(|_, _| Ok(b"h2"));
        let acceptor = acceptor.build();
        let client = Client::new_advanced(
            true, "localhost".into(), Some(vec!["h2".into()]),
            Some("http/1.1".into()), None, fingerprint, None, None,
        ).unwrap();
        let (client_io, server_io) = duplex(65536);
        let client = async {
            let stream = AnyStream::new(client_io);
            let result = if spliced {
                client.proxy_stream_spliced(stream).await.map(|(tls, _)| tls)
            } else {
                client.proxy_stream(stream).await
            };
            let error = result.err().expect("ALPN mismatch must fail");
            assert!(error.to_string().contains("unexpected alpn protocol"));
        };
        let server = async {
            accept(&acceptor, server_io).await.unwrap();
        };
        tokio::join!(client, server);
    }
}

#[tokio::test]
async fn test_vision_tls_switches_both_directions_to_raw() {
    setup_default_crypto_provider();
    for fingerprint in [Some("chrome"), None] {
        let (cert, key) = generate_test_cert();
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_certificate(&X509::from_pem(cert.as_bytes()).unwrap()).unwrap();
        let key = PKey::private_key_from_pem(key.as_bytes()).unwrap();
        acceptor.set_private_key(&key).unwrap();
        let acceptor = acceptor.build();
        let (client_io, server_io) = duplex(65536);
        let server = async {
            let mut tls = accept(&acceptor, server_io).await.unwrap();
            let mut data = [0; 4];
            tls.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"ping");
            tls.write_all(b"pong").await.unwrap();
            tls.flush().await.unwrap();
            // Simulate the server's CMD_DIRECT transition: subsequent
            // bytes are inner TLS records, outside the outer TLS layer.
            tls.get_mut().write_all(b"\x17\x03\x03\x00\x04raw!").await.unwrap();
            tls.get_mut().read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"raw?");
        };
        let client = async {
            let client = Client::new_advanced(
                true, "localhost".into(), None, None, None,
                fingerprint, None, None,
            ).unwrap();
            let layer = TransportLayer::Tls(client);
            let (mut stream, flags) = layer.wrap_spliced(AnyStream::new(client_io)).await.unwrap();
            let flags = flags.expect("TLS Vision transport must support splice");
            stream.write_all(b"ping").await.unwrap();
            stream.flush().await.unwrap();
            let mut reply = [0; 4];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"pong");
            flags.read_flag.store(true, Ordering::Release);
            let mut raw = [0; 9];
            stream.read_exact(&mut raw).await.unwrap();
            assert_eq!(&raw, b"\x17\x03\x03\x00\x04raw!");
            flags.write_flag.store(true, Ordering::Release);
            stream.write_all(b"raw?").await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
        };
        timeout(Duration::from_secs(10), async {
            tokio::join!(client, server);
        }).await.unwrap();
    }
}

fn generate_test_cert() -> (String, String) {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.distinguished_name = DistinguishedName::new();
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn spawn_server(cert_pem: &str, key_pem: &str) -> (u16, thread::JoinHandle<Vec<u8>>) {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_pem(cert_pem.as_bytes()).unwrap())
        .unwrap();
    let pkey = PKey::private_key_from_pem(key_pem.as_bytes()).unwrap();
    acceptor.set_private_key(&pkey).unwrap();
    let acceptor = acceptor.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut tls: SslStream<_> = acceptor.accept(stream).unwrap();
        use std::io::Read;
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).ok();
        buf
    });
    (port, handle)
}

#[tokio::test]
async fn test_transport_tls_client_chrome_fingerprint() {
    let (cert, key) = generate_test_cert();
    let (port, server) = spawn_server(&cert, &key);

    let opts = TLSOptions {
        skip_cert_verify: true,
        sni: "localhost".to_string(),
        alpn: Some(vec!["h2".to_string(), "http/1.1".to_string()]),
        client_fingerprint: Some("chrome".to_string()),
        ..Default::default()
    };

    let client: Client = opts.try_into().unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut stream = client.proxy_stream(AnyStream::Tcp(tcp)).await.unwrap();

    stream.write_all(b"ping from chrome").await.unwrap();
    stream.shutdown().await.unwrap();

    let received = server.join().unwrap();
    assert_eq!(received, b"ping from chrome");
}
