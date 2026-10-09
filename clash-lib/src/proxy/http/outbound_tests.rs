use super::*;
use tokio::io::{AsyncReadExt, duplex};
use crate::{config::internal::proxy::OutboundProxyProtocol, session::SocksAddr};

#[tokio::test]
async fn connect_auth_headers_and_buffered_payload() {
    let config: OutboundProxyProtocol = yaml_serde::from_str(r#"
name: http-test
type: http
server: localhost
port: 8080
username: user
password: pass
dialer-proxy: upstream
tfo: true
headers:
  X-Test: value
"#).unwrap();
    let OutboundProxyProtocol::Http(config) = config else { panic!("expected HTTP") };
    assert_eq!(config.common_opts.connect_via.as_deref(), Some("upstream"));
    let handler: Handler = config.try_into().unwrap();
    assert!(handler.opts.common_opts.tfo);
    assert!(!handler.support_udp().await);
    let (client, mut server) = duplex(4096);
    let peer = tokio::spawn(async move {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(server.read_u8().await.unwrap());
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("CONNECT [::1]:443 HTTP/1.1\r\n"));
        assert!(request.contains("Host: [::1]:443\r\n"));
        assert!(request.contains("proxy-authorization: Basic dXNlcjpwYXNz\r\n"));
        assert!(request.contains("x-test: value\r\n"));
        server.write_all(b"HTTP/1.1 200 Connection established\r\n\r\npayload").await.unwrap();
    });
    let sess = Session {
        destination: SocksAddr::Ip("[::1]:443".parse().unwrap()),
        ..Default::default()
    };
    let mut stream = handler.handshake(AnyStream::new(client), &sess).await.unwrap();
    let mut payload = String::new();
    stream.read_to_string(&mut payload).await.unwrap();
    assert_eq!(payload, "payload");
    peer.await.unwrap();
}

#[tokio::test]
async fn rejected_malformed_truncated_and_oversized_responses() {
    for (response, kind) in [
        (b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".to_vec(), io::ErrorKind::PermissionDenied),
        (b"HTTP/1.1 500 Error\r\n\r\n".to_vec(), io::ErrorKind::PermissionDenied),
        (b"INVALID 200 OK\r\n\r\n".to_vec(), io::ErrorKind::InvalidData),
        (b"HTTP/1.1 200 OK\r\n".to_vec(), io::ErrorKind::UnexpectedEof),
        (vec![b'x'; MAX_RESPONSE_HEADER], io::ErrorKind::InvalidData),
    ] {
        let (client, mut server) = duplex(MAX_RESPONSE_HEADER * 2);
        server.write_all(&response).await.unwrap();
        drop(server);
        let error = read_response(AnyStream::new(client)).await.err().unwrap();
        assert_eq!(error.kind(), kind);
    }
}

#[test]
fn reject_header_injection() {
    let opts = HandlerOptions {
        headers: HashMap::from([("X-Test".to_owned(), "value\r\nInjected: yes".to_owned())]),
        ..Default::default()
    };
    assert!(Handler::new(opts, None).is_err());
}

#[tokio::test]
async fn https_proxy_connect() {
    use boring::{pkey::PKey, ssl::{SslAcceptor, SslMethod}, x509::X509};
    use rcgen::{CertificateParams, KeyPair};
    use tokio_boring::accept;
    use crate::setup_default_crypto_provider;

    setup_default_crypto_provider();
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap().self_signed(&key).unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor.set_certificate(&X509::from_pem(cert.pem().as_bytes()).unwrap()).unwrap();
    acceptor.set_private_key(&PKey::private_key_from_pem(key.serialize_pem().as_bytes()).unwrap()).unwrap();
    let acceptor = acceptor.build();
    let config: OutboundProxyProtocol = yaml_serde::from_str(r#"
name: https-test
type: http
server: localhost
port: 443
tls: true
sni: localhost
skip-cert-verify: true
"#).unwrap();
    let OutboundProxyProtocol::Http(config) = config else { panic!("expected HTTP") };
    let handler: Handler = config.try_into().unwrap();
    let (client, server) = duplex(65536);
    let server = async {
        let mut tls = accept(&acceptor, server).await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(tls.read_u8().await.unwrap());
        }
        assert!(request.starts_with(b"CONNECT example.com:80 HTTP/1.1\r\n"));
        tls.write_all(b"HTTP/1.1 200 OK\r\n\r\npong").await.unwrap();
        tls.flush().await.unwrap();
    };
    let client = async {
        let sess = Session {
            destination: SocksAddr::Domain("example.com".into(), 80),
            ..Default::default()
        };
        let mut stream = handler.handshake(AnyStream::new(client), &sess).await.unwrap();
        let mut data = [0; 4];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"pong");
    };
    tokio::join!(client, server);
}
