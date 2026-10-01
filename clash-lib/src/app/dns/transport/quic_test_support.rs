//! Local QUIC and SOCKS5 fixtures: no external DNS or proxy services.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

use super::dial::DialContext;
use crate::app::dns::endpoint::{DnsEndpoint, DnsProtocol, DnsStrategy};
use crate::proxy::socks::inbound::Socks5UdpFramed;
use crate::proxy::socks::outbound::{Handler, HandlerOptions};
use crate::session::SocksAddr;

pub(super) fn server(alpn: &[u8]) -> (quinn::Endpoint, quinn::ClientConfig) {
    #[cfg(feature = "aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key =
        rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der())
            .unwrap();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    tls.alpn_protocols = vec![alpn.to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let endpoint =
        quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![alpn.to_vec()];
    let client = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ));
    (endpoint, client)
}

pub(super) struct SocksProxy {
    pub address: SocketAddr,
    pub relay_address: SocketAddr,
    pub associations: Arc<AtomicUsize>,
    pub forwarded: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl SocksProxy {
    pub async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forward = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let relay_address = forward.local_addr().unwrap();
        let associations = Arc::new(AtomicUsize::new(0));
        let forwarded = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&associations);
        let packets = Arc::clone(&forwarded);
        let task = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 2];
            control.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 5);
            let mut methods = vec![0; greeting[1] as usize];
            control.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&0));
            control.write_all(&[5, 0]).await.unwrap();
            let mut command = [0; 3];
            control.read_exact(&mut command).await.unwrap();
            assert_eq!(command, [5, 3, 0]);
            SocksAddr::read_from(&mut control).await.unwrap();
            let mut response = vec![5, 0, 0];
            SocksAddr::Ip(relay.local_addr().unwrap()).write_buf(&mut response);
            control.write_all(&response).await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let mut relay = Socks5UdpFramed::new(relay);
            let mut client_peer = None;
            let mut buffer = [0; 65535];
            loop {
                tokio::select! {
                    _ = control.read_u8() => break,
                    packet = relay.next() => {
                        let Some(Ok(((target, data), peer))) = packet else { break; };
                        let SocksAddr::Ip(target) = target else { panic!("QUIC peer must be an IP"); };
                        client_peer = Some(peer);
                        forward.send_to(&data, target).await.unwrap();
                        packets.fetch_add(1, Ordering::SeqCst);
                    }
                    response = forward.recv_from(&mut buffer) => {
                        let (len, target) = response.unwrap();
                        relay.send(((bytes::Bytes::copy_from_slice(&buffer[..len]), SocksAddr::Ip(target)), client_peer.unwrap())).await.unwrap();
                    }
                }
            }
        });
        Self {
            address,
            relay_address,
            associations,
            forwarded,
            task,
        }
    }

    pub fn dial(&self, target: SocketAddr, protocol: DnsProtocol) -> DialContext {
        let endpoint = DnsEndpoint::parse(
            &target.to_string(),
            protocol,
            Some("localhost"),
            None,
            DnsStrategy::PreferIpv4,
        )
        .unwrap();
        let handler = Handler::new(
            HandlerOptions {
                name: "test-socks5".into(),
                server: self.address.ip().to_string(),
                port: self.address.port(),
                udp: true,
                ..Default::default()
            },
            None,
        );
        DialContext {
            endpoint,
            query_timeout: Duration::from_secs(2),
            dial_timeout: Duration::from_secs(2),
            outbound: Some(Arc::new(handler)),
            iface: None,
            so_mark: None,
            resolver: None,
        }
    }
}

impl Drop for SocksProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
