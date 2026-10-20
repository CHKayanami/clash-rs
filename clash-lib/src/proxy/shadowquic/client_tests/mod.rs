use std::{io, net::Ipv4Addr, sync::Arc, time::Duration};

use bytes::Bytes;
use quinn_jls::{
    Connection, Endpoint, ServerConfig, TransportConfig,
    crypto::rustls::QuicServerConfig,
    rustls::{
        ServerConfig as TlsServerConfig, jls::JlsServerConfig,
        pki_types::PrivatePkcs8KeyDer, version::TLS13,
    },
};
#[cfg(feature = "aws-lc-rs")]
use quinn_jls::rustls::crypto::aws_lc_rs as crypto_provider;
#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
use quinn_jls::rustls::crypto::ring as crypto_provider;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, time::timeout};

use crate::{
    app::dns::{MockClashResolver, ThreadSafeDNSResolver},
    proxy::{OutboundHandler, datagram::UdpPacket},
    session::{Session, SocksAddr},
};

use super::{Handler, HandlerOptions, endpoint::ClientEndpoint, protocol, udp::ClientConnection};

const DEADLINE: Duration = Duration::from_secs(5);

fn server(jls: bool) -> Endpoint {
    crate::setup_default_crypto_provider();
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let mut crypto = TlsServerConfig::builder_with_provider(
        Arc::new(crypto_provider::default_provider()),
    ).with_protocol_versions(&[&TLS13]).unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        ).unwrap();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    crypto.max_early_data_size = u32::MAX;
    crypto.send_half_rtt_data = true;
    if jls {
        crypto.jls_config = JlsServerConfig::default()
            .add_user("test-password".into(), "test-user".into())
            .with_server_name("localhost".into()).enable(true).into();
    }
    let mut config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto).unwrap(),
    ));
    let mut transport = TransportConfig::default();
    transport.max_concurrent_uni_streams(500u32.into());
    config.transport_config(Arc::new(transport));
    Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap()
}

fn options(server: &Endpoint) -> HandlerOptions {
    HandlerOptions {
        addr: server.local_addr().unwrap().to_string(),
        username: "test-user".into(),
        password: "test-password".into(),
        server_name: "localhost".into(),
        zero_rtt: false,
        ..Default::default()
    }
}

async fn connect(server: &Endpoint) -> (ClientEndpoint, Connection, Connection) {
    let opts = options(server);
    let endpoint = ClientEndpoint::new(
        &opts, server.local_addr().unwrap(), &Session::default(),
    ).await.unwrap();
    let (client, peer) = tokio::join!(endpoint.connect(&opts, server.local_addr().unwrap()), async {
        server.accept().await.unwrap().await.unwrap()
    });
    let client = client.unwrap();
    assert_eq!(client.is_jls(), Some(true));
    assert_eq!(peer.jls_chosen_user().as_deref(), Some("test-user"));
    (endpoint, client, peer)
}

mod batch;
mod config;
mod tcp;
mod udp;
