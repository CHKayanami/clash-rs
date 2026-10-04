use std::{net::SocketAddr, sync::{Arc, atomic::Ordering}, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, time::timeout};

use super::Handler;
use crate::{
    app::dns::{SystemResolver, ThreadSafeDNSResolver},
    config::internal::proxy::{CommonConfigOptions, OutboundVless, RealityOpt, XHttpOpt},
    proxy::{AnyStream, OutboundHandler, UdpPacket,
        transport::{TlsClient, TransportLayer}},
    session::{Session, SocksAddr},
};

#[derive(Deserialize)]
struct Fixture {
    server: String,
    uuid: String,
    tcp_target: String,
    udp_target: String,
    tls_target: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    port: u16,
    vision: bool,
    encryption: String,
    #[serde(default)]
    tls: bool,
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    alpn: Option<Vec<String>>,
    #[serde(default)]
    reality: Option<RealityOpt>,
    #[serde(default)]
    client_fingerprint: Option<String>,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    xhttp_opts: Option<XHttpOpt>,
}

fn handler(fixture: &Fixture, case: &Case, resume: bool) -> Result<Handler> {
    Ok(Handler::try_from(OutboundVless {
        common_opts: CommonConfigOptions {
            name: case.name.clone(),
            server: fixture.server.clone(),
            port: case.port,
            ..Default::default()
        },
        uuid: fixture.uuid.clone(),
        encryption: Some(if resume {
            case.encryption.clone()
        } else {
            case.encryption.replace(".0rtt.", ".1rtt.")
        }),
        udp: Some(true),
        tls: Some(case.tls),
        skip_cert_verify: Some(case.tls && case.reality.is_none()),
        server_name: case.server_name.clone(),
        alpn: case.alpn.clone(),
        reality_opts: case.reality.clone(),
        client_fingerprint: case.client_fingerprint.clone(),
        network: case.network.clone(),
        xhttp_opts: case.xhttp_opts.clone().map(Box::new),
        flow: case.vision.then(|| "xtls-rprx-vision".to_owned()),
        ..Default::default()
    })?)
}

fn session(target: &str) -> Result<Session> {
    Ok(Session {
        destination: SocksAddr::from(target.parse::<SocketAddr>()?),
        ..Default::default()
    })
}

async fn echo(stream: &mut AnyStream) -> Result<()> {
    for size in [1, 8193, 131072] {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let (mut reader, mut writer) = tokio::io::split(&mut *stream);
        let mut received = vec![0; size];
        tokio::try_join!(
            async {
                writer.write_all(&payload).await?;
                writer.flush().await
            },
            async { reader.read_exact(&mut received).await.map(|_| ()) },
        )?;
        ensure!(received == payload, "TCP echo payload mismatch ({size} bytes)");
    }
    Ok(())
}

async fn run_case(
    fixture: &Fixture, case: &Case, resolver: ThreadSafeDNSResolver,
) -> Result<()> {
    let client = handler(fixture, case, true)?;
    let tcp = session(&fixture.tcp_target)?;
    for connection in 0..3 {
        if connection > 0 && let Some(encryption) = &client.encryption {
            ensure!(encryption.cached_ticket().is_some(),
                "missing authenticated session ticket before resumption");
        }
        let mut stream = client.connect_stream(&tcp, resolver.clone()).await?;
        if let Some(protocols) = &case.alpn && case.network.as_deref() != Some("xhttp") {
            let negotiated = match &stream {
                AnyStream::Vless(vless) => vless.transport_alpn(),
                AnyStream::Vision(vision) => vision.transport_alpn(),
                _ => bail!("unexpected VLESS stream variant"),
            };
            if protocols.is_empty() {
                ensure!(negotiated.is_none(), "explicit empty ALPN was ignored");
            } else {
                // Xray Reality deliberately leaves server NextProtos unset.
                // The offered ClientHello is verified by the local handshake test.
                if let Some(selected) = negotiated {
                    ensure!(protocols.iter().any(|protocol| {
                        protocol.as_bytes() == selected
                    }), "negotiated ALPN was not offered");
                } else {
                    ensure!(case.reality.is_some(), "TLS ALPN was not negotiated");
                }
            }
        }
        echo(&mut stream).await.context(format!("TCP connection {connection}"))?;
        stream.shutdown().await?;
    }

    let full = handler(fixture, case, false)?;
    for _ in 0..2 {
        let mut stream = full.connect_stream(&tcp, resolver.clone()).await?;
        echo(&mut stream).await.context("forced 1-RTT")?;
        stream.shutdown().await?;
    }

    let udp = session(&fixture.udp_target)?;
    let mut datagram = client.connect_datagram(&udp, resolver.clone()).await?;
    for size in [32, 1200, 2048] {
        let payload = Bytes::from(vec![0x5a; size]);
        datagram.send(UdpPacket::new(payload.clone(),
            SocksAddr::any_ipv4(), udp.destination.clone())).await?;
        let received = datagram.next().await.context("XUDP stream closed")?;
        ensure!(received.data == payload, "XUDP echo mismatch ({size} bytes)");
    }

    if case.vision {
        let target = session(&fixture.tls_target)?;
        let stream = client.connect_stream(&target, resolver).await?;
        let (read_direct, write_direct) = match &stream {
            AnyStream::Vision(vision) => vision.direct_flags(),
            _ => bail!("expected Vision stream"),
        };
        let tls = TransportLayer::Tls(TlsClient::new(
            true, "localhost".to_owned(), None, None, None, None,
        )?);
        let mut stream = tls.wrap(stream).await.context("inner TLS handshake")?;
        echo(&mut stream).await.context("Vision TLS echo")?;
        ensure!(read_direct.load(Ordering::Acquire), "Vision read Direct not entered");
        ensure!(write_direct.load(Ordering::Acquire), "Vision write Direct not entered");
        stream.shutdown().await?;
    }
    Ok(())
}

/// The manifest supplies temporary public test credentials and remote echo targets.
/// Run explicitly with CLASH_VLESS_INTEROP_MANIFEST and --ignored --nocapture.
#[tokio::test]
#[ignore = "requires an explicitly provisioned remote Xray and fixture manifest"]
async fn xray_encryption_interop() -> Result<()> {
    run_fixture("CLASH_VLESS_INTEROP_MANIFEST").await
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned Xray XHTTP server and fixture manifest"]
async fn xray_xhttp_interop() -> Result<()> {
    run_fixture("CLASH_XHTTP_INTEROP_MANIFEST").await
}

/// Supply an OutboundVless JSON object via CLASH_XHTTP_NODE_CONFIG.
/// Credentials stay outside the repository and test output.
#[tokio::test]
#[ignore = "requires an explicitly supplied live VLESS XHTTP node"]
async fn xhttp_live_node_https() -> Result<()> {
    crate::tests::initialize();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let config = std::env::var("CLASH_XHTTP_NODE_CONFIG")
        .context("set CLASH_XHTTP_NODE_CONFIG to an OutboundVless JSON object")?;
    let opts: OutboundVless = serde_json::from_str(&config)
        .context("invalid node configuration")?;
    ensure!(opts.network.as_deref() == Some("xhttp"), "expected XHTTP transport");
    ensure!(opts.xhttp_opts.is_some(), "set xhttp-opts explicitly");
    let client = Handler::try_from(opts).context("build VLESS XHTTP handler")?;
    let resolver: ThreadSafeDNSResolver = Arc::new(SystemResolver::new(false)?);
    timeout(Duration::from_secs(30), async {
        let sess = Session {
            destination: "example.com:443".parse::<SocksAddr>()?,
            ..Default::default()
        };
        let stream = client.connect_stream(&sess, resolver).await
            .context("connect through VLESS XHTTP")?;
        let tls = TransportLayer::Tls(TlsClient::new(
            false, "example.com".to_owned(), None, None, None, None,
        )?);
        let mut stream = tls.wrap(stream).await
            .context("verify destination TLS through proxy")?;
        stream.write_all(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        ).await.context("send HTTPS request")?;
        stream.flush().await?;
        let mut response = Vec::new();
        stream.take(64 * 1024).read_to_end(&mut response).await
            .context("read HTTPS response")?;
        ensure!(response.starts_with(b"HTTP/1.1 200 ")
            || response.starts_with(b"HTTP/1.0 200 "), "expected HTTP 200");
        ensure!(response.windows(b"Example Domain".len())
            .any(|window| window == b"Example Domain"), "unexpected response body");
        println!("VLESS XHTTP: verified destination TLS and HTTPS response passed");
        Ok::<(), anyhow::Error>(())
    }).await.context("live node HTTPS probe timed out after 30 seconds")?
}

async fn run_fixture(manifest_env: &str) -> Result<()> {
    crate::tests::initialize();
    let path = std::env::var(manifest_env)
        .with_context(|| format!("set {manifest_env} to the test manifest"))?;
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(path)?)?;
    ensure!(!fixture.cases.is_empty(), "empty interoperability matrix");
    let resolver: ThreadSafeDNSResolver = Arc::new(SystemResolver::new(false)?);
    for case in &fixture.cases {
        timeout(Duration::from_secs(90), run_case(&fixture, case, resolver.clone()))
            .await.context(format!("{} timed out", case.name))?
            .with_context(|| case.name.clone())?;
        println!("{}: TCP{}, XUDP{} passed", case.name,
            if case.encryption != "none" { " 1-RTT/0-RTT, forced 1-RTT" } else { "" },
            if case.vision { ", TLS 1.3 Direct" } else { "" });
    }
    Ok(())
}
