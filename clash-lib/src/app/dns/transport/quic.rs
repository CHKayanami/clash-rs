use std::sync::Arc;
use std::time::Duration;

use super::dial::dial_candidates;
use crate::app::dns::endpoint::DnsEndpoint;

pub async fn dns_quic_config(alpn: &[&[u8]]) -> anyhow::Result<quinn::ClientConfig> {
    let client_config = crate::common::tls::build_tls_client_config(
        Arc::new(crate::common::tls::DefaultTlsVerifier::new(None, false)),
        None,
        None,
    )?;
    let mut tls_config = client_config;
    tls_config.alpn_protocols = alpn.iter().map(|&x| x.to_vec()).collect();

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|e| anyhow::anyhow!("QUIC client config error: {e}"))?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic_client_config));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    config.transport_config(Arc::new(transport));

    Ok(config)
}

pub struct SharedQuicEndpoint(tokio::sync::Mutex<[Option<quinn::Endpoint>; 2]>);

impl SharedQuicEndpoint {
    pub fn new() -> Self {
        Self(tokio::sync::Mutex::new([None, None]))
    }

    async fn get(&self, ipv6: bool) -> anyhow::Result<quinn::Endpoint> {
        let mut endpoints = self.0.lock().await;
        let endpoint = &mut endpoints[if ipv6 { 1 } else { 0 }];
        if let Some(endpoint) = endpoint.as_ref() {
            return Ok(endpoint.clone());
        }

        let bind_addr = if ipv6 {
            std::net::SocketAddr::from(([0; 16], 0))
        } else {
            std::net::SocketAddr::from(([0, 0, 0, 0], 0))
        };
        let mut created = quinn::Endpoint::client(bind_addr)?;
        let _ = created.set_default_client_config(dns_quic_config(&[b"doq", b"h3"]).await?);
        *endpoint = Some(created.clone());
        Ok(created)
    }

    pub async fn close(&self, timeout: Duration) {
        let endpoints = {
            let mut endpoints = self.0.lock().await;
            [endpoints[0].take(), endpoints[1].take()]
        };
        for endpoint in endpoints.into_iter().flatten() {
            endpoint.close(0_u32.into(), b"shutdown");
            let _ = tokio::time::timeout(timeout, endpoint.wait_idle()).await;
        }
    }
}

async fn quic_connect(
    endpoint: &SharedQuicEndpoint,
    config: &quinn::ClientConfig,
    addr: std::net::SocketAddr,
    sni: &str,
    label: &str,
) -> anyhow::Result<quinn::Connection> {
    let ep = endpoint.get(addr.is_ipv6()).await?;
    let connecting = ep
        .connect_with(config.clone(), addr, sni)
        .map_err(|e| anyhow::anyhow!("{label} connect_with: {e}"))?;
    connecting
        .await
        .map_err(|e| anyhow::anyhow!("{label} handshake: {e}"))
}

pub async fn quic_connect_endpoint(
    endpoint: &SharedQuicEndpoint,
    config: &quinn::ClientConfig,
    target: &DnsEndpoint,
    deadline: tokio::time::Instant,
    label: &str,
) -> anyhow::Result<quinn::Connection> {
    let addresses = tokio::time::timeout_at(deadline, target.resolve_addrs())
        .await
        .map_err(|_| anyhow::anyhow!("{label} address resolution timed out"))??;
    dial_candidates(addresses, deadline, label, |address, _| {
        quic_connect(endpoint, config, address, &target.sni, label)
    })
    .await
}
