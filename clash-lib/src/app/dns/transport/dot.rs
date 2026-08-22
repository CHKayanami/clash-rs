//! DNS over TLS (RFC 7858) with an idle connection pool.

use std::sync::Arc;

use parking_lot::Mutex;
use tokio_rustls::client::TlsStream;

use super::dial::DialContext;
use super::idle_pool::{IdlePoolState, close_idle_pool, idle_pool_exchange};
use super::retry::exchange_with_retry;
use crate::app::dispatcher::BoxedChainedStream;

type PooledDotStream = TlsStream<BoxedChainedStream>;

/// Idle-pool DoT client for one upstream.
pub struct DotPool {
    dial: DialContext,
    lifecycle: tokio::sync::RwLock<IdlePoolState>,
    idle: Mutex<Vec<PooledDotStream>>,
}

impl DotPool {
    pub fn new(dial: DialContext) -> anyhow::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            dial,
            lifecycle: tokio::sync::RwLock::new(IdlePoolState::Open),
            idle: Mutex::new(Vec::new()),
        }))
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry("DoT", || self.exchange_once(raw_query), || async {}).await
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        idle_pool_exchange(
            &self.lifecycle,
            &self.idle,
            || self.dial_tls(),
            raw_query,
            self.dial.query_timeout,
        )
        .await
    }

    async fn dial_tls(&self) -> anyhow::Result<PooledDotStream> {
        let deadline = tokio::time::Instant::now() + self.dial.dial_timeout;
        let tcp = self.dial.dial_tcp_until(deadline).await?;
        let server_name = rustls::pki_types::ServerName::try_from(self.dial.endpoint.sni.clone())
            .map_err(|e| anyhow::anyhow!("invalid SNI {}: {e}", self.dial.endpoint.sni))?;

        let client_config = crate::common::tls::build_tls_client_config(
            Arc::new(crate::common::tls::DefaultTlsVerifier::new(None, false)),
            None,
            None,
        )?;
        let mut config = client_config;
        config.alpn_protocols = vec![b"dot".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let tls_stream = tokio::time::timeout_at(deadline, connector.connect(server_name, tcp))
            .await
            .map_err(|_| anyhow::anyhow!("DoT TLS handshake timed out"))??;

        Ok(tls_stream)
    }

    pub async fn close(&self) {
        close_idle_pool(&self.lifecycle, &self.idle, self.dial.query_timeout).await;
    }
}
