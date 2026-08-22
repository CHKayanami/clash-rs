//! DNS over QUIC (RFC 9250).

use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Connection};

use crate::app::dns::endpoint::DnsEndpoint;
use super::lifecycle::LifecycleSlot;
use super::quic::{SharedQuicEndpoint, dns_quic_config, quic_connect_endpoint};
use super::retry::exchange_with_retry;

pub struct DoqClient {
    endpoint: DnsEndpoint,
    query_timeout: Duration,
    dial_timeout: Duration,
    quic_config: ClientConfig,
    quic_ep: SharedQuicEndpoint,
    connection: LifecycleSlot<Connection>,
}

impl DoqClient {
    pub async fn new(
        endpoint: DnsEndpoint,
        query_timeout: Duration,
        dial_timeout: Duration,
    ) -> anyhow::Result<Arc<Self>> {
        let quic_config = dns_quic_config(&[b"doq"]).await?;
        Ok(Arc::new(Self {
            endpoint,
            query_timeout,
            dial_timeout,
            quic_config,
            quic_ep: SharedQuicEndpoint::new(),
            connection: LifecycleSlot::new(),
        }))
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry(
            "DoQ",
            || self.exchange_once(raw_query),
            || async {
                self.close_connection().await;
            },
        )
        .await
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let conn = self.get_conn().await?;
        tokio::time::timeout(self.query_timeout, async {
            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .map_err(|e| anyhow::anyhow!("DoQ open_bi: {e}"))?;

            let orig_id = if raw_query.len() >= 2 {
                u16::from_be_bytes([raw_query[0], raw_query[1]])
            } else {
                0
            };
            let mut wire = raw_query.to_vec();
            if wire.len() >= 2 {
                wire[0..2].copy_from_slice(&[0, 0]);
            }
            crate::app::dns::framing::write_length_prefixed(&mut send, &wire).await?;
            send.finish()
                .map_err(|e| anyhow::anyhow!("DoQ finish send: {e}"))?;

            let mut resp = crate::app::dns::framing::read_length_prefixed(&mut recv, self.query_timeout).await?;
            if resp.len() >= 2 {
                resp[0..2].copy_from_slice(&orig_id.to_be_bytes());
            }
            Ok::<_, anyhow::Error>(resp)
        })
        .await
        .map_err(|_| anyhow::anyhow!("DoQ exchange timed out after {:?}", self.query_timeout))?
    }

    async fn get_conn(&self) -> anyhow::Result<Connection> {
        let connection = self.connection.acquire(|| self.dial()).await?;
        if connection.close_reason().is_some() {
            self.close_connection().await;
            return self
                .connection
                .acquire(|| self.dial())
                .await
                .map(|c| (*c).clone());
        }
        Ok((*connection).clone())
    }

    async fn dial(&self) -> anyhow::Result<Connection> {
        quic_connect_endpoint(
            &self.quic_ep,
            &self.quic_config,
            &self.endpoint,
            tokio::time::Instant::now() + self.dial_timeout,
            "DoQ",
        )
        .await
    }

    async fn close_connection(&self) {
        self.connection
            .close(|conn| async move {
                conn.close(0_u32.into(), b"closed");
            })
            .await;
    }

    pub async fn close(&self) {
        self.close_connection().await;
        self.quic_ep.close(Duration::from_millis(100)).await;
    }
}
