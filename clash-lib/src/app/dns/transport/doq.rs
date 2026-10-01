//! DNS over QUIC (RFC 9250).

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use quinn::{ClientConfig, Connection};

use super::lifecycle::LifecycleSlot;
use super::quic::{SharedQuicEndpoint, dns_quic_config, quic_connect_endpoint};
use super::retry::exchange_with_retry;
use crate::app::dns::endpoint::DnsEndpoint;

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
        Self::new_with_options(
            endpoint,
            query_timeout,
            dial_timeout,
            SharedQuicEndpoint::new(),
        )
        .await
    }

    pub async fn new_with_dial(
        dial: super::dial::DialContext,
    ) -> anyhow::Result<Arc<Self>> {
        Self::new_with_dial_tracked(dial, Arc::new(AtomicUsize::new(0))).await
    }

    pub async fn new_with_dial_tracked(
        dial: super::dial::DialContext,
        active_tasks: Arc<AtomicUsize>,
    ) -> anyhow::Result<Arc<Self>> {
        Self::new_with_options(
            dial.endpoint.clone(),
            dial.query_timeout,
            dial.dial_timeout,
            SharedQuicEndpoint::with_dial(dial, active_tasks),
        )
        .await
    }

    async fn new_with_options(
        endpoint: DnsEndpoint,
        query_timeout: Duration,
        dial_timeout: Duration,
        quic_ep: SharedQuicEndpoint,
    ) -> anyhow::Result<Arc<Self>> {
        let quic_config = dns_quic_config(&[b"doq"]).await?;
        Ok(Arc::new(Self {
            endpoint,
            query_timeout,
            dial_timeout,
            quic_config,
            quic_ep,
            connection: LifecycleSlot::new(),
        }))
    }

    pub async fn exchange(
        self: &Arc<Self>,
        raw_query: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let timeout = self.query_timeout + self.dial_timeout;
        tokio::time::timeout(
            timeout,
            exchange_with_retry("DoQ", || self.exchange_once(raw_query)),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!("DoQ query budget exhausted after {timeout:?}")
        })?
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let conn = self.get_conn().await?;
        let result = tokio::time::timeout(self.query_timeout, async {
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
            crate::app::dns::framing::write_length_prefixed(&mut send, &wire)
                .await?;
            send.finish()
                .map_err(|e| anyhow::anyhow!("DoQ finish send: {e}"))?;

            let mut resp = crate::app::dns::framing::read_length_prefixed(
                &mut recv,
                self.query_timeout,
            )
            .await?;
            if resp.len() >= 2 {
                resp[0..2].copy_from_slice(&orig_id.to_be_bytes());
            }
            Ok::<_, anyhow::Error>(resp)
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("DoQ exchange timed out after {:?}", self.query_timeout)
        })?;
        if result.is_err() && conn.close_reason().is_some() {
            self.connection
                .close_if(&conn, |connection| async move {
                    connection.close(0_u32.into(), b"failed");
                })
                .await;
            return result
                .map_err(|error| super::retry::ConnectionFailure(error).into());
        }
        result
    }

    async fn get_conn(&self) -> anyhow::Result<Arc<Connection>> {
        let connection = self.connection.acquire(|| self.dial()).await?;
        if connection.close_reason().is_some() {
            self.connection
                .close_if(&connection, |connection| async move {
                    connection.close(0_u32.into(), b"closed");
                })
                .await;
            return self.connection.acquire(|| self.dial()).await;
        }
        Ok(connection)
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

#[cfg(test)]
mod tests {
    use super::super::quic_test_support::{self, SocksProxy};
    use super::*;
    use crate::app::dns::endpoint::DnsProtocol;
    use crate::app::dns::query::{DnsName, QType, build_dns_query_wire_with_id};
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn doq_queries_use_socks5_udp_and_reuse_connection() {
        let (server, client_config) = quic_test_support::server(b"doq");
        let proxy = SocksProxy::new().await;
        let relay = proxy.relay_address;
        let server_endpoint = server.clone();
        let server_task = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            assert_eq!(connection.remote_address(), relay);
            for _ in 0..2 {
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let mut query = crate::app::dns::framing::read_length_prefixed(
                    &mut recv,
                    Duration::from_secs(2),
                )
                .await
                .unwrap();
                assert_eq!(query[..2], [0, 0]);
                query[2] |= 0x80;
                crate::app::dns::framing::write_length_prefixed(&mut send, &query)
                    .await
                    .unwrap();
                send.finish().unwrap();
            }
            connection.closed().await;
        });
        let active = Arc::new(AtomicUsize::new(0));
        let mut client = DoqClient::new_with_dial_tracked(
            proxy.dial(server.local_addr().unwrap(), DnsProtocol::Quic),
            active.clone(),
        )
        .await
        .unwrap();
        Arc::get_mut(&mut client).unwrap().quic_config = client_config;
        for id in [0x1234, 0x5678] {
            let query = build_dns_query_wire_with_id(
                id,
                &DnsName::from_domain("proxy.test").unwrap(),
                QType::A,
            );
            let response = client.exchange(&query).await.unwrap();
            assert_eq!(response[..2], id.to_be_bytes());
        }
        assert_eq!(proxy.associations.load(Ordering::SeqCst), 1);
        assert!(proxy.forwarded.load(Ordering::SeqCst) > 0);
        assert_eq!(client.connection.init_count(), 1);
        assert_eq!(active.load(Ordering::SeqCst), 2);
        client.close().await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
        server.close(0_u32.into(), b"test finished");
    }
}
