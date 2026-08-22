//! DNS over HTTP/3 (DoH3).

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::client::SendRequest;
use h3_quinn::Connection as H3QuinnConnection;
use quinn::ClientConfig;
use tokio::sync::Mutex;

use super::body::{DnsMessageBody, doh_content_length};
use super::doh_message::{build_doh_request, finish_doh_response};
use crate::app::dns::endpoint::DnsEndpoint;
use super::lifecycle::LifecycleSlot;
use super::owned_task::OwnedTask;
use super::quic::{SharedQuicEndpoint, dns_quic_config, quic_connect_endpoint};
use super::retry::exchange_with_retry;

type H3Sender = SendRequest<h3_quinn::OpenStreams, Bytes>;

struct H3Session {
    sender: Mutex<Option<H3Sender>>,
    connection: quinn::Connection,
    driver: OwnedTask,
}

pub struct Doh3Client {
    endpoint: DnsEndpoint,
    query_timeout: Duration,
    dial_timeout: Duration,
    quic_config: ClientConfig,
    quic_ep: SharedQuicEndpoint,
    session: LifecycleSlot<H3Session>,
    active_tasks: Arc<AtomicUsize>,
}

impl Doh3Client {
    pub async fn new(
        endpoint: DnsEndpoint,
        query_timeout: Duration,
        dial_timeout: Duration,
    ) -> anyhow::Result<Arc<Self>> {
        Self::new_tracked(
            endpoint,
            query_timeout,
            dial_timeout,
            Arc::new(AtomicUsize::new(0)),
        )
        .await
    }

    pub async fn new_tracked(
        endpoint: DnsEndpoint,
        query_timeout: Duration,
        dial_timeout: Duration,
        active_tasks: Arc<AtomicUsize>,
    ) -> anyhow::Result<Arc<Self>> {
        let quic_config = dns_quic_config(&[b"h3"]).await?;
        Ok(Arc::new(Self {
            endpoint,
            query_timeout,
            dial_timeout,
            quic_config,
            quic_ep: SharedQuicEndpoint::new(),
            session: LifecycleSlot::new(),
            active_tasks,
        }))
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry(
            "DoH3",
            || self.exchange_once(raw_query),
            || async {
                self.close_session().await;
            },
        )
        .await
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut sender = self.get_sender().await?;

        tokio::time::timeout(self.query_timeout, async {
            let orig_id = if raw_query.len() >= 2 {
                u16::from_be_bytes([raw_query[0], raw_query[1]])
            } else {
                0
            };
            let mut wire = raw_query.to_vec();
            if wire.len() >= 2 {
                wire[0..2].copy_from_slice(&[0, 0]);
            }

            let req = build_doh_request(&self.endpoint, None, "DoH3")?;

            let mut stream = sender
                .send_request(req)
                .await
                .map_err(|e| anyhow::anyhow!("DoH3 send_request: {e}"))?;

            stream
                .send_data(Bytes::from(wire))
                .await
                .map_err(|e| anyhow::anyhow!("DoH3 send_data: {e}"))?;

            stream
                .finish()
                .await
                .map_err(|e| anyhow::anyhow!("DoH3 finish: {e}"))?;

            let response = stream
                .recv_response()
                .await
                .map_err(|e| anyhow::anyhow!("DoH3 recv_response: {e}"))?;

            let status = response.status();
            let content_length = doh_content_length("DoH3", response.headers())?;
            let mut buf = DnsMessageBody::new("DoH3", content_length)?;
            while let Some(mut chunk) = stream
                .recv_data()
                .await
                .map_err(|e| anyhow::anyhow!("DoH3 recv_data: {e}"))?
            {
                while chunk.has_remaining() {
                    let slice = chunk.chunk();
                    buf.push(slice)?;
                    let len = slice.len();
                    chunk.advance(len);
                }
            }

            finish_doh_response("DoH3", status, buf.into_bytes(), orig_id)
        })
        .await
        .map_err(|_| anyhow::anyhow!("DoH3 query timed out after {:?}", self.query_timeout))?
    }

    async fn get_sender(&self) -> anyhow::Result<H3Sender> {
        let session = self.session.acquire(|| self.dial_session()).await?;
        if session.connection.close_reason().is_some() {
            self.close_session().await;
            let session = self.session.acquire(|| self.dial_session()).await?;
            let mut guard = session.sender.lock().await;
            return guard
                .as_mut()
                .map(|s| s.clone())
                .ok_or_else(|| anyhow::anyhow!("DoH3 sender closed"));
        }
        let mut guard = session.sender.lock().await;
        guard
            .as_mut()
            .map(|s| s.clone())
            .ok_or_else(|| anyhow::anyhow!("DoH3 sender closed"))
    }

    async fn dial_session(&self) -> anyhow::Result<H3Session> {
        let connection = quic_connect_endpoint(
            &self.quic_ep,
            &self.quic_config,
            &self.endpoint,
            tokio::time::Instant::now() + self.dial_timeout,
            "DoH3",
        )
        .await?;

        let h3_conn = H3QuinnConnection::new(connection.clone());
        let (driver, sender) = h3::client::new(h3_conn)
            .await
            .map_err(|e| anyhow::anyhow!("DoH3 client setup: {e}"))?;

        let driver_task = OwnedTask::spawn(
            async move {
                let mut driver = driver;
                let err = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
                tracing::debug!("DoH3 driver closed: {err:?}");
            },
            Arc::clone(&self.active_tasks),
        );

        Ok(H3Session {
            sender: Mutex::new(Some(sender)),
            connection,
            driver: driver_task,
        })
    }

    async fn close_session(&self) {
        self.session
            .close(|session| async move {
                let _ = session.sender.lock().await.take();
                session.connection.close(0_u32.into(), b"closed");
                session.driver.shutdown(Duration::from_millis(100)).await;
            })
            .await;
    }

    pub async fn close(&self) {
        self.close_session().await;
        self.quic_ep.close(Duration::from_millis(100)).await;
    }
}
