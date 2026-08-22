//! DNS over HTTPS (RFC 8484) over HTTP/2.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use bytes::Bytes;
use h2::client::{SendRequest, handshake};
use parking_lot::Mutex;

use super::body::{DnsMessageBody, doh_content_length};
use super::dial::DialContext;
use super::doh_message::{build_doh_request, finish_doh_response};
use super::lifecycle::LifecycleSlot;
use super::owned_task::OwnedTask;
use super::retry::exchange_with_retry;

type H2Sender = SendRequest<Bytes>;

struct H2Session {
    sender: Mutex<Option<H2Sender>>,
    driver: OwnedTask,
}

/// Shared DoH (HTTP/2) client for one upstream.
pub struct DohClient {
    dial: DialContext,
    session: LifecycleSlot<H2Session>,
    active_tasks: Arc<AtomicUsize>,
}

impl DohClient {
    pub fn new(dial: DialContext) -> anyhow::Result<Arc<Self>> {
        Self::new_tracked(dial, Arc::new(AtomicUsize::new(0)))
    }

    pub fn new_tracked(
        dial: DialContext,
        active_tasks: Arc<AtomicUsize>,
    ) -> anyhow::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            dial,
            session: LifecycleSlot::new(),
            active_tasks,
        }))
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry(
            "DoH",
            || self.exchange_once(raw_query),
            || async {
                self.close_session().await;
            },
        )
        .await
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let sender = self.get_sender().await?;

        tokio::time::timeout(self.dial.query_timeout, async {
            let mut sender = sender
                .ready()
                .await
                .map_err(|e| anyhow::anyhow!("DoH H2 sender ready error: {e}"))?;

            let orig_id = if raw_query.len() >= 2 {
                u16::from_be_bytes([raw_query[0], raw_query[1]])
            } else {
                0
            };
            let mut wire = raw_query.to_vec();
            if wire.len() >= 2 {
                wire[0..2].copy_from_slice(&[0, 0]); // Zero ID for wire cacheability
            }

            let req = build_doh_request(&self.dial.endpoint, Some(wire.len()), "DoH")?;

            let (response_fut, mut send_stream) = sender
                .send_request(req, false)
                .map_err(|e| anyhow::anyhow!("DoH send_request: {e}"))?;

            send_stream
                .send_data(Bytes::from(wire), true)
                .map_err(|e| anyhow::anyhow!("DoH send_data: {e}"))?;

            let response = response_fut
                .await
                .map_err(|e| anyhow::anyhow!("DoH response error: {e}"))?;

            let status = response.status();
            let content_length = doh_content_length("DoH", response.headers())?;
            let mut body = response.into_body();
            let mut buf = DnsMessageBody::new("DoH", content_length)?;
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(|e| anyhow::anyhow!("DoH body read: {e}"))?;
                buf.push(&chunk)?;
            }

            finish_doh_response("DoH", status, buf.into_bytes(), orig_id)
        })
        .await
        .map_err(|_| anyhow::anyhow!("DoH query timed out after {:?}", self.dial.query_timeout))?
    }

    async fn get_sender(&self) -> anyhow::Result<H2Sender> {
        let session = self.session.acquire(|| self.dial_session()).await?;
        let mut guard = session.sender.lock();
        guard
            .as_mut()
            .map(|s| s.clone())
            .ok_or_else(|| anyhow::anyhow!("DoH H2 sender closed"))
    }

    async fn dial_session(&self) -> anyhow::Result<H2Session> {
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
        config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let tls_stream = tokio::time::timeout_at(deadline, connector.connect(server_name, tcp))
            .await
            .map_err(|_| anyhow::anyhow!("DoH TLS handshake timed out"))??;

        let (sender, connection) = handshake(tls_stream)
            .await
            .map_err(|e| anyhow::anyhow!("DoH H2 handshake error: {e}"))?;

        let driver = OwnedTask::spawn(
            async move {
                if let Err(e) = connection.await {
                    tracing::debug!("DoH H2 connection closed: {e}");
                }
            },
            Arc::clone(&self.active_tasks),
        );

        Ok(H2Session {
            sender: Mutex::new(Some(sender)),
            driver,
        })
    }

    async fn close_session(&self) {
        self.session
            .close(|session| async move {
                let _ = session.sender.lock().take();
                session.driver.shutdown(Duration::from_millis(100)).await;
            })
            .await;
    }

    pub async fn close(&self) {
        self.close_session().await;
    }
}
