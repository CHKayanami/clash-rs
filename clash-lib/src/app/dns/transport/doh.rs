//! DNS over HTTPS (RFC 8484) over HTTP/2.

use crate::{app::dns::query::QueryContext, proxy::transport::h2_common::{ConnectionState, drive_connection, release_receive_capacity, send_bytes}};
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
    state: Arc<ConnectionState>,
}

/// Shared DoH (HTTP/2) client for one upstream.
pub struct DohClient {
    dial: DialContext,
    connector: tokio_rustls::TlsConnector,
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
        let mut config = crate::common::tls::build_tls_client_config(
            Arc::new(crate::common::tls::DefaultTlsVerifier::new(None, false)),
            None,
            None,
        )?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        Ok(Arc::new(Self {
            dial,
            connector,
            session: LifecycleSlot::new(),
            active_tasks,
        }))
    }

    pub async fn exchange(
        self: &Arc<Self>,
        query: &QueryContext,
    ) -> anyhow::Result<Vec<u8>> {
        let timeout = self.dial.query_timeout + self.dial.dial_timeout;
        tokio::time::timeout(
            timeout,
            exchange_with_retry("DoH", || self.exchange_once(query)),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!("DoH query budget exhausted after {timeout:?}")
        })?
    }

    async fn exchange_once(&self, query: &QueryContext) -> anyhow::Result<Vec<u8>> {
        let session = self.get_session().await?;
        let sender = session
            .sender
            .lock()
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("DoH H2 sender closed"))?;
        let result = tokio::time::timeout(self.dial.query_timeout, async {
            let mut sender = sender.ready().await.map_err(|e| {
                anyhow::Error::new(e).context("DoH H2 sender ready error")
            })?;

            let orig_id = query.txid().get();
            let wire = query.canonical_wire_arc();

            let req =
                build_doh_request(&self.dial.endpoint, Some(wire.len()), "DoH")?;

            let (response_fut, mut send_stream) = sender
                .send_request(req, false)
                .map_err(|e| anyhow::Error::new(e).context("DoH send_request"))?;

            send_bytes(&mut send_stream, Bytes::from_owner(wire), true).await
                .map_err(|e| anyhow::Error::new(e).context("DoH send_data"))?;

            let response = response_fut
                .await
                .map_err(|e| anyhow::Error::new(e).context("DoH response error"))?;

            let status = response.status();
            let content_length = doh_content_length("DoH", response.headers())?;
            let mut body = response.into_body();
            let mut buf = DnsMessageBody::new("DoH", content_length)?;
            while let Some(chunk) = body.data().await {
                let chunk = chunk
                    .map_err(|e| anyhow::Error::new(e).context("DoH body read"))?;
                buf.push(&chunk)?;
                release_receive_capacity(&mut body, chunk.len()).map_err(
                    |error| anyhow::Error::new(error).context("DoH flow control"),
                )?;
            }

            finish_doh_response("DoH", status, buf.into_bytes(), orig_id)
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "DoH query timed out after {:?}",
                self.dial.query_timeout
            )
        })?;
        let connection_failed = session.state.closed()
            || result.as_ref().err().is_some_and(|error| {
                error.chain().any(|cause| {
                    cause
                        .downcast_ref::<h2::Error>()
                        .is_some_and(|error| error.is_io() || error.is_go_away())
                })
            });
        if result.is_err() && connection_failed {
            self.session
                .close_if(&session, |session| async move {
                    session.sender.lock().take();
                    session.driver.shutdown(Duration::ZERO).await;
                })
                .await;
            return result
                .map_err(|error| super::retry::ConnectionFailure(error).into());
        }
        result
    }

    async fn get_session(&self) -> anyhow::Result<Arc<H2Session>> {
        let session = self.session.acquire(|| self.dial_session()).await?;
        if session.state.closed() {
            self.session
                .close_if(&session, |session| async move {
                    session.sender.lock().take();
                    session.driver.shutdown(Duration::ZERO).await;
                })
                .await;
            return self.session.acquire(|| self.dial_session()).await;
        }
        Ok(session)
    }

    async fn dial_session(&self) -> anyhow::Result<H2Session> {
        let deadline = tokio::time::Instant::now() + self.dial.dial_timeout;
        let tcp = self.dial.dial_tcp_until(deadline).await?;
        let server_name =
            rustls::pki_types::ServerName::try_from(self.dial.endpoint.sni.clone())
                .map_err(|e| {
                    anyhow::anyhow!("invalid SNI {}: {e}", self.dial.endpoint.sni)
                })?;

        let tls_stream = tokio::time::timeout_at(
            deadline,
            self.connector.connect(server_name, tcp),
        )
        .await
        .map_err(|_| anyhow::anyhow!("DoH TLS handshake timed out"))??;

        let (sender, connection) =
            tokio::time::timeout_at(deadline, handshake(tls_stream))
                .await
                .map_err(|_| anyhow::anyhow!("DoH H2 handshake timed out"))?
                .map_err(|e| anyhow::anyhow!("DoH H2 handshake error: {e}"))?;

        let state = Arc::new(ConnectionState::default());
        let driver_state = Arc::clone(&state);
        let driver = OwnedTask::spawn(
            drive_connection(connection, driver_state, None),
            Arc::clone(&self.active_tasks),
        );

        Ok(H2Session {
            sender: Mutex::new(Some(sender)),
            driver,
            state,
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

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use crate::app::dns::query::{IngressProfile, QueryContext};
    use super::*;
    use crate::app::dns::endpoint::{DnsEndpoint, DnsProtocol, DnsStrategy};

    #[tokio::test]
    async fn http_error_keeps_shared_h2_connection() {
        #[cfg(feature = "aws-lc-rs")]
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (client_io, server_io) = tokio::io::duplex(16384);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let mut requests = 0;
            while let Some(Ok((request, mut respond))) = connection.accept().await {
                requests += 1;
                let status = if requests == 1 { 500 } else { 200 };
                tokio::spawn(async move {
                    let mut body = request.into_body();
                    while let Some(data) = body.data().await {
                        let data = data.unwrap();
                        body.flow_control().release_capacity(data.len()).unwrap();
                    }
                    let response =
                        http::Response::builder().status(status).body(()).unwrap();
                    let mut stream = respond.send_response(response, false).unwrap();
                    stream.send_data(Bytes::from(vec![0; 12]), true).unwrap();
                });
            }
            requests
        });
        let (sender, connection) = handshake(client_io).await.unwrap();
        let endpoint = DnsEndpoint::parse(
            "127.0.0.1",
            DnsProtocol::Https,
            None,
            None,
            DnsStrategy::PreferIpv4,
        )
        .unwrap();
        let dial = DialContext {
            endpoint,
            query_timeout: Duration::from_secs(1),
            dial_timeout: Duration::from_secs(1),
            outbound: None,
            iface: None,
            so_mark: None,
            resolver: None,
        };
        let client = DohClient::new(dial).unwrap();
        let state = Arc::new(ConnectionState::default());
        let flag = state.clone();
        let driver = OwnedTask::spawn(
            async move {
                let _ = connection.await;
                flag.close();
            },
            client.active_tasks.clone(),
        );
        client
            .session
            .acquire(|| async {
                Ok(H2Session {
                    sender: Mutex::new(Some(sender)),
                    driver,
                    state,
                })
            })
            .await
            .unwrap();
        let mut query = vec![0; 12];
        query[..2].copy_from_slice(&[0x12, 0x34]);
        let error = client.exchange(&QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap()).await.unwrap_err();
        assert!(error.to_string().contains("500"));
        assert_eq!(client.session.close_count(), 0);
        assert_eq!(client.exchange(&QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap()).await.unwrap()[..2], [0x12, 0x34]);
        assert_eq!(client.session.init_count(), 1);
        client.close().await;
        assert_eq!(server.await.unwrap(), 2);
    }
}
