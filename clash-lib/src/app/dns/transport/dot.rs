//! DNS over TLS (RFC 7858) with RFC 7766 query pipelining multiplexing.

use crate::app::dns::query::QueryContext;

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use tokio::io::WriteHalf;
use tokio_rustls::client::TlsStream;

use super::dial::DialContext;
use super::lifecycle::LifecycleSlot;
use super::pipelined::PipelinedSession;
use super::retry::exchange_with_retry;
use crate::proxy::AnyStream;

type DotStream = TlsStream<AnyStream>;
type DotSession = PipelinedSession<WriteHalf<DotStream>>;

/// Pipelined DoT client for one upstream multiplexing concurrent queries over a single TLS session.
pub struct DotPool {
    dial: DialContext,
    connector: tokio_rustls::TlsConnector,
    session: LifecycleSlot<DotSession>,
    active_tasks: Arc<AtomicUsize>,
}

impl DotPool {
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
        config.alpn_protocols = vec![b"dot".to_vec()];
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
            exchange_with_retry("DoT", || self.exchange_once(query)),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!("DoT query budget exhausted after {timeout:?}")
        })?
    }

    async fn exchange_once(&self, query: &QueryContext) -> anyhow::Result<Vec<u8>> {
        let session = self.get_session().await?;
        let result = session.exchange(query, self.dial.query_timeout).await;
        if result.is_err() && session.is_closed() {
            self.session
                .close_if(&session, |session| async move {
                    session.shutdown(Duration::ZERO).await;
                })
                .await;
            return result
                .map_err(|error| super::retry::ConnectionFailure(error).into());
        }
        result
    }

    async fn get_session(&self) -> anyhow::Result<Arc<DotSession>> {
        let session = self.session.acquire(|| self.dial_session()).await?;
        if session.is_closed() {
            self.session
                .close_if(&session, |session| async move {
                    session.shutdown(Duration::ZERO).await;
                })
                .await;
            return self.session.acquire(|| self.dial_session()).await;
        }
        Ok(session)
    }

    async fn dial_session(&self) -> anyhow::Result<DotSession> {
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
        .map_err(|_| anyhow::anyhow!("DoT TLS handshake timed out"))??;

        let (reader, writer) = tokio::io::split(tls_stream);
        Ok(PipelinedSession::new(
            reader,
            writer,
            Arc::clone(&self.active_tasks),
        ))
    }

    async fn close_session(&self) {
        self.session
            .close(|session| async move {
                session.shutdown(Duration::from_millis(100)).await;
            })
            .await;
    }

    pub async fn close(&self) {
        self.close_session().await;
    }
}
