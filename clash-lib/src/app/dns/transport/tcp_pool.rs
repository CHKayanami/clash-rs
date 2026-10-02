//! Plain DNS-over-TCP (RFC 7766) with query pipelining multiplexing.

use crate::app::dns::query::QueryContext;

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use tokio::io::WriteHalf;

use super::dial::DialContext;
use super::lifecycle::LifecycleSlot;
use super::pipelined::PipelinedSession;
use super::retry::exchange_with_retry;
use crate::proxy::AnyStream;

type TcpSession = PipelinedSession<WriteHalf<AnyStream>>;

/// Pipelined plain-TCP DNS client for one upstream multiplexing concurrent queries over a single TCP connection.
pub struct TcpPool {
    dial: DialContext,
    session: LifecycleSlot<TcpSession>,
    active_tasks: Arc<AtomicUsize>,
}

impl TcpPool {
    pub fn new(dial: DialContext) -> Arc<Self> {
        Self::new_tracked(dial, Arc::new(AtomicUsize::new(0)))
    }

    pub fn new_tracked(
        dial: DialContext,
        active_tasks: Arc<AtomicUsize>,
    ) -> Arc<Self> {
        Arc::new(Self {
            dial,
            session: LifecycleSlot::new(),
            active_tasks,
        })
    }

    pub async fn exchange(
        self: &Arc<Self>,
        query: &QueryContext,
    ) -> anyhow::Result<Vec<u8>> {
        let timeout = self.dial.query_timeout + self.dial.dial_timeout;
        tokio::time::timeout(
            timeout,
            exchange_with_retry("TCP DNS", || self.exchange_once(query)),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!("TCP DNS query budget exhausted after {timeout:?}")
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

    async fn get_session(&self) -> anyhow::Result<Arc<TcpSession>> {
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

    async fn dial_session(&self) -> anyhow::Result<TcpSession> {
        let deadline = tokio::time::Instant::now() + self.dial.dial_timeout;
        let tcp = self.dial.dial_tcp_until(deadline).await?;
        let (reader, writer) = tokio::io::split(tcp);
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
