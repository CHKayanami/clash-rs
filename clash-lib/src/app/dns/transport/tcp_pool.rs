//! Idle pool for plain DNS-over-TCP (RFC 7766).

use std::sync::Arc;

use parking_lot::Mutex;

use super::dial::DialContext;
use super::idle_pool::{IdlePoolState, close_idle_pool, idle_pool_exchange};
use super::retry::exchange_with_retry;
use crate::app::dispatcher::BoxedChainedStream;

/// Idle-pool plain-TCP DNS client for one upstream.
pub struct TcpPool {
    dial: DialContext,
    lifecycle: tokio::sync::RwLock<IdlePoolState>,
    idle: Mutex<Vec<BoxedChainedStream>>,
}

impl TcpPool {
    pub fn new(dial: DialContext) -> Arc<Self> {
        Arc::new(Self {
            dial,
            lifecycle: tokio::sync::RwLock::new(IdlePoolState::Open),
            idle: Mutex::new(Vec::new()),
        })
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry("TCP DNS", || self.exchange_once(raw_query), || async {}).await
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        idle_pool_exchange(
            &self.lifecycle,
            &self.idle,
            || self.dial_new(),
            raw_query,
            self.dial.query_timeout,
        )
        .await
    }

    async fn dial_new(&self) -> anyhow::Result<BoxedChainedStream> {
        self.dial.dial_tcp().await
    }

    pub async fn close(&self) {
        close_idle_pool(&self.lifecycle, &self.idle, self.dial.query_timeout).await;
    }
}
