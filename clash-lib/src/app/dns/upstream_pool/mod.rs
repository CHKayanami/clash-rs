//! Per-upstream DNS query management with connection reuse and graceful shutdown.

mod admission;
mod entries;
mod query;
mod transports;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

pub use admission::{AdmissionGate, AdmissionPermit, ClosePermit};
pub use entries::UpstreamEntry;
pub use transports::{PooledTransport, TransportKey};

use crate::app::dns::ClashResolver;
use crate::proxy::utils::OutboundHandlerRegistry;

pub struct UpstreamPool {
    pub entries: HashMap<String, UpstreamEntry>,
    pub admission: AdmissionGate,
    pub outbounds: OutboundHandlerRegistry,
    pub bootstrap_resolver: Option<Arc<dyn ClashResolver>>,
    pub active_transport_tasks: Arc<AtomicUsize>,
    pub dns_query_timeout: Duration,
    pub dns_dial_timeout: Duration,
    pub fw_mark: Option<u32>,
    pub default_interface: Option<crate::app::net::OutboundInterface>,
    pub rule_dispatch: Option<Arc<crate::app::dns::RuleDispatch>>,
}

impl UpstreamPool {
    pub fn new(
        entries: HashMap<String, UpstreamEntry>,
        outbounds: OutboundHandlerRegistry,
        bootstrap_resolver: Option<Arc<dyn ClashResolver>>,
        fw_mark: Option<u32>,
        default_interface: Option<crate::app::net::OutboundInterface>,
        rule_dispatch: Option<Arc<crate::app::dns::RuleDispatch>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            entries,
            admission: AdmissionGate::new(),
            outbounds,
            bootstrap_resolver,
            active_transport_tasks: Arc::new(AtomicUsize::new(0)),
            dns_query_timeout: Duration::from_secs(5),
            dns_dial_timeout: Duration::from_secs(5),
            fw_mark,
            default_interface,
            rule_dispatch,
        })
    }

    pub async fn query(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let entry = self
            .entries
            .get(upstream_name)
            .ok_or_else(|| anyhow::anyhow!("unknown upstream '{upstream_name}'"))?;
        self.query_entry(entry, raw_query, None).await
    }

    pub async fn query_with_outbound(
        &self,
        upstream_name: &str,
        raw_query: &[u8],
        outbound: Option<&str>,
    ) -> anyhow::Result<Vec<u8>> {
        let entry = self
            .entries
            .get(upstream_name)
            .ok_or_else(|| anyhow::anyhow!("unknown upstream '{upstream_name}'"))?;
        self.query_entry(entry, raw_query, outbound).await
    }

    pub async fn close(&self) {
        if let Some(close_permit) = self.admission.acquire_close().await {
            self.admission.wait_for_idle().await;
            for entry in self.entries.values() {
                let transports = std::mem::take(&mut *entry.transports.lock());
                for slot in transports.into_values() {
                    slot.close(|t| async move { t.close().await }).await;
                }
                let udp_pools = {
                    let mut udp = entry.udp.lock();
                    std::mem::take(&mut udp.pools)
                };
                for (_, (_, pool)) in udp_pools {
                    pool.close().await;
                }
            }
            close_permit.complete();
        }
    }
}
