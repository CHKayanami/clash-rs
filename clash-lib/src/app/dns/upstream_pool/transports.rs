use std::sync::Arc;

use super::UpstreamPool;
use super::entries::UpstreamEntry;
use crate::app::dns::endpoint::DnsProtocol;
use crate::app::dns::transport::{
    DialContext, Doh3Client, DohClient, DoqClient, DotPool, LifecycleSlot, TcpPool,
};
use crate::proxy::AnyOutboundHandler;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TransportKey {
    pub resolved_outbound: Option<String>,
}

pub enum PooledTransport {
    Tcp(Arc<TcpPool>),
    Dot(Arc<DotPool>),
    Doh(Arc<DohClient>),
    Doq(Arc<DoqClient>),
    Doh3(Arc<Doh3Client>),
}

impl PooledTransport {
    pub async fn close(&self) {
        match self {
            Self::Tcp(transport) => transport.close().await,
            Self::Dot(transport) => transport.close().await,
            Self::Doh(transport) => transport.close().await,
            Self::Doq(transport) => transport.close().await,
            Self::Doh3(transport) => transport.close().await,
        }
    }

    pub async fn exchange(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Tcp(transport) => transport.exchange(raw_query).await,
            Self::Dot(transport) => transport.exchange(raw_query).await,
            Self::Doh(transport) => transport.exchange(raw_query).await,
            Self::Doq(transport) => transport.exchange(raw_query).await,
            Self::Doh3(transport) => transport.exchange(raw_query).await,
        }
    }
}

impl UpstreamPool {
    pub fn dial_context(
        &self,
        entry: &UpstreamEntry,
        outbound: Option<AnyOutboundHandler>,
    ) -> DialContext {
        DialContext {
            endpoint: entry.endpoint.clone(),
            query_timeout: self.dns_query_timeout,
            dial_timeout: self.dns_dial_timeout,
            outbound,
            iface: entry.interface.clone().or_else(|| self.default_interface.clone()),
            so_mark: self.fw_mark,
            resolver: self.bootstrap_resolver.clone(),
        }
    }

    pub async fn build_transport(
        &self,
        entry: &UpstreamEntry,
        outbound: Option<AnyOutboundHandler>,
    ) -> anyhow::Result<PooledTransport> {
        let dial = self.dial_context(entry, outbound);
        Ok(match entry.protocol {
            DnsProtocol::Udp | DnsProtocol::Tcp => PooledTransport::Tcp(TcpPool::new_tracked(
                dial,
                Arc::clone(&self.active_transport_tasks),
            )),
            DnsProtocol::Tls => PooledTransport::Dot(DotPool::new_tracked(
                dial,
                Arc::clone(&self.active_transport_tasks),
            )?),
            DnsProtocol::Https => PooledTransport::Doh(DohClient::new_tracked(
                dial,
                Arc::clone(&self.active_transport_tasks),
            )?),
            DnsProtocol::Quic => PooledTransport::Doq(
                DoqClient::new(
                    entry.endpoint.clone(),
                    self.dns_query_timeout,
                    self.dns_dial_timeout,
                )
                .await?,
            ),
            DnsProtocol::H3 => PooledTransport::Doh3(
                Doh3Client::new_tracked(
                    entry.endpoint.clone(),
                    self.dns_query_timeout,
                    self.dns_dial_timeout,
                    Arc::clone(&self.active_transport_tasks),
                )
                .await?,
            ),
        })
    }

    pub async fn get_pooled_transport(
        &self,
        entry: &UpstreamEntry,
        outbound_name: Option<&str>,
    ) -> anyhow::Result<Arc<PooledTransport>> {
        let (outbound_handler, effective_outbound_name) = if let Some(name) = outbound_name {
            (self.outbounds.read().get(name).cloned(), Some(name.to_string()))
        } else if let Some(ref name) = entry.outbound {
            (self.outbounds.read().get(name).cloned(), Some(name.clone()))
        } else if let Some(ref rd) = self.rule_dispatch {
            let network = match entry.protocol {
                DnsProtocol::Udp => crate::session::Network::Udp,
                _ => crate::session::Network::Tcp,
            };
            if let Some(handler) = rd.resolve_outbound(&entry.endpoint, network).await {
                let name = handler.name().to_string();
                (Some(handler), Some(name))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let key = TransportKey {
            resolved_outbound: effective_outbound_name,
        };

        let slot = {
            let mut transports = entry.transports.lock();
            transports
                .entry(key.clone())
                .or_insert_with(|| Arc::new(LifecycleSlot::new()))
                .clone()
        };

        slot.acquire(|| self.build_transport(entry, outbound_handler)).await
    }
}
