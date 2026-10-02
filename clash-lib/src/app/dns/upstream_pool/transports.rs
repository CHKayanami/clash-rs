use crate::app::dns::query::QueryContext;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use super::UpstreamPool;
use super::entries::{UpstreamEntry, UpstreamState};
use crate::app::dns::endpoint::DnsProtocol;
use crate::app::dns::transport::{
    DialContext, Doh3Client, DohClient, DoqClient, DotPool, LifecycleSlot, TcpPool,
};
use crate::proxy::AnyOutboundHandler;

pub(crate) struct ResolvedOutbound {
    pub handler: Option<AnyOutboundHandler>,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TransportKey {
    pub resolved_outbound: Option<String>,
}

/// A dedicated slot for the configured outbound, plus slots for other routes.
pub struct TransportPool {
    fixed_outbound: Option<String>,
    fixed: LifecycleSlot<PooledTransport>,
    dynamic: parking_lot::RwLock<
        HashMap<TransportKey, Arc<LifecycleSlot<PooledTransport>>>,
    >,
}

impl TransportPool {
    pub(super) fn new(fixed_outbound: Option<String>) -> Self {
        Self {
            fixed_outbound,
            fixed: LifecycleSlot::new(),
            dynamic: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    async fn acquire<F, Fut>(
        &self,
        outbound: &Option<String>,
        build: F,
    ) -> anyhow::Result<Arc<PooledTransport>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<PooledTransport>>,
    {
        if outbound == &self.fixed_outbound {
            return self.fixed.acquire(build).await;
        }
        let key = TransportKey {
            resolved_outbound: outbound.clone(),
        };
        let cached = self.dynamic.read().get(&key).cloned();
        let slot = match cached {
            Some(slot) => slot,
            None => {
                let mut dynamic = self.dynamic.write();
                dynamic
                    .entry(key)
                    .or_insert_with(|| Arc::new(LifecycleSlot::new()))
                    .clone()
            }
        };
        slot.acquire(build).await
    }

    pub(super) async fn close(&self) {
        self.fixed
            .close(|transport| async move { transport.close().await })
            .await;
        let dynamic = std::mem::take(&mut *self.dynamic.write());
        for slot in dynamic.into_values() {
            slot.close(|transport| async move { transport.close().await })
                .await;
        }
    }
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

    pub async fn exchange(&self, query: &QueryContext) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Tcp(transport) => transport.exchange(query).await,
            Self::Dot(transport) => transport.exchange(query).await,
            Self::Doh(transport) => transport.exchange(query).await,
            Self::Doq(transport) => transport.exchange(query).await,
            Self::Doh3(transport) => transport.exchange(query).await,
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
            iface: entry
                .interface
                .clone()
                .or_else(|| self.default_interface.clone()),
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
            DnsProtocol::Udp => anyhow::bail!("UDP upstream uses its UDP state"),
            DnsProtocol::Tcp => PooledTransport::Tcp(TcpPool::new_tracked(
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
                DoqClient::new_with_dial_tracked(
                    dial,
                    Arc::clone(&self.active_transport_tasks),
                )
                .await?,
            ),
            DnsProtocol::H3 => PooledTransport::Doh3(
                Doh3Client::new_with_dial(
                    dial,
                    Arc::clone(&self.active_transport_tasks),
                )
                .await?,
            ),
        })
    }

    pub(crate) async fn resolve_outbound(
        &self,
        entry: &UpstreamEntry,
        outbound_name: Option<&str>,
    ) -> anyhow::Result<ResolvedOutbound> {
        let resolved =
            if let Some(name) = outbound_name.or(entry.outbound.as_deref()) {
                let handler =
                    self.outbounds.read().get(name).cloned().ok_or_else(|| {
                        anyhow::anyhow!("unknown DNS outbound '{name}'")
                    })?;
                (Some(handler), Some(name.to_string()))
            } else if let Some(ref rd) = self.rule_dispatch {
                let network = match entry.protocol {
                    DnsProtocol::Udp | DnsProtocol::Quic | DnsProtocol::H3 => {
                        crate::session::Network::Udp
                    }
                    _ => crate::session::Network::Tcp,
                };
                if let Some(handler) =
                    rd.resolve_outbound(&entry.endpoint, network).await
                {
                    let name = handler.name().to_string();
                    (Some(handler), Some(name))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

        Ok(ResolvedOutbound {
            handler: resolved.0,
            name: resolved.1,
        })
    }

    pub(crate) async fn get_pooled_transport(
        &self,
        entry: &UpstreamEntry,
        outbound: &ResolvedOutbound,
    ) -> anyhow::Result<Arc<PooledTransport>> {
        let UpstreamState::Transport(pool) = entry.state.as_ref() else {
            anyhow::bail!("upstream '{}' uses UDP connection state", entry.name);
        };
        pool.acquire(&outbound.name, || {
            self.build_transport(entry, outbound.handler.clone())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use crate::app::dns::query::{IngressProfile, QueryContext};
    use super::*;
    use crate::app::dns::config::{DNSNetMode, NameServer};
    use crate::app::dns::query::{DnsName, QType, build_dns_query_wire};
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn fixed_and_override_routes_reuse_separate_connections_and_close() {
        for configured in [None, Some("fixed".to_string())] {
            let listener =
                tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let ns = NameServer {
                net: DNSNetMode::Tcp,
                host: url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                port: listener.local_addr().unwrap().port(),
                path: None,
                proxy: configured.clone(),
                interface: None,
            };
            let entry = UpstreamEntry::from_nameserver(&ns, None).unwrap();
            let mut entries = HashMap::new();
            entries.insert("test".to_string(), entry);
            let mut outbounds = HashMap::new();
            for name in ["fixed", "override"] {
                outbounds.insert(
                    name.to_string(),
                    Arc::new(crate::proxy::direct::Handler::new(name))
                        as AnyOutboundHandler,
                );
            }
            let pool = UpstreamPool::new(
                entries,
                Arc::new(parking_lot::RwLock::new(outbounds)),
                None,
                None,
                None,
                None,
            );
            let server = tokio::spawn(async move {
                let mut drivers = tokio::task::JoinSet::new();
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    drivers.spawn(async move {
                        let mut count = 0;
                        while let Ok(len) = stream.read_u16().await {
                            let mut wire = vec![0; len as usize];
                            stream.read_exact(&mut wire).await.unwrap();
                            wire[2] |= 0x80;
                            stream.write_u16(len).await.unwrap();
                            stream.write_all(&wire).await.unwrap();
                            count += 1;
                        }
                        count
                    });
                }
                let mut counts = Vec::new();
                while let Some(result) = drivers.join_next().await {
                    counts.push(result.unwrap());
                }
                counts
            });
            let query = build_dns_query_wire(
                &DnsName::from_domain("fixed.test").unwrap(),
                QType::A,
            );
            let mut queries = tokio::task::JoinSet::new();
            for _ in 0..10 {
                for outbound in [None, Some("override")] {
                    let pool = pool.clone();
                    let query = query.clone();
                    queries.spawn(async move {
                        let response = pool
                            .query("test", &QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap(), outbound)
                            .await
                            .unwrap();
                        assert_eq!(response[..2], query[..2]);
                    });
                }
            }
            tokio::time::timeout(Duration::from_secs(3), async {
                while let Some(result) = queries.join_next().await {
                    result.unwrap();
                }
            })
            .await
            .unwrap();
            let UpstreamState::Transport(state) =
                pool.entries["test"].state.as_ref()
            else {
                panic!("TCP upstream must have transport state");
            };
            assert_eq!(state.fixed.init_count(), 1);
            assert_eq!(state.dynamic.read().len(), 1);
            assert_eq!(pool.active_transport_tasks.load(Ordering::SeqCst), 2);
            pool.close().await;
            assert_eq!(state.fixed.close_count(), 1);
            assert!(state.dynamic.read().is_empty());
            assert_eq!(pool.active_transport_tasks.load(Ordering::SeqCst), 0);
            let counts = tokio::time::timeout(Duration::from_secs(1), server)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(counts, vec![10, 10]);
        }
    }
}
