#[cfg(test)]
use arc_swap::ArcSwap;
use crate::app::dns::query::QueryContext;
#[cfg(test)]
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use super::UpstreamPool;
use super::entries::{UpstreamEntry, UpstreamState};
use crate::app::dns::endpoint::DnsProtocol;
use crate::app::dns::transport::{
    DialContext, Doh3Client, DohClient, DoqClient, DotPool, LifecycleSlot, TcpPool,
};
use crate::proxy::OutboundNode;

use super::routes::{ResolvedOutbound, RouteCache, TransportKey};

pub struct TransportPool {
    routes: RouteCache<LifecycleSlot<PooledTransport>>,
}

impl TransportPool {
    pub(super) fn new() -> Self { Self { routes: RouteCache::default() } }

    async fn acquire<F, Fut>(
        &self, outbound: &ResolvedOutbound, build: F,
    ) -> anyhow::Result<Arc<PooledTransport>>
    where F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<PooledTransport>>,
    {
        self.routes.get_routed(&outbound.key, outbound.managed, LifecycleSlot::new).acquire(build).await
    }

    pub(super) fn rebind(&self, previous: Option<&TransportKey>, next: Option<&TransportKey>) {
        self.routes.rebind(previous, next, LifecycleSlot::new);
    }

    pub(super) async fn close(&self) {
        for slot in self.routes.take() {
            slot.close(|transport| async move { transport.close().await }).await;
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
        outbound: Option<OutboundNode>,
    ) -> DialContext {
        DialContext {
            endpoint: entry.endpoint.clone(),
            query_timeout: self.dns_query_timeout,
            dial_timeout: self.dns_dial_timeout,
            outbound,
            iface: self.outbound_interface(entry),
            so_mark: self.fw_mark,
            resolver: self.bootstrap_resolver.clone(),
        }
    }

    pub async fn build_transport(
        &self,
        entry: &UpstreamEntry,
        outbound: Option<OutboundNode>,
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

    pub(super) async fn resolve_outbound(
        &self,
        entry: &UpstreamEntry,
        outbound_name: Option<&str>,
    ) -> anyhow::Result<ResolvedOutbound> {
        let resolved =
            if let Some(name) = outbound_name.or(entry.outbound.as_deref()) {
                let handler =
                    self.outbounds.load().get(name).cloned().ok_or_else(|| {
                        anyhow::anyhow!("unknown DNS outbound '{name}'")
                    })?;
                Some(handler)
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
                    Some(handler)
                } else {
                    None
                }
            } else {
                None
            };

        Ok(ResolvedOutbound::new(resolved))
    }

    pub(super) async fn get_pooled_transport(
        &self,
        entry: &UpstreamEntry,
        outbound: &ResolvedOutbound,
    ) -> anyhow::Result<Arc<PooledTransport>> {
        let UpstreamState::Transport(pool) = entry.state.as_ref() else {
            anyhow::bail!("upstream '{}' uses UDP connection state", entry.name);
        };
        pool.acquire(outbound, || {
            self.build_transport(entry, outbound.handler().cloned())
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

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "changes global network configuration; run this test in isolation"]
    fn dns_inherits_the_current_runtime_interface() {
        use crate::app::net::{NetworkConfig, OutboundInterface, get_default_outbound_interface};
        use crate::app::dns::config::Config as DnsConfig;

        struct Restore(NetworkConfig);
        impl Drop for Restore {
            fn drop(&mut self) { self.0.apply(); }
        }
        let _restore = Restore(NetworkConfig::capture());
        NetworkConfig::resolve(None, false, None).apply();
        let nameservers = DnsConfig::parse_nameserver(&["192.0.2.53".to_owned()]).unwrap();
        let mut entry = UpstreamEntry::from_nameserver(&nameservers[0], None).unwrap();
        // Resolvers are prepared before runtime network configuration is
        // committed. Selection must happen at dial time, not pool creation.
        let mut pool = UpstreamPool::new(HashMap::new(),
            Arc::new(ArcSwap::from_pointee(HashMap::new())), None, None, None, None);
        assert!(pool.dial_context(&entry, None).iface.is_none());
        NetworkConfig::resolve(Some("lo0"), false, None).apply();
        let runtime = get_default_outbound_interface().unwrap();
        assert_eq!(runtime.name, "lo0");
        assert!(Arc::ptr_eq(&pool.dial_context(&entry, None).iface.unwrap(), &runtime));

        let configured = Arc::new(OutboundInterface {
            name: "configured".to_owned(), ..Default::default()
        });
        Arc::get_mut(&mut pool).unwrap().default_interface = Some(configured.clone());
        assert!(Arc::ptr_eq(&pool.dial_context(&entry, None).iface.unwrap(), &configured));
        entry.interface = Some(runtime.clone());
        assert!(Arc::ptr_eq(&pool.dial_context(&entry, None).iface.unwrap(), &runtime));
    }

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
                    OutboundNode::protocol(Arc::new(crate::proxy::direct::Handler::new(name))),
                );
            }
            let pool = UpstreamPool::new(
                entries,
                Arc::new(ArcSwap::from_pointee(outbounds)),
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
            assert_eq!(state.routes.len(), 2);
            assert!(state.routes.values().iter().all(|slot| slot.init_count() == 1));
            assert_eq!(pool.active_transport_tasks.load(Ordering::SeqCst), 2);
            pool.close().await;
            assert_eq!(state.routes.len(), 0);
            assert_eq!(pool.active_transport_tasks.load(Ordering::SeqCst), 0);
            let counts = tokio::time::timeout(Duration::from_secs(1), server)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(counts, vec![10, 10]);
        }
    }
}
