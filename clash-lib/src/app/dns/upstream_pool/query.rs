use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tracing::{debug, trace, warn};
use ipnet::IpNet;

use super::UpstreamPool;
use super::admission::AdmissionPermit;
use super::entries::{UpstreamEntry, UpstreamState};
use super::udp::UdpUpstream;
use super::transports::ResolvedOutbound;
use crate::app::dns::transport::UdpPool;
use crate::app::dns::ecs::EcsQuery;
use crate::app::dns::query::QueryContext;

impl UpstreamPool {
    pub async fn udp_pool(
        &self,
        entry: &UpstreamEntry,
        address: SocketAddr,
        outbound_name: Option<&str>,
    ) -> anyhow::Result<Arc<UdpPool>> {
        let udp = entry.udp_state()?;
        let outbound = self.resolve_outbound(entry, outbound_name).await?;
        if udp.fixed_address(&entry.endpoint, &outbound.name) == Some(address) {
            return udp
                .acquire_fixed(address, || {
                    self.build_udp_pool(entry, address, &outbound)
                })
                .await;
        }
        udp.for_address(address, &outbound.name)
            .acquire(|| self.build_udp_pool(entry, address, &outbound))
            .await
    }

    async fn query_fixed_udp(
        &self,
        entry: &UpstreamEntry,
        udp: &UdpUpstream,
        address: SocketAddr,
        outbound: &ResolvedOutbound,
        query: &QueryContext,
    ) -> anyhow::Result<Vec<u8>> {
        let mut last_error = None;
        let domain = query.qdomain().unwrap_or("<unknown>");
        let qtype = query.logged_qtype();
        for attempt in 1..=2 {
            let result = async {
                let pool = udp
                    .acquire_fixed(address, || {
                        self.build_udp_pool(entry, address, outbound)
                    })
                    .await?;
                pool.exchange(query).await
            }
            .await;
            match result {
                Ok(response) => {
                    debug!(
                        upstream = %entry.name,
                        %address,
                        outbound = ?outbound.name,
                        %domain,
                        %qtype,
                        attempt,
                        "fixed UDP DNS query succeeded"
                    );
                    return Ok(response);
                }
                Err(error) => {
                    warn!(
                        upstream = %entry.name,
                        %address,
                        outbound = ?outbound.name,
                        %domain,
                        %qtype,
                        attempt,
                        "fixed UDP DNS query failed: {error}"
                    );
                    last_error = Some(error);
                }
            }
        }
        Err(last_error
            .unwrap_or_else(|| anyhow::anyhow!("fixed UDP DNS query failed")))
    }

    async fn build_udp_pool(
        &self,
        entry: &UpstreamEntry,
        address: SocketAddr,
        outbound: &ResolvedOutbound,
    ) -> anyhow::Result<Arc<UdpPool>> {
        let effective_outbound = &outbound.name;
        let dial = self.dial_context(entry, outbound.handler.clone());
        if dial.outbound.is_some() {
            debug!(
                upstream = %entry.name,
                %address,
                outbound = ?effective_outbound,
                "creating proxied UDP DNS pool"
            );
            tokio::time::timeout(
                dial.dial_timeout,
                UdpPool::new_proxied(
                    &dial,
                    address,
                    Arc::clone(&self.active_transport_tasks),
                ),
            )
            .await
            .map_err(|_| anyhow::anyhow!("proxied UDP DNS dial timed out"))?
        } else {
            trace!(
                upstream = %entry.name,
                %address,
                "creating direct UDP DNS pool"
            );
            UdpPool::new_direct(
                address,
                dial.so_mark,
                dial.iface.as_ref(),
                dial.query_timeout,
                Arc::clone(&self.active_transport_tasks),
            )
            .await
        }
    }

    pub async fn admit_query(&self) -> anyhow::Result<AdmissionPermit<'_>> {
        self.admission
            .admit()
            .ok_or_else(|| anyhow::anyhow!("DNS upstream pool is closed"))
    }

    pub async fn query_entry(
        &self,
        entry: &UpstreamEntry,
        query: &QueryContext,
        outbound_name: Option<&str>,
    ) -> anyhow::Result<Vec<u8>> {
        let _permit = self.admit_query().await?;
        let timeout = self.dns_query_timeout + self.dns_dial_timeout;
        tokio::time::timeout(
            timeout,
            self.query_entry_inner(entry, query, outbound_name),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "DNS upstream '{}' query budget exhausted after {timeout:?}",
                entry.name
            )
        })?
    }

    async fn query_entry_inner(
        &self,
        entry: &UpstreamEntry,
        query: &QueryContext,
        outbound_name: Option<&str>,
    ) -> anyhow::Result<Vec<u8>> {
        let start = Instant::now();
        let outbound = self.resolve_outbound(entry, outbound_name).await?;
        let effective_outbound = &outbound.name;

        let ecs_query = if let Some(ref ecs) = entry.ecs
            && let Some(subnet) = ecs.ipv4.map(IpNet::V4).or_else(|| ecs.ipv6.map(IpNet::V6))
        {
            EcsQuery::prepare(query, subnet)?
        } else {
            None
        };

        let outgoing_query = if let Some(ref eq) = ecs_query {
            eq.query()
        } else {
            query
        };

        let domain_str = query.qdomain().unwrap_or("<unknown>");
        let qtype = query.logged_qtype();

        debug!(
            upstream = %entry.name,
            protocol = ?entry.protocol,
            outbound = ?effective_outbound,
            domain = %domain_str,
            qtype = %qtype,
            ecs = ecs_query.is_some(),
            "querying DNS upstream"
        );

        let udp = match entry.state.as_ref() {
            UpstreamState::Udp(udp) => Some(udp),
            UpstreamState::Transport(_) => None,
        };
        let fixed_address =
            udp.and_then(|udp| udp.fixed_address(&entry.endpoint, &outbound.name));
        let response = if let (Some(udp), Some(address)) = (udp, fixed_address) {
            self.query_fixed_udp(
                entry,
                udp,
                address,
                &outbound,
                outgoing_query,
            )
            .await?
        } else if let Some(udp) = udp {
            let addresses = entry.endpoint.resolve_addrs().await?;
            let snapshot = udp.snapshot(&addresses, &outbound.name)?;

            let mut last_error = None;
            let mut successful_resp = None;
            for (index, attempt) in snapshot.attempts.into_iter().enumerate() {
                let address = attempt.address;
                let pool = match attempt
                    .acquire(|| self.build_udp_pool(entry, address, &outbound))
                    .await
                {
                    Ok(pool) => pool,
                    Err(error) => {
                        warn!(
                            upstream = %entry.name,
                            %address,
                            outbound = ?effective_outbound,
                            domain = %domain_str,
                            qtype = %qtype,
                            attempt = index + 1,
                            "failed to initialize UDP pool: {error}"
                        );
                        last_error = Some(error);
                        continue;
                    }
                };
                match pool.exchange(outgoing_query).await {
                    Ok(response) => {
                        let elapsed = start.elapsed();
                        debug!(
                            upstream = %entry.name,
                            %address,
                            outbound = ?effective_outbound,
                            domain = %domain_str,
                            qtype = %qtype,
                            attempt = index + 1,
                            elapsed_ms = elapsed.as_millis(),
                            "DNS upstream query succeeded"
                        );
                        if snapshot.current != Some(address) {
                            udp.mark_current(address, &outbound.name);
                        }
                        successful_resp = Some(response);
                        break;
                    }
                    Err(error) => {
                        warn!(
                            upstream = %entry.name,
                            %address,
                            outbound = ?effective_outbound,
                            domain = %domain_str,
                            qtype = %qtype,
                            attempt = index + 1,
                            "UDP DNS query to upstream address failed: {error}"
                        );
                        last_error = Some(error);
                    }
                }
            }
            match successful_resp {
                Some(resp) => resp,
                None => {
                    entry.endpoint.invalidate_addresses();
                    return Err(last_error.unwrap_or_else(|| {
                        anyhow::anyhow!("UDP DNS query failed")
                    }));
                }
            }
        } else {
            let transport = self.get_pooled_transport(entry, &outbound).await?;
            match transport.exchange(outgoing_query).await {
                Ok(response) => {
                    let elapsed = start.elapsed();
                    debug!(
                        upstream = %entry.name,
                        protocol = ?entry.protocol,
                        outbound = ?effective_outbound,
                        domain = %domain_str,
                        qtype = %qtype,
                        elapsed_ms = elapsed.as_millis(),
                        "DNS upstream query succeeded"
                    );
                    response
                }
                Err(error) => {
                    warn!(
                        upstream = %entry.name,
                        protocol = ?entry.protocol,
                        outbound = ?effective_outbound,
                        domain = %domain_str,
                        qtype = %qtype,
                        "DNS upstream query failed: {error}"
                    );
                    return Err(error);
                }
            }
        };

        if let Some(eq) = ecs_query {
            match eq.restore_response(response) {
                Ok(restored) => Ok(restored),
                Err(error) => {
                    warn!(
                        upstream = %entry.name,
                        domain = %domain_str,
                        qtype = %qtype,
                        "failed to restore ECS response: {error}"
                    );
                    Err(anyhow::anyhow!("failed to restore ECS response: {error}"))
                }
            }
        } else {
            Ok(response)
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use crate::app::dns::query::{IngressProfile, QueryContext};
    use super::*;
    use crate::app::dns::MockClashResolver;
    use crate::app::dns::config::{DNSNetMode, NameServer};
    use crate::app::dns::query::{DnsName, QType, build_dns_query_wire};
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    fn pool() -> Arc<UpstreamPool> {
        UpstreamPool::new(
            HashMap::new(),
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            None,
            None,
            None,
            None,
        )
    }

    #[tokio::test]
    async fn fixed_ip_retries_and_reuses_its_dedicated_pool() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let ns = NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            port: address.port(),
            path: None,
            proxy: None,
            interface: None,
        };
        let entry = UpstreamEntry::from_nameserver(&ns, None).unwrap();
        let mut pool = pool();
        let inner = Arc::get_mut(&mut pool).unwrap();
        inner.dns_query_timeout = Duration::from_millis(100);
        inner.dns_dial_timeout = Duration::from_secs(1);
        let server = tokio::spawn(async move {
            let mut buffer = [0; 512];
            for index in 0..3 {
                let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
                if index != 0 {
                    buffer[2] |= 0x80;
                    socket.send_to(&buffer[..len], peer).await.unwrap();
                }
            }
        });
        let query = build_dns_query_wire(
            &DnsName::from_domain("fixed.test").unwrap(),
            QType::A,
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            for _ in 0..2 {
                assert_eq!(
                    pool.query_entry(&entry, &QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap(), None).await.unwrap()[..2],
                    query[..2]
                );
            }
            server.await.unwrap();
        })
        .await
        .unwrap();
        let fixed = entry
            .udp_state()
            .unwrap()
            .acquire_fixed(address, || async {
                panic!("query must populate dedicated slot")
            })
            .await
            .unwrap();
        let public = pool.udp_pool(&entry, address, None).await.unwrap();
        assert!(Arc::ptr_eq(&fixed, &public));
        assert_eq!(
            pool.active_transport_tasks
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        let inner = Arc::get_mut(&mut pool).unwrap();
        inner.rule_dispatch = Some(crate::app::dns::RuleDispatch::new());
        let resolved = pool.resolve_outbound(&entry, None).await.unwrap();
        assert_eq!(
            entry
                .udp_state()
                .unwrap()
                .fixed_address(&entry.endpoint, &resolved.name),
            Some(address)
        );
        let routed = pool.udp_pool(&entry, address, None).await.unwrap();
        assert!(Arc::ptr_eq(&fixed, &routed));
        entry.udp_state().unwrap().close().await;
        assert!(fixed.is_closed());
        assert_eq!(
            pool.active_transport_tasks
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn concurrent_queries_share_bootstrap_and_udp_pool() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut bootstrap = MockClashResolver::new();
        bootstrap
            .expect_resolve_v4()
            .times(1)
            .returning(|_, _| Ok(Some(std::net::Ipv4Addr::LOCALHOST)));
        bootstrap
            .expect_resolve_v6()
            .times(1)
            .returning(|_, _| Ok(None));
        let ns = NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Domain("dns.example".into()),
            port: socket.local_addr().unwrap().port(),
            path: None,
            proxy: None,
            interface: None,
        };
        let entry = Arc::new(
            UpstreamEntry::from_nameserver(&ns, Some(Arc::new(bootstrap))).unwrap(),
        );
        let pool = pool();
        let server = tokio::spawn(async move {
            let mut buffer = [0; 512];
            for _ in 0..10 {
                let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
                buffer[2] |= 0x80;
                socket.send_to(&buffer[..len], peer).await.unwrap();
            }
        });
        let mut queries = tokio::task::JoinSet::new();
        for _ in 0..10 {
            let pool = pool.clone();
            let entry = entry.clone();
            queries.spawn(async move {
                let query = build_dns_query_wire(
                    &DnsName::from_domain("query.test").unwrap(),
                    QType::A,
                );
                pool.query_entry(&entry, &QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap(), None).await.unwrap()
            });
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while let Some(result) = queries.join_next().await {
                assert!(result.unwrap().len() >= 12);
            }
            server.await.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(
            pool.active_transport_tasks
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        entry.udp_state().unwrap().close().await;
    }

    #[tokio::test]
    async fn address_refresh_does_not_cancel_old_pool_queries() {
        let old_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let new_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ns = NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            port: old_server.local_addr().unwrap().port(),
            path: None,
            proxy: None,
            interface: None,
        };
        let entry = UpstreamEntry::from_nameserver(&ns, None).unwrap();
        let pool = pool();
        let old = pool
            .udp_pool(&entry, old_server.local_addr().unwrap(), None)
            .await
            .unwrap();
        let exchange_pool = old.clone();
        let exchange = tokio::spawn(async move {
            let query = build_dns_query_wire(
                &DnsName::from_domain("refresh.test").unwrap(),
                QType::A,
            );
            exchange_pool.exchange(&QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap()).await
        });
        let mut response = [0; 512];
        let (len, peer) = old_server.recv_from(&mut response).await.unwrap();
        let new = pool
            .udp_pool(&entry, new_server.local_addr().unwrap(), None)
            .await
            .unwrap();
        response[2] |= 0x80;
        old_server.send_to(&response[..len], peer).await.unwrap();
        assert!(exchange.await.unwrap().is_ok());
        old.close().await;
        new.close().await;
    }
}
