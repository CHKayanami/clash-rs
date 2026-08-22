use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tracing::{debug, trace, warn};

use super::UpstreamPool;
use super::admission::AdmissionPermit;
use super::entries::UpstreamEntry;
use crate::app::dns::endpoint::DnsProtocol;
use crate::app::dns::transport::UdpPool;

fn udp_attempt_addresses(
    addresses: &[SocketAddr],
    current: Option<SocketAddr>,
) -> Option<[SocketAddr; 2]> {
    let first = current
        .filter(|address| addresses.contains(address))
        .or_else(|| addresses.first().copied())?;
    let retry = addresses
        .iter()
        .copied()
        .find(|address| address.is_ipv4() != first.is_ipv4())
        .or_else(|| addresses.iter().copied().find(|address| *address != first))
        .unwrap_or(first);
    Some([first, retry])
}

impl UpstreamPool {
    pub async fn udp_pool(
        &self,
        entry: &UpstreamEntry,
        address: SocketAddr,
        outbound_name: Option<&str>,
    ) -> anyhow::Result<Arc<UdpPool>> {
        let (outbound_handler, effective_outbound) = if let Some(name) = outbound_name.or(entry.outbound.as_deref()) {
            (self.outbounds.read().get(name).cloned(), Some(name.to_string()))
        } else if let Some(ref rd) = self.rule_dispatch {
            if let Some(handler) = rd.resolve_outbound(&entry.endpoint, crate::session::Network::Udp).await {
                let name = handler.name().to_string();
                (Some(handler), Some(name))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let family = usize::from(address.is_ipv6());
        let cache_key = (effective_outbound.clone(), family);

        if let Some((cached_address, pool)) = entry.udp.lock().pools.get(&cache_key)
            && *cached_address == address
        {
            return Ok(Arc::clone(pool));
        }

        let dial = self.dial_context(entry, outbound_handler);
        let candidate = if dial.outbound.is_some() {
            debug!(
                upstream = %entry.name,
                %address,
                outbound = ?effective_outbound,
                "creating proxied UDP DNS pool"
            );
            UdpPool::new_proxied(&dial, address, Arc::clone(&self.active_transport_tasks)).await?
        } else {
            trace!(
                upstream = %entry.name,
                %address,
                "creating direct UDP DNS pool"
            );
            UdpPool::new_direct(
                address,
                dial.so_mark,
                dial.iface.as_ref().map(|i| i.name.as_str()),
                dial.query_timeout,
                Arc::clone(&self.active_transport_tasks),
            )
            .await?
        };

        let (pool, unused) = {
            let mut state = entry.udp.lock();
            if let Some((cached_address, pool)) = state.pools.get(&cache_key)
                && *cached_address == address
            {
                (Arc::clone(pool), Some(candidate))
            } else {
                if state
                    .current
                    .is_some_and(|current| current.is_ipv6() == address.is_ipv6())
                {
                    state.current = None;
                }
                state
                    .pools
                    .insert(cache_key, (address, Arc::clone(&candidate)));
                (candidate, None)
            }
        };
        if let Some(unused) = unused {
            unused.close().await;
        }
        Ok(pool)
    }

    pub async fn admit_query(&self) -> anyhow::Result<AdmissionPermit<'_>> {
        self.admission
            .admit()
            .ok_or_else(|| anyhow::anyhow!("DNS upstream pool is closed"))
    }

    pub async fn query_entry(
        &self,
        entry: &UpstreamEntry,
        raw_query: &[u8],
        outbound_name: Option<&str>,
    ) -> anyhow::Result<Vec<u8>> {
        let _permit = self.admit_query().await?;
        let start = Instant::now();
        let effective_outbound: Option<String> = if let Some(name) = outbound_name.or(entry.outbound.as_deref()) {
            Some(name.to_string())
        } else if let Some(ref rd) = self.rule_dispatch {
            let network = match entry.protocol {
                DnsProtocol::Udp => crate::session::Network::Udp,
                _ => crate::session::Network::Tcp,
            };
            rd.resolve_outbound(&entry.endpoint, network).await.map(|h| h.name().to_string())
        } else {
            None
        };

        let ecs_query = if let Some(ref ecs) = entry.ecs
            && let Some(ipv4) = ecs.ipv4
        {
            crate::app::dns::ecs::EcsQuery::prepare(raw_query, ipv4).ok().flatten()
        } else {
            None
        };

        let outgoing_query = if let Some(ref eq) = ecs_query {
            eq.wire()
        } else {
            raw_query
        };

        debug!(
            upstream = %entry.name,
            protocol = ?entry.protocol,
            outbound = ?effective_outbound,
            ecs = ecs_query.is_some(),
            "querying DNS upstream"
        );

        let response = if entry.protocol == DnsProtocol::Udp {
            let addresses = entry.endpoint.resolve_addrs().await?;
            let current = entry.udp.lock().current;
            let attempts = udp_attempt_addresses(&addresses, current)
                .ok_or_else(|| anyhow::anyhow!("UDP DNS resolved to no addresses"))?;

            let mut last_error = None;
            let mut successful_resp = None;
            for address in attempts {
                let pool = match self.udp_pool(entry, address, outbound_name).await {
                    Ok(pool) => pool,
                    Err(error) => {
                        warn!(
                            upstream = %entry.name,
                            %address,
                            outbound = ?effective_outbound,
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
                            elapsed_ms = elapsed.as_millis(),
                            "DNS upstream query succeeded"
                        );
                        entry.udp.lock().mark_current(address, effective_outbound.as_deref());
                        successful_resp = Some(response);
                        break;
                    }
                    Err(error) => {
                        warn!(
                            upstream = %entry.name,
                            %address,
                            outbound = ?effective_outbound,
                            "UDP DNS query to upstream address failed: {error}"
                        );
                        last_error = Some(error);
                    }
                }
            }
            match successful_resp {
                Some(resp) => resp,
                None => return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("UDP DNS query failed"))),
            }
        } else {
            let transport = self.get_pooled_transport(entry, outbound_name).await?;
            match transport.exchange(outgoing_query).await {
                Ok(response) => {
                    let elapsed = start.elapsed();
                    debug!(
                        upstream = %entry.name,
                        protocol = ?entry.protocol,
                        outbound = ?effective_outbound,
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
