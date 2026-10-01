//! Per-outbound UDP state with independent pool initialization for each address family.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use parking_lot::Mutex;

use crate::app::dns::endpoint::{DnsEndpoint, DnsStrategy};
use crate::app::dns::transport::UdpPool;

struct CachedPool {
    address: SocketAddr,
    pool: Arc<UdpPool>,
}

#[derive(Default)]
struct UdpSlot {
    active: ArcSwapOption<CachedPool>,
    init: tokio::sync::Mutex<()>,
}

impl UdpSlot {
    fn cached(&self, address: SocketAddr) -> Option<Arc<UdpPool>> {
        self.active
            .load()
            .as_ref()
            .filter(|cached| cached.address == address && !cached.pool.is_closed())
            .map(|cached| Arc::clone(&cached.pool))
    }

    async fn acquire<F, Fut>(
        &self,
        address: SocketAddr,
        build: F,
    ) -> anyhow::Result<Arc<UdpPool>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<Arc<UdpPool>>>,
    {
        if let Some(pool) = self.cached(address) {
            return Ok(pool);
        }
        let _init = self.init.lock().await;
        if let Some(pool) = self.cached(address) {
            return Ok(pool);
        }
        let pool = build().await?;
        // In-flight exchanges retain the old pool during address refreshes.
        self.active.store(Some(Arc::new(CachedPool {
            address,
            pool: Arc::clone(&pool),
        })));
        Ok(pool)
    }
}

struct OutboundUdp {
    current: Option<SocketAddr>,
    slots: [Arc<UdpSlot>; 2],
}

impl Default for OutboundUdp {
    fn default() -> Self {
        Self {
            current: None,
            slots: std::array::from_fn(|_| Arc::new(UdpSlot::default())),
        }
    }
}

struct FixedUdp {
    host: String,
    address: SocketAddr,
    strategy: DnsStrategy,
    outbound: Option<String>,
    slot: UdpSlot,
}

/// Owns UDP pools and address preferences; callers do not access its locks.
#[derive(Default)]
pub struct UdpUpstream {
    fixed: Option<FixedUdp>,
    outbounds: Mutex<HashMap<Option<String>, OutboundUdp>>,
}

pub(super) struct UdpSnapshot {
    pub current: Option<SocketAddr>,
    pub attempts: [UdpAttempt; 2],
}

pub(super) struct UdpAttempt {
    pub address: SocketAddr,
    pub pool: Option<Arc<UdpPool>>,
    slot: Arc<UdpSlot>,
}

impl UdpAttempt {
    pub async fn acquire<F, Fut>(self, build: F) -> anyhow::Result<Arc<UdpPool>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<Arc<UdpPool>>>,
    {
        if let Some(pool) = self.pool.filter(|pool| !pool.is_closed()) {
            return Ok(pool);
        }
        self.slot.acquire(self.address, build).await
    }
}

impl UdpUpstream {
    pub(super) fn new(endpoint: &DnsEndpoint, outbound: Option<String>) -> Self {
        let fixed = endpoint.host.parse().ok().map(|ip| FixedUdp {
            host: endpoint.host.clone(),
            address: SocketAddr::new(ip, endpoint.port),
            strategy: endpoint.strategy,
            outbound,
            slot: UdpSlot::default(),
        });
        Self {
            fixed,
            outbounds: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn fixed_address(
        &self,
        endpoint: &DnsEndpoint,
        outbound: &Option<String>,
    ) -> Option<SocketAddr> {
        self.fixed
            .as_ref()
            .filter(|fixed| {
                fixed.host == endpoint.host
                    && fixed.address.port() == endpoint.port
                    && fixed.strategy == endpoint.strategy
                    && &fixed.outbound == outbound
                    && match endpoint.strategy {
                        DnsStrategy::Ipv4Only => fixed.address.is_ipv4(),
                        DnsStrategy::Ipv6Only => fixed.address.is_ipv6(),
                        _ => true,
                    }
            })
            .map(|fixed| fixed.address)
    }

    pub(super) async fn acquire_fixed<F, Fut>(
        &self,
        address: SocketAddr,
        build: F,
    ) -> anyhow::Result<Arc<UdpPool>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<Arc<UdpPool>>>,
    {
        self.fixed
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing fixed UDP route"))?
            .slot
            .acquire(address, build)
            .await
    }

    fn route<'a>(
        outbounds: &'a mut HashMap<Option<String>, OutboundUdp>,
        outbound: &Option<String>,
    ) -> &'a mut OutboundUdp {
        if !outbounds.contains_key(outbound) {
            outbounds.insert(outbound.clone(), OutboundUdp::default());
        }
        outbounds.get_mut(outbound).unwrap()
    }

    fn attempt(route: &OutboundUdp, address: SocketAddr) -> UdpAttempt {
        let slot = Arc::clone(&route.slots[usize::from(address.is_ipv6())]);
        UdpAttempt {
            address,
            pool: slot.cached(address),
            slot,
        }
    }

    pub(super) fn snapshot(
        &self,
        addresses: &[SocketAddr],
        outbound: &Option<String>,
    ) -> anyhow::Result<UdpSnapshot> {
        let mut outbounds = self.outbounds.lock();
        let route = Self::route(&mut outbounds, outbound);
        let first = route
            .current
            .filter(|address| addresses.contains(address))
            .or_else(|| addresses.first().copied())
            .ok_or_else(|| anyhow::anyhow!("UDP DNS resolved to no addresses"))?;
        let retry = addresses
            .iter()
            .copied()
            .find(|address| address.is_ipv4() != first.is_ipv4())
            .or_else(|| addresses.iter().copied().find(|address| *address != first))
            .unwrap_or(first);
        Ok(UdpSnapshot {
            current: route.current,
            attempts: [Self::attempt(route, first), Self::attempt(route, retry)],
        })
    }

    pub(super) fn for_address(
        &self,
        address: SocketAddr,
        outbound: &Option<String>,
    ) -> UdpAttempt {
        let mut outbounds = self.outbounds.lock();
        Self::attempt(Self::route(&mut outbounds, outbound), address)
    }

    pub(super) fn mark_current(
        &self,
        address: SocketAddr,
        outbound: &Option<String>,
    ) {
        let mut outbounds = self.outbounds.lock();
        if let Some(route) = outbounds.get_mut(outbound)
            && route.slots[usize::from(address.is_ipv6())]
                .active
                .load()
                .as_ref()
                .is_some_and(|cached| {
                    cached.address == address && !cached.pool.is_closed()
                })
        {
            route.current = Some(address);
        }
    }

    pub(crate) async fn close(&self) {
        if let Some(fixed) = &self.fixed
            && let Some(cached) = fixed.slot.active.swap(None)
        {
            cached.pool.close().await;
        }
        let outbounds = std::mem::take(&mut *self.outbounds.lock());
        for route in outbounds.into_values() {
            for slot in route.slots {
                if let Some(cached) = slot.active.swap(None) {
                    cached.pool.close().await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    async fn pool() -> Arc<UdpPool> {
        UdpPool::new_direct(
            "127.0.0.1:853".parse().unwrap(),
            None,
            None,
            Duration::from_secs(1),
            Arc::new(AtomicUsize::new(0)),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn fixed_slot_reuses_and_rebuilds_without_populating_routes() {
        let endpoint = DnsEndpoint::parse(
            "127.0.0.1:53",
            crate::app::dns::endpoint::DnsProtocol::Udp,
            None,
            None,
            DnsStrategy::PreferIpv4,
        )
        .unwrap();
        let outbound = Some("fixed".to_string());
        let udp = UdpUpstream::new(&endpoint, outbound.clone());
        let address = udp.fixed_address(&endpoint, &outbound).unwrap();
        let old = pool().await;
        udp.acquire_fixed(address, || async { Ok(old.clone()) })
            .await
            .unwrap();
        let cached = udp
            .acquire_fixed(address, || async {
                panic!("warm fixed route must reuse its pool")
            })
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&cached, &old));
        old.close().await;
        let replacement = pool().await;
        let rebuilt = udp
            .acquire_fixed(address, || async { Ok(replacement.clone()) })
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&rebuilt, &replacement));
        assert!(udp.outbounds.lock().is_empty());
        assert!(
            udp.fixed_address(&endpoint, &Some("other".into()))
                .is_none()
        );
        let mut changed = endpoint.clone();
        changed.port = 5353;
        assert!(udp.fixed_address(&changed, &outbound).is_none());
        changed.port = 53;
        changed.strategy = DnsStrategy::Ipv6Only;
        assert!(udp.fixed_address(&changed, &outbound).is_none());
        udp.close().await;
        assert!(replacement.is_closed());
    }

    #[test]
    fn fixed_route_supports_both_families_but_not_domain_names() {
        for host in ["127.0.0.1:53", "[::1]:53", "dns.example:53"] {
            let endpoint = DnsEndpoint::parse(
                host,
                crate::app::dns::endpoint::DnsProtocol::Udp,
                None,
                None,
                DnsStrategy::PreferIpv4,
            )
            .unwrap();
            let udp = UdpUpstream::new(&endpoint, None);
            assert_eq!(
                udp.fixed_address(&endpoint, &None).is_some(),
                host != "dns.example:53"
            );
        }
    }

    #[tokio::test]
    async fn stale_snapshots_rebuild_a_closed_pool_once() {
        let udp = UdpUpstream::default();
        let address = "127.0.0.1:53".parse().unwrap();
        let old = pool().await;
        udp.for_address(address, &None)
            .acquire(|| async { Ok(old.clone()) })
            .await
            .unwrap();
        let snapshot = udp.snapshot(&[address], &None).unwrap();
        assert_eq!(snapshot.current, None);
        let attempts = snapshot.attempts;
        old.close().await;
        let replacement = pool().await;
        let builds = AtomicUsize::new(0);
        for attempt in attempts {
            let current = attempt
                .acquire(|| async {
                    builds.fetch_add(1, Ordering::SeqCst);
                    Ok(replacement.clone())
                })
                .await
                .unwrap();
            assert!(Arc::ptr_eq(&current, &replacement));
        }
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert!(Arc::ptr_eq(
            udp.for_address(address, &None).pool.as_ref().unwrap(),
            &replacement,
        ));
        udp.close().await;
    }

    #[tokio::test]
    async fn initialization_is_deduplicated_without_blocking_other_keys() {
        let udp = Arc::new(UdpUpstream::default());
        let pool = pool().await;
        let v4 = "127.0.0.1:853".parse().unwrap();
        let v6 = "[::1]:853".parse().unwrap();
        let first_outbound = Some("slow".to_string());
        let second_outbound = Some("other".to_string());
        let initializations = Arc::new(AtomicUsize::new(0));
        let (started, start) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let attempt = udp.for_address(v4, &first_outbound);
        let candidate = Arc::clone(&pool);
        let count = Arc::clone(&initializations);
        let first = tokio::spawn(async move {
            attempt
                .acquire(|| async {
                    count.fetch_add(1, Ordering::SeqCst);
                    started.send(()).unwrap();
                    released.await.unwrap();
                    Ok(candidate)
                })
                .await
                .unwrap()
        });
        start.await.unwrap();
        // One blocked initializer must not serialize another outbound or family.
        for (address, outbound) in [(v4, &second_outbound), (v6, &first_outbound)] {
            let attempt = udp.for_address(address, outbound);
            tokio::time::timeout(
                Duration::from_secs(1),
                attempt.acquire(|| async { Ok(Arc::clone(&pool)) }),
            )
            .await
            .expect("different UDP keys must initialize independently")
            .unwrap();
        }
        let attempt = udp.for_address(v4, &first_outbound);
        let candidate = Arc::clone(&pool);
        let count = Arc::clone(&initializations);
        let second = tokio::spawn(async move {
            attempt
                .acquire(|| async {
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(candidate)
                })
                .await
                .unwrap()
        });
        tokio::task::yield_now().await;
        assert_eq!(initializations.load(Ordering::SeqCst), 1);
        release.send(()).unwrap();
        let first = first.await.unwrap();
        let second = second.await.unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(initializations.load(Ordering::SeqCst), 1);
        udp.close().await;
    }

    #[tokio::test]
    async fn snapshots_keep_outbound_address_preferences_independent() {
        let udp = UdpUpstream::default();
        let pool = pool().await;
        let v4 = "127.0.0.1:853".parse().unwrap();
        let v6 = "[::1]:853".parse().unwrap();
        let ipv6_route = Some("ipv6-route".to_string());
        let ipv4_route = Some("ipv4-route".to_string());
        for (address, outbound) in [(v6, &ipv6_route), (v4, &ipv4_route)] {
            udp.for_address(address, outbound)
                .acquire(|| async { Ok(Arc::clone(&pool)) })
                .await
                .unwrap();
            udp.mark_current(address, outbound);
        }
        let addresses = [v4, v6];
        let snapshot = udp.snapshot(&addresses, &ipv6_route).unwrap();
        assert_eq!(snapshot.current, Some(v6));
        let [first, retry] = snapshot.attempts;
        assert_eq!([first.address, retry.address], [v6, v4]);
        assert!(Arc::ptr_eq(first.pool.as_ref().unwrap(), &pool));
        assert!(retry.pool.is_none());
        let snapshot = udp.snapshot(&addresses, &ipv4_route).unwrap();
        assert_eq!(snapshot.current, Some(v4));
        let [first, retry] = snapshot.attempts;
        assert_eq!([first.address, retry.address], [v4, v6]);
        assert!(Arc::ptr_eq(first.pool.as_ref().unwrap(), &pool));
        assert!(retry.pool.is_none());
        // A preferred address removed by a bootstrap refresh is not retried.
        let snapshot = udp.snapshot(&[v4], &ipv6_route).unwrap();
        assert_eq!(snapshot.current, Some(v6));
        assert_eq!(snapshot.attempts[0].address, v4);
        udp.close().await;
    }
}
