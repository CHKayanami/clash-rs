//! Per-outbound UDP state with independent pool initialization for each address family.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwapOption;

use crate::app::dns::endpoint::{DnsEndpoint, DnsStrategy};
use crate::app::dns::transport::{
    UdpPool, NETWORK_RETRY_DELAY, SocketFailure, network_error,
};
use tokio::time::Instant;
use super::routes::{RouteCache, TransportKey};

struct CachedPool {
    address: SocketAddr,
    pool: Arc<UdpPool>,
}

struct RetryFailure {
    address: SocketAddr,
    until: Instant,
    error: SocketFailure,
}

#[derive(Default)]
struct UdpSlot {
    active: ArcSwapOption<CachedPool>,
    init: tokio::sync::Mutex<()>,
    retry: ArcSwapOption<RetryFailure>,
}

impl UdpSlot {
    fn cached(&self, address: SocketAddr) -> Option<Arc<UdpPool>> {
        self.active
            .load()
            .as_ref()
            .filter(|cached| cached.address == address && !cached.pool.is_closed())
            .map(|cached| Arc::clone(&cached.pool))
    }

    fn retry_error(&self, address: SocketAddr) -> Option<io::Error> {
        if let Some(cached) = self.active.load().as_ref()
            && cached.address == address
            && let Some(error) = cached.pool.retry_error()
        {
            return Some(error);
        }
        self.retry.load().as_ref().and_then(|failure| {
            (failure.address == address && Instant::now() < failure.until)
                .then(|| failure.error.error())
        })
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
        if let Some(error) = self.retry_error(address) {
            return Err(error.into());
        }
        let _init = self.init.lock().await;
        if let Some(pool) = self.cached(address) {
            return Ok(pool);
        }
        if let Some(error) = self.retry_error(address) {
            return Err(error.into());
        }
        let pool = match build().await {
            Ok(pool) => pool,
            Err(error) => {
                if let Some(failure) = network_error(&error) {
                    self.retry.store(Some(Arc::new(RetryFailure {
                        address,
                        until: Instant::now() + NETWORK_RETRY_DELAY,
                        error: failure,
                    })));
                }
                return Err(error);
            }
        };
        self.retry.store(None);
        // In-flight exchanges retain the old pool during address refreshes.
        self.active.store(Some(Arc::new(CachedPool {
            address,
            pool: Arc::clone(&pool),
        })));
        Ok(pool)
    }
}

struct OutboundUdp {
    current: ArcSwapOption<SocketAddr>,
    slots: [Arc<UdpSlot>; 2],
}

impl Default for OutboundUdp {
    fn default() -> Self {
        Self {
            current: ArcSwapOption::empty(),
            slots: std::array::from_fn(|_| Arc::new(UdpSlot::default())),
        }
    }
}

struct FixedUdp {
    host: String,
    address: SocketAddr,
    strategy: DnsStrategy,
    slot: UdpSlot,
}

/// Owns UDP pools and address preferences; callers do not access its locks.
#[derive(Default)]
pub struct UdpUpstream {
    fixed: Option<FixedUdp>,
    outbounds: RouteCache<OutboundUdp>,
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
        // Proxied routes always use the selected protocol node's cache entry.
        let fixed = if outbound.is_none() {
            endpoint.host.parse().ok().map(|ip| FixedUdp {
                host: endpoint.host.clone(),
                address: SocketAddr::new(ip, endpoint.port),
                strategy: endpoint.strategy,
                slot: UdpSlot::default(),
            })
        } else { None };
        Self {
            fixed,
            outbounds: RouteCache::default(),
        }
    }

    pub(super) fn fixed_address(
        &self,
        endpoint: &DnsEndpoint,
        outbound: &TransportKey,
    ) -> Option<SocketAddr> {
        self.fixed
            .as_ref()
            .filter(|fixed| {
                fixed.host == endpoint.host
                    && fixed.address.port() == endpoint.port
                    && fixed.strategy == endpoint.strategy
                    && outbound.is_direct()
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
        outbound: &TransportKey,
        managed: bool,
    ) -> anyhow::Result<UdpSnapshot> {
        let route = self.outbounds.get_routed(outbound, managed, OutboundUdp::default);
        let current = route.current.load().as_deref().copied();
        let first = current
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
            current,
            attempts: [Self::attempt(&route, first), Self::attempt(&route, retry)],
        })
    }

    pub(super) fn for_address(
        &self,
        address: SocketAddr,
        outbound: &TransportKey,
        managed: bool,
    ) -> UdpAttempt {
        let route = self.outbounds.get_routed(outbound, managed, OutboundUdp::default);
        Self::attempt(&route, address)
    }

    pub(super) fn mark_current(
        &self,
        address: SocketAddr,
        outbound: &TransportKey,
        managed: bool,
    ) {
        let route = self.outbounds.get_routed(outbound, managed, OutboundUdp::default);
        if route.slots[usize::from(address.is_ipv6())]
                .active
                .load()
                .as_ref()
                .is_some_and(|cached| {
                    cached.address == address && !cached.pool.is_closed()
                })
        {
            route.current.store(Some(Arc::new(address)));
        }
    }

    pub(super) fn rebind(&self, previous: Option<&TransportKey>, next: Option<&TransportKey>) {
        self.outbounds.rebind(previous, next, OutboundUdp::default);
    }

    pub(crate) async fn close(&self) {
        if let Some(fixed) = &self.fixed
            && let Some(cached) = fixed.slot.active.swap(None)
        {
            cached.pool.close().await;
        }
        for route in self.outbounds.take() {
            let slots = route.slots.clone();
            for slot in slots {
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
    #[cfg(unix)]
    use libc::ENETUNREACH;
    #[cfg(windows)]
    use windows::Win32::Networking::WinSock::WSAENETUNREACH;
    #[cfg(windows)]
    const ENETUNREACH: i32 = WSAENETUNREACH.0;
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
    async fn cooldown_does_not_wait_for_init_or_block_other_addresses() {
        let slot = UdpSlot::default();
        let address = "127.0.0.1:53".parse().unwrap();
        let other_address = "127.0.0.2:53".parse().unwrap();
        let error = io::Error::from_raw_os_error(ENETUNREACH);
        let failure = network_error(&error.into()).unwrap();
        slot.retry.store(Some(Arc::new(RetryFailure {
            address, until: Instant::now() + NETWORK_RETRY_DELAY, error: failure,
        })));
        let init = slot.init.lock().await;
        let result = tokio::time::timeout(Duration::from_millis(100),
            slot.acquire(address, || async { panic!("cooldown must skip initialization") }),
        ).await.expect("cooldown must not wait for init");
        assert_eq!(result.err().unwrap().downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(ENETUNREACH));
        drop(init);
        let pool = slot.acquire(other_address, || async { Ok(pool().await) }).await.unwrap();
        assert!(slot.retry.load().is_none());
        pool.close().await;
    }

    #[tokio::test]
    async fn network_failure_cools_down_and_coalesces_rebuilds() {
        let slot = Arc::new(UdpSlot::default());
        let address = "127.0.0.1:53".parse().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let error = slot.acquire(address, || async {
            attempts.fetch_add(1, Ordering::Relaxed);
            Err(io::Error::from(io::ErrorKind::NetworkUnreachable).into())
        }).await.err().unwrap();
        assert_eq!(network_error(&error).unwrap().error().kind(), io::ErrorKind::NetworkUnreachable);
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let slot = slot.clone();
            let attempts = attempts.clone();
            tasks.push(tokio::spawn(async move {
                slot.acquire(address, || async {
                    attempts.fetch_add(1, Ordering::Relaxed);
                    Ok(pool().await)
                }).await
            }));
        }
        for task in tasks {
            assert!(task.await.unwrap().is_err());
        }
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        slot.retry.store(Some(Arc::new(RetryFailure {
            address, until: Instant::now(), error: network_error(&error).unwrap(),
        })));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let slot = slot.clone();
            let attempts = attempts.clone();
            tasks.push(tokio::spawn(async move {
                slot.acquire(address, || async {
                    attempts.fetch_add(1, Ordering::Relaxed);
                    Ok(pool().await)
                }).await.unwrap()
            }));
        }
        let first = tasks.remove(0).await.unwrap();
        for task in tasks {
            assert!(Arc::ptr_eq(&first, &task.await.unwrap()));
        }
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
        assert!(slot.retry.load().is_none());
        first.close().await;
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
        let outbound = TransportKey::default();
        let udp = UdpUpstream::new(&endpoint, None);
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
        assert_eq!(udp.outbounds.len(), 0);
        assert!(
            udp.fixed_address(&endpoint, &TransportKey::named("other"))
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
    fn fixed_slot_is_only_allocated_for_direct_ip_upstreams() {
        for host in ["127.0.0.1:53", "[::1]:53", "dns.example:53"] {
            let endpoint = DnsEndpoint::parse(
                host,
                crate::app::dns::endpoint::DnsProtocol::Udp,
                None,
                None,
                DnsStrategy::PreferIpv4,
            )
            .unwrap();
            for outbound in [None, Some("proxy-group".to_owned())] {
                let expected = outbound.is_none() && host != "dns.example:53";
                let udp = UdpUpstream::new(&endpoint, outbound);
                assert_eq!(udp.fixed.is_some(), expected);
                assert_eq!(
                    udp.fixed_address(&endpoint, &TransportKey::default()).is_some(),
                    expected,
                );
            }
        }
    }

    #[tokio::test]
    async fn stale_snapshots_rebuild_a_closed_pool_once() {
        let udp = UdpUpstream::default();
        let address = "127.0.0.1:53".parse().unwrap();
        let old = pool().await;
        udp.for_address(address, &TransportKey::default(), false)
            .acquire(|| async { Ok(old.clone()) })
            .await
            .unwrap();
        let snapshot = udp.snapshot(&[address], &TransportKey::default(), false).unwrap();
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
            udp.for_address(address, &TransportKey::default(), false).pool.as_ref().unwrap(),
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
        let first_outbound = TransportKey::named("slow");
        let second_outbound = TransportKey::named("other");
        let initializations = Arc::new(AtomicUsize::new(0));
        let (started, start) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let attempt = udp.for_address(v4, &first_outbound, false);
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
            let attempt = udp.for_address(address, outbound, false);
            tokio::time::timeout(
                Duration::from_secs(1),
                attempt.acquire(|| async { Ok(Arc::clone(&pool)) }),
            )
            .await
            .expect("different UDP keys must initialize independently")
            .unwrap();
        }
        let attempt = udp.for_address(v4, &first_outbound, false);
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
        let ipv6_route = TransportKey::named("ipv6-route");
        let ipv4_route = TransportKey::named("ipv4-route");
        for (address, outbound) in [(v6, &ipv6_route), (v4, &ipv4_route)] {
            udp.for_address(address, outbound, false)
                .acquire(|| async { Ok(Arc::clone(&pool)) })
                .await
                .unwrap();
            udp.mark_current(address, outbound, false);
        }
        let addresses = [v4, v6];
        let snapshot = udp.snapshot(&addresses, &ipv6_route, false).unwrap();
        assert_eq!(snapshot.current, Some(v6));
        let [first, retry] = snapshot.attempts;
        assert_eq!([first.address, retry.address], [v6, v4]);
        assert!(Arc::ptr_eq(first.pool.as_ref().unwrap(), &pool));
        assert!(retry.pool.is_none());
        let snapshot = udp.snapshot(&addresses, &ipv4_route, false).unwrap();
        assert_eq!(snapshot.current, Some(v4));
        let [first, retry] = snapshot.attempts;
        assert_eq!([first.address, retry.address], [v4, v6]);
        assert!(Arc::ptr_eq(first.pool.as_ref().unwrap(), &pool));
        assert!(retry.pool.is_none());
        // A preferred address removed by a bootstrap refresh is not retried.
        let snapshot = udp.snapshot(&[v4], &ipv6_route, false).unwrap();
        assert_eq!(snapshot.current, Some(v6));
        assert_eq!(snapshot.attempts[0].address, v4);
        udp.close().await;
    }
}
