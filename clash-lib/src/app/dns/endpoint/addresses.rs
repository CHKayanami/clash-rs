//! Bootstrap resolution shared by endpoint clones and all DNS transports.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use tokio::time::Instant;

use super::DnsEndpoint;
use crate::app::dns::ClashResolver;

// The resolver API exposes IPs without TTLs. Reuse them for at most one minute;
// failed candidate dials invalidate the cache before the next attempt.
const CACHE_LIFETIME: Duration = Duration::from_secs(60);

struct ResolvedAddresses {
    host: String,
    resolver: Option<Arc<dyn ClashResolver>>,
    ips: Arc<[IpAddr]>,
    expires: Instant,
}

impl ResolvedAddresses {
    fn matches(&self, endpoint: &DnsEndpoint) -> bool {
        self.host == endpoint.host
            && match (&self.resolver, &endpoint.bootstrap_resolver) {
                (Some(cached), Some(current)) => Arc::ptr_eq(cached, current),
                (None, None) => true,
                _ => false,
            }
    }
}

#[derive(Default)]
pub(super) struct AddressCache {
    active: ArcSwapOption<ResolvedAddresses>,
    resolve: tokio::sync::Mutex<()>,
}

impl AddressCache {
    fn cached(&self, endpoint: &DnsEndpoint) -> Option<Arc<[IpAddr]>> {
        self.active
            .load()
            .as_ref()
            .filter(|cached| {
                cached.expires > Instant::now() && cached.matches(endpoint)
            })
            .map(|cached| Arc::clone(&cached.ips))
    }

    pub(super) async fn ips(
        &self,
        endpoint: &DnsEndpoint,
    ) -> anyhow::Result<Arc<[IpAddr]>> {
        if let Some(ips) = self.cached(endpoint) {
            return Ok(ips);
        }
        let _resolve = self.resolve.lock().await;
        if let Some(ips) = self.cached(endpoint) {
            return Ok(ips);
        }
        let ips: Arc<[IpAddr]> = endpoint.resolve_ips().await?.into();
        endpoint.select_addrs(&ips)?;
        self.active.store(Some(Arc::new(ResolvedAddresses {
            host: endpoint.host.clone(),
            resolver: endpoint.bootstrap_resolver.clone(),
            ips: Arc::clone(&ips),
            expires: Instant::now() + CACHE_LIFETIME,
        })));
        Ok(ips)
    }

    pub(super) fn invalidate(&self, endpoint: &DnsEndpoint) {
        self.active.rcu(|cached| {
            cached
                .as_ref()
                .filter(|cached| !cached.matches(endpoint))
                .cloned()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::{
        ResolverKind,
        endpoint::{DnsProtocol, DnsStrategy},
    };
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::{Notify, Semaphore};

    struct BlockingResolver {
        calls: AtomicUsize,
        started: Notify,
        release: Semaphore,
    }

    #[async_trait::async_trait]
    impl ClashResolver for BlockingResolver {
        async fn resolve_v4(
            &self,
            _: &str,
            _: bool,
        ) -> anyhow::Result<Option<Ipv4Addr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            self.release.acquire().await.unwrap().forget();
            Ok(Some(Ipv4Addr::LOCALHOST))
        }
        async fn resolve_v6(
            &self,
            _: &str,
            _: bool,
        ) -> anyhow::Result<Option<Ipv6Addr>> {
            Ok(None)
        }
        async fn resolve(&self, _: &str, _: bool) -> anyhow::Result<Option<IpAddr>> {
            unreachable!()
        }
        async fn exchange(&self, _: &[u8]) -> anyhow::Result<Vec<u8>> {
            unreachable!()
        }
        fn cached_for(&self, _: IpAddr) -> Option<String> {
            None
        }
        fn reverse_lookup(&self, _: IpAddr) -> Option<String> {
            None
        }
        fn is_fake_ip(&self, _: IpAddr) -> bool {
            false
        }
        fn fake_ip_enabled(&self) -> bool {
            false
        }
        async fn after_router_inited(&self, _: Arc<crate::app::router::Router>) {}
        fn ipv6(&self) -> bool {
            true
        }
        fn set_ipv6(&self, _: bool) {}
        fn kind(&self) -> ResolverKind {
            ResolverKind::System
        }
    }

    #[tokio::test]
    async fn concurrent_endpoint_clones_share_in_flight_bootstrap() {
        let bootstrap = Arc::new(BlockingResolver {
            calls: AtomicUsize::new(0),
            started: Notify::new(),
            release: Semaphore::new(0),
        });
        let endpoint = DnsEndpoint::parse(
            "dns.example",
            DnsProtocol::Udp,
            None,
            Some(bootstrap.clone()),
            DnsStrategy::PreferIpv4,
        )
        .unwrap();
        let mut lookups = tokio::task::JoinSet::new();
        let first = endpoint.clone();
        lookups.spawn(async move { first.resolve_addrs().await.unwrap() });
        bootstrap.started.notified().await;
        for _ in 0..9 {
            let endpoint = endpoint.clone();
            lookups.spawn(async move { endpoint.resolve_addrs().await.unwrap() });
        }
        tokio::task::yield_now().await;
        assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 1);
        bootstrap.release.add_permits(10);
        tokio::time::timeout(Duration::from_secs(1), async {
            while let Some(result) = lookups.join_next().await {
                assert_eq!(
                    result.unwrap(),
                    vec!["127.0.0.1:53".parse::<std::net::SocketAddr>().unwrap()]
                );
            }
        })
        .await
        .unwrap();
        assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 1);
    }
}
