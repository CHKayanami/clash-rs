use std::{
    collections::HashMap,
    io::Cursor,
    sync::{
        Arc, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwapOption;
use murmur3::murmur3_32;
use public_suffix::{DEFAULT_PROVIDER, EffectiveTLDProvider};

use crate::{
    app::remote_content_manager::ProxyManager,
    proxy::{OutboundNode, utils::provider_helper::MemberUrls},
    session::Session,
};

pub(super) struct StickySnapshotIndex {
    /// Weak reference ensures stale indexes never pin superseded provider
    /// snapshots or retired protocol handlers.
    snapshot: Weak<Vec<OutboundNode>>,
    name_to_index: HashMap<String, usize>,
}

impl StickySnapshotIndex {
    fn build(proxies: &Arc<Vec<OutboundNode>>) -> Self {
        let mut name_to_index = HashMap::with_capacity(proxies.len());
        for (index, proxy) in proxies.iter().enumerate() {
            // Keep first occurrence to match `Iterator::position`.
            name_to_index.entry(proxy.name().to_owned()).or_insert(index);
        }
        Self {
            snapshot: Arc::downgrade(proxies),
            name_to_index,
        }
    }

    fn matches(&self, proxies: &Arc<Vec<OutboundNode>>) -> bool {
        self.snapshot
            .upgrade()
            .is_some_and(|snap| Arc::ptr_eq(&snap, proxies))
    }

    fn is_live(&self) -> bool {
        self.snapshot.strong_count() > 0
    }
}

pub enum Strategy {
    RoundRobin(AtomicUsize),
    ConsistentHashing,
    StickySession {
        manager: ProxyManager,
        cache: moka::sync::Cache<u64, String>,
        snapshot_index: ArcSwapOption<StickySnapshotIndex>,
        #[cfg(test)]
        index_builds: AtomicUsize,
    },
}

fn get_key(sess: &Session) -> String {
    match &sess.destination {
        crate::session::SocksAddr::Ip(addr) => addr.ip().to_string(),
        crate::session::SocksAddr::Domain(host, _) => DEFAULT_PROVIDER
            .effective_tld_plus_one(host)
            .map(|s| s.to_string())
            .unwrap_or_default(),
    }
}

fn get_key_src_and_dst(sess: &Session) -> String {
    let dst = get_key(sess);
    let src = match &sess.source {
        std::net::SocketAddr::V4(socket_addr_v4) => socket_addr_v4.ip().to_string(),
        std::net::SocketAddr::V6(socket_addr_v6) => socket_addr_v6.ip().to_string(),
    };
    format!("{src}-{dst}")
}

fn jump_hash(key: u64, buckets: i32) -> i32 {
    let mut key = key;
    let mut b = -1i64;
    let mut j = 0i64;
    while j < buckets as i64 {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        j = ((b + 1) as f64 * (1i64 << 31) as f64 / ((key >> 33) + 1) as f64) as i64;
    }
    b as i32
}

pub fn strategy_rr() -> Strategy { Strategy::RoundRobin(AtomicUsize::new(0)) }
pub fn strategy_consistent_hashring() -> Strategy { Strategy::ConsistentHashing }

#[cfg(test)]
static TEST_LRU_STATE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(CACHE_MISS);
#[cfg(test)]
const CACHE_MISS: usize = 0;
#[cfg(test)]
const CACHE_HIT: usize = 1;
#[cfg(test)]
const CACHE_UPDATE: usize = 2;

pub fn strategy_sticky_session(manager: ProxyManager) -> Strategy {
    let cache = moka::sync::Cache::builder()
        .max_capacity(1024)
        .time_to_live(std::time::Duration::from_secs(60 * 10))
        .build();
    Strategy::StickySession {
        manager,
        cache,
        snapshot_index: ArcSwapOption::new(None),
        #[cfg(test)]
        index_builds: AtomicUsize::new(0),
    }
}

impl Strategy {
    pub(crate) fn invalidate_stale_cache(&self) {
        if let Self::StickySession { snapshot_index, .. } = self
            && snapshot_index
                .load()
                .as_deref()
                .is_some_and(|idx| !idx.is_live())
        {
            snapshot_index.store(None);
        }
    }

    pub(crate) fn pick(
        &self,
        proxies: Arc<Vec<OutboundNode>>,
        urls: &MemberUrls,
        fallback_url: Option<&str>,
        sess: &Session,
    ) -> std::io::Result<OutboundNode> {
        if proxies.is_empty() { return Err(std::io::Error::other("no proxy found")); }
        match self {
            Self::RoundRobin(index) => {
                let len = proxies.len();
                let previous = index.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some((value % len).wrapping_add(1))
                }).expect("round-robin update always succeeds");
                Ok(proxies[previous % len].clone())
            }
            Self::ConsistentHashing => {
                let key = murmur3_32(&mut Cursor::new(get_key(sess)), 0).unwrap() as u64;
                Ok(proxies[jump_hash(key, proxies.len() as i32) as usize].clone())
            }
            Self::StickySession {
                manager,
                cache,
                snapshot_index,
                #[cfg(test)]
                index_builds,
            } => {
                let key = murmur3_32(&mut Cursor::new(get_key_src_and_dst(sess)), 0).unwrap() as u64;
                let index = get_or_build_sticky_index(
                    snapshot_index,
                    &proxies,
                    #[cfg(test)]
                    index_builds,
                );
                sticky_pick(proxies, urls, fallback_url, key, manager, cache, &index)
            }
        }
    }
}

fn get_or_build_sticky_index(
    snapshot_index: &ArcSwapOption<StickySnapshotIndex>,
    proxies: &Arc<Vec<OutboundNode>>,
    #[cfg(test)] index_builds: &AtomicUsize,
) -> Arc<StickySnapshotIndex> {
    if let Some(existing) = snapshot_index.load_full()
        && existing.matches(proxies)
    {
        return existing;
    }

    #[cfg(test)]
    index_builds.fetch_add(1, Ordering::Relaxed);
    let built = Arc::new(StickySnapshotIndex::build(proxies));
    snapshot_index.rcu(|current| {
        if let Some(existing) = current
            && existing.matches(proxies)
        {
            return Some(existing.clone());
        }
        Some(built.clone())
    });

    if let Some(current) = snapshot_index.load_full()
        && current.matches(proxies)
    {
        current
    } else {
        built
    }
}

fn sticky_pick(
    proxies: Arc<Vec<OutboundNode>>,
    urls: &MemberUrls,
    fallback_url: Option<&str>,
    key: u64,
    manager: &ProxyManager,
    cache: &moka::sync::Cache<u64, String>,
    snapshot_index: &StickySnapshotIndex,
) -> std::io::Result<OutboundNode> {
    let timestamp = || SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    if proxies.is_empty() {
        return Err(std::io::Error::other("no proxy found"));
    }
    let cached_name = cache.get(&key);
    let cached_index = cached_name
        .as_deref()
        .and_then(|name| snapshot_index.name_to_index.get(name).copied());
    let (start_index, hit) = match cached_index {
        Some(index) => {
            #[cfg(test)]
            {
                TEST_LRU_STATE
                    .store(CACHE_HIT, std::sync::atomic::Ordering::Relaxed);
            }
            (index, true)
        }
        None => (
            jump_hash(key + timestamp(), proxies.len() as i32) as usize,
            false,
        ),
    };

    // Visit each member once, starting with the cached choice when it
    // is still present. Random retries can miss a healthy member.
    for offset in 0..proxies.len() {
        let index = (start_index + offset) % proxies.len();
        let proxy = &proxies[index];
        if manager.alive_for(proxy, urls.url_at(index, fallback_url)) {
            // now it's a valid proxy
            // check if it's the same as the last one(likely)
            // update the cache if:
            //   1. the index is not the same as the start_index
            //   2. the start_index is not fetched from the cache
            if index != start_index || !hit {
                cache.insert(key, proxy.name().to_owned());
                #[cfg(test)]
                {
                    TEST_LRU_STATE.store(
                        CACHE_UPDATE,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
            }
            return Ok(proxy.clone());
        }
    }
    cache.invalidate(&key);
    #[cfg(test)]
    {
        TEST_LRU_STATE
            .store(CACHE_MISS, std::sync::atomic::Ordering::Relaxed);
    }
    Err(std::io::Error::other("no proxy found"))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        sync::Arc,
    };

    use super::*;
    use crate::{
        app::remote_content_manager::ProxyManager,
        proxy::utils::test_utils::noop::{NoopOutboundHandler, NoopResolver},
        session::SocksAddr,
    };

    macro_rules! assert_cache_state {
        ($state:expr_2021) => {
            assert_eq!(
                TEST_LRU_STATE.load(std::sync::atomic::Ordering::Relaxed),
                $state
            );
        };
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_sticky_session() {
        let resolver = Arc::new(NoopResolver);
        let proxies: Arc<Vec<OutboundNode>> = Arc::new(vec![
            OutboundNode::protocol(Arc::new(NoopOutboundHandler {
                name: "a".to_string(),
            })),
            OutboundNode::protocol(Arc::new(NoopOutboundHandler {
                name: "b".to_string(),
            })),
            OutboundNode::protocol(Arc::new(NoopOutboundHandler {
                name: "c".to_string(),
            })),
        ]);
        let manager = ProxyManager::new(resolver, None);
        // if the proxy alive state isn't set, will return true by default
        // so we need to clear the alive states first
        manager.report_alive("a", false, None).await;
        manager.report_alive("b", false, None).await;
        manager.report_alive("c", false, None).await;

        let strategy_fn = strategy_sticky_session(manager.clone());
        let no_urls = MemberUrls::Uniform(None);

        // all proxies is not alive since we have not setup the proxy manager
        let res = strategy_fn.pick(proxies.clone(), &no_urls, None, &Session::default());
        assert!(res.is_err());
        assert_cache_state!(CACHE_MISS);

        manager.report_alive("a", true, None).await;
        manager.report_alive("b", true, None).await;
        manager.report_alive("c", true, None).await;

        let mut session1 = Session::default();
        let src1 = Ipv4Addr::new(127, 0, 0, 1);
        let dst1 = Ipv4Addr::new(1, 1, 1, 1);
        session1.source = SocketAddr::V4(SocketAddrV4::new(src1, 8964));
        session1.destination =
            SocksAddr::Ip(SocketAddr::V4(SocketAddrV4::new(dst1, 80)));

        // 1.1 first time, cache miss & update
        let res = strategy_fn.pick(proxies.clone(), &no_urls, None, &session1);
        assert_cache_state!(CACHE_UPDATE);
        let session1_outbound_name_1 = res.unwrap().name().to_owned();

        // 1.2 second time, cache hit
        let res = strategy_fn.pick(proxies.clone(), &no_urls, None, &session1);
        assert_eq!(res.unwrap().name(), session1_outbound_name_1);
        assert_cache_state!(CACHE_HIT);
        // 1.3 third time, cache hit
        let res = strategy_fn.pick(proxies.clone(), &no_urls, None, &session1);
        assert_eq!(res.unwrap().name(), session1_outbound_name_1);
        assert_cache_state!(CACHE_HIT);

        // 1.4 change the source address, cache miss & update
        let dst1_2 = Ipv4Addr::new(8, 8, 8, 8);
        session1.destination =
            SocksAddr::Ip(SocketAddr::V4(SocketAddrV4::new(dst1_2, 80)));
        let res = strategy_fn.pick(proxies.clone(), &no_urls, None, &session1);
        assert_cache_state!(CACHE_UPDATE);
        let session1_outbound_name_2 = res.unwrap().name().to_owned();

        // 1.5 cache hit
        let res = strategy_fn.pick(proxies.clone(), &no_urls, None, &session1);
        assert_eq!(res.unwrap().name(), session1_outbound_name_2);
        assert_cache_state!(CACHE_HIT);

        for i in 1..100 {
            // 1.6 change the src address, cache miss & update
            let src1_new = Ipv4Addr::new(192, 168, 2, i);
            session1.source = SocketAddr::V4(SocketAddrV4::new(src1_new, 8964));
            let res = strategy_fn.pick(proxies.clone(), &no_urls, None, &session1);
            assert_cache_state!(CACHE_UPDATE);
            let session1_outbound_name_new = res.unwrap().name().to_owned();

            // 1.6 cache hit
            let res = strategy_fn.pick(proxies.clone(), &no_urls, None, &session1);
            assert_eq!(res.unwrap().name(), session1_outbound_name_new);
            assert_cache_state!(CACHE_HIT);
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_sticky_session_survives_reorder_and_checks_all_members() {
        let manager = ProxyManager::new(Arc::new(NoopResolver), None);
        let strategy = strategy_sticky_session(manager.clone());
        let no_urls = MemberUrls::Uniform(None);
        let make_proxy = |name: &str| -> OutboundNode {
            OutboundNode::protocol(Arc::new(NoopOutboundHandler {
                name: name.to_owned(),
            }))
        };
        let a = make_proxy("a");
        let b = make_proxy("b");
        let sess = Session::default();

        assert_eq!(
            strategy
                .pick(Arc::new(vec![a.clone()]), &no_urls, None, &sess)
                .unwrap()
                .name(),
            "a"
        );
        assert_eq!(
            strategy
                .pick(Arc::new(vec![b.clone(), a.clone()]), &no_urls, None, &sess)
                .unwrap()
                .name(),
            "a"
        );

        manager.report_alive("a", false, None).await;
        let mut members = vec![a];
        for i in 0..6 {
            let name = format!("dead-{i}");
            manager.report_alive(&name, false, None).await;
            members.push(make_proxy(&name));
        }
        members.push(b);
        assert_eq!(
            strategy
                .pick(Arc::new(members), &no_urls, None, &sess)
                .unwrap()
                .name(),
            "b"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn round_robin_distributes_concurrent_picks_and_handles_resize() {
        let strategy = Arc::new(strategy_rr());
        let no_urls = MemberUrls::Uniform(None);
        let proxies = Arc::new((0..4).map(|index| {
            OutboundNode::protocol(Arc::new(NoopOutboundHandler { name: index.to_string() }))
        }).collect::<Vec<_>>());
        let tasks = (0..400).map(|_| {
            let strategy = strategy.clone();
            let proxies = proxies.clone();
            tokio::spawn(async move {
                let no_urls = MemberUrls::Uniform(None);
                strategy.pick(proxies, &no_urls, None, &Session::default()).unwrap()
                    .name().parse::<usize>().unwrap()
            })
        });
        let mut counts = [0; 4];
        for result in futures::future::join_all(tasks).await {
            counts[result.unwrap()] += 1;
        }
        assert_eq!(counts, [100; 4]);
        let session = Session::default();
        let small = Arc::new(vec![proxies[0].clone(), proxies[1].clone()]);
        // The previous call left index=4: shrinking normalizes to index=0.
        assert_eq!(strategy.pick(small.clone(), &no_urls, None, &session).unwrap().name(), "0");
        assert_eq!(strategy.pick(small, &no_urls, None, &session).unwrap().name(), "1");
        assert!(strategy.pick(Arc::new(Vec::new()), &no_urls, None, &session).is_err());
        assert_eq!(strategy.pick(proxies, &no_urls, None, &session).unwrap().name(), "2");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn sticky_session_reuses_snapshot_index_handles_duplicates_and_does_not_pin_old_snapshot() {
        let manager = ProxyManager::new(Arc::new(NoopResolver), None);
        let strategy = strategy_sticky_session(manager.clone());
        let no_urls = MemberUrls::Uniform(None);
        let make_proxy = |name: &str| -> OutboundNode {
            OutboundNode::protocol(Arc::new(NoopOutboundHandler {
                name: name.to_owned(),
            }))
        };

        let a1 = make_proxy("dup");
        let a1_id = a1.identity();
        let a1_weak = a1.downgrade();
        let b = make_proxy("b");
        let a2 = make_proxy("dup");
        let snap1 = Arc::new(vec![a1, b.clone(), a2]);
        let sess = Session::default();

        // Seed cache with "dup" via a single-member snapshot first, then pick on snap1.
        let seed_snap = Arc::new(vec![make_proxy("dup")]);
        assert_eq!(
            strategy.pick(seed_snap, &no_urls, None, &sess).unwrap().name(),
            "dup"
        );

        let builds_after_seed = match &strategy {
            Strategy::StickySession { index_builds, .. } => {
                index_builds.load(Ordering::Relaxed)
            }
            _ => unreachable!(),
        };
        assert_eq!(builds_after_seed, 1);

        // Repeated picks against snap1 must hit the FIRST "dup" (a1) and build index once.
        for _ in 0..5 {
            let picked = strategy.pick(snap1.clone(), &no_urls, None, &sess).unwrap();
            assert_eq!(picked.identity(), a1_id);
            assert_cache_state!(CACHE_HIT);
        }
        let builds_after_snap1 = match &strategy {
            Strategy::StickySession { index_builds, .. } => {
                index_builds.load(Ordering::Relaxed)
            }
            _ => unreachable!(),
        };
        assert_eq!(builds_after_snap1, 2);

        // When "dup" becomes unhealthy on snap1, failover starts at index 0 and
        // picks index 1 ("b"), preserving the exact existing lookup order.
        manager.report_alive("dup", false, None).await;
        let picked = strategy.pick(snap1.clone(), &no_urls, None, &sess).unwrap();
        assert_eq!(picked.name(), "b");
        assert_cache_state!(CACHE_UPDATE);

        // Dropping snap1 and invalidating must not pin retired handlers.
        drop(snap1);
        strategy.invalidate_stale_cache();
        assert!(
            a1_weak.upgrade().is_none(),
            "sticky snapshot index must not pin retired handlers"
        );

        // New snapshot rebuilds the index once and reuses it.
        let snap2 = Arc::new(vec![make_proxy("x"), b]);
        assert_eq!(
            strategy.pick(snap2.clone(), &no_urls, None, &sess).unwrap().name(),
            "b"
        );
        assert_eq!(
            strategy.pick(snap2, &no_urls, None, &sess).unwrap().name(),
            "b"
        );
        let builds_after_snap2 = match &strategy {
            Strategy::StickySession { index_builds, .. } => {
                index_builds.load(Ordering::Relaxed)
            }
            _ => unreachable!(),
        };
        assert_eq!(builds_after_snap2, 3);
    }

}
