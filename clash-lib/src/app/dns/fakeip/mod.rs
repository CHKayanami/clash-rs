use crate::Error;
use crate::app::router::ThreadSafeRuleProvider;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::{net, sync::Arc};

use async_trait::async_trait;
use portable_atomic::AtomicU128;
use tracing::debug;

mod file_store;
mod mem_store;

pub use file_store::FileStore;
pub use mem_store::InMemStore;

pub struct Opts {
    pub ipnet: ipnet::Ipv4Net,
    pub ipnet6: ipnet::Ipv6Net,
    pub domain_filter: Option<crate::app::dns::filters::DomainFilter>,
    pub store: Box<dyn Store>,
}

#[async_trait]
pub trait Store: Sync + Send {
    async fn get_by_host(&self, host: &str) -> Option<net::IpAddr>;
    async fn get_v6_by_host(&self, host: &str) -> Option<net::IpAddr>;

    async fn put_by_host(&self, host: &str, ip: net::IpAddr);
    async fn get_by_ip(&self, ip: net::IpAddr) -> Option<String>;
    async fn put_by_ip(&self, ip: net::IpAddr, host: &str);
    async fn del_by_ip(&self, ip: net::IpAddr);
    async fn exist(&self, ip: net::IpAddr) -> bool;
    async fn copy_to(&self, store: &dyn Store);
}

pub type ThreadSafeFakeDns = Arc<FakeDns>;

pub struct FakePoolV4 {
    pub min: u32,
    pub max: u32,
    pub offset: AtomicU32,
}

pub struct FakePoolV6 {
    pub prefix: [u8; 16],
    pub prefix_len: u8,
    pub min_host: u128,
    pub max_host: u128,
    pub offset: AtomicU128,
}

pub struct FakeDns {
    v4_pool: Option<FakePoolV4>,
    v6_pool: Option<FakePoolV6>,
    domain_filter: Option<crate::app::dns::filters::DomainFilter>,
    store: Box<dyn Store>,
    /// Memoized `should_skip` verdicts. Covers both static `fake-ip-filter`
    /// entries and `rule-set:` matches; cleared wholesale whenever one of the
    /// bound rule-sets reloads (see [`FakeDns::add_rule_set`]).
    skip_cache: moka::sync::Cache<String, bool>,
}

impl FakeDns {
    pub fn new(opt: Opts) -> Result<Self, Error> {
        // /31 and /32 leave no usable host addresses: `total` would underflow
        // and `pool_size` in `get()` would end up zero, panicking on `% 0`.
        // /0 would overflow the shift. Reject both up front.
        let prefix_len = opt.ipnet.prefix_len();
        if prefix_len > 30 {
            return Err(Error::InvalidConfig(format!(
                "fake ip range {} is too small, need /30 or wider",
                opt.ipnet
            )));
        }
        let host_bits = 32 - prefix_len;
        let total: u32 = if host_bits >= 32 {
            u32::MAX - 2
        } else {
            (1u32 << host_bits) - 2
        };
        let min = u32::from(opt.ipnet.network()).saturating_add(2);
        let v4_pool = Some(FakePoolV4 {
            min,
            max: min.saturating_add(total - 1),
            offset: AtomicU32::new(0),
        });

        // Same reasoning as above: /127 and /128 make `max_host` underflow.
        let prefix_len6 = opt.ipnet6.prefix_len();
        if prefix_len6 > 126 {
            return Err(Error::InvalidConfig(format!(
                "fake ipv6 range {} is too small, need /126 or wider",
                opt.ipnet6
            )));
        }
        let host_bits = 128 - prefix_len6;
        let max_host = if host_bits >= 128 {
            u128::MAX - 2
        } else {
            (1u128 << host_bits) - 2
        };
        let v6_pool = Some(FakePoolV6 {
            prefix: opt.ipnet6.network().octets(),
            prefix_len: prefix_len6,
            min_host: 1,
            max_host,
            offset: AtomicU128::new(0),
        });

        Ok(Self {
            v4_pool,
            v6_pool,
            domain_filter: opt.domain_filter,
            store: opt.store,
            skip_cache: moka::sync::Cache::builder().max_capacity(1000).build(),
        })
    }

    pub async fn lookup(&self, host: &str) -> net::IpAddr {
        if let Some(ip) = self.store.get_by_host(host).await {
            return ip;
        }

        let ip = self.get(host).await;
        self.store.put_by_host(host, ip).await;
        ip
    }

    pub async fn lookupv6(&self, host: &str) -> net::IpAddr {
        if let Some(ip) = self.store.get_v6_by_host(host).await {
            return ip;
        }

        let ip = self.getv6(host).await;
        self.store.put_by_host(host, ip).await;
        ip
    }

    pub async fn reverse_lookup(&self, ip: net::IpAddr) -> Option<String> {
        self.store.get_by_ip(ip).await
    }

    pub async fn add_rule_set(
        &self,
        rp_map: &HashMap<String, ThreadSafeRuleProvider>,
    ) {
        if let Some(filter) = &self.domain_filter {
            if let Some(providers) = filter.add_rule_set(rp_map) {
                // Subscribe before publishing the providers, so no query can be
                // served from a cache that isn't wired for invalidation yet.
                //
                // `moka` cache handles are cheap to clone and share one backing
                // store, so the callback carries a handle rather than a
                // back-reference to `FakeDns` — no reference cycle, and nothing
                // here keeps the resolver alive.
                for rp in providers {
                    let cache = self.skip_cache.clone();
                    let name = rp.name().to_owned();
                    rp.on_change(Arc::new(move || {
                        debug!(
                            "rule-set {} reloaded, clearing fake-ip skip cache",
                            name
                        );
                        cache.invalidate_all();
                    }));
                }

                // Verdicts computed before the rule-sets were bound assumed there
                // were none; drop them.
                self.skip_cache.invalidate_all();
            }
        }
    }

    pub fn should_skip(&self, domain: &str) -> bool {
        if let Some(cached) = self.skip_cache.get(domain) {
            return cached;
        }

        let verdict = self.compute_should_skip(domain);
        self.skip_cache.insert(domain.to_owned(), verdict);
        verdict
    }

    /// Uncached `should_skip`. Every exit here must be invalidated by something
    /// — the static trie is fixed for the process lifetime, and rule-set
    /// matches are covered by the `on_change` subscription installed in
    /// [`FakeDns::add_rule_set`].
    fn compute_should_skip(&self, domain: &str) -> bool {
        if let Some(filter) = &self.domain_filter {
            filter.apply(domain)
        } else {
            false
        }
    }

    #[allow(dead_code)]
    pub async fn exist(&self, ip: net::IpAddr) -> bool {
        self.store.exist(ip).await
    }

    pub async fn is_fake_ip(&self, ip: net::IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_broadcast() || v4.is_multicast() {
                    return false;
                }
                // 检查 v4 存储和网段
                if let Some(pool) = &self.v4_pool {
                    let u = u32::from(v4);
                    if u < pool.min || u > pool.max {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_multicast() {
                    return false;
                }
                // Mirror the v4 arm: reject anything outside the configured
                // pool before paying for a store lookup.
                match &self.v6_pool {
                    Some(pool) => {
                        let u = u128::from(v6);
                        let mask = Self::v6_prefix_mask(pool.prefix_len);
                        if u & mask != u128::from_be_bytes(pool.prefix) & mask {
                            return false;
                        }
                        let host_id = u & !mask;
                        if host_id < pool.min_host || host_id > pool.max_host {
                            return false;
                        }
                    }
                    None => return false,
                }
            }
        }
        self.store.exist(ip).await
    }

    #[allow(dead_code)]
    pub async fn copy_from(&self, src: &Self) {
        src.store.copy_to(&*self.store).await;
    }

    async fn get(&self, host: &str) -> net::IpAddr {
        let mut allocated_v4 = None;
        if let Some(pool) = &self.v4_pool {
            let pool_size = pool.max - pool.min + 1;
            let mut current_try = 0;
            loop {
                let candidate_offset = pool
                    .offset
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |val| {
                        Some((val + 1) % pool_size)
                    })
                    .unwrap();
                let ip = Ipv4Addr::from(pool.min + candidate_offset);
                let ip_addr = IpAddr::V4(ip);
                if current_try >= pool_size {
                    self.store.del_by_ip(ip_addr).await;
                    allocated_v4 = Some(ip);
                    break;
                }
                if !self.store.exist(ip_addr).await {
                    allocated_v4 = Some(ip);
                    break;
                }
                current_try += 1;
            }
        }

        if let Some(v4) = allocated_v4 {
            let ip = IpAddr::V4(v4);
            self.store.put_by_ip(ip, host).await;
            ip
        } else {
            panic!("IPv4 subnet not configured");
        }
    }

    /// ----------------------------------------
    /// 2. 仅分配/查询 IPv6 Fake IP (应对 AAAA 记录)
    /// ----------------------------------------
    pub async fn getv6(&self, host: &str) -> IpAddr {
        let pool = self.v6_pool.as_ref().unwrap();
        let pool_size = pool.max_host - pool.min_host + 1;
        let mut current_try = 0;
        let allocated_ip;
        loop {
            let candidate_offset = pool
                .offset
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |val| {
                    Some((val + 1) % pool_size)
                })
                .unwrap();
            let ip = Self::assemble_ipv6(
                &pool.prefix,
                pool.prefix_len,
                pool.min_host + candidate_offset,
            );
            let ip_addr = IpAddr::V6(ip);

            if current_try >= pool_size {
                // 撞圈，淘汰最老的一个
                self.store.del_by_ip(ip_addr).await;
                allocated_ip = Some(ip);
                break;
            }
            if !self.store.exist(ip_addr).await {
                allocated_ip = Some(ip);
                break;
            }
            current_try += 1;
        }

        // 3. 写入存储
        if let Some(ip) = allocated_ip {
            let ip_addr = IpAddr::V6(ip);
            self.store.put_by_ip(ip_addr, host).await;
            ip_addr
        } else {
            panic!("IPv6 subnet not configured");
        }
    }

    /// Network mask for an IPv6 prefix length. `u128::MAX << 128` would be an
    /// overflowing shift, so `/0` is special-cased.
    fn v6_prefix_mask(prefix_len: u8) -> u128 {
        if prefix_len == 0 {
            0
        } else {
            u128::MAX << (128 - prefix_len)
        }
    }

    // 辅助函数：IPv6 拼接
    fn assemble_ipv6(prefix: &[u8; 16], prefix_len: u8, host_id: u128) -> Ipv6Addr {
        let mut ip_u128 = u128::from_be_bytes(*prefix);
        let mask = Self::v6_prefix_mask(prefix_len);
        ip_u128 &= mask;
        ip_u128 |= host_id & !mask;
        Ipv6Addr::from(ip_u128)
    }
}

#[cfg(test)]
mod tests {
    use std::{net, sync::Arc};

    use crate::{app::dns::fakeip::mem_store::InMemStore, common::trie};

    use super::{FakeDns, Opts, Store};

    #[tokio::test]
    async fn test_inmem_basic() {
        let ipnet = "192.168.0.0/29".parse::<ipnet::IpNet>().unwrap();
        let store = Box::new(InMemStore::new(10));
        let pool = FakeDns::new(Opts {
            ipnet: match ipnet {
                ipnet::IpNet::V4(v4) => v4,
                _ => panic!(),
            },
            ipnet6: "fdfe:5a70:6451:982b::/64"
                .parse::<ipnet::Ipv6Net>()
                .unwrap(),
            domain_filter: None,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com").await;
        let last = pool.lookup("bar.com").await;

        let bar = pool.reverse_lookup(last).await;

        assert_eq!(first, net::IpAddr::from([192, 168, 0, 2]));
        assert_eq!(
            pool.lookup("foo.com").await,
            net::IpAddr::from([192, 168, 0, 2])
        );
        assert_eq!(last, net::IpAddr::from([192, 168, 0, 3]));
        assert!(bar.is_some());
        assert_eq!(bar, Some("bar.com".into()));
        assert!(pool.exist(net::IpAddr::from([192, 168, 0, 3])).await);
        assert!(!pool.exist(net::IpAddr::from([192, 168, 0, 4])).await);
        assert!(!pool.exist("::1".parse().unwrap()).await);
    }

    #[tokio::test]
    async fn test_inmem_cycle_used() {
        let store = Box::new(InMemStore::new(10));

        let ipnet = "192.168.0.0/29".parse::<ipnet::IpNet>().unwrap();
        let pool = FakeDns::new(Opts {
            ipnet: match ipnet {
                ipnet::IpNet::V4(v4) => v4,
                _ => panic!(),
            },
            ipnet6: "fdfe:5a70:6451:982b::/64"
                .parse::<ipnet::Ipv6Net>()
                .unwrap(),
            domain_filter: None,
            store,
        })
        .unwrap();

        let foo = pool.lookup("foo.com").await;
        let bar = pool.lookup("bar.com").await;

        for i in 0..4 {
            pool.lookup(&format!("{}.com", i)).await;
        }

        let baz = pool.lookup("baz.com").await;
        let next = pool.lookup("foo.com").await;
        assert_eq!(foo, baz);
        assert_eq!(next, bar);
    }

    #[tokio::test]
    async fn test_pool_skip() {
        let store = Box::new(InMemStore::new(10));

        let ipnet = "192.168.0.0/30".parse::<ipnet::IpNet>().unwrap();
        let mut tree = trie::StringTrie::new();
        tree.insert("example.com", Arc::new(false));

        let pool = FakeDns::new(Opts {
            ipnet: match ipnet {
                ipnet::IpNet::V4(v4) => v4,
                _ => panic!(),
            },
            ipnet6: "fdfe:5a70:6451:982b::/64"
                .parse::<ipnet::Ipv6Net>()
                .unwrap(),
            domain_filter: Some(crate::app::dns::filters::DomainFilter::new(vec![
                "example.com",
            ])),
            store,
        })
        .unwrap();

        assert!(pool.should_skip("example.com"));
        // Repeated lookups must be stable.
        assert!(pool.should_skip("example.com"));

        assert!(!pool.should_skip("foo.com"));
        assert!(!pool.should_skip("foo.com"));

        // Binding an empty rule-set map must not change static verdicts.
        pool.add_rule_set(&std::collections::HashMap::new()).await;
        assert!(pool.should_skip("example.com"));
        assert!(!pool.should_skip("foo.com"));
    }

    #[tokio::test]
    async fn test_pool_max_cache_size() {
        let store = Box::new(InMemStore::new(2));

        let ipnet = "192.168.0.0/24".parse::<ipnet::IpNet>().unwrap();
        let pool = FakeDns::new(Opts {
            ipnet: match ipnet {
                ipnet::IpNet::V4(v4) => v4,
                _ => panic!(),
            },
            ipnet6: "fdfe:5a70:6451:982b::/64"
                .parse::<ipnet::Ipv6Net>()
                .unwrap(),
            domain_filter: None,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com").await;

        pool.lookup("bar.com").await;
        pool.lookup("baz.com").await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let next = pool.lookup("foo.com").await;

        assert_ne!(first, next);
    }

    #[tokio::test]
    #[ignore = "copy not implemented"]
    async fn test_pool_clone() {
        let store = Box::new(InMemStore::new(2));

        let ipnet = "192.168.0.0/24".parse::<ipnet::IpNet>().unwrap();
        let pool = FakeDns::new(Opts {
            ipnet: match ipnet {
                ipnet::IpNet::V4(v4) => v4,
                _ => panic!(),
            },
            ipnet6: "fdfe:5a70:6451:982b::/64"
                .parse::<ipnet::Ipv6Net>()
                .unwrap(),
            domain_filter: None,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com").await;
        let last = pool.lookup("bar.com").await;
        assert_eq!(first, net::IpAddr::from([192, 168, 0, 2]));
        assert_eq!(last, net::IpAddr::from([192, 168, 0, 3]));

        let store = Box::new(InMemStore::new(2));

        let new_pool = FakeDns::new(Opts {
            ipnet: match ipnet {
                ipnet::IpNet::V4(v4) => v4,
                _ => panic!(),
            },
            ipnet6: "fdfe:5a70:6451:982b::/64"
                .parse::<ipnet::Ipv6Net>()
                .unwrap(),
            domain_filter: None,
            store,
        })
        .unwrap();

        new_pool.copy_from(&pool).await;

        assert!(new_pool.reverse_lookup(first).await.is_some());
        assert!(new_pool.reverse_lookup(last).await.is_some());
    }

    #[tokio::test]
    async fn test_is_fake_ip_excludes_broadcast_and_unallocated() {
        let store = Box::new(InMemStore::new(10));

        let ipnet = "198.18.0.0/16".parse::<ipnet::IpNet>().unwrap();
        let pool = FakeDns::new(Opts {
            ipnet: match ipnet {
                ipnet::IpNet::V4(v4) => v4,
                _ => panic!(),
            },
            ipnet6: "fdfe:5a70:6451:982b::/64"
                .parse::<ipnet::Ipv6Net>()
                .unwrap(),
            domain_filter: None,
            store,
        })
        .unwrap();

        // Allocate one real fake IP.
        let allocated = pool.lookup("foo.com").await;
        assert!(
            pool.is_fake_ip(allocated).await,
            "allocated IP must be fake"
        );

        // Directed broadcast for the /24 TUN subnet (198.18.0.0/24) – never
        // allocated, yet it falls inside the /16 range.
        let directed_broadcast: net::IpAddr = "198.18.0.255".parse().unwrap();
        assert!(
            !pool.is_fake_ip(directed_broadcast).await,
            "directed broadcast must not be treated as a fake IP"
        );

        // Global broadcast must never be a fake IP.
        let global_broadcast: net::IpAddr = "255.255.255.255".parse().unwrap();
        assert!(
            !pool.is_fake_ip(global_broadcast).await,
            "255.255.255.255 must not be a fake IP"
        );

        // A multicast address must never be a fake IP.
        let multicast: net::IpAddr = "224.0.0.1".parse().unwrap();
        assert!(
            !pool.is_fake_ip(multicast).await,
            "multicast must not be a fake IP"
        );

        // An IP in the range that was never allocated must not be fake.
        let unallocated: net::IpAddr = "198.18.1.1".parse().unwrap();
        assert!(
            !pool.is_fake_ip(unallocated).await,
            "unallocated in-range IP must not be treated as a fake IP"
        );
    }

    #[tokio::test]
    async fn test_file_store_basic() {
        use crate::app::dns::fakeip::file_store::FileStore;
        use crate::app::profile::ThreadSafeCacheFile;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let cache_path = temp_dir.path().join("test_cache.db");
        let cache_store =
            ThreadSafeCacheFile::new(cache_path.to_str().unwrap(), true);

        let ipnet = "192.168.0.0/29".parse::<ipnet::IpNet>().unwrap();
        let store = Box::new(FileStore::new(cache_store.clone()));
        let pool = FakeDns::new(Opts {
            ipnet: match ipnet {
                ipnet::IpNet::V4(v4) => v4,
                _ => panic!(),
            },
            ipnet6: "fdfe:5a70:6451:982b::/64"
                .parse::<ipnet::Ipv6Net>()
                .unwrap(),
            domain_filter: None,
            store,
        })
        .unwrap();

        // 1. Resolve host and get IPv4
        let first = pool.lookup("foo.com").await;
        // 2. Resolve host and get IPv6
        let first_v6 = pool.lookupv6("foo.com").await;

        assert_eq!(first, net::IpAddr::from([192, 168, 0, 2]));
        assert!(first_v6.is_ipv6());

        // 3. Query back
        let ip_v4 = pool.store.get_by_host("foo.com").await;
        let ip_v6 = pool.store.get_v6_by_host("foo.com").await;

        assert_eq!(ip_v4, Some(first));
        assert_eq!(ip_v6, Some(first_v6));

        // 4. Reverse lookups should return original host
        assert_eq!(
            pool.reverse_lookup(first).await,
            Some("foo.com".to_string())
        );
        assert_eq!(
            pool.reverse_lookup(first_v6).await,
            Some("foo.com".to_string())
        );

        // 5. Test existence
        assert!(pool.exist(first).await);
        assert!(pool.exist(first_v6).await);

        // 6. Test delete
        pool.store.del_by_ip(first).await;
        assert!(!pool.exist(first).await);
        assert!(pool.exist(first_v6).await);

        // v4 lookup should be None now
        assert_eq!(pool.store.get_by_host("foo.com").await, None);
        // v6 lookup should still be there
        assert_eq!(pool.store.get_v6_by_host("foo.com").await, Some(first_v6));
    }

    #[tokio::test]
    async fn test_file_store_fallback() {
        use crate::app::dns::fakeip::file_store::FileStore;
        use crate::app::profile::ThreadSafeCacheFile;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let cache_path = temp_dir.path().join("test_cache_fallback.db");
        let cache_store =
            ThreadSafeCacheFile::new(cache_path.to_str().unwrap(), true);

        // Manually write old format to the cache store (no suffix)
        let host = "old-style.com";
        let ip_v4_str = "192.168.0.2";
        let ip_v6_str = "fdfe:5a70:6451:982b::2";

        // Insert directly using cache_store set_host_to_ip
        cache_store.set_host_to_ip(host, ip_v4_str).await;

        let store = FileStore::new(cache_store.clone());

        // Test fallback lookup v4
        let res_v4 = store.get_by_host(host).await;
        assert_eq!(res_v4, Some(ip_v4_str.parse().unwrap()));

        // Lookup v6 for old-style.com should be None because the stored IP is v4
        let res_v6 = store.get_v6_by_host(host).await;
        assert_eq!(res_v6, None);

        // Now change it to store IPv6 in the old format
        cache_store.set_host_to_ip(host, ip_v6_str).await;

        // Test fallback lookup v6
        let res_v6_new = store.get_v6_by_host(host).await;
        assert_eq!(res_v6_new, Some(ip_v6_str.parse().unwrap()));

        // Lookup v4 should now be None
        let res_v4_new = store.get_by_host(host).await;
        assert_eq!(res_v4_new, None);
    }
}
