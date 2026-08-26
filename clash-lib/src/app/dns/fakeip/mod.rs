use std::{
    collections::HashMap,
    net::{self, IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use portable_atomic::AtomicU128;
use tracing::debug;

use crate::{
    Error,
    app::{dns::filters::DomainFilter, router::ThreadSafeRuleProvider},
    config::def::FakeIpFilterMode,
};

mod file_store;
mod mem_store;

pub use file_store::FileStore;
pub use mem_store::InMemStore;

pub struct Opts {
    pub ipnet: ipnet::Ipv4Net,
    pub ipnet6: ipnet::Ipv6Net,
    pub domain_filter: Option<DomainFilter>,
    pub filter_mode: FakeIpFilterMode,
    pub store: Box<dyn Store>,
}

pub trait Store: Sync + Send {
    fn get_by_host(&self, host: &str) -> Option<net::IpAddr>;
    fn get_v6_by_host(&self, host: &str) -> Option<net::IpAddr>;

    fn put_by_host(&self, host: &str, ip: net::IpAddr);
    fn get_by_ip(&self, ip: net::IpAddr) -> Option<String>;
    fn put_by_ip(&self, ip: net::IpAddr, host: &str);
    fn del_by_ip(&self, ip: net::IpAddr);
    fn exist(&self, ip: net::IpAddr) -> bool;
    fn copy_to(&self, store: &dyn Store);
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
    domain_filter: Option<DomainFilter>,
    filter_mode: FakeIpFilterMode,
    store: Box<dyn Store>,
    /// Memoized `should_skip` verdicts. Covers both static `fake-ip-filter`
    /// entries and `rule-set:` matches; cleared wholesale whenever one of the
    /// bound rule-sets reloads (see [`FakeDns::add_rule_set`]).
    skip_cache: Arc<quick_cache::sync::Cache<String, bool>>,
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
            filter_mode: opt.filter_mode,
            store: opt.store,
            skip_cache: Arc::new(quick_cache::sync::Cache::new(1000)),
        })
    }

    pub fn lookup(&self, host: &str) -> net::IpAddr {
        if let Some(ip) = self.store.get_by_host(host) {
            return ip;
        }

        let ip = self.get(host);
        self.store.put_by_host(host, ip);
        ip
    }

    pub fn lookupv6(&self, host: &str) -> net::IpAddr {
        if let Some(ip) = self.store.get_v6_by_host(host) {
            return ip;
        }

        let ip = self.getv6(host);
        self.store.put_by_host(host, ip);
        ip
    }

    pub fn reverse_lookup(&self, ip: net::IpAddr) -> Option<String> {
        self.store.get_by_ip(ip)
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
                // `Arc<quick_cache>` handles are cheap to clone and share one backing
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
                        cache.clear();
                    }));
                }

                // Verdicts computed before the rule-sets were bound assumed there
                // were none; drop them.
                self.skip_cache.clear();
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
        let matched = if let Some(filter) = &self.domain_filter {
            filter.apply(domain)
        } else {
            false
        };
        match self.filter_mode {
            FakeIpFilterMode::Blacklist => matched,
            FakeIpFilterMode::Whitelist => !matched,
        }
    }

    #[allow(dead_code)]
    pub fn exist(&self, ip: net::IpAddr) -> bool {
        self.store.exist(ip)
    }

    pub fn is_in_pool(&self, ip: net::IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_broadcast() || v4.is_multicast() {
                    return false;
                }
                if let Some(pool) = &self.v4_pool {
                    let u = u32::from(v4);
                    u >= pool.min && u <= pool.max
                } else {
                    false
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_multicast() {
                    return false;
                }
                match &self.v6_pool {
                    Some(pool) => {
                        let u = u128::from(v6);
                        let mask = Self::v6_prefix_mask(pool.prefix_len);
                        if u & mask != u128::from_be_bytes(pool.prefix) & mask {
                            return false;
                        }
                        let host_id = u & !mask;
                        host_id >= pool.min_host && host_id <= pool.max_host
                    }
                    None => false,
                }
            }
        }
    }

    pub fn is_fake_ip(&self, ip: net::IpAddr) -> bool {
        if !self.is_in_pool(ip) {
            return false;
        }
        self.store.exist(ip)
    }

    #[allow(dead_code)]
    pub fn copy_from(&self, src: &Self) {
        src.store.copy_to(&*self.store);
    }

    fn get(&self, host: &str) -> net::IpAddr {
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
                    self.store.del_by_ip(ip_addr);
                    allocated_v4 = Some(ip);
                    break;
                }
                if !self.store.exist(ip_addr) {
                    allocated_v4 = Some(ip);
                    break;
                }
                current_try += 1;
            }
        }

        if let Some(v4) = allocated_v4 {
            let ip = IpAddr::V4(v4);
            self.store.put_by_ip(ip, host);
            ip
        } else {
            panic!("IPv4 subnet not configured");
        }
    }

    /// ----------------------------------------
    /// 2. 仅分配/查询 IPv6 Fake IP (应对 AAAA 记录)
    /// ----------------------------------------
    pub fn getv6(&self, host: &str) -> IpAddr {
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
                self.store.del_by_ip(ip_addr);
                allocated_ip = Some(ip);
                break;
            }
            if !self.store.exist(ip_addr) {
                allocated_ip = Some(ip);
                break;
            }
            current_try += 1;
        }

        // 3. 写入存储
        if let Some(ip) = allocated_ip {
            let ip_addr = IpAddr::V6(ip);
            self.store.put_by_ip(ip_addr, host);
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

    use tempfile::tempdir;

    use super::{FakeDns, FileStore, InMemStore, Opts, Store};
    use crate::{
        app::{dns::filters::DomainFilter, profile::ThreadSafeCacheFile},
        common::trie,
        config::def::FakeIpFilterMode,
    };

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
            filter_mode: FakeIpFilterMode::Blacklist,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com");
        let last = pool.lookup("bar.com");

        let bar = pool.reverse_lookup(last);

        assert_eq!(first, net::IpAddr::from([192, 168, 0, 2]));
        assert_eq!(
            pool.lookup("foo.com"),
            net::IpAddr::from([192, 168, 0, 2])
        );
        assert_eq!(last, net::IpAddr::from([192, 168, 0, 3]));
        assert!(bar.is_some());
        assert_eq!(bar, Some("bar.com".into()));
        assert!(pool.exist(net::IpAddr::from([192, 168, 0, 3])));
        assert!(!pool.exist(net::IpAddr::from([192, 168, 0, 4])));
        assert!(!pool.exist("::1".parse().unwrap()));
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
            filter_mode: FakeIpFilterMode::Blacklist,
            store,
        })
        .unwrap();

        let foo = pool.lookup("foo.com");
        let bar = pool.lookup("bar.com");

        for i in 0..4 {
            pool.lookup(&format!("{}.com", i));
        }

        let baz = pool.lookup("baz.com");
        let next = pool.lookup("foo.com");
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
            domain_filter: Some(DomainFilter::new(vec!["example.com"])),
            filter_mode: FakeIpFilterMode::Blacklist,
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
    async fn test_pool_skip_whitelist() {
        let store = Box::new(InMemStore::new(10));

        let ipnet = "192.168.0.0/30".parse::<ipnet::IpNet>().unwrap();
        let pool = FakeDns::new(Opts {
            ipnet: match ipnet {
                ipnet::IpNet::V4(v4) => v4,
                _ => panic!(),
            },
            ipnet6: "fdfe:5a70:6451:982b::/64"
                .parse::<ipnet::Ipv6Net>()
                .unwrap(),
            domain_filter: Some(DomainFilter::new(vec!["example.com"])),
            filter_mode: FakeIpFilterMode::Whitelist,
            store,
        })
        .unwrap();

        // In whitelist mode, domains in fake-ip-filter get fake-ip (should NOT skip)
        assert!(!pool.should_skip("example.com"));
        assert!(!pool.should_skip("example.com"));

        // Domains NOT in fake-ip-filter resolve real IP (SHOULD skip)
        assert!(pool.should_skip("foo.com"));
        assert!(pool.should_skip("foo.com"));

        pool.add_rule_set(&std::collections::HashMap::new()).await;
        assert!(!pool.should_skip("example.com"));
        assert!(pool.should_skip("foo.com"));
    }

    #[tokio::test]
    async fn test_pool_skip_empty_filters() {
        let store = Box::new(InMemStore::new(10));
        let ipnet = "192.168.0.0/30".parse::<ipnet::IpNet>().unwrap();

        // Blacklist with no filter -> nothing is skipped (all fake IP)
        let blacklist_pool = FakeDns::new(Opts {
            ipnet: match ipnet {
                ipnet::IpNet::V4(v4) => v4,
                _ => panic!(),
            },
            ipnet6: "fdfe:5a70:6451:982b::/64"
                .parse::<ipnet::Ipv6Net>()
                .unwrap(),
            domain_filter: None,
            filter_mode: FakeIpFilterMode::Blacklist,
            store,
        })
        .unwrap();

        assert!(!blacklist_pool.should_skip("example.com"));
        assert!(!blacklist_pool.should_skip("foo.com"));

        // Whitelist with no filter -> everything is skipped (all real IP)
        let store_wl = Box::new(InMemStore::new(10));
        let whitelist_pool = FakeDns::new(Opts {
            ipnet: match ipnet {
                ipnet::IpNet::V4(v4) => v4,
                _ => panic!(),
            },
            ipnet6: "fdfe:5a70:6451:982b::/64"
                .parse::<ipnet::Ipv6Net>()
                .unwrap(),
            domain_filter: None,
            filter_mode: FakeIpFilterMode::Whitelist,
            store: store_wl,
        })
        .unwrap();

        assert!(whitelist_pool.should_skip("example.com"));
        assert!(whitelist_pool.should_skip("foo.com"));
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
            filter_mode: FakeIpFilterMode::Blacklist,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com");

        for i in 0..10 {
            pool.lookup(&format!("domain{i}.com"));
        }
        let next = pool.lookup("foo.com");

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
            filter_mode: FakeIpFilterMode::Blacklist,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com");
        let last = pool.lookup("bar.com");
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
            filter_mode: FakeIpFilterMode::Blacklist,
            store,
        })
        .unwrap();

        new_pool.copy_from(&pool);

        assert!(new_pool.reverse_lookup(first).is_some());
        assert!(new_pool.reverse_lookup(last).is_some());
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
            filter_mode: FakeIpFilterMode::Blacklist,
            store,
        })
        .unwrap();

        // Allocate one real fake IP.
        let allocated = pool.lookup("foo.com");
        assert!(
            pool.is_fake_ip(allocated),
            "allocated IP must be fake"
        );

        // Directed broadcast for the /24 TUN subnet (198.18.0.0/24) – never
        // allocated, yet it falls inside the /16 range.
        let directed_broadcast: net::IpAddr = "198.18.0.255".parse().unwrap();
        assert!(
            !pool.is_fake_ip(directed_broadcast),
            "directed broadcast must not be treated as a fake IP"
        );

        // Global broadcast must never be a fake IP.
        let global_broadcast: net::IpAddr = "255.255.255.255".parse().unwrap();
        assert!(
            !pool.is_fake_ip(global_broadcast),
            "255.255.255.255 must not be a fake IP"
        );

        // A multicast address must never be a fake IP.
        let multicast: net::IpAddr = "224.0.0.1".parse().unwrap();
        assert!(
            !pool.is_fake_ip(multicast),
            "multicast must not be a fake IP"
        );

        // An IP in the range that was never allocated must not be fake.
        let unallocated: net::IpAddr = "198.18.1.1".parse().unwrap();
        assert!(
            !pool.is_fake_ip(unallocated),
            "unallocated in-range IP must not be treated as a fake IP"
        );
    }

    #[tokio::test]
    async fn test_file_store_basic() {
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
            filter_mode: FakeIpFilterMode::Blacklist,
            store,
        })
        .unwrap();

        // 1. Resolve host and get IPv4
        let first = pool.lookup("foo.com");
        // 2. Resolve host and get IPv6
        let first_v6 = pool.lookupv6("foo.com");

        assert_eq!(first, net::IpAddr::from([192, 168, 0, 2]));
        assert!(first_v6.is_ipv6());

        // 3. Query back
        let ip_v4 = pool.store.get_by_host("foo.com");
        let ip_v6 = pool.store.get_v6_by_host("foo.com");

        assert_eq!(ip_v4, Some(first));
        assert_eq!(ip_v6, Some(first_v6));

        // 4. Reverse lookups should return original host
        assert_eq!(
            pool.reverse_lookup(first),
            Some("foo.com".to_string())
        );
        assert_eq!(
            pool.reverse_lookup(first_v6),
            Some("foo.com".to_string())
        );

        // 5. Test existence
        assert!(pool.exist(first));
        assert!(pool.exist(first_v6));

        // 6. Test delete
        pool.store.del_by_ip(first);
        assert!(!pool.exist(first));
        assert!(pool.exist(first_v6));

        // v4 lookup should be None now
        assert_eq!(pool.store.get_by_host("foo.com"), None);
        // v6 lookup should still be there
        assert_eq!(pool.store.get_v6_by_host("foo.com"), Some(first_v6));
    }

    #[tokio::test]
    async fn test_file_store_fallback() {
        let temp_dir = tempdir().unwrap();
        let cache_path = temp_dir.path().join("test_cache_fallback.db");
        let cache_store =
            ThreadSafeCacheFile::new(cache_path.to_str().unwrap(), true);

        // Manually write old format to the cache store (no suffix)
        let host = "old-style.com";
        let ip_v4_str = "192.168.0.2";
        let ip_v6_str = "fdfe:5a70:6451:982b::2";

        // Insert directly using cache_store set_host_to_ip
        cache_store.set_host_to_ip(host, ip_v4_str);

        let store = FileStore::new(cache_store.clone());

        // Test fallback lookup v4
        let res_v4 = store.get_by_host(host);
        assert_eq!(res_v4, Some(ip_v4_str.parse().unwrap()));

        // Lookup v6 for old-style.com should be None because the stored IP is v4
        let res_v6 = store.get_v6_by_host(host);
        assert_eq!(res_v6, None);

        // Now change it to store IPv6 in the old format
        cache_store.set_host_to_ip(host, ip_v6_str);

        // Test fallback lookup v6
        let res_v6_new = store.get_v6_by_host(host);
        assert_eq!(res_v6_new, Some(ip_v6_str.parse().unwrap()));

        // Lookup v4 should now be None
        let res_v4_new = store.get_by_host(host);
        assert_eq!(res_v4_new, None);
    }
}
