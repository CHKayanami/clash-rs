use std::net::IpAddr;
use std::num::NonZeroUsize;

use lru::LruCache;
use parking_lot::RwLock;

use super::Store;

struct Inner {
    itoh: LruCache<IpAddr, String>,
    htoi: LruCache<String, IpAddr>,
}

pub struct InMemStore {
    inner: RwLock<Inner>,
}

impl InMemStore {
    pub fn new(size: usize) -> Self {
        let cap = NonZeroUsize::new(size).unwrap_or(NonZeroUsize::new(1000).unwrap());
        Self {
            inner: RwLock::new(Inner {
                itoh: LruCache::new(cap),
                htoi: LruCache::new(cap),
            }),
        }
    }

    fn make_host_key(host: &str, is_v6: bool) -> String {
        if is_v6 {
            format!("{}#v6", host)
        } else {
            format!("{}#v4", host)
        }
    }

    pub(crate) fn take_by_wildcard(&self, pattern: &str) -> Vec<(IpAddr, String)> {
        let pattern = pattern.trim();
        let is_all = pattern == "*";
        let is_exact = !pattern.contains('*') && !pattern.contains('?');
        let matches: Vec<_> = {
            let inner = self.inner.read();
            inner.itoh.iter()
                .filter(|(_, host)| {
                    is_all
                        || if is_exact {
                            host.eq_ignore_ascii_case(pattern)
                        } else {
                            crate::common::utils::wildcard_match(pattern, host)
                        }
                })
                .map(|(ip, host)| (*ip, host.clone()))
                .collect()
        };
        let mut inner = self.inner.write();
        let mut removed = Vec::with_capacity(matches.len());
        for (ip, expected_host) in matches {
            if inner.itoh.peek(&ip) != Some(&expected_host) {
                continue;
            }
            if let Some(host) = inner.itoh.pop(&ip) {
                inner.htoi.pop(&Self::make_host_key(&host, ip.is_ipv6()));
                removed.push((ip, host));
            }
        }
        removed
    }
}

impl Store for InMemStore {
    fn get_by_host(&self, host: &str) -> Option<std::net::IpAddr> {
        let inner = self.inner.read();
        let v4_key = Self::make_host_key(host, false);
        inner.htoi.peek(&v4_key).copied()
    }

    fn get_v6_by_host(&self, host: &str) -> Option<std::net::IpAddr> {
        let inner = self.inner.read();
        let v6_key = Self::make_host_key(host, true);
        inner.htoi.peek(&v6_key).copied()
    }

    fn put_by_host(&self, host: &str, ip: std::net::IpAddr) {
        let mut inner = self.inner.write();
        let key = Self::make_host_key(host, ip.is_ipv6());
        if let Some((_, evicted_ip)) = inner.htoi.push(key, ip) {
            if evicted_ip != ip {
                inner.itoh.pop(&evicted_ip);
            }
        }
        if let Some((evicted_ip, evicted_host)) = inner.itoh.push(ip, host.to_string()) {
            if evicted_ip != ip {
                let ev_key = Self::make_host_key(&evicted_host, evicted_ip.is_ipv6());
                inner.htoi.pop(&ev_key);
            }
        }
    }

    fn get_by_ip(&self, ip: std::net::IpAddr) -> Option<String> {
        let inner = self.inner.read();
        inner.itoh.peek(&ip).cloned()
    }

    fn put_by_ip(&self, ip: std::net::IpAddr, host: &str) {
        let mut inner = self.inner.write();
        let key = Self::make_host_key(host, ip.is_ipv6());
        if let Some((evicted_ip, evicted_host)) = inner.itoh.push(ip, host.to_string()) {
            if evicted_ip != ip {
                let ev_key = Self::make_host_key(&evicted_host, evicted_ip.is_ipv6());
                inner.htoi.pop(&ev_key);
            }
        }
        if let Some((_, evicted_ip)) = inner.htoi.push(key, ip) {
            if evicted_ip != ip {
                inner.itoh.pop(&evicted_ip);
            }
        }
    }

    fn del_by_ip(&self, ip: std::net::IpAddr) {
        let mut inner = self.inner.write();
        if let Some(host) = inner.itoh.pop(&ip) {
            let key = Self::make_host_key(&host, ip.is_ipv6());
            inner.htoi.pop(&key);
        }
    }

    fn exist(&self, ip: std::net::IpAddr) -> bool {
        self.inner.read().itoh.peek(&ip).is_some()
    }

    fn copy_to(&self, #[allow(unused)] store: &dyn Store) {
        // TODO: copy
        // NOTE: use file based persistence store
    }

    fn search_by_wildcard_limited(
        &self,
        pattern: &str,
        limit: usize,
    ) -> (usize, Vec<(std::net::IpAddr, String)>) {
        let pattern = pattern.trim();
        let is_exact = !pattern.contains('*') && !pattern.contains('?');

        let is_wildcard_all = pattern == "*";
        let inner = self.inner.read();
        let mut count = 0;
        let mut results = Vec::new();
        for (ip, host) in inner.itoh.iter() {
            let matched = is_wildcard_all
                || if is_exact {
                    host.eq_ignore_ascii_case(pattern)
                } else {
                    crate::common::utils::wildcard_match(pattern, host)
                };
            if matched {
                count += 1;
                if results.len() < limit {
                    results.push((*ip, host.clone()));
                }
            }
        }
        (count, results)
    }

    fn del_by_wildcard(&self, pattern: &str) -> usize {
        self.take_by_wildcard(pattern).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_mem_store_basic() {
        let store = InMemStore::new(100);
        let host = "example.com";
        let ip_v4: IpAddr = "192.168.1.1".parse().unwrap();
        let ip_v6: IpAddr = "fd00::1".parse().unwrap();

        store.put_by_host(host, ip_v4);
        store.put_by_host(host, ip_v6);

        assert_eq!(store.get_by_host(host), Some(ip_v4));
        assert_eq!(store.get_v6_by_host(host), Some(ip_v6));

        assert_eq!(store.get_by_ip(ip_v4), Some(host.to_string()));
        assert_eq!(store.get_by_ip(ip_v6), Some(host.to_string()));

        assert!(store.exist(ip_v4));
        assert!(store.exist(ip_v6));

        store.del_by_ip(ip_v4);
        assert!(!store.exist(ip_v4));
        assert_eq!(store.get_by_host(host), None);
        assert_eq!(store.get_v6_by_host(host), Some(ip_v6));
    }

    #[test]
    fn test_cache_management_exact_match_ignores_case() {
        let store = InMemStore::new(100);
        let ip_v4: IpAddr = "192.168.1.1".parse().unwrap();
        let ip_v6: IpAddr = "fd00::1".parse().unwrap();
        store.put_by_ip(ip_v4, "example.com");
        store.put_by_ip(ip_v6, "Example.COM");

        let (count, items) = store.search_by_wildcard_limited("EXAMPLE.COM", 1);
        assert_eq!(count, 2);
        assert_eq!(items.len(), 1);
        assert_eq!(store.del_by_wildcard("EXAMPLE.COM"), 2);
        assert!(!store.exist(ip_v4));
        assert!(!store.exist(ip_v6));
    }
}
