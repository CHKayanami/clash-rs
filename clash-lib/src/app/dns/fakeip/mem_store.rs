use std::{
    collections::HashMap,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroUsize,
};

use lru::LruCache;
use parking_lot::RwLock;

use super::Store;

struct Family<A> {
    itoh: Option<LruCache<A, String>>,
    htoi: HashMap<String, A>,
}

impl<A: Copy + Eq + Hash + Into<IpAddr>> Family<A> {
    fn new(capacity: usize) -> Self {
        Self {
            itoh: NonZeroUsize::new(capacity).map(LruCache::new),
            htoi: HashMap::new(),
        }
    }

    fn put(&mut self, ip: A, host: &str) -> (bool, Vec<(IpAddr, String)>) {
        let Some(itoh) = &mut self.itoh else {
            return (false, vec![(ip.into(), host.to_owned())]);
        };
        let mut removed = Vec::new();
        // Remove conflicting mappings in both directions before inserting.
        if let Some(old_host) =
            itoh.peek(&ip).filter(|old| old.as_str() != host).cloned()
        {
            itoh.pop(&ip);
            self.htoi.remove(&old_host);
            removed.push((ip.into(), old_host));
        }
        if let Some(old_ip) = self.htoi.get(host).copied().filter(|old| *old != ip) {
            self.htoi.remove(host);
            if let Some(old_host) = itoh.pop(&old_ip) {
                removed.push((old_ip.into(), old_host));
            }
        }
        // Leave headroom by evicting 10% only when adding a new mapping
        // to a full family. Updating/replacing a mapping needs no extra space.
        if !itoh.contains(&ip) && itoh.len() == itoh.cap().get() {
            Self::evict_entries(itoh, &mut self.htoi, &mut removed);
        }
        itoh.put(ip, host.to_owned());
        self.htoi.insert(host.to_owned(), ip);
        (true, removed)
    }

    fn evict_entries(
        itoh: &mut LruCache<A, String>,
        htoi: &mut HashMap<String, A>,
        removed: &mut Vec<(IpAddr, String)>,
    ) {
        let batch_size = itoh.cap().get().div_ceil(10);
        removed.reserve(batch_size.min(itoh.len()));
        for _ in 0..batch_size {
            let Some((ip, host)) = itoh.pop_lru() else {
                break;
            };
            htoi.remove(&host);
            removed.push((ip.into(), host));
        }
    }

    fn evict_batch(&mut self) -> Vec<(IpAddr, String)> {
        let mut removed = Vec::new();
        if let Some(itoh) = &mut self.itoh {
            Self::evict_entries(itoh, &mut self.htoi, &mut removed);
        }
        removed
    }

    fn get_by_ip(&self, ip: A) -> Option<String> {
        self.itoh.as_ref()?.peek(&ip).cloned()
    }

    fn remove(&mut self, ip: A) -> Option<String> {
        let host = self.itoh.as_mut()?.pop(&ip)?;
        self.htoi.remove(&host);
        Some(host)
    }

    fn clear(&mut self) -> usize {
        let count = self.htoi.len();
        self.htoi.clear();
        if let Some(cache) = &mut self.itoh {
            cache.clear();
        }
        count
    }

    fn search(&self, pattern: &str, limit: usize) -> (usize, Vec<(IpAddr, String)>) {
        let mut count = 0;
        let mut result = Vec::new();
        if let Some(itoh) = &self.itoh {
            for (ip, host) in itoh.iter() {
                if matches_host(pattern, host) {
                    count += 1;
                    if result.len() < limit {
                        result.push(((*ip).into(), host.clone()));
                    }
                }
            }
        }
        (count, result)
    }
}

fn matches_host(pattern: &str, host: &str) -> bool {
    pattern == "*"
        || if !pattern.contains('*') && !pattern.contains('?') {
            host.eq_ignore_ascii_case(pattern)
        } else {
            crate::common::utils::wildcard_match(pattern, host)
        }
}

fn take_matching<A: Copy + Eq + Hash + Into<IpAddr>>(
    family: &RwLock<Family<A>>,
    pattern: &str,
) -> Vec<(IpAddr, String)> {
    if pattern == "*" {
        let mut guard = family.write();
        let mut removed = Vec::with_capacity(guard.htoi.len());
        if let Some(cache) = &mut guard.itoh {
            while let Some((ip, host)) = cache.pop_lru() {
                removed.push((ip.into(), host));
            }
        }
        guard.htoi.clear();
        return removed;
    }
    let matches: Vec<_> = {
        let guard = family.read();
        guard
            .itoh
            .iter()
            .flat_map(|cache| cache.iter())
            .filter(|(_, host)| matches_host(pattern, host))
            .map(|(ip, host)| (*ip, host.clone()))
            .collect()
    };
    let mut guard = family.write();
    matches
        .into_iter()
        .filter_map(|(ip, expected)| {
            if guard.itoh.as_ref()?.peek(&ip) != Some(&expected) {
                return None;
            }
            guard.remove(ip).map(|host| (ip.into(), host))
        })
        .collect()
}

pub struct InMemStore {
    v4: RwLock<Family<Ipv4Addr>>,
    v6: RwLock<Family<Ipv6Addr>>,
}

impl InMemStore {
    /// Test helper for a total budget without address-pool constraints.
    #[cfg(test)]
    pub fn new(size: usize) -> Self {
        let size = if size == 0 { 1000 } else { size };
        Self::with_capacities(size / 2 + size % 2, size / 2)
    }

    pub fn with_capacities(v4: usize, v6: usize) -> Self {
        Self {
            v4: RwLock::new(Family::new(v4)),
            v6: RwLock::new(Family::new(v6)),
        }
    }

    pub(crate) fn put_with_evictions(
        &self,
        ip: IpAddr,
        host: &str,
    ) -> (bool, Vec<(IpAddr, String)>) {
        match ip {
            IpAddr::V4(ip) => self.v4.write().put(ip, host),
            IpAddr::V6(ip) => self.v6.write().put(ip, host),
        }
    }

    pub(crate) fn evict_with_entries(&self, ip: IpAddr) -> Vec<(IpAddr, String)> {
        match ip {
            IpAddr::V4(_) => self.v4.write().evict_batch(),
            IpAddr::V6(_) => self.v6.write().evict_batch(),
        }
    }

    pub(crate) fn take_by_wildcard(&self, pattern: &str) -> Vec<(IpAddr, String)> {
        let mut removed = take_matching(&self.v4, pattern.trim());
        removed.extend(take_matching(&self.v6, pattern.trim()));
        removed
    }
}

impl Store for InMemStore {
    fn get_by_host(&self, host: &str) -> Option<IpAddr> {
        self.v4.read().htoi.get(host).copied().map(IpAddr::V4)
    }
    fn get_v6_by_host(&self, host: &str) -> Option<IpAddr> {
        self.v6.read().htoi.get(host).copied().map(IpAddr::V6)
    }
    fn put_by_ip(&self, ip: IpAddr, host: &str) {
        self.put_with_evictions(ip, host);
    }
    fn get_by_ip(&self, ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(ip) => self.v4.read().get_by_ip(ip),
            IpAddr::V6(ip) => self.v6.read().get_by_ip(ip),
        }
    }
    #[cfg(test)]
    fn del_by_ip(&self, ip: IpAddr) {
        match ip {
            IpAddr::V4(ip) => {
                self.v4.write().remove(ip);
            }
            IpAddr::V6(ip) => {
                self.v6.write().remove(ip);
            }
        }
    }
    fn evict_batch(&self, ip: IpAddr) -> Option<IpAddr> {
        self.evict_with_entries(ip).first().map(|(ip, _)| *ip)
    }
    fn exist(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self
                .v4
                .read()
                .itoh
                .as_ref()
                .is_some_and(|cache| cache.contains(&ip)),
            IpAddr::V6(ip) => self
                .v6
                .read()
                .itoh
                .as_ref()
                .is_some_and(|cache| cache.contains(&ip)),
        }
    }
    fn copy_to(&self, #[allow(unused)] store: &dyn Store) { /* TODO: copy */
    }
    fn search_by_wildcard_limited(
        &self,
        pattern: &str,
        limit: usize,
    ) -> (usize, Vec<(IpAddr, String)>) {
        let (v4_count, mut results) = self.v4.read().search(pattern.trim(), limit);
        let (v6_count, v6_results) = self
            .v6
            .read()
            .search(pattern.trim(), limit.saturating_sub(results.len()));
        results.extend(v6_results);
        (v4_count + v6_count, results)
    }
    fn del_by_wildcard(&self, pattern: &str) -> usize {
        if pattern.trim() == "*" {
            let v4_count = self.v4.write().clear();
            let v6_count = self.v6.write().clear();
            return v4_count + v6_count;
        }
        self.take_by_wildcard(pattern).len()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn clear_and_drain_keep_indexes_empty_and_capacity_reusable() {
        for drain in [false, true] {
            let store = super::InMemStore::with_capacities(2, 2);
            use super::Store;
            for ip in ["198.18.0.2", "198.18.0.3", "fc00::2", "fc00::3"] {
                store.put_by_ip(ip.parse().unwrap(), ip);
            }
            if drain {
                let entries = store.take_by_wildcard(" * ");
                assert_eq!(entries.len(), 4);
                for (ip, host) in entries {
                    assert_eq!(ip.to_string(), host);
                }
            } else {
                assert_eq!(store.del_by_wildcard(" * "), 4);
            }
            assert!(store.v4.read().htoi.is_empty());
            assert!(store.v6.read().htoi.is_empty());
            assert_eq!(store.search_by_wildcard_limited("*", 0).0, 0);
            assert_eq!(store.del_by_wildcard("*"), 0);
            store.put_by_ip("198.18.0.2".parse().unwrap(), "new.com");
            store.put_by_ip("fc00::2".parse().unwrap(), "new.com");
            assert_eq!(
                store.get_by_host("new.com"),
                Some("198.18.0.2".parse().unwrap())
            );
            assert_eq!(
                store.get_v6_by_host("new.com"),
                Some("fc00::2".parse().unwrap())
            );
        }
    }

    use super::*;

    #[test]
    fn full_family_evicts_ten_percent_and_refills_headroom() {
        let store = InMemStore::with_capacities(20, 20);
        for i in 1..=20 {
            store.put_by_ip(IpAddr::V4(Ipv4Addr::from(i)), &format!("v4-{i}.com"));
            store.put_by_ip(
                IpAddr::V6(Ipv6Addr::from(u128::from(i))),
                &format!("v6-{i}.com"),
            );
        }
        let (_, removed) =
            store.put_with_evictions(IpAddr::V4(Ipv4Addr::from(21)), "v4-21.com");
        assert_eq!(
            removed,
            vec![
                (IpAddr::V4(Ipv4Addr::from(1)), "v4-1.com".into()),
                (IpAddr::V4(Ipv4Addr::from(2)), "v4-2.com".into())
            ]
        );
        assert_eq!(store.v4.read().htoi.len(), 19);
        assert_eq!(store.v6.read().htoi.len(), 20);
        for i in 1..=2 {
            assert_eq!(store.get_by_host(&format!("v4-{i}.com")), None);
            assert_eq!(store.get_by_ip(IpAddr::V4(Ipv4Addr::from(i))), None);
        }
        let (_, removed) =
            store.put_with_evictions(IpAddr::V4(Ipv4Addr::from(22)), "v4-22.com");
        assert!(removed.is_empty());
        assert_eq!(store.v4.read().htoi.len(), 20);
        let (_, removed) =
            store.put_with_evictions(IpAddr::V4(Ipv4Addr::from(23)), "v4-23.com");
        assert_eq!(removed.len(), 2);
        assert_eq!(store.v4.read().htoi.len(), 19);
        assert_eq!(store.search_by_wildcard_limited("*", 0).0, 39);
    }

    #[test]
    fn eviction_batch_rounds_up_and_handles_small_capacities() {
        for (capacity, expected_evictions) in
            [(1, 1), (9, 1), (10, 1), (11, 2), (20, 2), (21, 3)]
        {
            let mut family = Family::<Ipv4Addr>::new(capacity);
            for i in 1..=capacity {
                family.put(Ipv4Addr::from(i as u32), &format!("{i}.com"));
            }
            let (_, removed) = family.put(Ipv4Addr::from(1000), "new.com");
            assert_eq!(removed.len(), expected_evictions);
            assert_eq!(family.htoi.len(), capacity - expected_evictions + 1);
            assert_eq!(family.itoh.as_ref().unwrap().len(), family.htoi.len());
        }
    }

    #[test]
    fn full_family_updates_and_replacements_do_not_batch_evict() {
        let mut family = Family::<Ipv4Addr>::new(20);
        for i in 1..=20 {
            family.put(Ipv4Addr::from(i), &format!("{i}.com"));
        }
        assert!(family.put(Ipv4Addr::from(1), "1.com").1.is_empty());
        assert_eq!(family.put(Ipv4Addr::from(1), "renamed.com").1.len(), 1);
        assert_eq!(family.put(Ipv4Addr::from(100), "renamed.com").1.len(), 1);
        assert_eq!(family.htoi.len(), 20);
        assert_eq!(family.itoh.as_ref().unwrap().len(), 20);
        for i in 2..=20 {
            assert_eq!(
                family.htoi.get(format!("{i}.com").as_str()),
                Some(&Ipv4Addr::from(i))
            );
        }
    }

    #[test]
    fn family_budgets_are_independent_and_total_is_bounded() {
        let store = InMemStore::new(5); // 3 IPv4 + 2 IPv6
        let v4: IpAddr = "198.18.0.2".parse().unwrap();
        store.put_by_ip(v4, "v4.com");
        for i in 1..=5 {
            store.put_by_ip(
                IpAddr::V6(Ipv6Addr::from(i as u128)),
                &format!("v6-{i}.com"),
            );
        }
        assert_eq!(store.get_by_host("v4.com"), Some(v4));
        assert_eq!(store.search_by_wildcard_limited("*", 0).0, 3);
        assert_eq!(store.get_v6_by_host("v6-1.com"), None);
        for i in 3..=7 {
            store.put_by_ip(
                IpAddr::V4(Ipv4Addr::new(198, 18, 0, i)),
                &format!("v4-{i}.com"),
            );
        }
        let (count, entries) = store.search_by_wildcard_limited("*", usize::MAX);
        assert_eq!(count, 5);
        assert_eq!(entries.iter().filter(|(ip, _)| ip.is_ipv4()).count(), 3);
        assert_eq!(entries.iter().filter(|(ip, _)| ip.is_ipv6()).count(), 2);
        assert_eq!(store.v4.read().htoi.len(), 3);
        assert_eq!(store.v6.read().htoi.len(), 2);
        assert_eq!(store.get_by_host("v4.com"), None);
        assert_eq!(
            store.get_v6_by_host("v6-5.com"),
            Some(IpAddr::V6(Ipv6Addr::from(5)))
        );
    }

    #[test]
    fn replacing_either_side_removes_old_mapping() {
        let store = InMemStore::with_capacities(2, 2);
        for (first, second) in [("198.18.0.2", "198.18.0.3"), ("fc00::2", "fc00::3")]
        {
            let first: IpAddr = first.parse().unwrap();
            let second: IpAddr = second.parse().unwrap();
            store.put_by_ip(first, "old.com");
            store.put_by_ip(first, "new.com");
            let lookup = |host: &str| {
                if first.is_ipv4() {
                    store.get_by_host(host)
                } else {
                    store.get_v6_by_host(host)
                }
            };
            assert_eq!(lookup("old.com"), None);
            store.put_by_ip(second, "new.com");
            assert!(!store.exist(first));
            assert_eq!(lookup("new.com"), Some(second));
            assert_eq!(store.get_by_ip(second).as_deref(), Some("new.com"));
        }
        assert_eq!(store.del_by_wildcard("*"), 2);
        assert_eq!(store.search_by_wildcard_limited("*", 0).0, 0);
    }

    #[test]
    fn zero_family_capacity_does_not_cache_mappings() {
        let store = InMemStore::with_capacities(1, 0);
        let ip: IpAddr = "fc00::2".parse().unwrap();
        store.put_by_ip(ip, "example.com");
        assert!(!store.exist(ip));
        assert_eq!(store.get_v6_by_host("example.com"), None);
        assert_eq!(store.search_by_wildcard_limited("*", 0).0, 0);
    }

    #[test]
    fn test_in_mem_store_basic() {
        let store = InMemStore::new(100);
        let host = "example.com";
        let ip_v4: IpAddr = "192.168.1.1".parse().unwrap();
        let ip_v6: IpAddr = "fd00::1".parse().unwrap();

        store.put_by_ip(ip_v4, host);
        store.put_by_ip(ip_v6, host);

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
