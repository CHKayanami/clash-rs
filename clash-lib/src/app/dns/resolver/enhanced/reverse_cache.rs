use std::net::IpAddr;
use std::time::{Duration, Instant};

use moka::Expiry;
use moka::sync::Cache;

/// Reverse DNS lookup entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReverseEntry {
    /// Exactly one domain mapped to this IP.
    Unique {
        domain: String,
        expires_at: Instant,
    },
    /// Multiple distinct domains resolved to this same IP (e.g. shared CDN IP),
    /// marked as ambiguous/poisoned so reverse lookup returns None.
    Ambiguous {
        expires_at: Instant,
    },
}

impl ReverseEntry {
    #[inline]
    pub fn is_fresh(&self, now: Instant) -> bool {
        match self {
            ReverseEntry::Unique { expires_at, .. } => now < *expires_at,
            ReverseEntry::Ambiguous { expires_at } => now < *expires_at,
        }
    }

    #[inline]
    pub fn expires_at(&self) -> Instant {
        match self {
            ReverseEntry::Unique { expires_at, .. } => *expires_at,
            ReverseEntry::Ambiguous { expires_at } => *expires_at,
        }
    }

    #[inline]
    pub fn domain(&self, now: Instant) -> Option<&str> {
        match self {
            ReverseEntry::Unique { domain, expires_at } if now < *expires_at => {
                Some(domain.as_str())
            }
            _ => None,
        }
    }
}

struct ReverseExpiry;

impl Expiry<IpAddr, ReverseEntry> for ReverseExpiry {
    fn expire_after_create(
        &self,
        _key: &IpAddr,
        value: &ReverseEntry,
        _created_at: Instant,
    ) -> Option<Duration> {
        let now = Instant::now();
        Some(value.expires_at().saturating_duration_since(now))
    }

    fn expire_after_update(
        &self,
        _key: &IpAddr,
        value: &ReverseEntry,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        let now = Instant::now();
        Some(value.expires_at().saturating_duration_since(now))
    }
}

/// Thread-safe reverse DNS lookup cache with per-entry TTL and conflict resolution.
#[derive(Clone)]
pub struct ReverseLookupCache {
    inner: Cache<IpAddr, ReverseEntry>,
    stale_retention: Duration,
}

impl ReverseLookupCache {
    pub fn new(capacity: usize, stale_retention: Duration) -> Self {
        let inner = Cache::builder()
            .max_capacity(capacity as u64)
            .expire_after(ReverseExpiry)
            .build();
        Self { inner, stale_retention }
    }

    /// Insert or update an IP -> host mapping.
    ///
    /// Entries remain valid for the effective forward TTL plus stale retention.
    /// - If the IP is not present (or expired), insert as `Unique`.
    /// - If the IP already exists for the SAME domain, refresh its TTL as `Unique`.
    /// - If the IP exists for a DIFFERENT domain (or already marked `Ambiguous`),
    ///   mark it as `Ambiguous` so subsequent reverse lookups will return `None`.
    pub fn insert(&self, ip: IpAddr, host: &str, ttl_secs: u32) {
        // Serialize read-modify-write operations only for the same IP.
        self.inner.entry(ip).and_upsert_with(|entry| {
            let now = Instant::now();
            let expires_at = now + Duration::from_secs(ttl_secs.max(1) as u64)
                + self.stale_retention;
            if let Some(existing) = entry.map(|entry| entry.into_value()) {
                if existing.is_fresh(now) {
                    return match existing {
                        ReverseEntry::Unique { domain, .. }
                            if domain.eq_ignore_ascii_case(host) =>
                        {
                            ReverseEntry::Unique { domain, expires_at }
                        }
                        existing => ReverseEntry::Ambiguous {
                            expires_at: expires_at.max(existing.expires_at()),
                        },
                    };
                }
            }
            ReverseEntry::Unique {
                domain: host.to_string(),
                expires_at,
            }
        });
    }

    /// Look up domain by IP.
    ///
    /// Returns `Some(domain)` if the mapping is unique and unexpired.
    /// Returns `None` if missing, expired, or marked ambiguous due to multi-domain conflict.
    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        let now = Instant::now();
        if let Some(entry) = self.inner.get(ip) {
            if let Some(domain) = entry.domain(now) {
                return Some(domain.to_string());
            }
            if !entry.is_fresh(now) {
                self.inner.invalidate(ip);
            }
        }
        None
    }

    /// Invalidate reverse mappings for domains matching a DNS cache deletion.
    /// Ambiguous entries have no usable domain mapping and are left to expire.
    pub fn invalidate_matching(&self, pattern: &str) {
        let pattern = pattern.trim();
        let is_all = pattern == "*";
        let is_exact = !pattern.contains('*') && !pattern.contains('?');
        let matching_ips: Vec<_> = self.inner.iter()
            .filter_map(|(ip, entry)| match entry {
                ReverseEntry::Unique { domain, .. }
                    if is_all
                        || (is_exact && domain.eq_ignore_ascii_case(pattern))
                        || (!is_exact && crate::common::utils::wildcard_match(pattern, &domain)) =>
                {
                    Some(ip)
                }
                _ => None,
            })
            .collect();
        for ip in matching_ips {
            self.inner.invalidate(ip.as_ref());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn test_reverse_cache_basic_and_refresh() {
        let cache = ReverseLookupCache::new(100, Duration::ZERO);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        cache.insert(ip, "example.com", 60);
        assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));

        // Case-insensitive same domain refresh
        cache.insert(ip, "EXAMPLE.COM", 120);
        assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn test_reverse_cache_conflict_marks_ambiguous() {
        let cache = ReverseLookupCache::new(100, Duration::ZERO);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        cache.insert(ip, "domain-a.com", 60);
        assert_eq!(cache.lookup(&ip), Some("domain-a.com".to_string()));

        // Another domain resolves to the same IP -> marked ambiguous
        cache.insert(ip, "domain-b.com", 60);
        assert_eq!(cache.lookup(&ip), None);

        // Subsequent lookup still returns None
        assert_eq!(cache.lookup(&ip), None);
    }

    #[test]
    fn test_reverse_cache_conflict_preserves_longest_expiration() {
        let cache = ReverseLookupCache::new(100, Duration::ZERO);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        cache.insert(ip, "domain-a.com", 300);
        let original_expiry = cache.inner.get(&ip).unwrap().expires_at();

        cache.insert(ip, "domain-b.com", 10);
        assert_eq!(cache.inner.get(&ip), Some(ReverseEntry::Ambiguous {
            expires_at: original_expiry,
        }));

        cache.insert(ip, "domain-c.com", 1);
        assert_eq!(cache.inner.get(&ip).unwrap().expires_at(), original_expiry);
        assert_eq!(cache.lookup(&ip), None);

        cache.insert(ip, "domain-d.com", 600);
        assert!(cache.inner.get(&ip).unwrap().expires_at() > original_expiry);
        assert_eq!(cache.lookup(&ip), None);
    }

    #[test]
    fn test_reverse_cache_includes_stale_retention_and_refreshes() {
        let retention = Duration::from_secs(3600);
        let cache = ReverseLookupCache::new(100, retention);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let before = Instant::now();
        cache.insert(ip, "example.com", 60);
        let after = Instant::now();
        let entry = cache.inner.get(&ip).unwrap();
        assert!(entry.expires_at() >= before + Duration::from_secs(3660));
        assert!(entry.expires_at() <= after + Duration::from_secs(3660));
        // The mapping remains usable after the forward answer becomes stale.
        assert_eq!(entry.domain(after + Duration::from_secs(120)), Some("example.com"));
        assert_eq!(entry.domain(after + Duration::from_secs(3660)), None);

        let before_refresh = Instant::now();
        cache.insert(ip, "EXAMPLE.COM", 120);
        let entry = cache.inner.get(&ip).unwrap();
        assert!(entry.expires_at() >= before_refresh + Duration::from_secs(3720));
        assert_eq!(cache.lookup(&ip).as_deref(), Some("example.com"));

        cache.insert(ip, "other.example", 1);
        assert_eq!(cache.inner.get(&ip), Some(ReverseEntry::Ambiguous {
            expires_at: entry.expires_at(),
        }));
        assert_eq!(cache.lookup(&ip), None);
    }

    #[test]
    fn test_reverse_cache_concurrent_conflicts() {
        let cache = ReverseLookupCache::new(1024, Duration::ZERO);
        let barrier = Barrier::new(8);
        thread::scope(|scope| {
            for worker in 0..8 {
                let cache = &cache;
                let barrier = &barrier;
                scope.spawn(move || {
                    let domain = format!("domain-{worker}.example");
                    for round in 0..64 {
                        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, round));
                        barrier.wait();
                        cache.insert(ip, &domain, 60);
                    }
                });
            }
        });
        for round in 0..64 {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, round));
            assert!(matches!(
                cache.inner.get(&ip), Some(ReverseEntry::Ambiguous { .. })
            ));
            assert_eq!(cache.lookup(&ip), None);
        }
    }

    #[test]
    fn test_reverse_cache_expiration() {
        let cache = ReverseLookupCache::new(100, Duration::ZERO);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        let now = Instant::now();
        // Insert with expired timestamp directly
        let expired_entry = ReverseEntry::Unique {
            domain: "expired.com".to_string(),
            expires_at: now - Duration::from_secs(10),
        };
        cache.inner.insert(ip, expired_entry);

        assert_eq!(cache.lookup(&ip), None);

        // Now insert fresh entry
        cache.insert(ip, "fresh.com", 60);
        assert_eq!(cache.lookup(&ip), Some("fresh.com".to_string()));
    }

    #[test]
    fn test_invalidate_matching_domains() {
        let cache = ReverseLookupCache::new(100, Duration::ZERO);
        let matching_ip: IpAddr = "1.2.3.4".parse().unwrap();
        let other_ip: IpAddr = "5.6.7.8".parse().unwrap();
        cache.insert(matching_ip, "example.com", 60);
        cache.insert(other_ip, "other.org", 60);

        cache.invalidate_matching("EXAMPLE.COM");
        assert_eq!(cache.lookup(&matching_ip), None);
        assert_eq!(cache.lookup(&other_ip).as_deref(), Some("other.org"));

        cache.invalidate_matching("*.org");
        assert_eq!(cache.lookup(&other_ip), None);
    }
}
