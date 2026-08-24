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
pub struct ReverseLookupCache {
    inner: Cache<IpAddr, ReverseEntry>,
}

impl ReverseLookupCache {
    pub fn new(capacity: usize) -> Self {
        let inner = Cache::builder()
            .max_capacity(capacity as u64)
            .expire_after(ReverseExpiry)
            .build();
        Self { inner }
    }

    /// Insert or update an IP -> host mapping.
    ///
    /// - If the IP is not present (or expired), insert as `Unique`.
    /// - If the IP already exists for the SAME domain, refresh its TTL as `Unique`.
    /// - If the IP exists for a DIFFERENT domain (or already marked `Ambiguous`),
    ///   mark it as `Ambiguous` so subsequent reverse lookups will return `None`.
    pub fn insert(&self, ip: IpAddr, host: &str, ttl_secs: u32) {
        let now = Instant::now();
        let ttl_secs = ttl_secs.max(1);
        let expires_at = now + Duration::from_secs(ttl_secs as u64);

        let new_entry = if let Some(existing) = self.inner.get(&ip) {
            if existing.is_fresh(now) {
                match existing {
                    ReverseEntry::Unique { ref domain, .. } if domain.eq_ignore_ascii_case(host) => {
                        ReverseEntry::Unique {
                            domain: domain.clone(),
                            expires_at,
                        }
                    }
                    ReverseEntry::Ambiguous { expires_at: old_exp } => {
                        // Maintain ambiguous state, take the longer expiration
                        ReverseEntry::Ambiguous {
                            expires_at: expires_at.max(old_exp),
                        }
                    }
                    _ => {
                        // Different domain mapped to the same IP: mark ambiguous
                        ReverseEntry::Ambiguous { expires_at }
                    }
                }
            } else {
                ReverseEntry::Unique {
                    domain: host.to_string(),
                    expires_at,
                }
            }
        } else {
            ReverseEntry::Unique {
                domain: host.to_string(),
                expires_at,
            }
        };

        self.inner.insert(ip, new_entry);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_reverse_cache_basic_and_refresh() {
        let cache = ReverseLookupCache::new(100);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        cache.insert(ip, "example.com", 60);
        assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));

        // Case-insensitive same domain refresh
        cache.insert(ip, "EXAMPLE.COM", 120);
        assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn test_reverse_cache_conflict_marks_ambiguous() {
        let cache = ReverseLookupCache::new(100);
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
    fn test_reverse_cache_expiration() {
        let cache = ReverseLookupCache::new(100);
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
}
