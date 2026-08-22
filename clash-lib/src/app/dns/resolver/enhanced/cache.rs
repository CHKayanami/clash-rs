use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::Expiry;
use moka::sync::Cache;

use crate::app::dns::query::QueryContext;
use crate::app::dns::response::ResponseTemplate;

/// Default wire TTL for serve-stale answers to encourage quick client retry.
pub const SERVE_STALE_WIRE_TTL: u32 = 30;

#[derive(Clone, Debug)]
pub struct CachedEntry {
    pub template: Arc<ResponseTemplate>,
    pub expires_at: Instant,
    pub stale_until: Instant,
}

impl CachedEntry {
    #[inline]
    pub fn is_fresh(&self, now: Instant) -> bool {
        now < self.expires_at
    }

    #[inline]
    pub fn is_stale_valid(&self, now: Instant) -> bool {
        now >= self.expires_at && now < self.stale_until
    }

    #[inline]
    pub fn remaining_ttl_secs(&self, now: Instant) -> u32 {
        self.expires_at
            .checked_duration_since(now)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    }
}

/// Lookup outcome for DNS caching with optimistic and serve-stale support.
#[derive(Clone, Debug)]
pub enum CacheLookup {
    /// Fresh cache hit with remaining TTL in seconds.
    Hit(Arc<ResponseTemplate>, u32),
    /// Expired positive answer within the serve-stale retention window.
    Stale(Arc<ResponseTemplate>),
    /// Cache miss or entry exceeded serve-stale retention.
    Miss,
}

struct DnsExpiry;

impl Expiry<Arc<[u8]>, CachedEntry> for DnsExpiry {
    fn expire_after_create(
        &self,
        _key: &Arc<[u8]>,
        value: &CachedEntry,
        created_at: Instant,
    ) -> Option<Duration> {
        Some(value.stale_until.saturating_duration_since(created_at))
    }
}

pub struct DnsCache {
    inner: Cache<Arc<[u8]>, CachedEntry>,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        let inner = Cache::builder()
            .max_capacity(capacity as u64)
            .expire_after(DnsExpiry)
            .build();
        Self { inner }
    }

    /// Look up cached DNS answers with support for fresh hits and stale retention.
    pub fn lookup(&self, query: &QueryContext, now: Instant) -> CacheLookup {
        let key = query.canonical_wire_arc();
        if let Some(entry) = self.inner.get(&key) {
            if entry.is_fresh(now) {
                let remaining_ttl = entry.remaining_ttl_secs(now).max(1);
                return CacheLookup::Hit(Arc::clone(&entry.template), remaining_ttl);
            } else if entry.is_stale_valid(now) {
                return CacheLookup::Stale(Arc::clone(&entry.template));
            } else {
                self.inner.invalidate(&key);
            }
        }
        CacheLookup::Miss
    }

    pub fn insert(
        &self,
        query: &QueryContext,
        template: Arc<ResponseTemplate>,
        min_ttl: u32,
        stale_retention: Duration,
    ) {
        let now = Instant::now();
        let ttl_secs = min_ttl.max(1);
        let expires_at = now + Duration::from_secs(ttl_secs as u64);
        let stale_until = expires_at + stale_retention;

        let entry = CachedEntry {
            template,
            expires_at,
            stale_until,
        };
        self.inner.insert(query.canonical_wire_arc(), entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::query::{DnsName, QType, build_dns_query_wire_with_id};
    use crate::app::dns::response::build_dns_ip_response;

    #[test]
    fn test_dns_cache_lookup_fresh_and_stale() {
        let cache = DnsCache::new(100);
        let name = DnsName::from_domain("example.com").unwrap();
        let query_bytes = build_dns_query_wire_with_id(0x1234, &name, QType::A);
        let query = QueryContext::parse(&query_bytes).unwrap();

        let resp_bytes = build_dns_ip_response(&query_bytes, &["1.2.3.4".parse().unwrap()], 10).unwrap();
        let template = Arc::new(ResponseTemplate::validate(&query, &resp_bytes).unwrap());

        // Cache miss initially
        assert!(matches!(cache.lookup(&query, Instant::now()), CacheLookup::Miss));

        // Insert with 10s TTL, 60s stale retention
        cache.insert(&query, template.clone(), 10, Duration::from_secs(60));

        let now = Instant::now();
        // Fresh hit
        match cache.lookup(&query, now) {
            CacheLookup::Hit(tmpl, remaining_ttl) => {
                let rendered = tmpl.render(&query).unwrap();
                let ips = crate::app::dns::wire::extract_ips_from_dns_response(&rendered);
                assert_eq!(ips, vec!["1.2.3.4".parse::<std::net::IpAddr>().unwrap()]);
                assert!(remaining_ttl <= 10);
            }
            _ => panic!("expected fresh cache hit"),
        }

        // Stale hit at +15s (after 10s TTL, before 70s total)
        let stale_time = now + Duration::from_secs(15);
        match cache.lookup(&query, stale_time) {
            CacheLookup::Stale(tmpl) => {
                let rendered = tmpl.render(&query).unwrap();
                let ips = crate::app::dns::wire::extract_ips_from_dns_response(&rendered);
                assert_eq!(ips, vec!["1.2.3.4".parse::<std::net::IpAddr>().unwrap()]);
            }
            _ => panic!("expected stale cache hit"),
        }

        // Miss after +75s (after 10s + 60s)
        let expired_time = now + Duration::from_secs(75);
        assert!(matches!(cache.lookup(&query, expired_time), CacheLookup::Miss));
    }
}
