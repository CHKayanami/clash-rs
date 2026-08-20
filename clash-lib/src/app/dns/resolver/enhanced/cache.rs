use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::{op, rr};
use moka::Expiry;
use moka::sync::Cache;

#[derive(Clone, Debug)]
pub struct CachedEntry {
    pub answers: Arc<[rr::Record]>,
    pub expires_at: Instant,
}

impl CachedEntry {
    #[inline]
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    #[inline]
    pub fn remaining_ttl_secs(&self, now: Instant) -> u32 {
        self.expires_at
            .checked_duration_since(now)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    }
}

struct DnsExpiry;

impl Expiry<op::Query, CachedEntry> for DnsExpiry {
    fn expire_after_create(
        &self,
        _key: &op::Query,
        value: &CachedEntry,
        _created_at: Instant,
    ) -> Option<Duration> {
        let now = Instant::now();
        value.expires_at.checked_duration_since(now)
    }
}

pub struct DnsCache {
    inner: Cache<op::Query, CachedEntry>,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        let inner = Cache::builder()
            .max_capacity(capacity as u64)
            .expire_after(DnsExpiry)
            .build();
        Self { inner }
    }

    /// Look up cached DNS answers. If present and not expired, adjusts TTL to the remaining
    /// lifetime and returns the records. If expired, invalidates the entry and returns `None`.
    pub fn get(&self, query: &op::Query, now: Instant) -> Option<Vec<rr::Record>> {
        if let Some(entry) = self.inner.get(query) {
            if entry.is_expired(now) {
                self.inner.invalidate(query);
                return None;
            }
            let remaining_ttl = entry.remaining_ttl_secs(now).max(1);
            let mut answers: Vec<rr::Record> = entry.answers.to_vec();
            for ans in &mut answers {
                ans.ttl = remaining_ttl;
            }
            return Some(answers);
        }
        None
    }

    /// Insert DNS answers into the cache.
    pub fn insert(&self, query: op::Query, answers: Vec<rr::Record>, now: Instant) {
        if answers.is_empty() {
            return;
        }
        let min_ttl = answers.iter().map(|r| r.ttl).min().unwrap_or(0);
        if min_ttl == 0 {
            return;
        }
        let expires_at = now + Duration::from_secs(min_ttl as u64);
        let entry = CachedEntry {
            answers: answers.into(),
            expires_at,
        };
        self.inner.insert(query, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_cache_ttl_and_expiry() {
        let cache = DnsCache::new(16);
        let mut query = op::Query::new();
        query.set_name(rr::Name::from_str_relaxed("example.com.").unwrap());
        query.set_query_type(rr::RecordType::A);

        let record = rr::Record::from_rdata(
            rr::Name::from_str_relaxed("example.com.").unwrap(),
            300,
            rr::RData::A(rr::rdata::A(std::net::Ipv4Addr::new(1, 1, 1, 1))),
        );

        let now = Instant::now();
        cache.insert(query.clone(), vec![record], now);

        // Immediate lookup
        let hit = cache.get(&query, now).expect("must hit");
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].ttl, 300);

        // After 100 seconds
        let later = now + Duration::from_secs(100);
        let hit_later = cache.get(&query, later).expect("must hit");
        assert_eq!(hit_later[0].ttl, 200);

        // After 301 seconds (expired)
        let expired = now + Duration::from_secs(301);
        assert!(cache.get(&query, expired).is_none());
    }
}
