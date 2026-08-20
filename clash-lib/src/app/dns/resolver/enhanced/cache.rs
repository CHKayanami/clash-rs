use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::{op, rr};
use moka::Expiry;
use moka::sync::Cache;

/// Default wire TTL for serve-stale answers to encourage quick client retry.
const SERVE_STALE_WIRE_TTL: u32 = 30;

#[derive(Clone, Debug)]
pub struct CachedEntry {
    pub answers: Arc<[rr::Record]>,
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

    #[allow(dead_code)]
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

/// Lookup outcome for DNS caching with optimistic and serve-stale support.
#[derive(Debug, PartialEq, Eq)]
pub enum CacheLookup {
    /// Fresh cache hit with updated remaining TTL.
    Hit(Vec<rr::Record>),
    /// Expired positive answer within the serve-stale retention window (wire TTL set to 30s).
    /// Used for stale-while-revalidate background refresh and fallback.
    Stale(Vec<rr::Record>),
    /// Cache miss or entry exceeded serve-stale retention.
    Miss,
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
        value.stale_until.checked_duration_since(now)
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

    /// Look up cached DNS answers with support for fresh hits and stale retention.
    pub fn lookup(&self, query: &op::Query, now: Instant) -> CacheLookup {
        if let Some(entry) = self.inner.get(query) {
            if entry.is_fresh(now) {
                let remaining_ttl = entry.remaining_ttl_secs(now).max(1);
                let mut answers: Vec<rr::Record> = entry.answers.to_vec();
                for ans in &mut answers {
                    ans.ttl = remaining_ttl;
                }
                return CacheLookup::Hit(answers);
            } else if entry.is_stale_valid(now) {
                let mut answers: Vec<rr::Record> = entry.answers.to_vec();
                for ans in &mut answers {
                    ans.ttl = SERVE_STALE_WIRE_TTL;
                }
                return CacheLookup::Stale(answers);
            } else {
                self.inner.invalidate(query);
                return CacheLookup::Miss;
            }
        }
        CacheLookup::Miss
    }

    /// Look up cached DNS answers. Returns `Some` only if fresh (not expired).
    #[allow(dead_code)]
    pub fn get(&self, query: &op::Query, now: Instant) -> Option<Vec<rr::Record>> {
        match self.lookup(query, now) {
            CacheLookup::Hit(answers) => Some(answers),
            _ => None,
        }
    }

    /// Get stale cache entry if available within retention period (for serve-stale fallback).
    pub fn get_stale(&self, query: &op::Query, now: Instant) -> Option<Vec<rr::Record>> {
        if let Some(entry) = self.inner.get(query) {
            if entry.is_stale_valid(now) {
                let mut answers: Vec<rr::Record> = entry.answers.to_vec();
                for ans in &mut answers {
                    ans.ttl = SERVE_STALE_WIRE_TTL;
                }
                return Some(answers);
            }
        }
        None
    }

    /// Insert DNS answers into the cache using default (unmodified) TTL and 1h stale retention.
    #[allow(dead_code)]
    pub fn insert(&self, query: op::Query, answers: Vec<rr::Record>, now: Instant) {
        self.insert_with_policy(
            query,
            answers,
            0,
            None,
            Duration::from_secs(3600),
            now,
        );
    }

    /// Insert DNS answers applying optimistic TTL overrides, fixed domain TTL, and stale retention.
    pub fn insert_with_policy(
        &self,
        query: op::Query,
        mut answers: Vec<rr::Record>,
        optimistic_ttl: u32,
        fixed_ttl: Option<u32>,
        stale_retention: Duration,
        now: Instant,
    ) {
        if answers.is_empty() {
            return;
        }

        // 1. Calculate effective TTL
        let raw_min_ttl = answers.iter().map(|r| r.ttl).min().unwrap_or(0);
        let effective_ttl = if let Some(fttl) = fixed_ttl {
            if fttl == 0 {
                // fixed_domain_ttl = 0 means never cache this domain
                return;
            }
            fttl
        } else if optimistic_ttl > 0 {
            raw_min_ttl.max(optimistic_ttl)
        } else {
            raw_min_ttl
        };

        if effective_ttl == 0 {
            return;
        }

        // 2. Adjust record wire TTLs
        for record in &mut answers {
            record.ttl = effective_ttl;
        }

        let expires_at = now + Duration::from_secs(effective_ttl as u64);
        let stale_until = expires_at + stale_retention;

        let entry = CachedEntry {
            answers: answers.into(),
            expires_at,
            stale_until,
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

        // After 301 seconds (expired fresh, but within stale retention)
        let expired = now + Duration::from_secs(301);
        assert!(cache.get(&query, expired).is_none());
        match cache.lookup(&query, expired) {
            CacheLookup::Stale(stale) => {
                assert_eq!(stale[0].ttl, SERVE_STALE_WIRE_TTL);
            }
            _ => panic!("expected Stale lookup outcome"),
        }
    }

    #[test]
    fn test_optimistic_cache_ttl_override() {
        let cache = DnsCache::new(16);
        let mut query = op::Query::new();
        query.set_name(rr::Name::from_str_relaxed("cdn.example.com.").unwrap());
        query.set_query_type(rr::RecordType::A);

        // Raw record has short TTL of 30s
        let record = rr::Record::from_rdata(
            rr::Name::from_str_relaxed("cdn.example.com.").unwrap(),
            30,
            rr::RData::A(rr::rdata::A(std::net::Ipv4Addr::new(2, 2, 2, 2))),
        );

        let now = Instant::now();
        // Optimistic TTL override to 600s
        cache.insert_with_policy(
            query.clone(),
            vec![record],
            600,
            None,
            Duration::from_secs(3600),
            now,
        );

        // Immediate lookup -> TTL must be boosted to 600
        let hit = cache.get(&query, now).expect("must hit");
        assert_eq!(hit[0].ttl, 600);

        // At 100s, raw TTL (30s) would have expired, but optimistic TTL keeps it fresh
        let at_100s = now + Duration::from_secs(100);
        let hit_100s = cache.get(&query, at_100s).expect("must still hit");
        assert_eq!(hit_100s[0].ttl, 500);
    }

    #[test]
    fn test_fixed_domain_ttl_zero_skips_cache() {
        let cache = DnsCache::new(16);
        let mut query = op::Query::new();
        query.set_name(rr::Name::from_str_relaxed("ddns.example.com.").unwrap());
        query.set_query_type(rr::RecordType::A);

        let record = rr::Record::from_rdata(
            rr::Name::from_str_relaxed("ddns.example.com.").unwrap(),
            300,
            rr::RData::A(rr::rdata::A(std::net::Ipv4Addr::new(3, 3, 3, 3))),
        );

        let now = Instant::now();
        // fixed_ttl = Some(0) -> must not cache
        cache.insert_with_policy(
            query.clone(),
            vec![record],
            600,
            Some(0),
            Duration::from_secs(3600),
            now,
        );

        assert!(cache.get(&query, now).is_none());
        assert_eq!(cache.lookup(&query, now), CacheLookup::Miss);
    }

    #[test]
    fn test_fixed_domain_ttl_override_priority() {
        let cache = DnsCache::new(16);
        let mut query = op::Query::new();
        query.set_name(rr::Name::from_str_relaxed("custom.example.com.").unwrap());
        query.set_query_type(rr::RecordType::A);

        let record = rr::Record::from_rdata(
            rr::Name::from_str_relaxed("custom.example.com.").unwrap(),
            30,
            rr::RData::A(rr::rdata::A(std::net::Ipv4Addr::new(4, 4, 4, 4))),
        );

        let now = Instant::now();
        // fixed_ttl = Some(120), optimistic = 600 -> fixed TTL has higher priority
        cache.insert_with_policy(
            query.clone(),
            vec![record],
            600,
            Some(120),
            Duration::from_secs(3600),
            now,
        );

        let hit = cache.get(&query, now).expect("must hit");
        assert_eq!(hit[0].ttl, 120);
    }

    #[test]
    fn test_serve_stale_and_total_expiry() {
        let cache = DnsCache::new(16);
        let mut query = op::Query::new();
        query.set_name(rr::Name::from_str_relaxed("stale.example.com.").unwrap());
        query.set_query_type(rr::RecordType::A);

        let record = rr::Record::from_rdata(
            rr::Name::from_str_relaxed("stale.example.com.").unwrap(),
            60,
            rr::RData::A(rr::rdata::A(std::net::Ipv4Addr::new(5, 5, 5, 5))),
        );

        let now = Instant::now();
        // TTL 60s, stale retention 300s -> fresh 0..60s, stale 60..360s, expired >360s
        cache.insert_with_policy(
            query.clone(),
            vec![record],
            0,
            None,
            Duration::from_secs(300),
            now,
        );

        // At 50s -> Fresh
        let at_50s = now + Duration::from_secs(50);
        assert!(matches!(cache.lookup(&query, at_50s), CacheLookup::Hit(_)));

        // At 100s -> Stale
        let at_100s = now + Duration::from_secs(100);
        assert!(matches!(cache.lookup(&query, at_100s), CacheLookup::Stale(_)));
        let stale = cache.get_stale(&query, at_100s).expect("must get stale");
        assert_eq!(stale[0].ttl, SERVE_STALE_WIRE_TTL);

        // At 400s -> Completely Expired (Miss)
        let at_400s = now + Duration::from_secs(400);
        assert_eq!(cache.lookup(&query, at_400s), CacheLookup::Miss);
        assert!(cache.get_stale(&query, at_400s).is_none());
    }
}
