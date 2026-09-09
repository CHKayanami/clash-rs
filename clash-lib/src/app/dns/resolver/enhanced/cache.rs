use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use moka::Expiry;
use moka::sync::Cache;

use crate::app::dns::query::{QType, QueryContext};
use crate::app::dns::response::ResponseTemplate;

/// Default wire TTL for serve-stale answers to encourage quick client retry.
pub const SERVE_STALE_WIRE_TTL: u32 = 30;

static DEFAULT_SCOPE: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from(""));

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

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct DnsCacheKey {
    pub scope: Arc<str>,
    pub domain: Arc<str>,
    pub qtype: QType,
}

struct DnsExpiry;

impl Expiry<DnsCacheKey, CachedEntry> for DnsExpiry {
    fn expire_after_create(
        &self,
        _key: &DnsCacheKey,
        value: &CachedEntry,
        created_at: Instant,
    ) -> Option<Duration> {
        Some(value.stale_until.saturating_duration_since(created_at))
    }
}

#[derive(Clone)]
pub struct DnsCache {
    inner: Cache<DnsCacheKey, CachedEntry>,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        let inner = Cache::builder()
            .max_capacity(capacity as u64)
            .expire_after(DnsExpiry)
            .build();
        Self { inner }
    }

    /// Look up cached DNS answers for a specific upstream/scope (zero heap-allocation).
    pub fn lookup_scoped(&self, scope: &Arc<str>, query: &QueryContext, now: Instant) -> CacheLookup {
        let domain = match query.qdomain_arc() {
            Some(d) => d,
            None => return CacheLookup::Miss,
        };
        let qtype = match query.qtype() {
            Some(t) => t,
            None => return CacheLookup::Miss,
        };
        let key = DnsCacheKey {
            scope: Arc::clone(scope),
            domain,
            qtype,
        };
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

    /// Look up cached DNS answers with support for fresh hits and stale retention (default scope).
    pub fn lookup(&self, query: &QueryContext, now: Instant) -> CacheLookup {
        self.lookup_scoped(&DEFAULT_SCOPE, query, now)
    }

    /// Insert cached DNS answer for a specific upstream/scope (zero heap-allocation).
    pub fn insert_scoped(
        &self,
        scope: &Arc<str>,
        query: &QueryContext,
        template: Arc<ResponseTemplate>,
        min_ttl: u32,
        stale_retention: Duration,
    ) {
        let domain = match query.qdomain_arc() {
            Some(d) => d,
            None => return,
        };
        let qtype = match query.qtype() {
            Some(t) => t,
            None => return,
        };
        let now = Instant::now();
        let ttl_secs = min_ttl.max(1);
        let expires_at = now + Duration::from_secs(ttl_secs as u64);
        let stale_until = expires_at + stale_retention;

        let entry = CachedEntry {
            template,
            expires_at,
            stale_until,
        };
        let key = DnsCacheKey {
            scope: Arc::clone(scope),
            domain,
            qtype,
        };
        self.inner.insert(key, entry);
    }

    /// Insert cached DNS answer (default scope).
    pub fn insert(
        &self,
        query: &QueryContext,
        template: Arc<ResponseTemplate>,
        min_ttl: u32,
        stale_retention: Duration,
    ) {
        self.insert_scoped(&DEFAULT_SCOPE, query, template, min_ttl, stale_retention);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::query::{build_dns_query_wire_with_id, DnsName, QType};
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

    #[test]
    fn test_dns_cache_scoped_isolation() {
        let cache = DnsCache::new(100);
        let name = DnsName::from_domain("example.com").unwrap();
        let query_bytes = build_dns_query_wire_with_id(0x1234, &name, QType::A);
        let query = QueryContext::parse(&query_bytes).unwrap();

        let resp_remote = build_dns_ip_response(&query_bytes, &["1.1.1.1".parse().unwrap()], 10).unwrap();
        let tmpl_remote = Arc::new(ResponseTemplate::validate(&query, &resp_remote).unwrap());

        let resp_local = build_dns_ip_response(&query_bytes, &["127.0.0.1".parse().unwrap()], 10).unwrap();
        let tmpl_local = Arc::new(ResponseTemplate::validate(&query, &resp_local).unwrap());

        let remote_scope: Arc<str> = Arc::from("remote");
        let local_scope: Arc<str> = Arc::from("local");
        let other_scope: Arc<str> = Arc::from("other");

        cache.insert_scoped(&remote_scope, &query, tmpl_remote, 10, Duration::from_secs(60));
        cache.insert_scoped(&local_scope, &query, tmpl_local, 10, Duration::from_secs(60));

        let now = Instant::now();
        // remote scope 返回 1.1.1.1
        match cache.lookup_scoped(&remote_scope, &query, now) {
            CacheLookup::Hit(tmpl, _) => {
                let rendered = tmpl.render(&query).unwrap();
                let ips = crate::app::dns::wire::extract_ips_from_dns_response(&rendered);
                assert_eq!(ips, vec!["1.1.1.1".parse::<std::net::IpAddr>().unwrap()]);
            }
            _ => panic!("expected remote cache hit"),
        }

        // local scope 返回 127.0.0.1
        match cache.lookup_scoped(&local_scope, &query, now) {
            CacheLookup::Hit(tmpl, _) => {
                let rendered = tmpl.render(&query).unwrap();
                let ips = crate::app::dns::wire::extract_ips_from_dns_response(&rendered);
                assert_eq!(ips, vec!["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]);
            }
            _ => panic!("expected local cache hit"),
        }

        // other scope 应当 miss
        assert!(matches!(cache.lookup_scoped(&other_scope, &query, now), CacheLookup::Miss));
    }

    #[test]
    fn test_dns_cache_case_insensitivity() {
        let cache = DnsCache::new(100);
        let name_upper = DnsName::from_domain("ExAmPlE.CoM").unwrap();
        let query_upper_wire = build_dns_query_wire_with_id(0x1111, &name_upper, QType::A);
        let query_upper = QueryContext::parse(&query_upper_wire).unwrap();

        let resp = build_dns_ip_response(&query_upper_wire, &["8.8.8.8".parse().unwrap()], 60).unwrap();
        let template = Arc::new(ResponseTemplate::validate(&query_upper, &resp).unwrap());

        let scope: Arc<str> = Arc::from("upstream1");
        cache.insert_scoped(&scope, &query_upper, template, 60, Duration::from_secs(60));

        // 客户端发来全小写的同域名查询
        let name_lower = DnsName::from_domain("example.com").unwrap();
        let query_lower_wire = build_dns_query_wire_with_id(0x2222, &name_lower, QType::A);
        let query_lower = QueryContext::parse(&query_lower_wire).unwrap();

        let now = Instant::now();
        match cache.lookup_scoped(&scope, &query_lower, now) {
            CacheLookup::Hit(tmpl, remaining_ttl) => {
                let rendered = tmpl.render(&query_lower).unwrap();
                // 验证 TxId 被重写为 caller 的 0x2222
                assert_eq!(u16::from_be_bytes([rendered[0], rendered[1]]), 0x2222);
                let ips = crate::app::dns::wire::extract_ips_from_dns_response(&rendered);
                assert_eq!(ips, vec!["8.8.8.8".parse::<std::net::IpAddr>().unwrap()]);
                assert!(remaining_ttl <= 60);
            }
            _ => panic!("expected case-insensitive cache hit"),
        }
    }
}
