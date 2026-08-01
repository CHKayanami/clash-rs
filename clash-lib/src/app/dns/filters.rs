use std::{
    net,
    sync::{Arc, OnceLock},
};

use crate::app::remote_content_manager::providers::rule_provider::ThreadSafeRuleProvider;
use crate::common::{mmdb::MmdbLookup, trie};
use crate::session::{Session, SocksAddr};

pub trait FallbackIPFilter: Sync + Send {
    fn apply(&self, ip: &net::IpAddr) -> bool;
}

/// A shared, lazily-populated MMDB handle.  The `OnceLock` starts empty and is
/// filled in after the `OutboundManager` (and its full outbound registry) is
/// ready, so that any MMDB download can use proxy groups if needed.
pub type PendingMmdb = Arc<OnceLock<MmdbLookup>>;

pub struct GeoIPFilter(String, Option<PendingMmdb>);

impl GeoIPFilter {
    pub fn new(code: &str, mmdb: Option<PendingMmdb>) -> Self {
        Self(code.to_owned(), mmdb)
    }
}

impl FallbackIPFilter for GeoIPFilter {
    fn apply(&self, ip: &net::IpAddr) -> bool {
        // When the OnceLock is not yet populated (e.g. during startup before the
        // MMDB is loaded) `lock.get()` returns `None`, making this return `true`
        // — the permissive default that lets all IPs through to the fallback
        // resolver.  Once the MMDB is set the filter behaves normally.
        !self
            .1
            .as_ref()
            .and_then(|lock| lock.get())
            .is_some_and(|mmdb| {
                mmdb.lookup_country(*ip)
                    .map(|x| x.country_code)
                    .is_ok_and(|x| x == self.0)
            })
    }
}

pub struct IPNetFilter(ipnet::IpNet);

impl IPNetFilter {
    pub fn new(ipnet: ipnet::IpNet) -> Self {
        Self(ipnet)
    }
}

impl FallbackIPFilter for IPNetFilter {
    fn apply(&self, ip: &net::IpAddr) -> bool {
        self.0.contains(ip)
    }
}

pub trait FallbackDomainFilter: Sync + Send {
    fn apply(&self, domain: &str) -> bool;
}

pub struct DomainFilter(trie::StringTrie<Option<String>>);

impl DomainFilter {
    pub fn new(domains: Vec<&str>) -> Self {
        let mut f = DomainFilter(trie::StringTrie::new());
        for d in domains {
            f.0.insert(d, Arc::new(None));
        }
        f
    }
}

impl FallbackDomainFilter for DomainFilter {
    fn apply(&self, domain: &str) -> bool {
        self.0.search(domain).is_some()
    }
}

pub struct BlackDomainFilter {
    domains: trie::StringTrie<Option<String>>,
    ruleset_names: Vec<String>,
    rule_providers: OnceLock<Vec<ThreadSafeRuleProvider>>,
}

impl BlackDomainFilter {
    pub fn new(domains_or_rulesets: Vec<&str>) -> Self {
        let mut domains = trie::StringTrie::new();
        let mut ruleset_names = Vec::new();

        for item in domains_or_rulesets {
            if item.starts_with("rule-set:") {
                ruleset_names.push(item.replace("rule-set:", ""));
            } else {
                domains.insert(item, Arc::new(None));
            }
        }

        Self {
            domains,
            ruleset_names,
            rule_providers: OnceLock::new(),
        }
    }

    pub fn apply(&self, domain: &str) -> bool {
        if self.domains.search(domain).is_some() {
            return true;
        }

        if let Some(rps) = self.rule_providers.get() {
            let sess = Session {
                destination: SocksAddr::Domain(domain.to_owned(), 443),
                ..Default::default()
            };
            return rps.iter().any(|rp| rp.search(&sess));
        }

        false
    }

    pub fn add_rule_set(
        &self,
        rp_map: &std::collections::HashMap<String, ThreadSafeRuleProvider>,
    ) {
        if !self.ruleset_names.is_empty() {
            let mut providers = Vec::new();
            for name in &self.ruleset_names {
                if let Some(rp) = rp_map.get(name) {
                    providers.push(rp.clone());
                }
            }
            let _ = self.rule_providers.set(providers);
        }
    }
}
