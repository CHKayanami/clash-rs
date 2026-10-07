use std::{
    collections::HashMap,
    net,
    sync::{Arc, OnceLock},
};

use crate::app::remote_content_manager::providers::rule_provider::{
    ThreadSafeRuleProvider, WeakRuleProvider,
};
use crate::app::dns::domain::{DomainMatcher, normalize_domain};
use crate::common::mmdb::MmdbLookup;
use crate::session::{Session, SocksAddr};

/// A shared, lazily-populated MMDB handle.  The `OnceLock` starts empty and is
/// filled in after the `OutboundManager` (and its full outbound registry) is
/// ready, so that any MMDB download can use proxy groups if needed.
pub type PendingMmdb = Arc<OnceLock<MmdbLookup>>;

fn bind_rule_sets<'a>(
    names: &[String],
    bound: &'a OnceLock<Vec<WeakRuleProvider>>,
    providers: &HashMap<String, ThreadSafeRuleProvider>,
) -> Option<&'a [WeakRuleProvider]> {
    if names.is_empty() {
        return None;
    }
    let providers = bound.get_or_init(|| {
        names.iter().filter_map(|name| providers.get(name))
            .map(Arc::downgrade).collect()
    });
    Some(providers.as_slice())
}

pub struct GeoIPFilter(String, Option<PendingMmdb>);

impl GeoIPFilter {
    pub fn new(code: &str, mmdb: Option<PendingMmdb>) -> Self {
        Self(code.to_owned(), mmdb)
    }

    pub fn apply(&self, ip: &net::IpAddr) -> bool {
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

pub struct IPNetFilter {
    subnets: Vec<ipnet::IpNet>,
    ruleset_names: Vec<String>,
    rule_providers: OnceLock<Vec<WeakRuleProvider>>,
}

impl IPNetFilter {
    pub fn new<S: AsRef<str>>(entries: impl IntoIterator<Item = S>) -> crate::Result<Self> {
        let mut subnets = Vec::new();
        let mut ruleset_names = Vec::new();

        for item in entries {
            let s = item.as_ref();
            if let Some(rs_name) = s.strip_prefix("rule-set:") {
                ruleset_names.push(rs_name.to_owned());
            } else {
                let net: ipnet::IpNet = s
                    .parse()
                    .map_err(|x: ipnet::AddrParseError| crate::Error::InvalidConfig(x.to_string()))?;
                subnets.push(net);
            }
        }

        Ok(Self {
            subnets,
            ruleset_names,
            rule_providers: OnceLock::new(),
        })
    }

    pub fn add_rule_set(
        &self,
        rp_map: &std::collections::HashMap<String, ThreadSafeRuleProvider>,
    ) -> Option<&[WeakRuleProvider]> {
        bind_rule_sets(&self.ruleset_names, &self.rule_providers, rp_map)
    }

    pub fn apply(&self, ip: &net::IpAddr) -> bool {
        if self.subnets.iter().any(|net| net.contains(ip)) {
            return true;
        }

        if let Some(rps) = self.rule_providers.get() {
            let sess = Session {
                destination: SocksAddr::Ip(net::SocketAddr::new(*ip, 443)),
                ..Default::default()
            };
            return rps.iter().any(|rp| rp.upgrade()
                .is_some_and(|rp| rp.search(&sess)));
        }

        false
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.subnets.is_empty() && self.ruleset_names.is_empty()
    }
}

pub struct DomainFilter {
    domains: DomainMatcher,
    ruleset_names: Vec<String>,
    // Router owns providers. HTTP providers can themselves refer to DNS, so
    // DNS filters must not keep them alive after that router is released.
    rule_providers: OnceLock<Vec<WeakRuleProvider>>,
}

impl DomainFilter {
    pub fn new<S: AsRef<str>>(entries: impl IntoIterator<Item = S>) -> Self {
        let mut domains = Vec::new();
        let mut ruleset_names = Vec::new();

        for item in entries {
            let s = item.as_ref();
            if let Some(rs_name) = s.strip_prefix("rule-set:") {
                ruleset_names.push(rs_name.to_owned());
            } else {
                domains.push(item);
            }
        }

        Self {
            domains: DomainMatcher::new(domains),
            ruleset_names,
            rule_providers: OnceLock::new(),
        }
    }

    pub fn apply(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        if self.domains.matches_normalized(&domain) {
            return true;
        }

        if let Some(rps) = self.rule_providers.get() {
            let sess = Session {
                destination: SocksAddr::Domain(domain.as_ref().into(), 443),
                ..Default::default()
            };
            return rps.iter().any(|rp| rp.upgrade()
                .is_some_and(|rp| rp.search(&sess)));
        }

        false
    }

    pub fn add_rule_set(
        &self,
        rp_map: &std::collections::HashMap<String, ThreadSafeRuleProvider>,
    ) -> Option<&[WeakRuleProvider]> {
        bind_rule_sets(&self.ruleset_names, &self.rule_providers, rp_map)
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.ruleset_names.is_empty()
    }
}

pub type BlackDomainFilter = DomainFilter;

pub struct FallbackFilter {
    domain_filter: Option<DomainFilter>,
    ip_net_filter: Option<IPNetFilter>,
    geo_ip_filter: Option<GeoIPFilter>,
}

impl FallbackFilter {
    pub fn new(
        domains: &[String],
        ip_cidrs: &[String],
        geo_ip: bool,
        geo_ip_code: &str,
        mmdb: Option<PendingMmdb>,
    ) -> Self {
        let domain_filter = if !domains.is_empty() {
            Some(DomainFilter::new(domains))
        } else {
            None
        };

        let ip_net_filter = if !ip_cidrs.is_empty() {
            match IPNetFilter::new(ip_cidrs) {
                Ok(f) => Some(f),
                Err(e) => {
                    tracing::warn!("invalid fallback ip_cidr config: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let geo_ip_filter = if geo_ip {
            Some(GeoIPFilter::new(geo_ip_code, mmdb))
        } else {
            None
        };

        Self {
            domain_filter,
            ip_net_filter,
            geo_ip_filter,
        }
    }

    pub fn match_domain(&self, domain: &str) -> bool {
        self.domain_filter
            .as_ref()
            .map_or(false, |f| f.apply(domain))
    }

    pub fn match_ip(&self, ip: &net::IpAddr) -> bool {
        if let Some(f) = &self.geo_ip_filter {
            if f.apply(ip) {
                return true;
            }
        }
        if let Some(f) = &self.ip_net_filter {
            if f.apply(ip) {
                return true;
            }
        }
        false
    }

    pub fn add_rule_set(
        &self,
        rp_map: &std::collections::HashMap<String, ThreadSafeRuleProvider>,
    ) {
        if let Some(f) = &self.domain_filter {
            f.add_rule_set(rp_map);
        }
        if let Some(f) = &self.ip_net_filter {
            f.add_rule_set(rp_map);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.domain_filter.is_none()
            && self.ip_net_filter.is_none()
            && self.geo_ip_filter.is_none()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use super::*;
    use crate::app::remote_content_manager::providers::rule_provider::{
        RuleProviderImpl, RuleSetBehavior, RuleSetFormat, ThreadSafeRuleProvider,
    };

    #[tokio::test]
    async fn test_domain_filter_static_and_ruleset() {
        let filter = DomainFilter::new(vec![
            "*.bad.domain",
            "exact.com",
            "rule-set:adblock",
        ]);

        assert!(!filter.is_empty());
        assert!(filter.apply("exact.com"));
        assert!(filter.apply("EXACT.COM."));
        assert!(filter.apply("sub.bad.domain"));
        assert!(!filter.apply("a.sub.bad.domain"));
        assert!(!filter.apply("good.com"));
        assert!(!filter.apply("ad.com"));

        // Setup mock rule provider
        let rule_provider = Arc::new(RuleProviderImpl::new(
            "adblock".to_string(),
            RuleSetBehavior::Domain,
            RuleSetFormat::Text,
            None,
            None,
            None,
            None,
            Some(vec!["ad.com".to_owned()]),
        )) as ThreadSafeRuleProvider;
        rule_provider.initialize().await.unwrap();

        let mut rp_map = std::collections::HashMap::new();
        rp_map.insert("adblock".to_string(), rule_provider);

        let bound = filter.add_rule_set(&rp_map);
        assert!(bound.is_some());
        assert_eq!(bound.unwrap().len(), 1);

        // After adding rule set, ad.com should match
        assert!(filter.apply("ad.com"));
        assert!(filter.apply("AD.COM."));
    }

    #[test]
    fn test_empty_domain_filter() {
        let empty_filter = DomainFilter::new(Vec::<&str>::new());
        assert!(empty_filter.is_empty());
        assert!(!empty_filter.apply("example.com"));
        let invalid = DomainFilter::new(["", ".", "a..example"]);
        assert!(invalid.is_empty());
        assert!(!invalid.apply("example.com"));
    }

    #[tokio::test]
    async fn test_ip_net_filter_static_and_ruleset() {
        let filter = IPNetFilter::new(vec![
            "192.168.0.0/16",
            "rule-set:blocked-ips",
        ])
        .unwrap();

        assert!(!filter.is_empty());
        let ip1: net::IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: net::IpAddr = "10.0.0.1".parse().unwrap();

        assert!(filter.apply(&ip1));
        assert!(!filter.apply(&ip2));

        // Setup mock IP rule provider
        let rule_provider = Arc::new(RuleProviderImpl::new(
            "blocked-ips".to_string(),
            RuleSetBehavior::Ipcidr,
            RuleSetFormat::Text,
            None,
            None,
            None,
            None,
            Some(vec!["10.0.0.0/8".to_owned()]),
        )) as ThreadSafeRuleProvider;
        rule_provider.initialize().await.unwrap();

        let mut rp_map = std::collections::HashMap::new();
        rp_map.insert("blocked-ips".to_string(), rule_provider);

        let bound = filter.add_rule_set(&rp_map);
        assert!(bound.is_some());

        // After adding rule set, 10.0.0.1 should match
        assert!(filter.apply(&ip2));
    }

    #[tokio::test]
    async fn test_fallback_filter_container() {
        let domains = vec!["+.google.com".to_string(), "rule-set:fallback-domains".to_string()];
        let ip_cidrs = vec!["10.0.0.0/8".to_string(), "rule-set:fallback-ips".to_string()];

        let filter = FallbackFilter::new(&domains, &ip_cidrs, false, "CN", None);

        assert!(!filter.is_empty());
        assert!(filter.match_domain("www.google.com"));
        assert!(!filter.match_domain("baidu.com"));

        let ip1: net::IpAddr = "10.1.2.3".parse().unwrap();
        let ip2: net::IpAddr = "192.168.1.1".parse().unwrap();

        assert!(filter.match_ip(&ip1));
        assert!(!filter.match_ip(&ip2));
    }
}

