use std::sync::{Arc, OnceLock};
use tracing::warn;

use crate::{
    app::router::{GeoSiteMatcher, Router, RuleMatcher, ThreadSafeRuleProvider},
    common::trie,
    session::{Session, SocksAddr},
};

pub struct NameServerPolicyContainer {
    static_trie: trie::StringTrie<Vec<String>>,
    geosite_entries: Vec<(String, Vec<String>)>,
    ruleset_entries: Vec<(String, Vec<String>)>,
    has_entries: bool,

    geosite_matchers: OnceLock<Vec<(GeoSiteMatcher, Vec<String>)>>,
    bound_rule_providers: OnceLock<Vec<(ThreadSafeRuleProvider, Vec<String>)>>,
}

impl Default for NameServerPolicyContainer {
    fn default() -> Self {
        Self::new()
    }
}

impl NameServerPolicyContainer {
    pub fn new() -> Self {
        Self {
            static_trie: trie::StringTrie::new(),
            geosite_entries: Vec::new(),
            ruleset_entries: Vec::new(),
            has_entries: false,
            geosite_matchers: OnceLock::new(),
            bound_rule_providers: OnceLock::new(),
        }
    }

    pub fn insert(&mut self, domain_key: &str, upstreams: Vec<String>) {
        let upstreams = Arc::new(upstreams);
        for sub in domain_key.split(',') {
            let sub = sub.trim();
            if sub.is_empty() {
                continue;
            }
            self.has_entries = true;

            if let Some(code) = sub.strip_prefix("geosite:") {
                self.geosite_entries
                    .push((code.to_owned(), (*upstreams).clone()));
            } else if let Some(rs_name) = sub.strip_prefix("rule-set:") {
                self.ruleset_entries
                    .push((rs_name.to_owned(), (*upstreams).clone()));
            } else {
                self.static_trie.insert(sub, upstreams.clone());
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.has_entries
    }

    pub fn add_rule_set(&self, router: &Router) {
        if !self.geosite_entries.is_empty() {
            let mut matchers = Vec::new();
            if let Some(geodata) = router.geodata() {
                for (code, upstreams) in &self.geosite_entries {
                    match GeoSiteMatcher::new(
                        code.clone(),
                        format!("nameserver-policy geosite:{}", code),
                        Some(geodata),
                    ) {
                        Ok(matcher) => matchers.push((matcher, upstreams.clone())),
                        Err(e) => {
                            warn!(
                                "nameserver-policy failed to create geosite matcher for {}: {}",
                                code, e
                            );
                        }
                    }
                }
            } else {
                warn!(
                    "nameserver-policy geosite entries configured but geodata is not available"
                );
            }
            let _ = self.geosite_matchers.set(matchers);
        }

        if !self.ruleset_entries.is_empty() {
            let mut providers = Vec::new();
            let rp_map = router.get_rule_providers();
            for (rs_name, upstreams) in &self.ruleset_entries {
                if let Some(rp) = rp_map.get(rs_name) {
                    providers.push((rp.clone(), upstreams.clone()));
                } else {
                    warn!(
                        "nameserver-policy rule-set provider not found: {}",
                        rs_name
                    );
                }
            }
            let _ = self.bound_rule_providers.set(providers);
        }
    }

    pub fn match_policy(&self, domain: &str) -> Option<&[String]> {
        if let Some(res) = self.static_trie.search(domain) {
            return res.get_data().map(|v| v.as_slice());
        }

        let sess = Session {
            destination: SocksAddr::Domain(domain.to_owned(), 0),
            ..Default::default()
        };

        if let Some(matchers) = self.geosite_matchers.get() {
            for (matcher, upstreams) in matchers {
                if matcher.apply(&sess) {
                    return Some(upstreams.as_slice());
                }
            }
        }

        if let Some(providers) = self.bound_rule_providers.get() {
            for (rp, upstreams) in providers {
                if rp.search(&sess) {
                    return Some(upstreams.as_slice());
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nameserver_policy_container_basic() {
        let mut container = NameServerPolicyContainer::new();
        container.insert("+.example.com, geosite:cn, rule-set:adblock", vec!["8.8.8.8".to_string()]);

        assert!(!container.is_empty());
        let matched = container.match_policy("test.example.com");
        assert!(matched.is_some());
        assert_eq!(matched.unwrap(), &["8.8.8.8".to_string()]);
        assert!(container.match_policy("other.com").is_none());
    }
}
