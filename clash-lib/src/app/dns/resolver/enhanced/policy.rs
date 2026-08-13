use std::sync::{Arc, OnceLock};
use tracing::warn;

use crate::{
    app::router::{GeoSiteMatcher, Router, RuleMatcher, ThreadSafeRuleProvider},
    common::trie,
    dns::ThreadSafeDNSClient,
    session::{Session, SocksAddr},
};

pub struct NameServerPolicyContainer {
    static_trie: trie::StringTrie<Vec<ThreadSafeDNSClient>>,
    geosite_entries: Vec<(String, Vec<ThreadSafeDNSClient>)>,
    ruleset_entries: Vec<(String, Vec<ThreadSafeDNSClient>)>,
    has_entries: bool,

    geosite_matchers: OnceLock<Vec<(GeoSiteMatcher, Vec<ThreadSafeDNSClient>)>>,
    bound_rule_providers:
        OnceLock<Vec<(ThreadSafeRuleProvider, Vec<ThreadSafeDNSClient>)>>,
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

    pub fn insert(&mut self, domain_key: &str, clients: Vec<ThreadSafeDNSClient>) {
        let clients = Arc::new(clients);
        for sub in domain_key.split(',') {
            let sub = sub.trim();
            if sub.is_empty() {
                continue;
            }
            self.has_entries = true;

            if let Some(code) = sub.strip_prefix("geosite:") {
                self.geosite_entries
                    .push((code.to_owned(), (*clients).clone()));
            } else if let Some(rs_name) = sub.strip_prefix("rule-set:") {
                self.ruleset_entries
                    .push((rs_name.to_owned(), (*clients).clone()));
            } else {
                self.static_trie.insert(sub, clients.clone());
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
                for (code, clients) in &self.geosite_entries {
                    match GeoSiteMatcher::new(
                        code.clone(),
                        format!("nameserver-policy geosite:{}", code),
                        Some(geodata),
                    ) {
                        Ok(matcher) => matchers.push((matcher, clients.clone())),
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
            for (rs_name, clients) in &self.ruleset_entries {
                if let Some(rp) = rp_map.get(rs_name) {
                    providers.push((rp.clone(), clients.clone()));
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

    pub fn search(&self, domain: &str) -> Option<&Vec<ThreadSafeDNSClient>> {
        if let Some(node) = self.static_trie.search(domain) {
            if let Some(clients) = node.get_data() {
                return Some(clients);
            }
        }

        let sess = Session {
            destination: SocksAddr::Domain(domain.to_owned(), 53),
            ..Default::default()
        };

        if let Some(matchers) = self.geosite_matchers.get() {
            for (matcher, clients) in matchers {
                if matcher.apply(&sess) {
                    return Some(clients);
                }
            }
        }

        if let Some(providers) = self.bound_rule_providers.get() {
            for (rp, clients) in providers {
                if rp.search(&sess) {
                    return Some(clients);
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
        container.insert("+.example.com, geosite:cn, rule-set:adblock", vec![]);

        assert!(!container.is_empty());
        assert!(container.search("test.example.com").is_some());
        assert!(container.search("other.com").is_none());
    }
}
