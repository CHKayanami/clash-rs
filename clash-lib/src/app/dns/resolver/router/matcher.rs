use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use ipnet::IpNet;

use crate::app::dns::query::QType;
use crate::app::remote_content_manager::providers::rule_provider::ThreadSafeRuleProvider;
use crate::common::trie::StringTrie;
use crate::session::{Session, SocksAddr};

#[derive(Clone, Default)]
pub struct DomainMatcher {
    trie: Arc<StringTrie<()>>,
}

impl DomainMatcher {
    pub fn new(domains: &[String]) -> Self {
        let mut trie = StringTrie::new();
        for d in domains {
            let normalized = d.trim().trim_end_matches('.').to_ascii_lowercase();
            if !normalized.is_empty() {
                trie.insert(&normalized, Arc::new(()));
            }
        }
        Self {
            trie: Arc::new(trie),
        }
    }

    pub fn matches(&self, domain: &str) -> bool {
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        self.trie.search(&normalized).is_some()
    }
}

#[derive(Clone, Default)]
pub struct RuleSetMatcher {
    names: Vec<String>,
    providers: Arc<OnceLock<Vec<ThreadSafeRuleProvider>>>,
}

impl RuleSetMatcher {
    pub fn new(names: &[String]) -> Self {
        Self {
            names: names.to_vec(),
            providers: Arc::new(OnceLock::new()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn bind_providers(&self, map: &HashMap<String, ThreadSafeRuleProvider>) {
        let mut list = Vec::new();
        for name in &self.names {
            let clean_name = name.strip_prefix("rule-set:").unwrap_or(name);
            if let Some(p) = map.get(clean_name) {
                list.push(p.clone());
            }
        }
        let _ = self.providers.set(list);
    }

    pub fn matches_domain(&self, domain: &str) -> bool {
        if self.names.is_empty() {
            return false;
        }
        if let Some(providers) = self.providers.get() {
            let session = Session {
                destination: SocksAddr::Domain(domain.to_string().into(), 443),
                ..Default::default()
            };
            return providers.iter().any(|p| p.search(&session));
        }
        false
    }

    pub fn matches_ip(&self, ip: &IpAddr) -> bool {
        if self.names.is_empty() {
            return false;
        }
        if let Some(providers) = self.providers.get() {
            let session = Session {
                destination: SocksAddr::Ip(SocketAddr::new(*ip, 443)),
                ..Default::default()
            };
            return providers.iter().any(|p| p.search(&session));
        }
        false
    }
}

#[derive(Clone, Default)]
pub struct QTypeMatcher {
    types: HashSet<QType>,
}

impl QTypeMatcher {
    pub fn new(types: HashSet<QType>) -> Self {
        Self { types }
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    pub fn matches(&self, qt: QType) -> bool {
        self.types.contains(&qt)
    }
}

#[derive(Clone, Default)]
pub struct IpNetMatcher {
    nets: Vec<IpNet>,
}

impl IpNetMatcher {
    pub fn new(nets: Vec<IpNet>) -> Self {
        Self { nets }
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    pub fn matches(&self, ip: &IpAddr) -> bool {
        self.nets.iter().any(|net| net.contains(ip))
    }
}
