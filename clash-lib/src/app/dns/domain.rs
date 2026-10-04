use std::{borrow::Cow, sync::Arc};

use crate::{
    common::domainset::{DomainSet, DomainSetBuilder, DomainSetQuery},
    proxy::utils::OutboundHandlerRegistry,
};

pub(super) fn normalize_domain(domain: &str) -> Cow<'_, str> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(domain.to_ascii_lowercase())
    } else {
        Cow::Borrowed(domain)
    }
}

#[derive(Clone, Default)]
pub(super) struct DomainMatcher {
    set: Arc<DomainSet>,
}

impl DomainMatcher {
    pub(super) fn new<S: AsRef<str>>(domains: impl IntoIterator<Item = S>) -> Self {
        let mut builder = DomainSetBuilder::new();
        for domain in domains {
            let normalized = normalize_domain(domain.as_ref());
            if !normalized.is_empty() {
                builder.insert(&normalized);
            }
        }
        Self { set: Arc::new(builder.build()) }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    pub(super) fn matches(&self, domain: &str) -> bool {
        self.matches_normalized(&normalize_domain(domain))
    }

    pub(super) fn matches_normalized(&self, domain: &str) -> bool {
        self.set.has(domain)
    }

    pub(super) fn matches_query(&self, query: &DomainSetQuery<'_>) -> bool {
        self.set.has_query(query)
    }
}

pub(super) fn proxy_server_domain_matcher(
    outbounds: &OutboundHandlerRegistry,
) -> Option<DomainMatcher> {
    let names: Vec<_> = {
        let handlers = outbounds.read();
        handlers.values().filter_map(|handler| handler.server_name())
            .map(str::to_owned).collect()
    };
    // Release the registry lock before building the compressed set.
    let matcher = DomainMatcher::new(names);
    if matcher.is_empty() { None } else { Some(matcher) }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{DomainMatcher, normalize_domain};
    use crate::common::trie::StringTrie;

    #[test]
    fn test_dns_domain_set_matches_trie_patterns() {
        for patterns in [
            vec!["*.example", "ab.example"],
            vec!["*.x", "foo.a.x"],
            vec!["+.suffix.example", ".sub.example", "*.*.multi.example"],
            vec!["+"],
            vec!["EXACT.EXAMPLE.", "é.example", "a+b.example", "a*.example"],
            vec![],
        ] {
            let matcher = DomainMatcher::new(&patterns);
            let cloned = matcher.clone();
            let mut reference = StringTrie::new();
            for pattern in &patterns {
                reference.insert(&normalize_domain(pattern), Arc::new(()));
            }
            for domain in [
                "exact.example", "EXACT.EXAMPLE.", " é.EXAMPLE. ",
                "suffix.example", "a.suffix.example", "b.example", "a.x",
                "sub.example", "a.sub.example", "a.b.multi.example",
                "a.b.example", "a+b.example", "a*.example", "azb.example",
                "other.example", "", ".", ".example", "a..example",
            ] {
                let expected = reference.search(&normalize_domain(domain)).is_some();
                assert_eq!(matcher.matches(domain), expected, "{patterns:?}: {domain:?}");
                assert_eq!(cloned.matches(domain), expected, "{patterns:?}: {domain:?}");
            }
        }
    }

    #[test]
    fn test_dns_domain_set_empty_and_normalization() {
        let empty = DomainMatcher::new(["", " ", ".", "a..example"]);
        assert!(empty.is_empty());
        assert!(!empty.matches("example"));
        let matcher = DomainMatcher::new([" EXACT.EXAMPLE. ", "*.sub.example"]);
        assert!(matcher.matches(" EXACT.example. "));
        assert!(matcher.matches("one.sub.example"));
        assert!(!matcher.matches("one.two.sub.example"));
        assert!(!matcher.matches("sub.example"));
        let long = format!("{}.example", "a".repeat(300));
        assert!(DomainMatcher::new([&long]).matches(&long));
    }
}
