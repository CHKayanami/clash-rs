use crate::app::dns::normalize_domain;
use crate::common::domainset::{DomainSet, DomainSetBuilder};
use crate::Error;

#[derive(Default)]
pub(super) struct DomainMatcher {
    domains: DomainSet,
    keywords: Vec<String>,
}

impl DomainMatcher {
    pub(super) fn new(patterns: &[String]) -> Self {
        let mut builder = DomainSetBuilder::new();
        let mut matcher = Self::default();
        for pattern in patterns {
            let pattern = normalize_domain(pattern);
            if let Some(keyword) = keyword(&pattern) {
                matcher.keywords.push(keyword.to_string());
            } else {
                assert!(insert_domain(&mut builder, &pattern),
                    "invalid sniffer domain pattern: {pattern}");
            }
        }
        matcher.domains = builder.build();
        matcher
    }

    pub(super) fn matches(&self, domain: &str) -> bool {
        if self.domains.is_empty() && self.keywords.is_empty() {
            return false;
        }
        let domain = normalize_domain(domain);
        if self.domains.has(&domain) {
            return true;
        }
        let domain = domain.as_bytes();
        self.keywords.iter().any(|keyword| {
            domain.windows(keyword.len())
                .any(|part| part == keyword.as_bytes())
        })
    }
}

fn keyword(pattern: &str) -> Option<&str> {
    if pattern.starts_with('*') && pattern.ends_with('*') && pattern.len() > 2 {
        Some(&pattern[1..pattern.len() - 1])
    } else {
        None
    }
}

fn insert_domain(builder: &mut DomainSetBuilder, pattern: &str) -> bool {
    if pattern.contains('*') || pattern == "+" {
        return builder.insert(pattern);
    }
    // Keep the existing base-and-subdomain behavior for non-wildcard rules.
    let suffix = pattern.strip_prefix("+.")
        .or_else(|| pattern.strip_prefix('.'))
        .unwrap_or(pattern);
    builder.insert(&format!("+.{suffix}"))
}

pub(crate) fn validate_domain_patterns(
    name: &str, patterns: &[String],
) -> Result<(), Error> {
    let mut builder = DomainSetBuilder::new();
    for pattern in patterns {
        let normalized = normalize_domain(pattern);
        if keyword(&normalized).is_none()
            && !insert_domain(&mut builder, &normalized)
        {
            return Err(Error::InvalidConfig(format!(
                "sniffer.{name}: invalid domain pattern '{pattern}'"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(pattern: &str) -> DomainMatcher {
        DomainMatcher::new(&[pattern.to_string()])
    }

    #[test]
    fn domain_forms_preserve_base_suffix_and_case_matching() {
        for pattern in ["example.com", ".example.com", "+.EXAMPLE.COM"] {
            let matcher = matcher(pattern);
            for domain in ["example.com", "EXAMPLE.COM", "a.b.Example.com"] {
                assert!(matcher.matches(domain), "{pattern}: {domain}");
            }
            for domain in ["badexample.com", "example.com.evil", "other.com"] {
                assert!(!matcher.matches(domain), "{pattern}: {domain}");
            }
        }
        assert!(matcher("Mijia Cloud").matches("MIJIA CLOUD"));
        assert!(!DomainMatcher::default().matches("example.com"));
    }

    #[test]
    fn patterns_and_queries_share_dns_normalization() {
        for pattern in [" EXAMPLE.COM. ", " .EXAMPLE.COM. ", "+.EXAMPLE.COM."] {
            let matcher = matcher(pattern);
            assert!(matcher.matches(" EXAMPLE.COM. "));
            assert!(matcher.matches(" sub.Example.com. "));
            assert!(!matcher.matches("badexample.com."));
        }
        let wildcard = matcher(" *.EXAMPLE.COM. ");
        assert!(wildcard.matches(" WWW.EXAMPLE.COM. "));
        assert!(!wildcard.matches("example.com."));
        assert!(!wildcard.matches("a.b.example.com."));
        assert!(matcher(" *CLOUD* ").matches(" MY.CLOUD.EXAMPLE. "));
        assert!(!DomainMatcher::default().matches(" . "));
    }

    #[test]
    fn keywords_and_label_wildcards_match() {
        assert!(matcher("*Cloud*").matches("my.CLOUD.example"));
        assert!(!matcher("*Cloud*").matches("example.com"));
        let wildcard = matcher("*.example.com");
        assert!(wildcard.matches("WWW.EXAMPLE.COM"));
        assert!(!wildcard.matches("example.com"));
        assert!(!wildcard.matches("a.b.example.com"));
        assert!(matcher("api.*.example.com").matches("api.eu.example.com"));
        assert!(!matcher("api.*.example.com").matches("api.example.com"));
    }
}
