use crate::{
    Error,
    app::router::rules::geodata::str_matcher::StringMatcher,
    common::{
        domain::has_valid_domain_labels,
        geodata::geodata_proto::{Domain, domain::Type},
        domainset::{DomainSet, DomainSetBuilder},
    },
};

pub struct SuccinctMatcherGroup {
    set: DomainSet,
    other_matchers: Vec<StringMatcher>,
    not: bool,
}

impl SuccinctMatcherGroup {
    pub fn try_new(domains: Vec<Domain>, not: bool) -> Result<Self, Error> {
        let mut builder = DomainSetBuilder::new();
        let mut other_matchers = Vec::new();
        for domain in domains {
            let t = Type::try_from(domain.r#type).map_err(|error| {
                Error::InvalidConfig(format!("invalid domain type: {error}"))
            })?;
            match t {
                Type::Plain => {
                    other_matchers.push(StringMatcher::keyword(domain.value)?);
                }
                Type::Regex => {
                    other_matchers.push(StringMatcher::regex(&domain.value)?);
                }
                Type::Domain | Type::Full => {
                    // Geosite Full/Domain values are literal domain names.
                    // Reject pattern syntax before adding our suffix marker.
                    if !has_valid_domain_labels(&domain.value)
                        || domain.value.trim().is_empty()
                        || domain.value.contains(['*', '+'])
                    {
                        return Err(Error::InvalidConfig(format!(
                            "invalid geosite domain: {:?}", domain.value
                        )));
                    }
                    let key = if t == Type::Domain {
                        format!("+.{}", domain.value)
                    } else {
                        domain.value
                    };
                    if !builder.insert(&key) {
                        return Err(Error::InvalidConfig(format!(
                            "invalid geosite domain: {key:?}"
                        )));
                    }
                }
            }
        }
        Ok(Self {
            set: builder.build(),
            other_matchers,
            not,
        })
    }

    pub fn apply(&self, domain: &str) -> bool {
        if !has_valid_domain_labels(domain) {
            return false;
        }
        let matched = self.set.has(domain)
            || self.other_matchers.iter().any(|matcher| matcher.matches(domain));
        if self.not { !matched } else { matched }
    }
}

#[cfg(test)]
mod tests {
    use super::SuccinctMatcherGroup;
    use crate::common::geodata::geodata_proto::{Domain, domain::Type};

    fn entry(t: Type, value: &str) -> Domain {
        Domain { r#type: t as i32, value: value.to_owned(), ..Default::default() }
    }

    #[test]
    fn test_geosite_full_and_suffix() {
        let group = SuccinctMatcherGroup::try_new(vec![
            entry(Type::Full, "FULL.EXAMPLE"),
            entry(Type::Full, "full.example"),
            entry(Type::Domain, "SUFFIX.EXAMPLE"),
            entry(Type::Full, "é.example"),
        ], false).unwrap();
        assert_eq!(group.set.len(), 4);
        for domain in ["full.example", "FULL.EXAMPLE", "suffix.example",
            "a.SUFFIX.example", "a.b.suffix.example", "é.EXAMPLE"]
        {
            assert!(group.apply(domain), "{domain}");
        }
        for domain in ["a.full.example", "badsuffix.example", "example",
            "", ".suffix.example", "a..suffix.example", "suffix.example."]
        {
            assert!(!group.apply(domain), "{domain}");
        }
    }

    #[test]
    fn test_geosite_keywords_regex_and_negation() {
        let entries = vec![
            entry(Type::Full, "exact.example"),
            entry(Type::Plain, "KEYWORD"),
            entry(Type::Regex, r"^UPPER\.example$"),
            entry(Type::Regex, r"(?i)^FLAG\.example$"),
        ];
        let group = SuccinctMatcherGroup::try_new(entries.clone(), false).unwrap();
        let negated = SuccinctMatcherGroup::try_new(entries, true).unwrap();
        for (domain, matched) in [
            ("EXACT.example", true), ("a.keyword.example", true),
            ("UPPER.example", true), ("upper.example", false),
            ("flag.EXAMPLE", true), ("other.example", false),
        ] {
            assert_eq!(group.apply(domain), matched, "{domain}");
            assert_eq!(negated.apply(domain), !matched, "{domain}");
        }
        assert!(!negated.apply("a..example"));
        let empty = SuccinctMatcherGroup::try_new(vec![], false).unwrap();
        assert!(!empty.apply("example"));
        let empty = SuccinctMatcherGroup::try_new(vec![], true).unwrap();
        assert!(empty.apply("example"));
        assert!(!empty.apply(""));
    }

    #[test]
    fn test_geosite_rejects_invalid_entries() {
        for t in [Type::Full, Type::Domain] {
            for value in ["", " ", ".example", "example.", "a..example",
                "*.example", "+.example", "a+b.example", "a*.example"]
            {
                assert!(SuccinctMatcherGroup::try_new(
                    vec![entry(t, value)], false,
                ).is_err(), "{t:?}: {value}");
            }
        }
        for t in [Type::Plain, Type::Regex] {
            assert!(SuccinctMatcherGroup::try_new(vec![entry(t, "")], false).is_err());
        }
        assert!(SuccinctMatcherGroup::try_new(
            vec![entry(Type::Regex, "[")], false,
        ).is_err());
        let invalid_type = Domain { r#type: 99, ..Default::default() };
        assert!(SuccinctMatcherGroup::try_new(vec![invalid_type], false).is_err());
    }
}
