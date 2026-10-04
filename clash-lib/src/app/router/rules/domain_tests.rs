use crate::{
    app::router::{Rule, RuleMatcher, map_rule_type},
    app::router::rules::domain_keyword::DomainKeyword,
    config::internal::rule::RuleType,
    session::{Session, SocksAddr},
};

fn rule(proto: &str, payload: &str) -> Rule {
    map_rule_type(
        RuleType::new(proto, payload, "DIRECT", None).unwrap(),
        None, None, None,
    ).unwrap()
}

fn matches(rule: &Rule, domain: &str) -> bool {
    rule.apply(&Session {
        destination: SocksAddr::Domain(domain.into(), 443),
        ..Default::default()
    })
}

#[test]
fn test_domain_rules_case_and_boundaries() {
    let exact = rule("DOMAIN", "EXAMPLE.COM");
    let suffix = rule("DOMAIN-SUFFIX", "EXAMPLE.COM");
    let keyword = rule("DOMAIN-KEYWORD", "EXAMPLE");
    for (domain, full, sub, contains) in [
        ("example.com", true, true, true),
        ("EXAMPLE.COM", true, true, true),
        ("a.Example.com", false, true, true),
        ("a.b.example.com", false, true, true),
        ("badexample.com", false, false, true),
        ("example.net", false, false, true),
        ("other.com", false, false, false),
    ] {
        assert_eq!(matches(&exact, domain), full, "{domain}");
        assert_eq!(matches(&suffix, domain), sub, "{domain}");
        assert_eq!(matches(&keyword, domain), contains, "{domain}");
    }
    let unicode = rule("DOMAIN-SUFFIX", "é.example");
    assert!(matches(&unicode, "a.é.EXAMPLE"));
    assert!(!matches(&unicode, "aé.example"));
}

#[test]
fn test_domain_rules_reject_invalid_destinations() {
    for rule in [
        rule("DOMAIN", "example.com"),
        rule("DOMAIN-SUFFIX", "example.com"),
        rule("DOMAIN-KEYWORD", "example"),
        rule("DOMAIN-REGEX", ".*"),
    ] {
        for domain in ["", ".example.com", "a..example.com", "example.com."] {
            assert!(!matches(&rule, domain), "{}: {domain:?}", rule.type_name());
        }
        assert!(!rule.apply(&Session::default()));
    }
    let empty_keyword = DomainKeyword {
        keyword: String::new(), target: "DIRECT".to_owned(),
    };
    assert!(!empty_keyword.apply(&Session {
        destination: SocksAddr::Domain("example.com".into(), 443),
        ..Default::default()
    }));
}

#[test]
fn test_domain_regex_preserves_case_flags() {
    let sensitive = rule("DOMAIN-REGEX", r"^UPPER\.example$");
    let insensitive = rule("DOMAIN-REGEX", r"(?i)^UPPER\.example$");
    assert!(matches(&sensitive, "UPPER.example"));
    assert!(!matches(&sensitive, "upper.example"));
    assert!(matches(&insensitive, "upper.EXAMPLE"));
}

#[test]
fn test_domain_typed_rules_validate_payloads() {
    for rule in [
        RuleType::Domain { domain: String::new(), target: "DIRECT".to_owned() },
        RuleType::DomainSuffix {
            domain_suffix: "a..example".to_owned(), target: "DIRECT".to_owned(),
        },
        RuleType::DomainKeyword {
            domain_keyword: String::new(), target: "DIRECT".to_owned(),
        },
    ] {
        assert!(map_rule_type(rule, None, None, None).is_err());
    }
}
