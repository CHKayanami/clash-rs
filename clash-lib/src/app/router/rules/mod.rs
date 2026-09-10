use enum_dispatch::enum_dispatch;
use erased_serde::Serialize;
use std::{collections::HashMap, fmt::Display};

use crate::session::Session;

pub mod composite;
pub mod domain;
pub mod domain_keyword;
pub mod domain_regex;
pub mod domain_suffix;
pub mod final_;
pub mod geodata;
pub mod geoip;
pub mod ipcidr;
pub mod network;
pub mod port;
pub mod process;
pub mod ruleset;

/// ASCII case-insensitive `str::contains`, without allocating.
///
/// Hostnames are case-insensitive, but nothing normalizes the destination on
/// the way in — a client is free to send `Example.COM`.
pub(crate) fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// ASCII case-insensitive `str::ends_with`, without allocating.
pub(crate) fn ends_with_ignore_ascii_case(haystack: &str, suffix: &str) -> bool {
    let (haystack, suffix) = (haystack.as_bytes(), suffix.as_bytes());
    haystack.len() >= suffix.len()
        && haystack[haystack.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

#[enum_dispatch]
pub trait RuleMatcher: Send + Sync + Unpin + Display {
    /// check if the rule should apply to the session
    fn apply(&self, sess: &Session) -> bool;

    /// the Proxy to use
    fn target(&self) -> &str;

    /// the actual content of the rule
    fn payload(&self) -> String;

    /// the type of the rule
    fn type_name(&self) -> &str;

    fn should_resolve_ip(&self) -> bool {
        false
    }

    /// whether the rule needs [`Session::process_name`] to be populated before
    /// [`RuleMatcher::apply`] is called
    fn should_resolve_process(&self) -> bool {
        false
    }

    fn size(&self) -> u16 {
        0
    }

    fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let mut m: HashMap<String, Box<dyn Serialize + Send>> = HashMap::new();
        m.insert("type".to_string(), Box::new(self.type_name().to_owned()));
        m.insert("proxy".to_string(), Box::new(self.target().to_owned()));
        m.insert("payload".to_string(), Box::new(self.payload()));
        m.insert("size".to_string(), Box::new(self.size()));
        m
    }
}

#[enum_dispatch(RuleMatcher)]
pub enum Rule {
    Domain(domain::Domain),
    DomainRegex(domain_regex::DomainRegex),
    DomainSuffix(domain_suffix::DomainSuffix),
    DomainKeyword(domain_keyword::DomainKeyword),
    IpCidr(ipcidr::IpCidr),
    GeoIP(geoip::GeoIP),
    GeoSite(geodata::GeoSiteMatcher),
    Port(port::Port),
    Process(process::Process),
    RuleSet(ruleset::RuleSet),
    Network(network::NetworkRule),
    Composite(composite::CompositeRule),
    Final(final_::Final),
}

impl Display for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(r) => write!(f, "{r}"),
            Self::DomainRegex(r) => write!(f, "{r}"),
            Self::DomainSuffix(r) => write!(f, "{r}"),
            Self::DomainKeyword(r) => write!(f, "{r}"),
            Self::IpCidr(r) => write!(f, "{r}"),
            Self::GeoIP(r) => write!(f, "{r}"),
            Self::GeoSite(r) => write!(f, "{r}"),
            Self::Port(r) => write!(f, "{r}"),
            Self::Process(r) => write!(f, "{r}"),
            Self::RuleSet(r) => write!(f, "{r}"),
            Self::Network(r) => write!(f, "{r}"),
            Self::Composite(r) => write!(f, "{r}"),
            Self::Final(r) => write!(f, "{r}"),
        }
    }
}
