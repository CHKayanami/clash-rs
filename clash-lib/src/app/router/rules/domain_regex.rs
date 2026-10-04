use crate::{
    app::router::rules::{RuleMatcher, matching_domain},
    session::Session,
};

#[derive(Clone)]
pub struct DomainRegex {
    pub regex: regex::Regex,
    pub target: String,
}

impl std::fmt::Display for DomainRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} regex {}", self.target, self.regex)
    }
}

impl RuleMatcher for DomainRegex {
    fn apply(&self, sess: &Session) -> bool {
        matching_domain(sess).is_some_and(|domain| self.regex.is_match(domain))
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.regex.to_string()
    }

    fn type_name(&self) -> &str {
        "DomainRegex"
    }
}
