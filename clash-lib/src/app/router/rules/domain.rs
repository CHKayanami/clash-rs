use crate::session;

use super::{RuleMatcher, matching_domain};

#[derive(Clone)]
pub struct Domain {
    pub domain: String,
    pub target: String,
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} domain {}", self.target, self.domain)
    }
}

impl RuleMatcher for Domain {
    fn apply(&self, sess: &session::Session) -> bool {
        matching_domain(sess).is_some_and(|domain| {
            self.domain.eq_ignore_ascii_case(domain)
        })
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.domain.clone()
    }

    fn type_name(&self) -> &str {
        "Domain"
    }
}
