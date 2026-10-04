use std::fmt::Display;

use crate::session;

use super::{RuleMatcher, contains_ignore_ascii_case, matching_domain};

#[derive(Clone)]
pub struct DomainKeyword {
    pub keyword: String,
    pub target: String,
}

impl Display for DomainKeyword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} keyword {}", self.target, self.keyword)
    }
}

impl RuleMatcher for DomainKeyword {
    fn apply(&self, sess: &session::Session) -> bool {
        !self.keyword.is_empty() && matching_domain(sess).is_some_and(|domain| {
            contains_ignore_ascii_case(domain, &self.keyword)
        })
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.keyword.to_owned()
    }

    fn type_name(&self) -> &str {
        "DomainKeyword"
    }
}
