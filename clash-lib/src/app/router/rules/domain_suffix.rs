use crate::{
    app::router::rules::{RuleMatcher, ends_with_ignore_ascii_case},
    session::{Session, SocksAddr},
};

#[derive(Clone)]
pub struct DomainSuffix {
    pub suffix: String,
    pub target: String,
}

impl std::fmt::Display for DomainSuffix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} suffix {}", self.target, self.suffix)
    }
}

impl RuleMatcher for DomainSuffix {
    fn apply(&self, sess: &Session) -> bool {
        match &sess.destination {
            SocksAddr::Ip(_) => false,
            SocksAddr::Domain(domain, _) => {
                if domain.eq_ignore_ascii_case(&self.suffix) {
                    true
                } else if domain.len() > self.suffix.len() {
                    let index = domain.len() - self.suffix.len() - 1;
                    domain.as_bytes()[index] == b'.'
                        && ends_with_ignore_ascii_case(domain, &self.suffix)
                } else {
                    false
                }
            }
        }
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.suffix.clone()
    }

    fn type_name(&self) -> &str {
        "DomainSuffix"
    }
}
