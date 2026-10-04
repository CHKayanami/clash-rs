use regex::Regex;

use crate::{Error, app::router::rules::contains_ignore_ascii_case};

pub enum StringMatcher {
    Keyword(String),
    Regex(Regex),
}

impl StringMatcher {
    pub fn keyword(value: String) -> Result<Self, Error> {
        if value.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "geosite keyword must not be empty".to_owned(),
            ));
        }
        Ok(Self::Keyword(value))
    }

    pub fn regex(pattern: &str) -> Result<Self, Error> {
        if pattern.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "geosite regex must not be empty".to_owned(),
            ));
        }
        Regex::new(pattern).map(Self::Regex).map_err(|error| {
            Error::InvalidConfig(format!("invalid geosite regex: {error}"))
        })
    }

    pub fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Keyword(keyword) => contains_ignore_ascii_case(domain, keyword),
            Self::Regex(regex) => regex.is_match(domain),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StringMatcher;

    #[test]
    fn test_keyword_and_regex_semantics() {
        let keyword = StringMatcher::keyword("EXAMPLE".to_owned()).unwrap();
        assert!(keyword.matches("www.example.com"));
        assert!(keyword.matches("WWW.EXAMPLE.COM"));
        assert!(!keyword.matches("other.com"));
        let regex = StringMatcher::regex(r"^UPPER\.example$").unwrap();
        assert!(regex.matches("UPPER.example"));
        assert!(!regex.matches("upper.example"));
        let regex = StringMatcher::regex(r"(?i)^UPPER\.example$").unwrap();
        assert!(regex.matches("upper.EXAMPLE"));
        for value in ["", " "] {
            assert!(StringMatcher::keyword(value.to_owned()).is_err());
            assert!(StringMatcher::regex(value).is_err());
        }
        assert!(StringMatcher::regex("[").is_err());
    }
}
