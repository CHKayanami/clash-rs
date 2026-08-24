use crate::{
    app::{
        remote_content_manager::providers::rule_provider::ThreadSafeRuleProvider,
        router::rules::RuleMatcher,
    },
    session::Session,
};

#[derive(Clone)]
pub struct RuleSet {
    pub rule_set: String,
    pub target: String,
    pub rule_provider: ThreadSafeRuleProvider,
    pub no_resolve: bool,
}

impl RuleSet {
    pub fn new(
        rule_set: String,
        target: String,
        rule_provider: ThreadSafeRuleProvider,
        no_resolve: bool,
    ) -> Self {
        Self {
            rule_set,
            target,
            rule_provider,
            no_resolve,
        }
    }
}

impl std::fmt::Display for RuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} rule-set {}", self.target, self.rule_set)
    }
}

impl RuleMatcher for RuleSet {
    fn apply(&self, sess: &Session) -> bool {
        self.rule_provider.search(sess)
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn should_resolve_ip(&self) -> bool {
        if self.no_resolve {
            false
        } else {
            self.rule_provider.should_resolve_ip()
        }
    }

    fn should_resolve_process(&self) -> bool {
        self.rule_provider.should_resolve_process()
    }

    fn size(&self) -> u16 {
        self.rule_provider.count().try_into().unwrap_or(u16::MAX)
    }

    fn payload(&self) -> String {
        self.rule_set.clone()
    }

    fn type_name(&self) -> &str {
        "RuleSet"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::remote_content_manager::providers::rule_provider::{
        RuleProviderImpl, RuleSetBehavior, RuleSetFormat,
    };
    use std::sync::Arc;

    #[tokio::test]
    async fn test_ruleset_no_resolve() {
        let provider = Arc::new(RuleProviderImpl::new(
            "ip_rules".to_string(),
            RuleSetBehavior::Ipcidr,
            RuleSetFormat::Text,
            None,
            None,
            None,
            None,
            Some(vec!["1.1.1.1/32".to_owned()]),
        )) as ThreadSafeRuleProvider;
        provider.initialize().await.unwrap();

        // Default: should resolve IP
        let ruleset = RuleSet::new("ip_rules".to_string(), "DIRECT".to_string(), provider.clone(), false);
        assert!(ruleset.should_resolve_ip());

        // With no_resolve = true: should NOT resolve IP
        let ruleset_no_resolve = RuleSet::new("ip_rules".to_string(), "DIRECT".to_string(), provider, true);
        assert!(!ruleset_no_resolve.should_resolve_ip());
    }
}

