use std::collections::HashMap;
use std::net::IpAddr;

use tracing::debug;

use crate::app::dns::query::QType;
use crate::app::remote_content_manager::providers::rule_provider::ThreadSafeRuleProvider;

use super::config::{
    RequestAction, RequestRule, ResponseAction, ResponseRule, RouterConfig,
};
use super::matcher::{
    DomainMatcher, IpNetMatcher, QTypeMatcher, RuleSetMatcher,
};

#[derive(Clone)]
pub struct CompiledRequestRule {
    domain: DomainMatcher,
    rule_set: RuleSetMatcher,
    query_type: QTypeMatcher,
    source_ip: IpNetMatcher,
    action: RequestAction,
    invert: bool,
    has_domain: bool,
    has_rule_set: bool,
    has_query_type: bool,
    has_source_ip: bool,
}

impl CompiledRequestRule {
    pub fn new(rule: &RequestRule) -> Self {
        Self {
            has_domain: !rule.domain.is_empty(),
            domain: DomainMatcher::new(&rule.domain),
            has_rule_set: !rule.rule_set.is_empty(),
            rule_set: RuleSetMatcher::new(&rule.rule_set),
            has_query_type: !rule.query_type.is_empty(),
            query_type: QTypeMatcher::new(rule.query_type.clone()),
            has_source_ip: !rule.source_ip_cidr.is_empty(),
            source_ip: IpNetMatcher::new(rule.source_ip_cidr.clone()),
            action: rule.action.clone(),
            invert: rule.invert,
        }
    }

    fn matches_domain(&self, domain: &str) -> bool {
        (self.has_domain && self.domain.matches(domain))
            || (self.has_rule_set && self.rule_set.matches_domain(domain))
    }

    fn matches_source_ip(&self, source_ip: Option<IpAddr>) -> bool {
        match source_ip {
            Some(ip) => self.source_ip.matches(&ip),
            None => false,
        }
    }

    pub fn matches(&self, domain: &str, qtype: QType, source_ip: Option<IpAddr>) -> bool {
        // 1. 无任何匹配条件的空规则不生效
        if !self.has_domain && !self.has_rule_set && !self.has_query_type && !self.has_source_ip {
            return false;
        }

        // 2. 域名检查：配置了 domain 或 rule-set，但均未命中
        if (self.has_domain || self.has_rule_set) && !self.matches_domain(domain) {
            return self.invert;
        }

        // 3. 查询类型检查：配置了 query-type，但未匹配
        if self.has_query_type && !self.query_type.matches(qtype) {
            return self.invert;
        }

        // 4. 客户端源 IP 检查：配置了 source-ip，但未匹配
        if self.has_source_ip && !self.matches_source_ip(source_ip) {
            return self.invert;
        }

        !self.invert
    }

    pub fn action(&self) -> &RequestAction {
        &self.action
    }
}

#[derive(Clone)]
pub struct CompiledResponseRule {
    from_upstream: Option<String>,
    domain: DomainMatcher,
    rule_set: RuleSetMatcher,
    query_type: QTypeMatcher,
    ip_cidr: IpNetMatcher,
    action: ResponseAction,
    invert: bool,
    has_domain: bool,
    has_rule_set: bool,
    has_query_type: bool,
    has_ip_cidr: bool,
}

impl CompiledResponseRule {
    pub fn new(rule: &ResponseRule) -> Self {
        Self {
            from_upstream: rule.from_upstream.clone(),
            has_domain: !rule.domain.is_empty(),
            domain: DomainMatcher::new(&rule.domain),
            has_rule_set: !rule.rule_set.is_empty(),
            rule_set: RuleSetMatcher::new(&rule.rule_set),
            has_query_type: !rule.query_type.is_empty(),
            query_type: QTypeMatcher::new(rule.query_type.clone()),
            has_ip_cidr: !rule.ip_cidr.is_empty(),
            ip_cidr: IpNetMatcher::new(rule.ip_cidr.clone()),
            action: rule.action.clone(),
            invert: rule.invert,
        }
    }

    fn matches_ip(&self, ip: &IpAddr) -> bool {
        (self.has_ip_cidr && self.ip_cidr.matches(ip))
            || (self.has_rule_set && self.rule_set.matches_ip(ip))
    }

    pub fn matches(
        &self,
        from_upstream: &str,
        domain: &str,
        qtype: QType,
        answer_ips: &[IpAddr],
    ) -> bool {
        // 1. 无任何匹配条件的空规则不生效
        if self.from_upstream.is_none()
            && !self.has_domain
            && !self.has_query_type
            && !self.has_ip_cidr
            && !self.has_rule_set
        {
            return false;
        }

        // 2. 来源上游检查
        if let Some(ref expected) = self.from_upstream {
            if expected != from_upstream {
                return false;
            }
        }

        // 3. 域名检查
        if self.has_domain && !self.domain.matches(domain) {
            return self.invert;
        }

        // 4. 查询类型检查
        if self.has_query_type && !self.query_type.matches(qtype) {
            return self.invert;
        }

        // 5. 响应 IP / 归属规则集检查 (无 IP 可供判定时直接不匹配；有 IP 时若均不匹配则返回 self.invert)
        if self.has_ip_cidr || self.has_rule_set {
            if answer_ips.is_empty() {
                return false;
            }
            if !answer_ips.iter().any(|ip| self.matches_ip(ip)) {
                return self.invert;
            }
        }

        !self.invert
    }

    pub fn action(&self) -> &ResponseAction {
        &self.action
    }
}

#[derive(Clone)]
pub struct DnsRouter {
    request_rules: Vec<CompiledRequestRule>,
    request_fallback: RequestAction,
    response_rules: Vec<CompiledResponseRule>,
    response_fallback: ResponseAction,
}

impl DnsRouter {
    pub fn new(cfg: &RouterConfig) -> Self {
        let request_rules = cfg.request_rules.iter().map(CompiledRequestRule::new).collect();
        let response_rules = cfg
            .response_rules
            .iter()
            .map(CompiledResponseRule::new)
            .collect();

        Self {
            request_rules,
            request_fallback: cfg.request_fallback.clone(),
            response_rules,
            response_fallback: cfg.response_fallback.clone(),
        }
    }

    pub fn bind_rule_providers(&self, map: &HashMap<String, ThreadSafeRuleProvider>) {
        for rule in &self.request_rules {
            rule.rule_set.bind_providers(map);
        }
        for rule in &self.response_rules {
            rule.rule_set.bind_providers(map);
        }
    }

    pub fn route_request(
        &self,
        domain: &str,
        qtype: QType,
        source_ip: Option<IpAddr>,
    ) -> &RequestAction {
        for rule in &self.request_rules {
            if rule.matches(domain, qtype, source_ip) {
                debug!(domain, ?qtype, action = ?rule.action(), "matched request rule");
                return rule.action();
            }
        }
        debug!(domain, ?qtype, action = ?self.request_fallback, "using request fallback");
        &self.request_fallback
    }

    pub fn route_response(
        &self,
        from_upstream: &str,
        domain: &str,
        qtype: QType,
        answer_ips: &[IpAddr],
    ) -> &ResponseAction {
        for rule in &self.response_rules {
            if rule.matches(from_upstream, domain, qtype, answer_ips) {
                debug!(
                    from_upstream,
                    domain,
                    ?qtype,
                    action = ?rule.action(),
                    "matched response rule"
                );
                return rule.action();
            }
        }
        &self.response_fallback
    }
}
