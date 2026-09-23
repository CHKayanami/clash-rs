use crate::{Error, print_and_exit};
use std::{fmt::Display, str::FromStr};

#[derive(Clone)]
pub enum RuleType {
    Domain {
        domain: String,
        target: String,
    },
    DomainSuffix {
        domain_suffix: String,
        target: String,
    },
    DomainRegex {
        regex: regex::Regex,
        target: String,
    },
    DomainKeyword {
        domain_keyword: String,
        target: String,
    },
    GeoIP {
        target: String,
        country_code: String,
        no_resolve: bool,
    },
    GeoSite {
        target: String,
        country_code: String,
    },
    IpCidr {
        ipnet: ipnet::IpNet,
        target: String,
        no_resolve: bool,
    },
    SrcCidr {
        ipnet: ipnet::IpNet,
        target: String,
        no_resolve: bool,
    },
    SRCPort {
        target: String,
        port: u16,
    },
    DSTPort {
        target: String,
        port: u16,
    },
    ProcessName {
        process_name: String,
        target: String,
    },
    ProcessPath {
        process_path: String,
        target: String,
    },
    RuleSet {
        rule_set: String,
        target: String,
        no_resolve: bool,
    },
    Match {
        target: String,
    },
    Network {
        network: crate::session::Network,
        target: String,
    },
    Composite {
        operator: String,
        expression: String,
        target: String,
    },
}

impl RuleType {
    pub fn target(&self) -> &str {
        match self {
            RuleType::Domain { target, .. } => target,
            RuleType::DomainSuffix { target, .. } => target,
            RuleType::DomainRegex { target, .. } => target,
            RuleType::DomainKeyword { target, .. } => target,
            RuleType::GeoIP { target, .. } => target,
            RuleType::GeoSite { target, .. } => target,
            RuleType::IpCidr { target, .. } => target,
            RuleType::SrcCidr { target, .. } => target,
            RuleType::SRCPort { target, .. } => target,
            RuleType::DSTPort { target, .. } => target,
            RuleType::ProcessName { target, .. } => target,
            RuleType::ProcessPath { target, .. } => target,
            RuleType::RuleSet { target, .. } => target,
            RuleType::Match { target } => target,
            RuleType::Network { target, .. } => target,
            RuleType::Composite { target, .. } => target,
        }
    }
}

impl Display for RuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleType::Domain { domain, target } => {
                write!(f, "DOMAIN,{domain},{target}")
            }
            RuleType::DomainRegex { regex, target } => {
                write!(f, "DOMAIN-REGEX,{regex},{target}")
            }
            RuleType::DomainSuffix { .. } => write!(f, "DOMAIN-SUFFIX"),
            RuleType::DomainKeyword { .. } => write!(f, "DOMAIN-KEYWORD"),
            RuleType::GeoIP { .. } => write!(f, "GEOIP"),
            RuleType::GeoSite { .. } => write!(f, "GEOSITE"),
            RuleType::IpCidr { .. } => write!(f, "IP-CIDR"),
            RuleType::SrcCidr { .. } => write!(f, "SRC-IP-CIDR"),
            RuleType::SRCPort { .. } => write!(f, "SRC-PORT"),
            RuleType::DSTPort { .. } => write!(f, "DST-PORT"),
            RuleType::ProcessName { .. } => write!(f, "PROCESS-NAME"),
            RuleType::ProcessPath { .. } => write!(f, "PROCESS-PATH"),
            RuleType::RuleSet { .. } => write!(f, "RULE-SET"),
            RuleType::Match { .. } => write!(f, "MATCH"),
            RuleType::Network { .. } => write!(f, "NETWORK"),
            RuleType::Composite { .. } => write!(f, "COMPOSITE"),
        }
    }
}

impl RuleType {
    pub fn new(
        proto: &str,
        payload: &str,
        target: &str,
        params: Option<Vec<&str>>,
    ) -> Result<Self, Error> {
        let no_resolve = params
            .as_ref()
            .map_or(false, |p| p.iter().any(|s| s.eq_ignore_ascii_case("no-resolve")));

        let proto_upper = proto.to_ascii_uppercase();

        match proto_upper.as_str() {
            "DOMAIN" => Ok(RuleType::Domain {
                domain: payload.to_string(),
                target: target.to_string(),
            }),
            "DOMAIN-REGEX" => Ok(RuleType::DomainRegex {
                regex: regex::Regex::new(payload)
                    .map_err(|e| Error::InvalidConfig(e.to_string()))?,
                target: target.to_string(),
            }),
            "DOMAIN-SUFFIX" => Ok(RuleType::DomainSuffix {
                domain_suffix: payload.to_string(),
                target: target.to_string(),
            }),
            "DOMAIN-KEYWORD" => Ok(RuleType::DomainKeyword {
                domain_keyword: payload.to_string(),
                target: target.to_string(),
            }),
            "GEOSITE" => Ok(RuleType::GeoSite {
                target: target.to_string(),
                country_code: payload.to_string(),
            }),
            "GEOIP" => Ok(RuleType::GeoIP {
                target: target.to_string(),
                country_code: payload.to_string(),
                no_resolve,
            }),
            "IP-CIDR" | "IP-CIDR6" => Ok(RuleType::IpCidr {
                ipnet: payload.parse()?,
                target: target.to_string(),
                no_resolve,
            }),
            "SRC-IP-CIDR" => Ok(RuleType::SrcCidr {
                ipnet: payload.parse()?,
                target: target.to_string(),
                no_resolve,
            }),
            "SRC-PORT" => Ok(RuleType::SRCPort {
                target: target.to_string(),
                port: payload.parse().unwrap_or_else(|_| {
                    print_and_exit!("invalid port: {}", payload)
                }),
            }),
            "DST-PORT" => Ok(RuleType::DSTPort {
                target: target.to_string(),
                port: payload.parse().unwrap_or_else(|_| {
                    print_and_exit!("invalid port: {}", payload)
                }),
            }),
            "PROCESS-NAME" => Ok(RuleType::ProcessName {
                process_name: payload.to_string(),
                target: target.to_string(),
            }),
            "PROCESS-PATH" => Ok(RuleType::ProcessPath {
                process_path: payload.to_string(),
                target: target.to_string(),
            }),
            "RULE-SET" => Ok(RuleType::RuleSet {
                rule_set: payload.to_string(),
                target: target.to_string(),
                no_resolve,
            }),
            "MATCH" => Ok(RuleType::Match {
                target: target.to_string(),
            }),
            "NETWORK" => {
                let network = match payload {
                    "TCP" | "tcp" => crate::session::Network::Tcp,
                    "UDP" | "udp" => crate::session::Network::Udp,
                    _ => {
                        return Err(Error::InvalidConfig(format!(
                            "invalid network type: {}, expected TCP or UDP",
                            payload
                        )));
                    }
                };
                Ok(RuleType::Network {
                    network,
                    target: target.to_string(),
                })
            }
            "AND" | "OR" | "NOT" => Ok(RuleType::Composite {
                operator: proto_upper,
                expression: payload.to_string(),
                target: target.to_string(),
            }),

            _ => Err(Error::InvalidConfig(format!(
                "unsupported rule type: {proto}"
            ))),
        }
    }
}

pub const RULE_PARAMS: &[&str] = &["no-resolve"];

pub fn proto_supports_params(proto: &str) -> bool {
    matches!(
        proto.to_ascii_uppercase().as_str(),
        "GEOIP" | "IP-CIDR" | "IP-CIDR6" | "SRC-IP-CIDR" | "RULE-SET"
    )
}

impl TryFrom<String> for RuleType {
    type Error = crate::Error;

    fn try_from(line: String) -> Result<Self, Self::Error> {
        let first_comma = line.find(',').ok_or_else(|| {
            Error::InvalidConfig(format!("invalid rule line (no comma): {line}"))
        })?;

        let proto = line[..first_comma].trim();

        // 1. Check if this is a composite rule: OPERATOR,((expression)),TARGET
        // Composite rules must start with AND, OR, or NOT followed by a comma
        if proto.eq_ignore_ascii_case("AND")
            || proto.eq_ignore_ascii_case("OR")
            || proto.eq_ignore_ascii_case("NOT")
        {
            let last_comma = line.rfind(',').ok_or_else(|| {
                Error::InvalidConfig(format!("invalid rule line (no comma): {line}"))
            })?;

            if first_comma == last_comma {
                return Err(Error::InvalidConfig(format!(
                    "composite rule needs at least 2 commas: {line}"
                )));
            }

            let operator = proto.to_ascii_uppercase();
            let expression = line[first_comma + 1..last_comma].trim();
            let target = line[last_comma + 1..].trim();

            return Ok(RuleType::Composite {
                operator,
                expression: expression.to_string(),
                target: target.to_string(),
            });
        }

        // 2. Check if this is MATCH rule: MATCH,TARGET
        if proto.eq_ignore_ascii_case("MATCH") {
            let target = line[first_comma + 1..].trim();
            return RuleType::new("MATCH", "", target, None);
        }

        // 3. For other rules: PROTO,PAYLOAD,TARGET[,PARAMS...]
        // We recognize PROTO from the left, and PARAMS/TARGET from the right,
        // preserving any commas inside PAYLOAD (such as in regular expressions).
        let mut rest = line[first_comma + 1..].trim();
        let mut params = Vec::new();

        // Only protocols that actually support trailing parameters (e.g. no-resolve)
        // should extract params from the right. Additionally, there must be at least 2
        // commas in `rest` (meaning total rule has >= 4 parts: PROTO,PAYLOAD,TARGET,PARAMS...),
        // so that for a 3-part rule like `IP-CIDR,192.168.1.0/24,no-resolve`, `no-resolve`
        // is properly recognized as the TARGET rather than a param with missing target.
        if proto_supports_params(proto) {
            while rest.matches(',').count() >= 2 {
                if let Some(comma) = rest.rfind(',') {
                    let candidate = rest[comma + 1..].trim();
                    if RULE_PARAMS.iter().any(|&p| p.eq_ignore_ascii_case(candidate)) {
                        params.push(candidate);
                        rest = rest[..comma].trim_end();
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            params.reverse();
        }

        // The last comma in remaining `rest` separates PAYLOAD and TARGET
        let last_comma = rest.rfind(',').ok_or_else(|| {
            Error::InvalidConfig(format!(
                "rule '{proto}' requires at least payload and target: {line}"
            ))
        })?;

        let payload = rest[..last_comma].trim();
        let target = rest[last_comma + 1..].trim();

        let params_opt = if params.is_empty() { None } else { Some(params) };
        RuleType::new(proto, payload, target, params_opt)
    }
}

impl FromStr for RuleType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_string().try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_regex_with_parentheses() {
        let rule = RuleType::try_from("DOMAIN-REGEX,^foo(bar)\\.com$,PROXY".to_string()).unwrap();
        match rule {
            RuleType::DomainRegex { regex, target } => {
                assert_eq!(target, "PROXY");
                assert!(regex.is_match("foobar.com"));
                assert!(!regex.is_match("foo.com"));
            }
            _ => panic!("Expected DomainRegex rule"),
        }
    }

    #[test]
    fn test_domain_regex_with_commas() {
        let rule = RuleType::try_from("DOMAIN-REGEX,^foo,bar$,PROXY".to_string()).unwrap();
        match rule {
            RuleType::DomainRegex { regex, target } => {
                assert_eq!(target, "PROXY");
                assert!(regex.is_match("foo,bar"));
                assert!(!regex.is_match("foo"));
            }
            _ => panic!("Expected DomainRegex rule"),
        }

        // Quantifier with comma
        let rule = RuleType::try_from("DOMAIN-REGEX,^a{1,3}$,PROXY".to_string()).unwrap();
        match rule {
            RuleType::DomainRegex { regex, target } => {
                assert_eq!(target, "PROXY");
                assert!(regex.is_match("aa"));
                assert!(!regex.is_match("aaaa"));
            }
            _ => panic!("Expected DomainRegex rule"),
        }
    }

    #[test]
    fn test_lowercase_composite_rule_parsing() {
        let rule = RuleType::try_from("and,((DOMAIN,example.com)),PROXY".to_string()).unwrap();
        match rule {
            RuleType::Composite { operator, expression, target } => {
                assert_eq!(operator, "AND");
                assert_eq!(expression, "((DOMAIN,example.com))");
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Composite rule"),
        }
    }

    #[test]
    fn test_composite_rule_parsing() {
        let rule = RuleType::try_from("AND,((DOMAIN,example.com),(NETWORK,TCP)),PROXY".to_string()).unwrap();
        match rule {
            RuleType::Composite { operator, expression, target } => {
                assert_eq!(operator, "AND");
                assert_eq!(expression, "((DOMAIN,example.com),(NETWORK,TCP))");
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Composite rule"),
        }

        let rule = RuleType::try_from("NOT,((DOMAIN,example.com)),DIRECT".to_string()).unwrap();
        match rule {
            RuleType::Composite { operator, expression, target } => {
                assert_eq!(operator, "NOT");
                assert_eq!(expression, "((DOMAIN,example.com))");
                assert_eq!(target, "DIRECT");
            }
            _ => panic!("Expected Composite rule"),
        }
    }

    #[test]
    fn test_network_rule_parsing() {
        // Test TCP network rule
        let rule = RuleType::try_from("NETWORK,TCP,PROXY".to_string()).unwrap();
        match rule {
            RuleType::Network { network, target } => {
                assert_eq!(network, crate::session::Network::Tcp);
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Network rule"),
        }

        // Test UDP network rule
        let rule = RuleType::try_from("NETWORK,UDP,PROXY".to_string()).unwrap();
        match rule {
            RuleType::Network { network, target } => {
                assert_eq!(network, crate::session::Network::Udp);
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Network rule"),
        }

        // Test lowercase network types
        let rule = RuleType::try_from("NETWORK,tcp,PROXY".to_string()).unwrap();
        match rule {
            RuleType::Network { network, target } => {
                assert_eq!(network, crate::session::Network::Tcp);
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Network rule"),
        }

        // Test invalid network type
        let rule = RuleType::try_from("NETWORK,INVALID,PROXY".to_string());
        assert!(rule.is_err());

        // Test RULE-SET without no-resolve
        let rule = RuleType::try_from("RULE-SET,my-rules,PROXY".to_string()).unwrap();
        match rule {
            RuleType::RuleSet {
                rule_set,
                target,
                no_resolve,
            } => {
                assert_eq!(rule_set, "my-rules");
                assert_eq!(target, "PROXY");
                assert!(!no_resolve);
            }
            _ => panic!("Expected RuleSet rule"),
        }

        // Test RULE-SET with no-resolve
        let rule = RuleType::try_from("RULE-SET,my-rules,PROXY,no-resolve".to_string()).unwrap();
        match rule {
            RuleType::RuleSet {
                rule_set,
                target,
                no_resolve,
            } => {
                assert_eq!(rule_set, "my-rules");
                assert_eq!(target, "PROXY");
                assert!(no_resolve);
            }
            _ => panic!("Expected RuleSet rule"),
        }
    }

    #[test]
    fn test_no_resolve_case_insensitivity() {
        // Uppercase NO-RESOLVE in IP-CIDR
        let rule = RuleType::try_from("IP-CIDR,192.168.1.0/24,DIRECT,NO-RESOLVE".to_string()).unwrap();
        match rule {
            RuleType::IpCidr { no_resolve, target, .. } => {
                assert_eq!(target, "DIRECT");
                assert!(no_resolve, "Uppercase NO-RESOLVE should be set to true");
            }
            _ => panic!("Expected IpCidr rule"),
        }

        // Mixed case No-Resolve in RULE-SET
        let rule = RuleType::try_from("RULE-SET,my-rules,PROXY,No-Resolve".to_string()).unwrap();
        match rule {
            RuleType::RuleSet { no_resolve, target, .. } => {
                assert_eq!(target, "PROXY");
                assert!(no_resolve, "Mixed case No-Resolve should be set to true");
            }
            _ => panic!("Expected RuleSet rule"),
        }

        // Uppercase NO-RESOLVE in GEOIP
        let rule = RuleType::try_from("GEOIP,CN,DIRECT,NO-RESOLVE".to_string()).unwrap();
        match rule {
            RuleType::GeoIP { no_resolve, target, .. } => {
                assert_eq!(target, "DIRECT");
                assert!(no_resolve, "Uppercase NO-RESOLVE should be set to true");
            }
            _ => panic!("Expected GeoIP rule"),
        }
    }

    #[test]
    fn test_target_named_no_resolve() {
        // 1. Protocols that do not support trailing parameters (e.g. DOMAIN, DOMAIN-REGEX, PROCESS-NAME)
        // should always treat 'no-resolve' as target.
        let rule = RuleType::try_from("DOMAIN,example.com,no-resolve".to_string()).unwrap();
        match rule {
            RuleType::Domain { domain, target } => {
                assert_eq!(domain, "example.com");
                assert_eq!(target, "no-resolve");
            }
            _ => panic!("Expected Domain rule"),
        }

        let rule = RuleType::try_from("DOMAIN-REGEX,^foo,bar$,no-resolve".to_string()).unwrap();
        match rule {
            RuleType::DomainRegex { regex, target } => {
                assert_eq!(target, "no-resolve");
                assert!(regex.is_match("foo,bar"));
            }
            _ => panic!("Expected DomainRegex rule"),
        }

        // 2. Protocols supporting parameters: 3-part rule should treat 'no-resolve' as target!
        let rule = RuleType::try_from("IP-CIDR,192.168.1.0/24,no-resolve".to_string()).unwrap();
        match rule {
            RuleType::IpCidr { ipnet, target, no_resolve } => {
                assert_eq!(ipnet.to_string(), "192.168.1.0/24");
                assert_eq!(target, "no-resolve");
                assert!(!no_resolve, "3-part rule should have no_resolve=false");
            }
            _ => panic!("Expected IpCidr rule"),
        }

        // 3. Protocols supporting parameters: 4-part rule with target=no-resolve and param=no-resolve
        let rule = RuleType::try_from("IP-CIDR,192.168.1.0/24,no-resolve,no-resolve".to_string()).unwrap();
        match rule {
            RuleType::IpCidr { ipnet, target, no_resolve } => {
                assert_eq!(ipnet.to_string(), "192.168.1.0/24");
                assert_eq!(target, "no-resolve");
                assert!(no_resolve, "4-part rule with trailing no-resolve should have no_resolve=true");
            }
            _ => panic!("Expected IpCidr rule"),
        }

        // 4. RULE-SET with target no-resolve
        let rule = RuleType::try_from("RULE-SET,my-rules,no-resolve".to_string()).unwrap();
        match rule {
            RuleType::RuleSet { rule_set, target, no_resolve } => {
                assert_eq!(rule_set, "my-rules");
                assert_eq!(target, "no-resolve");
                assert!(!no_resolve);
            }
            _ => panic!("Expected RuleSet rule"),
        }
    }

    #[test]
    fn test_match_rule_case_insensitivity() {
        let rule = RuleType::try_from("match,DIRECT".to_string()).unwrap();
        match rule {
            RuleType::Match { target } => {
                assert_eq!(target, "DIRECT");
            }
            _ => panic!("Expected Match rule"),
        }

        let rule = RuleType::try_from("Match,PROXY".to_string()).unwrap();
        match rule {
            RuleType::Match { target } => {
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Match rule"),
        }
    }
}
