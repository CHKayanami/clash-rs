use std::collections::HashMap;
use tracing::warn;

use crate::app::router::ThreadSafeRuleProvider;

/// Check if an IP is in the standard reserved/loopback/broadcast range.
pub fn is_reserved_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4 (multicast), 255.255.255.255
            octets[0] == 0
                || octets[0] == 127
                || (octets[0] == 169 && octets[1] == 254)
                || (octets[0] >= 224 && octets[0] <= 239)
                || octets == [255, 255, 255, 255]
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// Resolves raw IP/CIDR strings and `rule-set:` / `ruleset:` references against rule providers,
/// then performs deduplication and aggregation (merging subnets) using ipnet.
pub fn resolve_and_aggregate_ip_cidrs(
    entries: &[String],
    rule_providers: &HashMap<String, ThreadSafeRuleProvider>,
) -> Vec<String> {
    use std::str::FromStr;

    let mut v4_nets = Vec::new();
    let mut v6_nets = Vec::new();

    for item in entries {
        let s = item.trim();
        if s.is_empty() {
            continue;
        }

        let rs_name_opt = if let Some(name) = s.strip_prefix("rule-set:") {
            Some(name)
        } else if let Some(name) = s.strip_prefix("ruleset:") {
            Some(name)
        } else if let Some(name) = s.strip_prefix("RULE-SET:") {
            Some(name)
        } else if let Some(name) = s.strip_prefix("RULESET:") {
            Some(name)
        } else {
            None
        };

        if let Some(rs_name) = rs_name_opt {
            let rs_name = rs_name.trim();
            if let Some(rp) = rule_providers.get(rs_name) {
                let nets = rp.get_ip_cidrs();
                tracing::info!(
                    "Resolved eBPF ruleset '{}' with {} IP/CIDR entries",
                    rs_name,
                    nets.len()
                );
                for net in nets {
                    match net {
                        ipnet::IpNet::V4(v4) => v4_nets.push(v4),
                        ipnet::IpNet::V6(v6) => v6_nets.push(v6),
                    }
                }
            } else {
                warn!(
                    "eBPF config references rule-set '{}', but it was not found in rule providers",
                    rs_name
                );
            }
        } else if let Ok(net) = ipnet::IpNet::from_str(s) {
            match net {
                ipnet::IpNet::V4(v4) => v4_nets.push(v4),
                ipnet::IpNet::V6(v6) => v6_nets.push(v6),
            }
        } else if let Ok(ip) = std::net::IpAddr::from_str(s) {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    if let Ok(net) = ipnet::Ipv4Net::new(v4, 32) {
                        v4_nets.push(net);
                    }
                }
                std::net::IpAddr::V6(v6) => {
                    if let Ok(net) = ipnet::Ipv6Net::new(v6, 128) {
                        v6_nets.push(net);
                    }
                }
            }
        } else {
            warn!(
                "eBPF config encountered invalid IP/CIDR or ruleset entry: '{}'",
                s
            );
        }
    }

    let merged_v4 = ipnet::Ipv4Net::aggregate(&v4_nets);
    let merged_v6 = ipnet::Ipv6Net::aggregate(&v6_nets);

    let mut result = Vec::with_capacity(merged_v4.len() + merged_v6.len());
    for n in merged_v4 {
        result.push(n.to_string());
    }
    for n in merged_v6 {
        result.push(n.to_string());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::app::remote_content_manager::providers::{
        rule_provider::{CidrTrie, RuleProviderImpl, RuleSetBehavior, RuleSetFormat},
        Provider,
    };
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_resolve_and_aggregate_with_rule_provider() {
        let mut providers = HashMap::new();

        let rp_direct = Arc::new(RuleProviderImpl::new(
            "direct-ips".to_string(),
            RuleSetBehavior::Ipcidr,
            RuleSetFormat::Text,
            None,
            None,
            None,
            None,
            Some(vec![
                "192.168.1.0/24".to_string(),
                "192.168.1.100/32".to_string(),
                "10.0.0.0/24".to_string(),
                "10.0.1.0/24".to_string(),
                "fe80::/10".to_string(),
            ]),
        ));
        let _ = rp_direct.initialize().await;
        providers.insert(
            "direct-ips".to_string(),
            rp_direct as crate::app::router::ThreadSafeRuleProvider,
        );

        let input = vec![
            "10.0.2.0/24".to_string(),
            "10.0.3.0/24".to_string(),
            "rule-set:direct-ips".to_string(),
            "1.1.1.1".to_string(),
            "::1".to_string(),
        ];

        let result = resolve_and_aggregate_ip_cidrs(&input, &providers);

        assert!(result.contains(&"10.0.0.0/22".to_string()));
        assert!(result.contains(&"192.168.1.0/24".to_string()));
        assert!(!result.contains(&"192.168.1.100/32".to_string()));
        assert!(result.contains(&"1.1.1.1/32".to_string()));
        assert!(result.contains(&"::1/128".to_string()));
        assert!(result.contains(&"fe80::/10".to_string()));
    }

    #[tokio::test]
    async fn test_resolve_and_aggregate_missing_provider() {
        let providers = HashMap::new();
        let input = vec![
            "rule-set:non-existent".to_string(),
            "192.168.0.1".to_string(),
        ];

        let result = resolve_and_aggregate_ip_cidrs(&input, &providers);
        assert_eq!(result, vec!["192.168.0.1/32".to_string()]);
    }

    #[test]
    fn test_bypass_dst_trie_filtering() {
        let mut trie = CidrTrie::new();
        trie.insert("192.168.1.0/24");
        trie.insert("10.0.0.0/8");
        trie.insert("fe80::/10");

        let ip_in_1: std::net::IpAddr = "192.168.1.50".parse().unwrap();
        let ip_in_2: std::net::IpAddr = "10.20.30.40".parse().unwrap();
        let ip_in_3: std::net::IpAddr = "fe80::1".parse().unwrap();
        let ip_out_1: std::net::IpAddr = "1.1.1.1".parse().unwrap();
        let ip_out_2: std::net::IpAddr = "192.168.2.1".parse().unwrap();

        assert!(trie.contains(ip_in_1));
        assert!(trie.contains(ip_in_2));
        assert!(trie.contains(ip_in_3));
        assert!(!trie.contains(ip_out_1));
        assert!(!trie.contains(ip_out_2));
    }
}
