use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use tracing::{debug, warn};

use crate::app::dns::query::QType;
use crate::app::dns::response::build_dns_ip_response;
use crate::common::trie::StringTrie;

const HOSTS_TTL: u32 = 3600;

#[derive(Clone, Default)]
pub struct HostsSnapshot {
    trie: Arc<StringTrie<Vec<IpAddr>>>,
}

impl HostsSnapshot {
    pub fn new(
        inline_hosts: &HashMap<String, Vec<IpAddr>>,
        files: &[String],
    ) -> Self {
        let mut trie = StringTrie::new();
        let mut collected: HashMap<String, Vec<IpAddr>> = HashMap::new();

        // 1. 加载外部文件到临时 map
        for file_path in files {
            let path = Path::new(file_path);
            if !path.exists() {
                warn!("hosts file does not exist: {file_path}");
                continue;
            }
            match fs::read_to_string(path) {
                Ok(content) => {
                    parse_hosts_file(&content, &mut collected);
                    debug!("loaded hosts file: {file_path}");
                }
                Err(err) => {
                    warn!("failed to read hosts file {file_path}: {err}");
                }
            }
        }

        // 批量插入外部文件条目
        for (domain, ips) in collected {
            trie.insert(&domain, Arc::new(ips));
        }

        // 2. 加载内联 hosts（内联优先级更高，覆盖外部文件）
        for (domain, ips) in inline_hosts {
            let domain_normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
            if !domain_normalized.is_empty() && !ips.is_empty() {
                trie.insert(&domain_normalized, Arc::new(ips.clone()));
            }
        }

        Self {
            trie: Arc::new(trie),
        }
    }

    pub fn lookup(&self, domain: &str, ipv6: bool) -> Option<Vec<IpAddr>> {
        let domain_normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let ips = self.trie.search(&domain_normalized)?.get_data()?;
        let filtered: Vec<IpAddr> = ips
            .iter()
            .copied()
            .filter(|ip| match ip {
                IpAddr::V4(_) => true,
                IpAddr::V6(_) => ipv6,
            })
            .collect();

        if filtered.is_empty() {
            None
        } else {
            Some(filtered)
        }
    }

    pub fn make_response(
        &self,
        raw_query: &[u8],
        domain: &str,
        qtype: QType,
        ipv6: bool,
    ) -> Option<Vec<u8>> {
        let domain_normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let ips = self.trie.search(&domain_normalized)?.get_data()?;

        let matching_ips: Vec<IpAddr> = match qtype {
            QType::A => ips.iter().copied().filter(|ip| ip.is_ipv4()).collect(),
            QType::AAAA if ipv6 => ips.iter().copied().filter(|ip| ip.is_ipv6()).collect(),
            _ => return None,
        };

        if matching_ips.is_empty() {
            return None;
        }

        build_dns_ip_response(raw_query, &matching_ips, HOSTS_TTL)
    }
}

fn parse_hosts_file(content: &str, map: &mut HashMap<String, Vec<IpAddr>>) {
    for line in content.lines() {
        let line = match line.split_once('#') {
            Some((before, _)) => before.trim(),
            None => line.trim(),
        };
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(ip_str) = parts.next() else {
            continue;
        };
        let Ok(ip) = ip_str.parse::<IpAddr>() else {
            continue;
        };

        for domain in parts {
            let domain_normalized = domain.trim_end_matches('.').to_ascii_lowercase();
            if domain_normalized.is_empty() {
                continue;
            }

            let ips = map.entry(domain_normalized).or_default();
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
}
