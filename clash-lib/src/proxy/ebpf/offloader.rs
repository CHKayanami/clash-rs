use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::time::Instant;

#[allow(unused_imports)]
use super::utils::is_reserved_ip;
#[allow(unused_imports)]
use crate::app::dns::ThreadSafeDNSResolver;
#[allow(unused_imports)]
use crate::app::remote_content_manager::providers::rule_provider::CidrTrie;

#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};

#[allow(dead_code)]
pub type DomainKey = Arc<str>;

/// Routing policy decision for domain offload.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingAction {
    Direct,
    Proxy,
}

/// A domain owner entry in the desired state.
#[allow(dead_code)]
#[derive(Debug)]
pub struct DomainOwner {
    pub ips: HashSet<IpAddr>,
    pub action: RoutingAction,
    pub expires_at: Instant,
    pub sequence: u64,
}

/// Deadline min-heap entry for precise TTL expiration.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeadlineEntry {
    pub at: Instant,
    pub domain: DomainKey,
    pub sequence: u64,
}

/// Reconciler state machine tracking domain ownership, reverse IP mappings,
/// conflict detection, and TTL expiration.
#[allow(dead_code)]
pub struct OffloadDesiredState {
    pub sequence: u64,
    pub owners: HashMap<DomainKey, DomainOwner>,
    pub reverse: HashMap<IpAddr, HashSet<DomainKey>>,
    pub desired: HashMap<IpAddr, bool>,
    pub applied: HashSet<IpAddr>,
    pub dirty_ips: HashSet<IpAddr>,
    pub revisions: HashMap<IpAddr, u64>,
    pub expiry_deadlines: BinaryHeap<Reverse<DeadlineEntry>>,
}

impl Default for OffloadDesiredState {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl OffloadDesiredState {
    pub fn new() -> Self {
        Self {
            sequence: 0,
            owners: HashMap::new(),
            reverse: HashMap::new(),
            desired: HashMap::new(),
            applied: HashSet::new(),
            dirty_ips: HashSet::new(),
            revisions: HashMap::new(),
            expiry_deadlines: BinaryHeap::new(),
        }
    }

    /// Observe a new DNS resolution outcome for a domain.
    pub fn observe(
        &mut self,
        domain: impl Into<DomainKey>,
        ips: &[IpAddr],
        action: RoutingAction,
        ttl: std::time::Duration,
        now: Instant,
    ) {
        self.expire(now);

        self.sequence = self.sequence.wrapping_add(1);
        let seq = self.sequence;
        let expires_at = now + ttl;
        let domain_key: DomainKey = domain.into();
        let mut new_ips = HashSet::with_capacity(ips.len());
        for &ip in ips {
            new_ips.insert(ip);
        }

        let mut affected_ips = Vec::with_capacity(ips.len() + 4);
        let mut final_ips = HashSet::with_capacity(ips.len() + 2);
        let incoming_has_v4 = ips.iter().any(|ip| ip.is_ipv4());
        let incoming_has_v6 = ips.iter().any(|ip| ip.is_ipv6());

        if let Some(old_owner) = self.owners.get(&domain_key) {
            for old_ip in &old_owner.ips {
                let should_replace = (old_ip.is_ipv4() && incoming_has_v4)
                    || (old_ip.is_ipv6() && incoming_has_v6);
                if should_replace {
                    if !new_ips.contains(old_ip) {
                        if let Some(domains) = self.reverse.get_mut(old_ip) {
                            domains.remove(&domain_key);
                            if domains.is_empty() {
                                self.reverse.remove(old_ip);
                            }
                        }
                        affected_ips.push(*old_ip);
                    }
                } else {
                    // Retain IPs of the other address family that were not part of this DNS query
                    final_ips.insert(*old_ip);
                }
            }
        }

        for ip in &new_ips {
            final_ips.insert(*ip);
            self.reverse
                .entry(*ip)
                .or_default()
                .insert(Arc::clone(&domain_key));
            affected_ips.push(*ip);
        }

        self.owners.insert(
            Arc::clone(&domain_key),
            DomainOwner {
                ips: final_ips,
                action,
                expires_at,
                sequence: seq,
            },
        );

        self.expiry_deadlines.push(Reverse(DeadlineEntry {
            at: expires_at,
            domain: domain_key,
            sequence: seq,
        }));

        self.recompute_ips(affected_ips);
    }

    /// Expire domain owners whose TTLs have passed.
    pub fn expire(&mut self, now: Instant) {
        self.prune_stale_heads();
        while let Some(Reverse(deadline)) = self.expiry_deadlines.peek() {
            if deadline.at > now {
                break;
            }
            let deadline = self.expiry_deadlines.pop().unwrap().0;
            if self.owners.get(&deadline.domain).is_some_and(|owner| {
                owner.sequence == deadline.sequence && owner.expires_at <= now
            }) {
                self.remove_owner(&deadline.domain);
            }
            self.prune_stale_heads();
        }
    }

    fn remove_owner(&mut self, domain: &str) {
        if let Some((domain_key, owner)) = self.owners.remove_entry(domain) {
            tracing::info!(
                "[eBPF DirectOffloader] Domain TTL expired: {} (holding {} IPs: {:?})",
                domain_key,
                owner.ips.len(),
                owner.ips
            );
            for ip in &owner.ips {
                if let Some(domains) = self.reverse.get_mut(ip) {
                    domains.remove(&domain_key);
                    if domains.is_empty() {
                        self.reverse.remove(ip);
                    }
                }
            }
            self.recompute_ips(owner.ips);
        }
    }

    fn prune_stale_heads(&mut self) {
        while self.expiry_deadlines.peek().is_some_and(|entry| {
            let deadline = &entry.0;
            !self.owners.get(&deadline.domain).is_some_and(|owner| {
                owner.sequence == deadline.sequence && owner.expires_at == deadline.at
            })
        }) {
            self.expiry_deadlines.pop();
        }
    }

    /// Recompute desired bypass status for given IPs.
    /// Conflict resolution: if ANY owner requires PROXY, desired is None (bypass forbidden).
    fn recompute_ips(&mut self, ips: impl IntoIterator<Item = IpAddr>) {
        for ip in ips {
            let mut has_direct = false;
            let mut has_proxy = false;

            if let Some(domains) = self.reverse.get(&ip) {
                for domain in domains {
                    if let Some(owner) = self.owners.get(domain) {
                        match owner.action {
                            RoutingAction::Direct => has_direct = true,
                            RoutingAction::Proxy => {
                                has_proxy = true;
                                break;
                            }
                        }
                    }
                }
            }

            let next_desired = if has_proxy {
                None
            } else if has_direct {
                Some(true)
            } else {
                None
            };

            let is_changed = match (self.desired.get(&ip).copied(), next_desired) {
                (Some(curr), Some(next)) => curr != next,
                (Some(_), None) | (None, Some(_)) => true,
                (None, None) => false,
            };

            if is_changed {
                let rev = self.revisions.entry(ip).or_default();
                *rev = rev.wrapping_add(1);

                if let Some(desired_val) = next_desired {
                    self.desired.insert(ip, desired_val);
                } else {
                    self.desired.remove(&ip);
                }
                self.dirty_ips.insert(ip);
            }
        }
    }

    pub fn next_deadline(&mut self) -> Option<Instant> {
        self.prune_stale_heads();
        self.expiry_deadlines.peek().map(|e| e.0.at)
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct DnsObservation {
    pub domain: DomainKey,
    pub ips: Vec<IpAddr>,
    pub action: RoutingAction,
    pub ttl: std::time::Duration,
}

#[allow(dead_code)]
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct DirectOffloader {
    tx: tokio::sync::mpsc::UnboundedSender<DnsObservation>,
    resolver: ThreadSafeDNSResolver,
    bypass_dst_trie: Arc<CidrTrie>,
}

#[cfg(target_os = "linux")]
impl DirectOffloader {
    pub fn new(
        manager: Arc<tokio::sync::OnceCell<Arc<clash_ebpf::EbpfManager>>>,
        resolver: ThreadSafeDNSResolver,
        bypass_dst_trie: Arc<CidrTrie>,
    ) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DnsObservation>();

        tokio::spawn(async move {
            let mut state = OffloadDesiredState::new();

            let mut add_v4 = Vec::new();
            let mut add_v6 = Vec::new();
            let mut del_v4 = Vec::new();
            let mut del_v6 = Vec::new();

            loop {
                let now = Instant::now();
                state.expire(now);

                // Flush dirty IPs to eBPF manager in batch
                if !state.dirty_ips.is_empty() {
                    add_v4.clear();
                    add_v6.clear();
                    del_v4.clear();
                    del_v6.clear();

                    for ip in &state.dirty_ips {
                        let desired = state.desired.get(ip).copied();
                        let applied = state.applied.contains(ip);

                        match (desired, applied) {
                            (Some(true), false) => match ip {
                                IpAddr::V4(v4) => add_v4.push(*v4),
                                IpAddr::V6(v6) => add_v6.push(*v6),
                            },
                            (None, true) => match ip {
                                IpAddr::V4(v4) => del_v4.push(*v4),
                                IpAddr::V6(v6) => del_v6.push(*v6),
                            },
                            _ => {}
                        }
                    }

                    if !add_v4.is_empty() || !add_v6.is_empty() || !del_v4.is_empty() || !del_v6.is_empty() {
                        if let Some(mgr) = manager.get() {
                            if let Err(e) = mgr
                                .update_dynamic_bypass_batch(&add_v4, &add_v6, &del_v4, &del_v6)
                                .await
                            {
                                tracing::warn!("eBPF dynamic bypass batch update failed: {e}");
                            } else {
                                if !add_v4.is_empty() || !add_v6.is_empty() {
                                    tracing::info!(
                                        "[eBPF DirectOffloader] Dynamic bypass added: IPv4={:?}, IPv6={:?}",
                                        add_v4,
                                        add_v6
                                    );
                                }
                                for v4 in &add_v4 {
                                    state.applied.insert(IpAddr::V4(*v4));
                                }
                                for v6 in &add_v6 {
                                    state.applied.insert(IpAddr::V6(*v6));
                                }
                                if !del_v4.is_empty() || !del_v6.is_empty() {
                                    tracing::info!(
                                        "[eBPF DirectOffloader] Dynamic bypass removed: IPv4={:?}, IPv6={:?}",
                                        del_v4,
                                        del_v6
                                    );
                                }
                                for v4 in &del_v4 {
                                    state.applied.remove(&IpAddr::V4(*v4));
                                }
                                for v6 in &del_v6 {
                                    state.applied.remove(&IpAddr::V6(*v6));
                                }
                            }
                        }
                    }
                    state.dirty_ips.clear();
                }

                let next_deadline = state.next_deadline();

                tokio::select! {
                    Some(obs) = rx.recv() => {
                        let now = Instant::now();
                        state.observe(obs.domain, &obs.ips, obs.action, obs.ttl, now);
                        while let Ok(obs) = rx.try_recv() {
                            state.observe(obs.domain, &obs.ips, obs.action, obs.ttl, now);
                        }
                    }
                    _ = async {
                        if let Some(deadline) = next_deadline {
                            tokio::time::sleep_until(deadline).await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        // Expire deadline reached, loop will call state.expire(now)
                    }
                }
            }
        });

        Self {
            tx,
            resolver,
            bypass_dst_trie,
        }
    }

    pub async fn observe(
        &self,
        domain: DomainKey,
        ips: Vec<IpAddr>,
        action: RoutingAction,
        ttl: std::time::Duration,
    ) {
        let mut valid_ips = Vec::with_capacity(ips.len());
        for ip in ips {
            if !is_reserved_ip(ip) && !self.resolver.is_fake_ip(ip) {
                valid_ips.push(ip);
            }
        }
        if !valid_ips.is_empty() {
            let _ = self.tx.send(DnsObservation {
                domain,
                ips: valid_ips,
                action,
                ttl,
            });
        }
    }
}

#[allow(dead_code)]
#[cfg(not(target_os = "linux"))]
#[derive(Clone)]
pub struct DirectOffloader;

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
impl DirectOffloader {
    #[allow(dead_code)]
    pub async fn observe(
        &self,
        _domain: DomainKey,
        _ips: Vec<IpAddr>,
        _action: RoutingAction,
        _ttl: std::time::Duration,
    ) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offload_desired_state_conflict_and_ttl() {
        let mut state = OffloadDesiredState::new();
        let now = Instant::now();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // 1. Observe DIRECT domain-a -> should be desired for offload
        state.observe(
            "domain-a.com",
            &[ip],
            RoutingAction::Direct,
            std::time::Duration::from_secs(300),
            now,
        );
        assert_eq!(state.desired.get(&ip), Some(&true));
        assert!(state.dirty_ips.contains(&ip));
        state.dirty_ips.clear();

        // 2. Observe PROXY domain-b with the SAME IP -> conflict! Should be removed from desired
        state.observe(
            "domain-b.com",
            &[ip],
            RoutingAction::Proxy,
            std::time::Duration::from_secs(60),
            now,
        );
        assert_eq!(state.desired.get(&ip), None);
        assert!(state.dirty_ips.contains(&ip));
        state.dirty_ips.clear();

        // 3. Observe another DIRECT domain-c -> still conflict (domain-b active) -> remains forbidden
        state.observe(
            "domain-c.com",
            &[ip],
            RoutingAction::Direct,
            std::time::Duration::from_secs(300),
            now,
        );
        assert_eq!(state.desired.get(&ip), None);

        // 4. Advance time by 61 seconds -> domain-b (proxy) expires!
        // Remaining domains: domain-a (direct) and domain-c (direct) -> self-heals to desired=true
        let later_61s = now + std::time::Duration::from_secs(61);
        state.expire(later_61s);
        assert_eq!(state.desired.get(&ip), Some(&true));
        assert!(state.dirty_ips.contains(&ip));
        state.dirty_ips.clear();

        // 5. Advance time by 301 seconds -> all direct domains expire -> desired becomes None
        let later_301s = now + std::time::Duration::from_secs(301);
        state.expire(later_301s);
        assert_eq!(state.desired.get(&ip), None);
        assert!(state.dirty_ips.contains(&ip));
        assert!(state.owners.is_empty());
        assert!(state.reverse.is_empty());
    }

    #[test]
    fn test_offload_desired_state_batch_multiple_ips() {
        let mut state = OffloadDesiredState::new();
        let now = Instant::now();
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "1.1.1.2".parse().unwrap();
        let ip3: IpAddr = "2606:4700:4700::1111".parse().unwrap();

        // Observe multiple IPs for a single direct domain
        state.observe(
            "cloudflare-dns.com",
            &[ip1, ip2, ip3],
            RoutingAction::Direct,
            std::time::Duration::from_secs(300),
            now,
        );

        assert_eq!(state.desired.len(), 3);
        assert!(state.dirty_ips.contains(&ip1));
        assert!(state.dirty_ips.contains(&ip2));
        assert!(state.dirty_ips.contains(&ip3));
    }
}
