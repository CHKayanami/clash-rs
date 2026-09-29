use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::net::IpAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::time::Instant;

use super::utils::is_reserved_ip;
use crate::app::dns::{ClashResolver, ThreadSafeDNSResolver};
use crate::app::remote_content_manager::providers::rule_provider::CidrTrie;

pub type DomainKey = Arc<str>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingAction {
    Direct,
    Proxy,
}

struct DomainOwner {
    v4_ips: Vec<IpAddr>,
    v6_ips: Vec<IpAddr>,
    action: RoutingAction,
    last_seen: u64,
}

#[derive(Default)]
struct IpActionCounts {
    // A count cannot exceed max_owners (8192).
    direct: u16,
    proxy: u16,
}

// Match DYNAMIC_BYPASS_DST_IPS and DYNAMIC_BYPASS_DST_IP6S map capacities.
const DEFAULT_MAX_V4_IPS: usize = 16384;
const DEFAULT_MAX_V6_IPS: usize = 16384;
// Domains commonly own multiple IPs; keep a separate bound on owner metadata.
const DEFAULT_MAX_OWNERS: usize = 8192;

/// DNS observations replace the addresses of the observed family. An unobserved
/// family keeps its last state. No DNS TTL is used to change kernel bypass state.
pub struct OffloadDesiredState {
    max_v4_ips: usize,
    max_v6_ips: usize,
    max_owners: usize,
    sequence: u64,
    owners: HashMap<DomainKey, DomainOwner>,
    ip_action_counts: HashMap<IpAddr, IpActionCounts>,
    tracked_v4: usize,
    tracked_v6: usize,
    desired: HashSet<IpAddr>,
    applied: HashSet<IpAddr>,
    dirty_ips: HashSet<IpAddr>,
}

impl OffloadDesiredState {
    pub fn new() -> Self {
        Self::with_capacity(
            DEFAULT_MAX_V4_IPS,
            DEFAULT_MAX_V6_IPS,
            DEFAULT_MAX_OWNERS,
        )
    }

    fn with_capacity(
        max_v4_ips: usize,
        max_v6_ips: usize,
        max_owners: usize,
    ) -> Self {
        Self {
            max_v4_ips,
            max_v6_ips,
            max_owners,
            sequence: 0,
            owners: HashMap::new(),
            ip_action_counts: HashMap::new(),
            tracked_v4: 0,
            tracked_v6: 0,
            desired: HashSet::new(),
            applied: HashSet::new(),
            dirty_ips: HashSet::new(),
        }
    }

    fn observe_batch(
        &mut self,
        observations: impl IntoIterator<Item = DnsObservation>,
    ) {
        let mut affected = HashSet::new();
        for observation in observations {
            self.observe_one(observation, &mut affected);
        }
        self.recompute_ips(affected);
    }

    fn observe_one(&mut self, obs: DnsObservation, affected: &mut HashSet<IpAddr>) {
        let mut incoming_v4 = Vec::new();
        let mut incoming_v6 = Vec::new();
        for ip in obs.ips {
            if ip.is_ipv4() {
                incoming_v4.push(ip);
            } else {
                incoming_v6.push(ip);
            }
        }
        incoming_v4.sort_unstable();
        incoming_v4.dedup();
        incoming_v6.sort_unstable();
        incoming_v6.dedup();
        let has_v4 = !incoming_v4.is_empty();
        let has_v6 = !incoming_v6.is_empty();

        if let Some(owner) = self.owners.get_mut(&obs.domain) {
            if owner.action == obs.action
                && (!has_v4 || owner.v4_ips == incoming_v4)
                && (!has_v6 || owner.v6_ips == incoming_v6)
            {
                self.sequence = self.sequence.wrapping_add(1);
                owner.last_seen = self.sequence;
                return;
            }
        }

        let previous = self.owners.remove(&obs.domain);
        if let Some(old) = &previous {
            for ip in old.v4_ips.iter().chain(&old.v6_ips) {
                self.change_count(*ip, old.action, false);
                affected.insert(*ip);
            }
        }
        self.sequence = self.sequence.wrapping_add(1);
        let owner = DomainOwner {
            v4_ips: if has_v4 {
                incoming_v4
            } else {
                previous
                    .as_ref()
                    .map(|old| old.v4_ips.clone())
                    .unwrap_or_default()
            },
            v6_ips: if has_v6 {
                incoming_v6
            } else {
                previous
                    .as_ref()
                    .map(|old| old.v6_ips.clone())
                    .unwrap_or_default()
            },
            action: obs.action,
            last_seen: self.sequence,
        };
        for ip in owner.v4_ips.iter().chain(&owner.v6_ips) {
            self.change_count(*ip, owner.action, true);
            affected.insert(*ip);
        }
        let domain = Arc::clone(&obs.domain);
        self.owners.insert(obs.domain, owner);
        if !self.enforce_capacity(&domain, affected) {
            if let Some(old) = previous {
                for ip in old.v4_ips.iter().chain(&old.v6_ips) {
                    self.change_count(*ip, old.action, true);
                    affected.insert(*ip);
                }
                self.owners.insert(domain, old);
            }
        }
    }

    fn change_count(&mut self, ip: IpAddr, action: RoutingAction, add: bool) {
        let tracked = if ip.is_ipv4() {
            &mut self.tracked_v4
        } else {
            &mut self.tracked_v6
        };
        match (add, self.ip_action_counts.entry(ip)) {
            (true, Entry::Vacant(entry)) => {
                let Some(next) = tracked.checked_add(1) else {
                    tracing::warn!(
                        "eBPF offloader tracked IP count overflow for {ip}"
                    );
                    return;
                };
                let counts = match action {
                    RoutingAction::Direct => IpActionCounts {
                        direct: 1,
                        proxy: 0,
                    },
                    RoutingAction::Proxy => IpActionCounts {
                        direct: 0,
                        proxy: 1,
                    },
                };
                entry.insert(counts);
                *tracked = next;
            }
            (true, Entry::Occupied(mut entry)) => {
                let counts = entry.get_mut();
                let count = match action {
                    RoutingAction::Direct => &mut counts.direct,
                    RoutingAction::Proxy => &mut counts.proxy,
                };
                if let Some(next) = count.checked_add(1) {
                    *count = next;
                } else {
                    tracing::warn!("eBPF offloader owner count overflow for {ip}");
                }
            }
            (false, Entry::Vacant(_)) => {
                tracing::warn!(
                    "eBPF offloader tried to remove an unknown owner for {ip}"
                );
            }
            (false, Entry::Occupied(mut entry)) => {
                let counts = entry.get_mut();
                let count = match action {
                    RoutingAction::Direct => &mut counts.direct,
                    RoutingAction::Proxy => &mut counts.proxy,
                };
                let Some(next) = count.checked_sub(1) else {
                    tracing::warn!("eBPF offloader owner count underflow for {ip}");
                    return;
                };
                *count = next;
                if counts.direct == 0 && counts.proxy == 0 {
                    entry.remove();
                    if let Some(next) = tracked.checked_sub(1) {
                        *tracked = next;
                    } else {
                        tracing::warn!(
                            "eBPF offloader tracked IP count underflow for {ip}"
                        );
                    }
                }
            }
        }
    }

    fn remove_owner(&mut self, domain: &DomainKey, affected: &mut HashSet<IpAddr>) {
        if let Some(owner) = self.owners.remove(domain) {
            for ip in owner.v4_ips.iter().chain(&owner.v6_ips) {
                self.change_count(*ip, owner.action, false);
                affected.insert(*ip);
            }
        }
    }

    /// Plan all evictions before changing existing owners. Shared IPs only free
    /// capacity when their last owner is removed.
    fn enforce_capacity(
        &mut self,
        observed: &DomainKey,
        affected: &mut HashSet<IpAddr>,
    ) -> bool {
        let fits = |owners: usize, v4: usize, v6: usize| {
            owners <= self.max_owners
                && v4 <= self.max_v4_ips
                && v6 <= self.max_v6_ips
        };
        if fits(self.owners.len(), self.tracked_v4, self.tracked_v6) {
            return true;
        }

        let Some(new_owner) = self.owners.get(observed) else {
            return false;
        };
        if self.max_owners == 0
            || new_owner.v4_ips.len() > self.max_v4_ips
            || new_owner.v6_ips.len() > self.max_v6_ips
        {
            self.remove_owner(observed, affected);
            return false;
        }

        if self.tracked_v4 <= self.max_v4_ips && self.tracked_v6 <= self.max_v6_ips {
            if let Some(oldest) = self
                .owners
                .iter()
                .filter(|(domain, _)| *domain != observed)
                .min_by_key(|(_, owner)| owner.last_seen)
                .map(|(domain, _)| Arc::clone(domain))
            {
                self.remove_owner(&oldest, affected);
                return true;
            }
            self.remove_owner(observed, affected);
            return false;
        }

        let excess_v4 = self.tracked_v4.saturating_sub(self.max_v4_ips);
        let excess_v6 = self.tracked_v6.saturating_sub(self.max_v6_ips);
        let mut candidates: Vec<_> = self
            .owners
            .iter()
            .filter(|(domain, _)| *domain != observed)
            .map(|(domain, owner)| {
                let v4_gain = owner
                    .v4_ips
                    .iter()
                    .filter(|ip| {
                        self.ip_action_counts
                            .get(ip)
                            .is_some_and(|counts| counts.direct + counts.proxy == 1)
                    })
                    .count();
                let v6_gain = owner
                    .v6_ips
                    .iter()
                    .filter(|ip| {
                        self.ip_action_counts
                            .get(ip)
                            .is_some_and(|counts| counts.direct + counts.proxy == 1)
                    })
                    .count();
                (
                    Arc::clone(domain),
                    owner,
                    v4_gain.min(excess_v4) + v6_gain.min(excess_v6),
                )
            })
            .collect();
        candidates.sort_unstable_by_key(|(_, owner, gain)| {
            (std::cmp::Reverse(*gain), owner.last_seen)
        });

        let mut remaining_owners = self.owners.len();
        let mut remaining_v4 = self.tracked_v4;
        let mut remaining_v6 = self.tracked_v6;
        let mut remaining_counts = HashMap::<IpAddr, usize>::new();
        let mut evictions = Vec::new();
        while !fits(remaining_owners, remaining_v4, remaining_v6) {
            let mut deferred = Vec::new();
            let mut progressed = false;
            for (domain, owner, gain) in candidates.drain(..) {
                if fits(remaining_owners, remaining_v4, remaining_v6) {
                    break;
                }
                let excess_v4 = remaining_v4.saturating_sub(self.max_v4_ips);
                let excess_v6 = remaining_v6.saturating_sub(self.max_v6_ips);
                let mut freed_v4 = 0;
                let mut freed_v6 = 0;
                for ip in owner.v4_ips.iter().chain(&owner.v6_ips) {
                    let remaining =
                        remaining_counts.get(ip).copied().unwrap_or_else(|| {
                            self.ip_action_counts
                                .get(ip)
                                .map(|counts| {
                                    usize::from(counts.direct)
                                        + usize::from(counts.proxy)
                                })
                                .unwrap_or(0)
                        });
                    if remaining == 1 {
                        if ip.is_ipv4() {
                            freed_v4 += 1;
                        } else {
                            freed_v6 += 1;
                        }
                    }
                }
                let useful = freed_v4.min(excess_v4) + freed_v6.min(excess_v6);
                if useful == 0 && remaining_owners <= self.max_owners {
                    deferred.push((domain, owner, gain));
                    continue;
                }
                for ip in owner.v4_ips.iter().chain(&owner.v6_ips) {
                    let remaining =
                        remaining_counts.entry(*ip).or_insert_with(|| {
                            self.ip_action_counts
                                .get(ip)
                                .map(|counts| {
                                    usize::from(counts.direct)
                                        + usize::from(counts.proxy)
                                })
                                .unwrap_or(0)
                        });
                    if let Some(next) = remaining.checked_sub(1) {
                        *remaining = next;
                        if next == 0 {
                            if ip.is_ipv4() {
                                remaining_v4 = remaining_v4.saturating_sub(1);
                            } else {
                                remaining_v6 = remaining_v6.saturating_sub(1);
                            }
                        }
                    }
                }
                remaining_owners = remaining_owners.saturating_sub(1);
                evictions.push(domain);
                progressed = true;
            }
            if !progressed {
                break;
            }
            candidates = deferred;
        }

        if !fits(remaining_owners, remaining_v4, remaining_v6) {
            self.remove_owner(observed, affected);
            return false;
        }
        for domain in evictions {
            self.remove_owner(&domain, affected);
        }
        true
    }

    fn recompute_ips(&mut self, ips: HashSet<IpAddr>) {
        for ip in ips {
            let direct = self
                .ip_action_counts
                .get(&ip)
                .is_some_and(|counts| counts.direct > 0 && counts.proxy == 0);
            if direct != self.desired.contains(&ip) {
                if direct {
                    self.desired.insert(ip);
                } else {
                    self.desired.remove(&ip);
                }
                self.dirty_ips.insert(ip);
            }
        }
    }
}

#[derive(Debug)]
struct DnsObservation {
    domain: DomainKey,
    ips: Vec<IpAddr>,
    action: RoutingAction,
}

#[derive(Clone)]
pub struct DirectOffloader {
    tx: tokio::sync::mpsc::UnboundedSender<DnsObservation>,
    resolver: Weak<dyn ClashResolver>,
    bypass_dst_trie: Arc<CidrTrie>,
    proxy_dst_trie: Arc<CidrTrie>,
    abort_handle: Arc<tokio::task::AbortHandle>,
}

impl DirectOffloader {
    pub fn new(
        manager: Weak<clash_ebpf::EbpfManager>,
        resolver: ThreadSafeDNSResolver,
        bypass_dst_trie: Arc<CidrTrie>,
        proxy_dst_trie: Arc<CidrTrie>,
    ) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DnsObservation>();
        let handle = tokio::spawn(async move {
            const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(1);
            const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
            let mut state = OffloadDesiredState::new();
            let mut retry_delay = INITIAL_RETRY_DELAY;
            let mut retry_at = None;

            loop {
                if !state.dirty_ips.is_empty()
                    && retry_at.is_none_or(|deadline| Instant::now() >= deadline)
                {
                    let mut add_v4 = Vec::new();
                    let mut add_v6 = Vec::new();
                    let mut del_v4 = Vec::new();
                    let mut del_v6 = Vec::new();
                    for ip in &state.dirty_ips {
                        match (
                            state.desired.contains(ip),
                            state.applied.contains(ip),
                            ip,
                        ) {
                            (true, false, IpAddr::V4(v4)) => add_v4.push(*v4),
                            (true, false, IpAddr::V6(v6)) => add_v6.push(*v6),
                            (false, true, IpAddr::V4(v4)) => del_v4.push(*v4),
                            (false, true, IpAddr::V6(v6)) => del_v6.push(*v6),
                            _ => {}
                        }
                    }
                    let has_updates = !add_v4.is_empty()
                        || !add_v6.is_empty()
                        || !del_v4.is_empty()
                        || !del_v6.is_empty();
                    let mut flush_succeeded = !has_updates;
                    if has_updates {
                        if let Some(mgr) = manager.upgrade() {
                            match mgr
                                .update_dynamic_bypass_batch(
                                    &add_v4, &add_v6, &del_v4, &del_v6,
                                )
                                .await
                            {
                                Ok(()) => {
                                    flush_succeeded = true;
                                    if !add_v4.is_empty() || !add_v6.is_empty() {
                                        tracing::info!(
                                            "[eBPF DirectOffloader] Dynamic bypass added: IPv4={:?}, IPv6={:?}",
                                            add_v4,
                                            add_v6
                                        );
                                    }
                                    if !del_v4.is_empty() || !del_v6.is_empty() {
                                        tracing::info!(
                                            "[eBPF DirectOffloader] Dynamic bypass removed: IPv4={:?}, IPv6={:?}",
                                            del_v4,
                                            del_v6
                                        );
                                    }
                                    for ip in add_v4
                                        .into_iter()
                                        .map(IpAddr::V4)
                                        .chain(add_v6.into_iter().map(IpAddr::V6))
                                    {
                                        state.applied.insert(ip);
                                    }
                                    for ip in del_v4
                                        .into_iter()
                                        .map(IpAddr::V4)
                                        .chain(del_v6.into_iter().map(IpAddr::V6))
                                    {
                                        state.applied.remove(&ip);
                                    }
                                }
                                Err(e) => tracing::warn!(
                                    "eBPF dynamic bypass batch update failed: {e} (retrying in {retry_delay:?})"
                                ),
                            }
                        } else {
                            tracing::debug!(
                                "eBPF manager not initialized yet, deferring dynamic bypass flush (retrying in {retry_delay:?})"
                            );
                        }
                    }
                    if flush_succeeded {
                        state.dirty_ips.clear();
                        retry_at = None;
                        retry_delay = INITIAL_RETRY_DELAY;
                    } else {
                        retry_at = Some(Instant::now() + retry_delay);
                        retry_delay = (retry_delay * 2).min(MAX_RETRY_DELAY);
                    }
                }

                tokio::select! {
                    observation = rx.recv() => match observation {
                        Some(obs) => {
                            const MAX_BATCH_OBSERVATIONS: usize = 256;
                            let batch = std::iter::once(obs).chain(
                                std::iter::from_fn(|| rx.try_recv().ok())
                                    .take(MAX_BATCH_OBSERVATIONS - 1),
                            );
                            state.observe_batch(batch);
                        }
                        None => break,
                    },
                    _ = async {
                        if let Some(deadline) = retry_at {
                            tokio::time::sleep_until(deadline).await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {}
                }
            }
        });
        Self {
            tx,
            resolver: Arc::downgrade(&resolver),
            bypass_dst_trie,
            proxy_dst_trie,
            abort_handle: Arc::new(handle.abort_handle()),
        }
    }

    pub fn stop(&self) {
        self.abort_handle.abort();
    }

    pub async fn observe(
        &self,
        domain: DomainKey,
        mut ips: Vec<IpAddr>,
        action: RoutingAction,
    ) {
        let mut effective_action = action;
        let resolver = self.resolver.upgrade();
        ips.retain(|ip| {
            let is_fake_ip = resolver
                .as_ref()
                .is_some_and(|resolver| resolver.is_fake_ip(*ip));
            if is_reserved_ip(*ip) || is_fake_ip {
                return false;
            }
            if self.proxy_dst_trie.contains(*ip) {
                effective_action = RoutingAction::Proxy;
            } else if self.bypass_dst_trie.contains(*ip) {
                return false;
            }
            true
        });
        if !ips.is_empty() {
            let _ = self.tx.send(DnsObservation {
                domain,
                ips,
                action: effective_action,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::{MockClashResolver, ThreadSafeDNSResolver};

    fn observe(
        state: &mut OffloadDesiredState,
        domain: &str,
        ips: &[IpAddr],
        action: RoutingAction,
    ) {
        state.observe_batch(vec![DnsObservation {
            domain: domain.into(),
            ips: ips.to_vec(),
            action,
        }]);
    }

    #[tokio::test]
    async fn direct_offloader_does_not_retain_resolver() {
        let resolver: ThreadSafeDNSResolver = Arc::new(MockClashResolver::new());
        let weak_resolver = Arc::downgrade(&resolver);
        let offloader = DirectOffloader::new(
            Weak::new(),
            resolver.clone(),
            Arc::new(CidrTrie::new()),
            Arc::new(CidrTrie::new()),
        );
        drop(resolver);
        assert!(weak_resolver.upgrade().is_none());
        drop(offloader);
        tokio::task::yield_now().await;
    }

    #[test]
    fn state_changes_only_when_direct_status_changes() {
        let mut state = OffloadDesiredState::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        observe(&mut state, "a.com", &[ip], RoutingAction::Direct);
        assert!(state.desired.contains(&ip));
        assert!(state.dirty_ips.remove(&ip));
        observe(&mut state, "a.com", &[ip], RoutingAction::Direct);
        assert!(state.dirty_ips.is_empty());
        observe(&mut state, "b.com", &[ip], RoutingAction::Proxy);
        assert!(!state.desired.contains(&ip));
        assert!(state.dirty_ips.remove(&ip));
        observe(&mut state, "b.com", &[ip], RoutingAction::Proxy);
        assert!(state.dirty_ips.is_empty());
        observe(&mut state, "b.com", &[ip], RoutingAction::Direct);
        assert!(state.desired.contains(&ip));
        assert!(state.dirty_ips.contains(&ip));
    }

    #[test]
    fn repeated_reordered_dns_answers_reuse_owner_state() {
        let mut state = OffloadDesiredState::new();
        let a: IpAddr = "1.1.1.1".parse().unwrap();
        let b: IpAddr = "2.2.2.2".parse().unwrap();
        observe(&mut state, "a.com", &[b, a, a], RoutingAction::Direct);
        assert_eq!(state.tracked_v4, 2);
        assert_eq!(state.ip_action_counts.get(&a).unwrap().direct, 1);
        state.dirty_ips.clear();
        let last_seen = state.owners.get("a.com").unwrap().last_seen;

        observe(&mut state, "a.com", &[a, b], RoutingAction::Direct);
        assert!(state.dirty_ips.is_empty());
        assert_eq!(state.tracked_v4, 2);
        assert_eq!(state.ip_action_counts.get(&a).unwrap().direct, 1);
        assert!(state.owners.get("a.com").unwrap().last_seen > last_seen);
    }

    #[test]
    fn address_changes_and_families_are_independent() {
        let mut state = OffloadDesiredState::new();
        let v4a: IpAddr = "1.2.3.4".parse().unwrap();
        let v4b: IpAddr = "1.2.3.5".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        observe(&mut state, "a.com", &[v4a], RoutingAction::Direct);
        state.dirty_ips.clear();
        observe(&mut state, "a.com", &[v6], RoutingAction::Direct);
        assert!(state.desired.contains(&v4a));
        assert!(state.desired.contains(&v6));
        assert_eq!(state.dirty_ips, HashSet::from([v6]));
        state.dirty_ips.clear();
        observe(&mut state, "a.com", &[v4b], RoutingAction::Direct);
        assert!(!state.desired.contains(&v4a));
        assert!(state.desired.contains(&v4b));
        assert!(state.desired.contains(&v6));
        assert_eq!(state.dirty_ips, HashSet::from([v4a, v4b]));
    }

    #[test]
    fn capacity_evicts_oldest_observation_without_ttl() {
        let mut state = OffloadDesiredState::with_capacity(2, 2, 2);
        let a: IpAddr = "1.1.1.1".parse().unwrap();
        let b: IpAddr = "2.2.2.2".parse().unwrap();
        let c: IpAddr = "3.3.3.3".parse().unwrap();
        observe(&mut state, "a.com", &[a], RoutingAction::Direct);
        observe(&mut state, "b.com", &[b], RoutingAction::Direct);
        observe(&mut state, "a.com", &[a], RoutingAction::Direct);
        state.dirty_ips.clear();
        observe(&mut state, "c.com", &[c], RoutingAction::Direct);
        assert!(state.desired.contains(&a));
        assert!(!state.desired.contains(&b));
        assert!(state.desired.contains(&c));
        assert_eq!(state.dirty_ips, HashSet::from([b, c]));
    }

    #[test]
    fn ipv6_capacity_is_independent_of_ipv4() {
        let mut state = OffloadDesiredState::with_capacity(2, 1, 3);
        let v4: IpAddr = "1.1.1.1".parse().unwrap();
        let v6a: IpAddr = "2001:db8::1".parse().unwrap();
        let v6b: IpAddr = "2001:db8::2".parse().unwrap();
        observe(&mut state, "a.com", &[v6a], RoutingAction::Direct);
        observe(&mut state, "b.com", &[v4], RoutingAction::Direct);
        observe(&mut state, "c.com", &[v6b], RoutingAction::Direct);
        assert!(!state.desired.contains(&v6a));
        assert!(state.desired.contains(&v4));
        assert!(state.desired.contains(&v6b));
    }

    #[test]
    fn shared_ip_capacity_evicts_only_an_owner_that_releases_space() {
        let mut state = OffloadDesiredState::with_capacity(2, 2, 3);
        let shared: IpAddr = "1.1.1.1".parse().unwrap();
        let old_unique: IpAddr = "2.2.2.2".parse().unwrap();
        let new_unique: IpAddr = "3.3.3.3".parse().unwrap();
        observe(&mut state, "a.com", &[shared], RoutingAction::Direct);
        observe(
            &mut state,
            "b.com",
            &[shared, old_unique],
            RoutingAction::Direct,
        );
        state.dirty_ips.clear();

        observe(&mut state, "c.com", &[new_unique], RoutingAction::Direct);
        assert!(state.owners.contains_key("a.com"));
        assert!(!state.owners.contains_key("b.com"));
        assert!(state.owners.contains_key("c.com"));
        assert!(state.desired.contains(&shared));
        assert!(!state.desired.contains(&old_unique));
        assert!(state.desired.contains(&new_unique));
        assert_eq!(state.dirty_ips, HashSet::from([old_unique, new_unique]));
        assert_eq!(state.tracked_v4, 2);
    }

    #[test]
    fn shared_ip_capacity_rejects_new_owner_without_cascading() {
        let mut state = OffloadDesiredState::with_capacity(1, 1, 3);
        let shared: IpAddr = "1.1.1.1".parse().unwrap();
        let new_ip: IpAddr = "2.2.2.2".parse().unwrap();
        observe(&mut state, "a.com", &[shared], RoutingAction::Direct);
        observe(&mut state, "b.com", &[shared], RoutingAction::Direct);
        state.dirty_ips.clear();

        observe(&mut state, "c.com", &[new_ip], RoutingAction::Direct);
        assert!(state.owners.contains_key("a.com"));
        assert!(state.owners.contains_key("b.com"));
        assert!(!state.owners.contains_key("c.com"));
        assert_eq!(state.desired, HashSet::from([shared]));
        assert!(state.dirty_ips.is_empty());
        assert_eq!(state.tracked_v4, 1);
    }

    #[test]
    fn missing_or_zero_action_count_does_not_underflow() {
        let mut state = OffloadDesiredState::new();
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        state.change_count(ip, RoutingAction::Direct, false);
        assert!(state.ip_action_counts.is_empty());
        assert_eq!(state.tracked_v4, 0);

        state.change_count(ip, RoutingAction::Direct, true);
        state.change_count(ip, RoutingAction::Proxy, false);
        assert_eq!(state.ip_action_counts.get(&ip).unwrap().direct, 1);
        assert_eq!(state.ip_action_counts.get(&ip).unwrap().proxy, 0);
        assert_eq!(state.tracked_v4, 1);

        state.change_count(ip, RoutingAction::Direct, false);
        assert!(state.ip_action_counts.is_empty());
        assert_eq!(state.tracked_v4, 0);
    }

    #[test]
    fn rejected_update_restores_existing_domain() {
        let mut state = OffloadDesiredState::with_capacity(1, 1, 3);
        let shared: IpAddr = "1.1.1.1".parse().unwrap();
        let new_ip: IpAddr = "2.2.2.2".parse().unwrap();
        observe(&mut state, "a.com", &[shared], RoutingAction::Direct);
        observe(&mut state, "b.com", &[shared], RoutingAction::Direct);
        state.dirty_ips.clear();

        observe(
            &mut state,
            "b.com",
            &[shared, new_ip],
            RoutingAction::Direct,
        );
        assert_eq!(state.desired, HashSet::from([shared]));
        assert!(state.owners.contains_key("a.com"));
        assert!(state.owners.contains_key("b.com"));
        assert!(!state.owners.get("b.com").unwrap().v4_ips.contains(&new_ip));
        assert_eq!(state.tracked_v4, 1);
        assert!(state.dirty_ips.is_empty());
    }

    #[test]
    fn large_domain_can_replace_multiple_small_domains() {
        let mut state = OffloadDesiredState::with_capacity(3, 3, 4);
        let old: [IpAddr; 3] =
            ["1.1.1.1", "1.1.1.2", "1.1.1.3"].map(|ip| ip.parse().unwrap());
        let new: [IpAddr; 3] =
            ["2.2.2.1", "2.2.2.2", "2.2.2.3"].map(|ip| ip.parse().unwrap());
        for (domain, ip) in ["a.com", "b.com", "c.com"].into_iter().zip(old) {
            observe(&mut state, domain, &[ip], RoutingAction::Direct);
        }
        state.dirty_ips.clear();

        observe(&mut state, "large.com", &new, RoutingAction::Direct);
        assert_eq!(state.owners.len(), 1);
        assert!(state.owners.contains_key("large.com"));
        assert_eq!(state.desired, HashSet::from(new));
        assert_eq!(state.tracked_v4, 3);
        assert_eq!(state.dirty_ips.len(), 6);
    }

    #[test]
    fn oversized_domain_is_rejected_without_evictions() {
        let mut state = OffloadDesiredState::with_capacity(2, 2, 3);
        let old: IpAddr = "1.1.1.1".parse().unwrap();
        let new: [IpAddr; 3] =
            ["2.2.2.1", "2.2.2.2", "2.2.2.3"].map(|ip| ip.parse().unwrap());
        observe(&mut state, "old.com", &[old], RoutingAction::Direct);
        state.dirty_ips.clear();

        observe(&mut state, "large.com", &new, RoutingAction::Direct);
        assert_eq!(state.owners.len(), 1);
        assert!(state.owners.contains_key("old.com"));
        assert_eq!(state.desired, HashSet::from([old]));
        assert_eq!(state.tracked_v4, 1);
        assert!(state.dirty_ips.is_empty());
    }

    #[test]
    fn large_domain_replaces_shared_and_unique_small_domains() {
        let mut state = OffloadDesiredState::with_capacity(3, 3, 4);
        let shared: IpAddr = "1.1.1.1".parse().unwrap();
        let second: IpAddr = "1.1.1.2".parse().unwrap();
        let third: IpAddr = "1.1.1.3".parse().unwrap();
        let new: [IpAddr; 3] =
            ["2.2.2.1", "2.2.2.2", "2.2.2.3"].map(|ip| ip.parse().unwrap());
        observe(&mut state, "a.com", &[shared], RoutingAction::Direct);
        observe(
            &mut state,
            "b.com",
            &[shared, second],
            RoutingAction::Direct,
        );
        observe(&mut state, "c.com", &[third], RoutingAction::Direct);

        observe(&mut state, "large.com", &new, RoutingAction::Direct);
        assert_eq!(state.owners.len(), 1);
        assert!(state.owners.contains_key("large.com"));
        assert_eq!(state.desired, HashSet::from(new));
        assert_eq!(state.tracked_v4, 3);
    }

    #[test]
    fn default_owner_limit_is_8192_distinct_domains() {
        let mut state = OffloadDesiredState::new();
        for i in 0..8193u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            observe(
                &mut state,
                &format!("d{i}.com"),
                &[ip],
                RoutingAction::Direct,
            );
        }
        assert_eq!(state.owners.len(), 8192);
        assert_eq!(state.desired.len(), 8192);
        assert!(!state.owners.contains_key("d0.com"));
        assert!(state.owners.contains_key("d8192.com"));
    }

    #[test]
    fn owner_only_limit_evicts_oldest_without_scanning_ip_ownership() {
        let mut state = OffloadDesiredState::with_capacity(10, 10, 2);
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        observe(&mut state, "a.com", &[ip], RoutingAction::Direct);
        observe(&mut state, "b.com", &[ip], RoutingAction::Direct);
        state.dirty_ips.clear();

        observe(&mut state, "c.com", &[ip], RoutingAction::Direct);
        assert!(!state.owners.contains_key("a.com"));
        assert!(state.owners.contains_key("b.com"));
        assert!(state.owners.contains_key("c.com"));
        assert_eq!(state.desired, HashSet::from([ip]));
        assert!(state.dirty_ips.is_empty());
    }
}
