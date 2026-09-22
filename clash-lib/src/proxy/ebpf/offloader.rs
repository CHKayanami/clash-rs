use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::time::Instant;

use super::utils::is_reserved_ip;
use crate::app::dns::{ClashResolver, ThreadSafeDNSResolver};
use crate::app::remote_content_manager::providers::rule_provider::CidrTrie;

pub type DomainKey = Arc<str>;

/// Routing policy decision for domain offload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingAction {
    Direct,
    Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddressFamily {
    V4,
    V6,
}

/// A domain owner entry in the desired state, with decoupled v4 and v6 lifecycles.
#[derive(Debug)]
pub struct DomainOwner {
    pub v4_ips: HashSet<IpAddr>,
    pub v6_ips: HashSet<IpAddr>,
    pub action: RoutingAction,
    pub v4_expires_at: Option<Instant>,
    pub v6_expires_at: Option<Instant>,
    pub v4_sequence: u64,
    pub v6_sequence: u64,
}

/// Deadline min-heap entry for precise TTL expiration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeadlineEntry {
    pub at: Instant,
    pub domain: DomainKey,
    pub family: AddressFamily,
    pub sequence: u64,
}

/// Direct / Proxy owner action counter per IP address for O(1) state resolution.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IpActionCounts {
    pub direct_count: usize,
    pub proxy_count: usize,
}

pub const DEFAULT_MAX_DESIRED_IPS: usize = 8192;
pub const DEFAULT_MAX_OWNERS: usize = 4096;

/// Reconciler state machine tracking domain ownership, reverse IP mappings,
/// conflict detection, and TTL expiration.
pub struct OffloadDesiredState {
    pub max_desired_ips: usize,
    pub max_owners: usize,
    pub sequence: u64,
    pub owners: HashMap<DomainKey, DomainOwner>,
    pub reverse: HashMap<IpAddr, HashSet<DomainKey>>,
    pub ip_action_counts: HashMap<IpAddr, IpActionCounts>,
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

impl OffloadDesiredState {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_DESIRED_IPS, DEFAULT_MAX_OWNERS)
    }

    pub fn with_capacity(max_desired_ips: usize, max_owners: usize) -> Self {
        Self {
            max_desired_ips,
            max_owners,
            sequence: 0,
            owners: HashMap::new(),
            reverse: HashMap::new(),
            ip_action_counts: HashMap::new(),
            desired: HashMap::new(),
            applied: HashSet::new(),
            dirty_ips: HashSet::new(),
            revisions: HashMap::new(),
            expiry_deadlines: BinaryHeap::new(),
        }
    }

    /// Observe a batch of DNS resolution outcomes for optimal batched state recomputation.
    pub fn observe_batch(
        &mut self,
        observations: Vec<DnsObservation>,
        now: Instant,
    ) {
        self.expire(now);
        let mut affected_ips = HashSet::new();
        for obs in observations {
            self.observe_internal(
                obs.domain,
                &obs.ips,
                obs.action,
                obs.ttl,
                now,
                &mut affected_ips,
            );
        }
        if !affected_ips.is_empty() {
            self.recompute_ips(affected_ips);
        }
        self.enforce_capacity();
    }

    fn observe_internal(
        &mut self,
        domain_key: DomainKey,
        ips: &[IpAddr],
        action: RoutingAction,
        ttl: std::time::Duration,
        now: Instant,
        affected_ips: &mut HashSet<IpAddr>,
    ) {
        self.sequence = self.sequence.wrapping_add(1);
        let seq = self.sequence;
        let expires_at = now + ttl;

        let incoming_v4: HashSet<IpAddr> =
            ips.iter().filter(|ip| ip.is_ipv4()).copied().collect();
        let incoming_v6: HashSet<IpAddr> =
            ips.iter().filter(|ip| ip.is_ipv6()).copied().collect();
        let has_v4 = !incoming_v4.is_empty();
        let has_v6 = !incoming_v6.is_empty();

        if !self.owners.contains_key(&domain_key) {
            let mut owner = DomainOwner {
                v4_ips: HashSet::new(),
                v6_ips: HashSet::new(),
                action,
                v4_expires_at: if has_v4 { Some(expires_at) } else { None },
                v6_expires_at: if has_v6 { Some(expires_at) } else { None },
                v4_sequence: if has_v4 { seq } else { 0 },
                v6_sequence: if has_v6 { seq } else { 0 },
            };

            if has_v4 {
                for ip in &incoming_v4 {
                    self.add_ip_ownership(&domain_key, *ip, action);
                    affected_ips.insert(*ip);
                }
                owner.v4_ips = incoming_v4;
                self.expiry_deadlines.push(Reverse(DeadlineEntry {
                    at: expires_at,
                    domain: Arc::clone(&domain_key),
                    family: AddressFamily::V4,
                    sequence: seq,
                }));
            }

            if has_v6 {
                for ip in &incoming_v6 {
                    self.add_ip_ownership(&domain_key, *ip, action);
                    affected_ips.insert(*ip);
                }
                owner.v6_ips = incoming_v6;
                self.expiry_deadlines.push(Reverse(DeadlineEntry {
                    at: expires_at,
                    domain: Arc::clone(&domain_key),
                    family: AddressFamily::V6,
                    sequence: seq,
                }));
            }

            self.owners.insert(domain_key, owner);
            return;
        }

        let (old_action, old_v4, old_v6) = match self.owners.get(&domain_key) {
            Some(o) => (o.action, o.v4_ips.clone(), o.v6_ips.clone()),
            None => unreachable!(),
        };
        let action_changed = old_action != action;

        let mut to_remove = Vec::new();
        let mut to_add = Vec::new();
        let mut to_switch = Vec::new();

        if action_changed {
            if !has_v4 {
                for ip in &old_v4 {
                    to_switch.push(*ip);
                }
            }
            if !has_v6 {
                for ip in &old_v6 {
                    to_switch.push(*ip);
                }
            }
        }

        if has_v4 {
            for old_ip in &old_v4 {
                if !incoming_v4.contains(old_ip) {
                    to_remove.push((*old_ip, old_action));
                }
            }
            for new_ip in &incoming_v4 {
                if !old_v4.contains(new_ip) {
                    to_add.push(*new_ip);
                } else if action_changed {
                    to_switch.push(*new_ip);
                }
            }
        }

        if has_v6 {
            for old_ip in &old_v6 {
                if !incoming_v6.contains(old_ip) {
                    to_remove.push((*old_ip, old_action));
                }
            }
            for new_ip in &incoming_v6 {
                if !old_v6.contains(new_ip) {
                    to_add.push(*new_ip);
                } else if action_changed {
                    to_switch.push(*new_ip);
                }
            }
        }

        for (ip, act) in to_remove {
            self.remove_ip_ownership(&domain_key, ip, act);
            affected_ips.insert(ip);
        }
        for ip in to_add {
            self.add_ip_ownership(&domain_key, ip, action);
            affected_ips.insert(ip);
        }
        for ip in to_switch {
            self.switch_ip_action(ip, old_action, action);
            affected_ips.insert(ip);
        }

        let owner = self.owners.get_mut(&domain_key).unwrap();
        owner.action = action;
        if has_v4 {
            owner.v4_ips = incoming_v4;
            owner.v4_expires_at = Some(expires_at);
            owner.v4_sequence = seq;
            self.expiry_deadlines.push(Reverse(DeadlineEntry {
                at: expires_at,
                domain: Arc::clone(&domain_key),
                family: AddressFamily::V4,
                sequence: seq,
            }));
        }

        if has_v6 {
            owner.v6_ips = incoming_v6;
            owner.v6_expires_at = Some(expires_at);
            owner.v6_sequence = seq;
            self.expiry_deadlines.push(Reverse(DeadlineEntry {
                at: expires_at,
                domain: domain_key,
                family: AddressFamily::V6,
                sequence: seq,
            }));
        }
    }

    fn add_ip_ownership(
        &mut self,
        domain: &DomainKey,
        ip: IpAddr,
        action: RoutingAction,
    ) {
        self.reverse
            .entry(ip)
            .or_default()
            .insert(Arc::clone(domain));
        let counts = self.ip_action_counts.entry(ip).or_default();
        match action {
            RoutingAction::Direct => counts.direct_count += 1,
            RoutingAction::Proxy => counts.proxy_count += 1,
        }
    }

    fn remove_ip_ownership(
        &mut self,
        domain: &str,
        ip: IpAddr,
        action: RoutingAction,
    ) {
        if let Some(domains) = self.reverse.get_mut(&ip) {
            domains.remove(domain);
            if domains.is_empty() {
                self.reverse.remove(&ip);
            }
        }
        if let Some(counts) = self.ip_action_counts.get_mut(&ip) {
            match action {
                RoutingAction::Direct => {
                    counts.direct_count = counts.direct_count.saturating_sub(1)
                }
                RoutingAction::Proxy => {
                    counts.proxy_count = counts.proxy_count.saturating_sub(1)
                }
            }
            if counts.direct_count == 0 && counts.proxy_count == 0 {
                self.ip_action_counts.remove(&ip);
            }
        }
    }

    fn switch_ip_action(
        &mut self,
        ip: IpAddr,
        old_action: RoutingAction,
        new_action: RoutingAction,
    ) {
        if let Some(counts) = self.ip_action_counts.get_mut(&ip) {
            match old_action {
                RoutingAction::Direct => {
                    counts.direct_count = counts.direct_count.saturating_sub(1)
                }
                RoutingAction::Proxy => {
                    counts.proxy_count = counts.proxy_count.saturating_sub(1)
                }
            }
            match new_action {
                RoutingAction::Direct => counts.direct_count += 1,
                RoutingAction::Proxy => counts.proxy_count += 1,
            }
        }
    }

    /// Expire domain owners whose TTLs have passed.
    pub fn expire(&mut self, now: Instant) {
        self.prune_stale_heads();
        let mut affected_ips = HashSet::new();

        while let Some(Reverse(deadline)) = self.expiry_deadlines.peek() {
            if deadline.at > now {
                break;
            }
            let deadline = self.expiry_deadlines.pop().unwrap().0;
            self.expire_entry(&deadline, now, &mut affected_ips);
            self.prune_stale_heads();
        }

        if !affected_ips.is_empty() {
            self.recompute_ips(affected_ips);
        }
    }

    fn expire_entry(
        &mut self,
        deadline: &DeadlineEntry,
        now: Instant,
        affected_ips: &mut HashSet<IpAddr>,
    ) {
        self.expire_entry_internal(deadline, Some(now), affected_ips);
    }

    fn expire_entry_internal(
        &mut self,
        deadline: &DeadlineEntry,
        now: Option<Instant>,
        affected_ips: &mut HashSet<IpAddr>,
    ) {
        let (fully_expired, removed_ips) = match self
            .owners
            .get_mut(&deadline.domain)
        {
            Some(owner) => {
                let mut removed = Vec::new();
                match deadline.family {
                    AddressFamily::V4 => {
                        let should_expire = owner.v4_sequence == deadline.sequence
                            && match now {
                                Some(t) => {
                                    owner.v4_expires_at.is_some_and(|exp| exp <= t)
                                }
                                None => true, // Force eviction regardless of TTL
                            };
                        if should_expire {
                            for ip in &owner.v4_ips {
                                removed.push((*ip, owner.action));
                            }
                            owner.v4_ips.clear();
                            owner.v4_expires_at = None;
                        }
                    }
                    AddressFamily::V6 => {
                        let should_expire = owner.v6_sequence == deadline.sequence
                            && match now {
                                Some(t) => {
                                    owner.v6_expires_at.is_some_and(|exp| exp <= t)
                                }
                                None => true, // Force eviction regardless of TTL
                            };
                        if should_expire {
                            for ip in &owner.v6_ips {
                                removed.push((*ip, owner.action));
                            }
                            owner.v6_ips.clear();
                            owner.v6_expires_at = None;
                        }
                    }
                }
                let empty = owner.v4_ips.is_empty() && owner.v6_ips.is_empty();
                (empty, removed)
            }
            None => (false, Vec::new()),
        };

        for (ip, action) in removed_ips {
            self.remove_ip_ownership(&deadline.domain, ip, action);
            affected_ips.insert(ip);
        }

        if fully_expired {
            if let Some((domain_key, _)) = self.owners.remove_entry(&deadline.domain)
            {
                if now.is_some() {
                    tracing::info!(
                        "[eBPF DirectOffloader] Domain TTL expired and cleared: {}",
                        domain_key
                    );
                } else {
                    tracing::info!(
                        "[eBPF DirectOffloader] Domain evicted due to capacity limit: {}",
                        domain_key
                    );
                }
            }
        }
    }

    /// Enforce maximum desired IPs and domain owners capacity via Earliest-Deadline Eviction.
    fn enforce_capacity(&mut self) {
        let mut affected_ips = HashSet::new();
        while (self.desired.len() > self.max_desired_ips
            || self.owners.len() > self.max_owners)
            && !self.expiry_deadlines.is_empty()
        {
            self.prune_stale_heads();
            if let Some(Reverse(deadline)) = self.expiry_deadlines.pop() {
                self.expire_entry_internal(&deadline, None, &mut affected_ips);
                if !affected_ips.is_empty() {
                    let ips_to_recompute: Vec<_> = affected_ips.drain().collect();
                    self.recompute_ips(ips_to_recompute);
                }
            } else {
                break;
            }
        }
    }

    fn prune_stale_heads(&mut self) {
        while self.expiry_deadlines.peek().is_some_and(|entry| {
            let deadline = &entry.0;
            match self.owners.get(&deadline.domain) {
                Some(owner) => match deadline.family {
                    AddressFamily::V4 => {
                        owner.v4_sequence != deadline.sequence
                            || owner.v4_expires_at != Some(deadline.at)
                    }
                    AddressFamily::V6 => {
                        owner.v6_sequence != deadline.sequence
                            || owner.v6_expires_at != Some(deadline.at)
                    }
                },
                None => true,
            }
        }) {
            self.expiry_deadlines.pop();
        }
    }

    /// Recompute desired bypass status for given IPs in O(1) via ip_action_counts.
    /// Conflict resolution: if ANY owner requires PROXY, desired is None (bypass forbidden).
    fn recompute_ips(&mut self, ips: impl IntoIterator<Item = IpAddr>) {
        for ip in ips {
            let next_desired = if let Some(counts) = self.ip_action_counts.get(&ip) {
                if counts.proxy_count > 0 {
                    None
                } else if counts.direct_count > 0 {
                    Some(true)
                } else {
                    None
                }
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

#[derive(Debug)]
pub struct DnsObservation {
    pub domain: DomainKey,
    pub ips: Vec<IpAddr>,
    pub action: RoutingAction,
    pub ttl: std::time::Duration,
}

#[derive(Clone)]
pub struct DirectOffloader {
    tx: tokio::sync::mpsc::UnboundedSender<DnsObservation>,
    resolver: Weak<dyn ClashResolver>,
    bypass_dst_trie: Arc<CidrTrie>,
    proxy_dst_trie: Arc<CidrTrie>,
}

impl DirectOffloader {
    pub fn new(
        manager: Arc<tokio::sync::OnceCell<Arc<clash_ebpf::EbpfManager>>>,
        resolver: ThreadSafeDNSResolver,
        bypass_dst_trie: Arc<CidrTrie>,
        proxy_dst_trie: Arc<CidrTrie>,
    ) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DnsObservation>();

        tokio::spawn(async move {
            const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(1);
            const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

            let mut state = OffloadDesiredState::new();
            let mut retry_delay = INITIAL_RETRY_DELAY;
            let mut retry_at = None;

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

                    let has_updates = !add_v4.is_empty()
                        || !add_v6.is_empty()
                        || !del_v4.is_empty()
                        || !del_v6.is_empty();
                    let mut flush_succeeded = !has_updates;
                    if has_updates {
                        if let Some(mgr) = manager.get() {
                            if let Err(e) = mgr
                                .update_dynamic_bypass_batch(
                                    &add_v4, &add_v6, &del_v4, &del_v6,
                                )
                                .await
                            {
                                tracing::warn!(
                                    "eBPF dynamic bypass batch update failed: {e} (retrying in {retry_delay:?})"
                                );
                            } else {
                                flush_succeeded = true;
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

                let next_deadline = state.next_deadline();
                let next_wakeup = match (next_deadline, retry_at) {
                    (Some(deadline), Some(retry)) => Some(deadline.min(retry)),
                    (Some(deadline), None) => Some(deadline),
                    (None, Some(retry)) => Some(retry),
                    (None, None) => None,
                };

                tokio::select! {
                    observation = rx.recv() => {
                        match observation {
                            Some(obs) => {
                                let now = Instant::now();
                                let mut batch = vec![obs];
                                while let Ok(next_obs) = rx.try_recv() {
                                    batch.push(next_obs);
                                }
                                state.observe_batch(batch, now);
                            }
                            None => break,
                        }
                    }
                    _ = async {
                        if let Some(deadline) = next_wakeup {
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
            resolver: Arc::downgrade(&resolver),
            bypass_dst_trie,
            proxy_dst_trie,
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
        let mut effective_action = action;

        for ip in ips {
            let is_fake_ip = self
                .resolver
                .upgrade()
                .is_some_and(|resolver| resolver.is_fake_ip(ip));
            if is_reserved_ip(ip) || is_fake_ip {
                continue;
            }
            if self.proxy_dst_trie.contains(ip) {
                // Static PROXY destination IP configuration override: never allow dynamic bypass
                effective_action = RoutingAction::Proxy;
            } else if self.bypass_dst_trie.contains(ip) {
                // Static BYPASS already enforced by kernel BYPASS_DST_IPS, skip dynamic insertion
                continue;
            }
            valid_ips.push(ip);
        }
        if !valid_ips.is_empty() {
            let _ = self.tx.send(DnsObservation {
                domain,
                ips: valid_ips,
                action: effective_action,
                ttl,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::{MockClashResolver, ThreadSafeDNSResolver};

    fn observe_one(
        state: &mut OffloadDesiredState,
        domain: &str,
        ips: &[IpAddr],
        action: RoutingAction,
        ttl: std::time::Duration,
        now: Instant,
    ) {
        state.observe_batch(
            vec![DnsObservation {
                domain: domain.into(),
                ips: ips.to_vec(),
                action,
                ttl,
            }],
            now,
        );
    }

    #[tokio::test]
    async fn direct_offloader_does_not_retain_resolver() {
        let resolver: ThreadSafeDNSResolver = Arc::new(MockClashResolver::new());
        let weak_resolver = Arc::downgrade(&resolver);
        let manager = Arc::new(tokio::sync::OnceCell::new());

        let offloader = DirectOffloader::new(
            manager,
            resolver.clone(),
            Arc::new(CidrTrie::new()),
            Arc::new(CidrTrie::new()),
        );

        drop(resolver);
        assert!(
            weak_resolver.upgrade().is_none(),
            "the DNS hook/offloader relationship must not retain the resolver"
        );

        // Dropping the last sender closes the worker channel, allowing the
        // background reconciler to terminate instead of surviving a reload.
        drop(offloader);
        tokio::task::yield_now().await;
    }

    #[test]
    fn test_offload_desired_state_conflict_and_ttl() {
        let mut state = OffloadDesiredState::new();
        let now = Instant::now();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // 1. Observe DIRECT domain-a -> should be desired for offload
        observe_one(
            &mut state,
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
        observe_one(
            &mut state,
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
        observe_one(
            &mut state,
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
        assert!(state.ip_action_counts.is_empty());
    }

    #[test]
    fn test_offload_desired_state_batch_multiple_ips() {
        let mut state = OffloadDesiredState::new();
        let now = Instant::now();
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "1.1.1.2".parse().unwrap();
        let ip3: IpAddr = "2606:4700:4700::1111".parse().unwrap();

        // Observe multiple IPs for a single direct domain
        observe_one(
            &mut state,
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

    #[test]
    fn test_offload_desired_state_dual_stack_independent_ttl() {
        let mut state = OffloadDesiredState::new();
        let now = Instant::now();
        let ipv4: IpAddr = "1.2.3.4".parse().unwrap();
        let ipv6: IpAddr = "2001:db8::1".parse().unwrap();

        // 1. Receive A record for example.com with TTL = 300s
        observe_one(
            &mut state,
            "example.com",
            &[ipv4],
            RoutingAction::Direct,
            std::time::Duration::from_secs(300),
            now,
        );
        assert_eq!(state.desired.get(&ipv4), Some(&true));

        // 2. 1 second later, receive AAAA record for example.com with TTL = 60s
        let later_1s = now + std::time::Duration::from_secs(1);
        observe_one(
            &mut state,
            "example.com",
            &[ipv6],
            RoutingAction::Direct,
            std::time::Duration::from_secs(60),
            later_1s,
        );
        assert_eq!(state.desired.get(&ipv4), Some(&true));
        assert_eq!(state.desired.get(&ipv6), Some(&true));

        // 3. 62 seconds later: IPv6 expired, but IPv4 remains valid and bypassed!
        let later_62s = now + std::time::Duration::from_secs(62);
        state.expire(later_62s);
        assert_eq!(
            state.desired.get(&ipv4),
            Some(&true),
            "IPv4 must not be evicted prematurely by IPv6 TTL"
        );
        assert_eq!(state.desired.get(&ipv6), None, "IPv6 should have expired");

        // 4. 301 seconds later: IPv4 expires, owner completely cleaned up
        let later_301s = now + std::time::Duration::from_secs(301);
        state.expire(later_301s);
        assert_eq!(state.desired.get(&ipv4), None);
        assert!(state.owners.is_empty());
        assert!(state.reverse.is_empty());
        assert!(state.ip_action_counts.is_empty());
    }

    #[test]
    fn test_offload_desired_state_observe_batch() {
        let mut state = OffloadDesiredState::new();
        let now = Instant::now();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        let batch = vec![
            DnsObservation {
                domain: Arc::from("d1.com"),
                ips: vec![ip1],
                action: RoutingAction::Direct,
                ttl: std::time::Duration::from_secs(100),
            },
            DnsObservation {
                domain: Arc::from("d2.com"),
                ips: vec![ip2],
                action: RoutingAction::Direct,
                ttl: std::time::Duration::from_secs(100),
            },
        ];

        state.observe_batch(batch, now);
        assert_eq!(state.desired.get(&ip1), Some(&true));
        assert_eq!(state.desired.get(&ip2), Some(&true));
        assert_eq!(state.dirty_ips.len(), 2);
    }

    #[test]
    fn test_offload_desired_state_capacity_limit_eviction() {
        // Limit capacity to 2 IPs / 2 owners
        let mut state = OffloadDesiredState::with_capacity(2, 2);
        let now = Instant::now();
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();
        let ip3: IpAddr = "3.3.3.3".parse().unwrap();

        // 1. Insert domain 1 with shortest TTL (100s)
        observe_one(
            &mut state,
            "d1.com",
            &[ip1],
            RoutingAction::Direct,
            std::time::Duration::from_secs(100),
            now,
        );
        // 2. Insert domain 2 with medium TTL (200s)
        observe_one(
            &mut state,
            "d2.com",
            &[ip2],
            RoutingAction::Direct,
            std::time::Duration::from_secs(200),
            now,
        );

        assert_eq!(state.desired.len(), 2);
        assert_eq!(state.desired.get(&ip1), Some(&true));
        assert_eq!(state.desired.get(&ip2), Some(&true));

        // 3. Insert domain 3 with longest TTL (300s) -> triggers capacity eviction!
        // d1.com has the earliest deadline, so it should be evicted first.
        observe_one(
            &mut state,
            "d3.com",
            &[ip3],
            RoutingAction::Direct,
            std::time::Duration::from_secs(300),
            now,
        );

        assert_eq!(
            state.desired.len(),
            2,
            "Capacity must be capped at max_desired_ips"
        );
        assert_eq!(state.owners.len(), 2, "Owners must be capped at max_owners");
        assert_eq!(
            state.desired.get(&ip1),
            None,
            "Earliest expiring domain (d1) should be evicted"
        );
        assert_eq!(state.desired.get(&ip2), Some(&true));
        assert_eq!(state.desired.get(&ip3), Some(&true));
    }
}
