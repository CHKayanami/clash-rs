use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::mem::swap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::warn;

use super::{DomainKey, RoutingAction};

#[derive(Debug, Clone, PartialEq, Eq)]
enum EvictKey {
    Domain(DomainKey),
    DirectIp(IpAddr),
}

#[derive(Clone, Copy)]
enum OwnerRef<'a> {
    Domain(&'a str),
    DirectIp(IpAddr),
}

enum EvictCandidate<'a> {
    Domain(&'a DomainKey, &'a DomainOwner),
    DirectIp(IpAddr, &'a DirectIpOwner),
}

impl EvictCandidate<'_> {
    fn last_seen(&self) -> u64 {
        match self {
            Self::Domain(_, owner) => owner.last_seen,
            Self::DirectIp(_, owner) => owner.last_seen,
        }
    }

    fn to_evict_key(&self) -> EvictKey {
        match self {
            Self::Domain(domain, _) => EvictKey::Domain((*domain).clone()),
            Self::DirectIp(ip, _) => EvictKey::DirectIp(*ip),
        }
    }

    fn any_ip(&self, mut predicate: impl FnMut(IpAddr) -> bool) -> bool {
        match self {
            Self::Domain(_, owner) => owner
                .v4_ips
                .iter()
                .chain(&owner.v6_ips)
                .any(|&ip| predicate(ip)),
            Self::DirectIp(ip, _) => predicate(*ip),
        }
    }

    fn for_each_ip(&self, mut f: impl FnMut(IpAddr)) {
        match self {
            Self::Domain(_, owner) => {
                for &ip in owner.v4_ips.iter().chain(&owner.v6_ips) {
                    f(ip);
                }
            }
            Self::DirectIp(ip, _) => f(*ip),
        }
    }
}

struct DomainOwner {
    v4_ips: Vec<IpAddr>,
    v6_ips: Vec<IpAddr>,
    action: RoutingAction,
    outbound: Option<Arc<str>>,
    rule_offloadable: bool,
    last_seen: u64,
}

struct DirectIpOwner {
    action: RoutingAction,
    outbound: Option<Arc<str>>,
    rule_offloadable: bool,
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
// Reserve separate headroom for pure-IP route owners so P2P/IP traffic cannot starve domain owners.
const DEFAULT_MAX_DIRECT_IP_OWNERS: usize = DEFAULT_MAX_OWNERS / 2;
// Cap incremental route-discovered IPs per family for a single domain.
const MAX_ROUTE_IPS_PER_FAMILY: usize = 16;
// Reserve one tenth of each capacity to avoid evicting on every new observation.
const EVICTION_RESERVE_DIVISOR: usize = 10;

fn eviction_batch(max_ips: usize) -> usize {
    (max_ips / EVICTION_RESERVE_DIVISOR).max(1)
}

/// DNS observations replace the addresses of the observed family. An unobserved
/// family keeps its last state. No DNS TTL is used to change kernel bypass state.
pub(super) struct OffloadDesiredState {
    max_v4_ips: usize,
    max_v6_ips: usize,
    max_owners: usize,
    max_direct_ip_owners: usize,
    sequence: u64,
    domain_owners: HashMap<DomainKey, DomainOwner>,
    direct_ip_owners: HashMap<IpAddr, DirectIpOwner>,
    ip_action_counts: HashMap<IpAddr, IpActionCounts>,
    tracked_v4: usize,
    tracked_v6: usize,
    // Trigger proactive reclaim only when free capacity crosses below the threshold.
    reclaim_armed_v4: bool,
    reclaim_armed_v6: bool,
    pub(super) desired: HashSet<IpAddr>,
    pub(super) applied: HashSet<IpAddr>,
    pub(super) dirty_ips: HashSet<IpAddr>,
}

impl OffloadDesiredState {
    pub(super) fn new() -> Self {
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
        Self::with_limits(
            max_v4_ips,
            max_v6_ips,
            max_owners,
            (max_owners / 2).max(1).min(DEFAULT_MAX_DIRECT_IP_OWNERS),
        )
    }

    fn with_limits(
        max_v4_ips: usize,
        max_v6_ips: usize,
        max_owners: usize,
        max_direct_ip_owners: usize,
    ) -> Self {
        Self {
            max_v4_ips,
            max_v6_ips,
            max_owners,
            max_direct_ip_owners,
            sequence: 0,
            domain_owners: HashMap::new(),
            direct_ip_owners: HashMap::new(),
            ip_action_counts: HashMap::new(),
            tracked_v4: 0,
            tracked_v6: 0,
            reclaim_armed_v4: true,
            reclaim_armed_v6: true,
            desired: HashSet::new(),
            applied: HashSet::new(),
            dirty_ips: HashSet::new(),
        }
    }

    fn total_owners(&self) -> usize {
        self.domain_owners.len() + self.direct_ip_owners.len()
    }

    pub(super) fn observe(
        &mut self,
        observation: Observation,
        affected: &mut HashSet<IpAddr>,
    ) {
        match observation {
            Observation::Dns(obs) => self.observe_dns_one(obs, affected),
            Observation::RouteDomain(obs) => self.observe_route_domain_one(obs, affected),
            Observation::RouteIp(obs) => self.observe_route_ip_one(obs, affected),
        }
    }

    fn observe_dns_one(&mut self, obs: DnsObservation, affected: &mut HashSet<IpAddr>) {
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

        if let Some(owner) = self.domain_owners.get_mut(&obs.domain) {
            if owner.action == obs.action
                && (!has_v4 || owner.v4_ips == incoming_v4)
                && (!has_v6 || owner.v6_ips == incoming_v6)
            {
                self.sequence = self.sequence.wrapping_add(1);
                owner.last_seen = self.sequence;
                owner.outbound = obs.outbound;
                owner.rule_offloadable = obs.rule_offloadable;
                return;
            }
        }

        self.sequence = self.sequence.wrapping_add(1);
        let owner = DomainOwner {
            v4_ips: incoming_v4,
            v6_ips: incoming_v6,
            action: obs.action,
            outbound: obs.outbound,
            rule_offloadable: obs.rule_offloadable,
            last_seen: self.sequence,
        };
        self.update_domain_owner(obs.domain, owner, affected);
    }

    fn observe_route_domain_one(
        &mut self,
        obs: RouteDomainObservation,
        affected: &mut HashSet<IpAddr>,
    ) {
        let is_v4 = obs.ip.is_ipv4();
        let ips = if let Some(owner) = self.domain_owners.get_mut(&obs.domain) {
            let list = if is_v4 { &owner.v4_ips } else { &owner.v6_ips };
            match list.binary_search(&obs.ip) {
                Ok(_) if owner.action == obs.action => {
                    self.sequence = self.sequence.wrapping_add(1);
                    owner.last_seen = self.sequence;
                    owner.outbound = Some(obs.outbound);
                    owner.rule_offloadable = obs.rule_offloadable;
                    return;
                }
                Ok(_) => Vec::new(),
                Err(mut position) => {
                    let mut ips = list.clone();
                    if ips.len() >= MAX_ROUTE_IPS_PER_FAMILY {
                        ips.remove(0);
                        position = position.saturating_sub(1);
                    }
                    ips.insert(position, obs.ip);
                    ips
                }
            }
        } else {
            vec![obs.ip]
        };

        let (v4_ips, v6_ips) = if is_v4 {
            (ips, Vec::new())
        } else {
            (Vec::new(), ips)
        };
        self.sequence = self.sequence.wrapping_add(1);
        let owner = DomainOwner {
            v4_ips,
            v6_ips,
            action: obs.action,
            outbound: Some(obs.outbound),
            rule_offloadable: obs.rule_offloadable,
            last_seen: self.sequence,
        };
        self.update_domain_owner(obs.domain, owner, affected);
    }

    /// Empty incoming families retain their existing addresses.
    fn update_domain_owner(
        &mut self,
        domain: DomainKey,
        mut owner: DomainOwner,
        affected: &mut HashSet<IpAddr>,
    ) {
        let Some(mut previous) = self.domain_owners.remove(&domain) else {
            self.insert_domain_owner_checked(domain, owner, None, affected);
            return;
        };

        let keep_v4 = owner.v4_ips.is_empty();
        let keep_v6 = owner.v6_ips.is_empty();
        let action_changed = owner.action != previous.action;
        if action_changed {
            self.change_domain_owner_counts(&previous, false, affected);
        } else {
            if !keep_v4 {
                self.change_ip_list(&previous.v4_ips, &owner.v4_ips, owner.action, affected);
            }
            if !keep_v6 {
                self.change_ip_list(&previous.v6_ips, &owner.v6_ips, owner.action, affected);
            }
        }
        if keep_v4 {
            swap(&mut previous.v4_ips, &mut owner.v4_ips);
        }
        if keep_v6 {
            swap(&mut previous.v6_ips, &mut owner.v6_ips);
        }
        if action_changed {
            self.change_domain_owner_counts(&owner, true, affected);
        }

        self.domain_owners.insert(domain.clone(), owner);
        if !self.enforce_capacity(OwnerRef::Domain(&domain), affected) {
            // Recover the unchanged families from the rejected owner before restoring.
            let mut rejected = self
                .remove_domain_owner_returning(&domain, affected)
                .expect("capacity enforcement keeps the observed owner");
            if keep_v4 {
                swap(&mut previous.v4_ips, &mut rejected.v4_ips);
            }
            if keep_v6 {
                swap(&mut previous.v6_ips, &mut rejected.v6_ips);
            }
            self.insert_domain_owner(domain, previous, affected);
        }
    }

    fn change_ip_list(
        &mut self,
        mut previous: &[IpAddr],
        mut incoming: &[IpAddr],
        action: RoutingAction,
        affected: &mut HashSet<IpAddr>,
    ) {
        while let (Some((&old, old_tail)), Some((&new, new_tail))) =
            (previous.split_first(), incoming.split_first())
        {
            match old.cmp(&new) {
                Ordering::Less => {
                    self.change_count(old, action, false);
                    affected.insert(old);
                    previous = old_tail;
                }
                Ordering::Greater => {
                    self.change_count(new, action, true);
                    affected.insert(new);
                    incoming = new_tail;
                }
                Ordering::Equal => {
                    previous = old_tail;
                    incoming = new_tail;
                }
            }
        }
        for (&ip, add) in previous
            .iter()
            .map(|ip| (ip, false))
            .chain(incoming.iter().map(|ip| (ip, true)))
        {
            self.change_count(ip, action, add);
            affected.insert(ip);
        }
    }

    fn observe_route_ip_one(
        &mut self,
        obs: RouteIpObservation,
        affected: &mut HashSet<IpAddr>,
    ) {
        if let Some(existing) = self.direct_ip_owners.get_mut(&obs.ip)
            && existing.action == obs.action
        {
            self.sequence = self.sequence.wrapping_add(1);
            existing.last_seen = self.sequence;
            existing.outbound = Some(obs.outbound);
            existing.rule_offloadable = obs.rule_offloadable;
            return;
        }

        let previous = self.remove_direct_ip_owner_returning(obs.ip, affected);
        // A proxy observation only vetoes an IP another owner still tracks.
        if obs.action == RoutingAction::Proxy && !self.ip_action_counts.contains_key(&obs.ip) {
            return;
        }
        self.sequence = self.sequence.wrapping_add(1);
        let owner = DirectIpOwner {
            action: obs.action,
            outbound: Some(obs.outbound),
            rule_offloadable: obs.rule_offloadable,
            last_seen: self.sequence,
        };
        self.insert_direct_ip_owner_checked(obs.ip, owner, previous, affected);
    }

    fn insert_domain_owner_checked(
        &mut self,
        domain: DomainKey,
        owner: DomainOwner,
        previous: Option<DomainOwner>,
        affected: &mut HashSet<IpAddr>,
    ) {
        self.insert_domain_owner(domain.clone(), owner, affected);
        if !self.enforce_capacity(OwnerRef::Domain(&domain), affected) {
            self.remove_domain_owner(&domain, affected);
            if let Some(old) = previous {
                self.insert_domain_owner(domain, old, affected);
            }
        }
    }

    fn insert_domain_owner(
        &mut self,
        domain: DomainKey,
        owner: DomainOwner,
        affected: &mut HashSet<IpAddr>,
    ) {
        self.change_domain_owner_counts(&owner, true, affected);
        self.domain_owners.insert(domain, owner);
    }

    fn insert_direct_ip_owner_checked(
        &mut self,
        ip: IpAddr,
        owner: DirectIpOwner,
        previous: Option<DirectIpOwner>,
        affected: &mut HashSet<IpAddr>,
    ) {
        self.insert_direct_ip_owner(ip, owner, affected);
        if !self.enforce_capacity(OwnerRef::DirectIp(ip), affected) {
            self.remove_direct_ip_owner(ip, affected);
            if let Some(old) = previous {
                self.insert_direct_ip_owner(ip, old, affected);
            }
        }
    }

    fn insert_direct_ip_owner(
        &mut self,
        ip: IpAddr,
        owner: DirectIpOwner,
        affected: &mut HashSet<IpAddr>,
    ) {
        self.change_count(ip, owner.action, true);
        affected.insert(ip);
        self.direct_ip_owners.insert(ip, owner);
    }

    fn change_domain_owner_counts(
        &mut self,
        owner: &DomainOwner,
        add: bool,
        affected: &mut HashSet<IpAddr>,
    ) {
        for &ip in owner.v4_ips.iter().chain(&owner.v6_ips) {
            self.change_count(ip, owner.action, add);
            affected.insert(ip);
        }
    }

    fn remove_domain_owner_returning(
        &mut self,
        domain: &DomainKey,
        affected: &mut HashSet<IpAddr>,
    ) -> Option<DomainOwner> {
        let owner = self.domain_owners.remove(domain)?;
        self.change_domain_owner_counts(&owner, false, affected);
        Some(owner)
    }

    fn remove_domain_owner(&mut self, domain: &DomainKey, affected: &mut HashSet<IpAddr>) {
        let _ = self.remove_domain_owner_returning(domain, affected);
    }

    fn remove_direct_ip_owner_returning(
        &mut self,
        ip: IpAddr,
        affected: &mut HashSet<IpAddr>,
    ) -> Option<DirectIpOwner> {
        let owner = self.direct_ip_owners.remove(&ip)?;
        self.change_count(ip, owner.action, false);
        affected.insert(ip);
        Some(owner)
    }

    fn remove_direct_ip_owner(&mut self, ip: IpAddr, affected: &mut HashSet<IpAddr>) {
        let _ = self.remove_direct_ip_owner_returning(ip, affected);
    }

    fn remove_evict_key(&mut self, key: &EvictKey, affected: &mut HashSet<IpAddr>) {
        match key {
            EvictKey::Domain(domain) => self.remove_domain_owner(domain, affected),
            EvictKey::DirectIp(ip) => self.remove_direct_ip_owner(*ip, affected),
        }
    }

    pub(super) fn reconcile_outbounds(
        &mut self,
        outbound_actions: &HashMap<Arc<str>, RoutingAction>,
    ) {
        let mut domain_updates = Vec::new();
        for (domain, owner) in &self.domain_owners {
            if !owner.rule_offloadable {
                continue;
            }
            let Some(outbound) = &owner.outbound else {
                continue;
            };
            let Some(&new_action) = outbound_actions.get(outbound) else {
                continue;
            };
            if new_action != owner.action {
                domain_updates.push((domain.clone(), new_action));
            }
        }

        let mut ip_updates = Vec::new();
        for (&ip, owner) in &self.direct_ip_owners {
            if !owner.rule_offloadable {
                continue;
            }
            let Some(outbound) = &owner.outbound else {
                continue;
            };
            let Some(&new_action) = outbound_actions.get(outbound) else {
                continue;
            };
            if new_action != owner.action {
                ip_updates.push((ip, new_action));
            }
        }

        if domain_updates.is_empty() && ip_updates.is_empty() {
            return;
        }

        let mut affected = HashSet::new();
        for (domain, new_action) in domain_updates {
            if let Some(mut owner) = self.domain_owners.remove(&domain) {
                let old_action = owner.action;
                for &ip in owner.v4_ips.iter().chain(&owner.v6_ips) {
                    self.change_count(ip, old_action, false);
                    self.change_count(ip, new_action, true);
                    affected.insert(ip);
                }
                owner.action = new_action;
                self.domain_owners.insert(domain, owner);
            }
        }

        for (ip, new_action) in ip_updates {
            if new_action == RoutingAction::Proxy {
                let old = self.remove_direct_ip_owner_returning(ip, &mut affected);
                if self.ip_action_counts.contains_key(&ip)
                    && let Some(old) = old
                {
                    self.sequence = self.sequence.wrapping_add(1);
                    let proxy_owner = DirectIpOwner {
                        action: RoutingAction::Proxy,
                        outbound: old.outbound,
                        rule_offloadable: old.rule_offloadable,
                        last_seen: self.sequence,
                    };
                    self.insert_direct_ip_owner_checked(
                        ip,
                        proxy_owner,
                        None,
                        &mut affected,
                    );
                }
            } else if let Some(owner) = self.direct_ip_owners.get_mut(&ip) {
                let old_action = owner.action;
                owner.action = new_action;
                self.change_count(ip, old_action, false);
                self.change_count(ip, new_action, true);
                affected.insert(ip);
            }
        }

        self.recompute_ips(affected);
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
                    warn!("eBPF offloader tracked IP count overflow for {ip}");
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
                    warn!("eBPF offloader owner count overflow for {ip}");
                }
            }
            (false, Entry::Vacant(_)) => {
                warn!("eBPF offloader tried to remove an unknown owner for {ip}");
            }
            (false, Entry::Occupied(mut entry)) => {
                let counts = entry.get_mut();
                let count = match action {
                    RoutingAction::Direct => &mut counts.direct,
                    RoutingAction::Proxy => &mut counts.proxy,
                };
                let Some(next) = count.checked_sub(1) else {
                    warn!("eBPF offloader owner count underflow for {ip}");
                    return;
                };
                *count = next;
                if counts.direct == 0 && counts.proxy == 0 {
                    entry.remove();
                    if let Some(next) = tracked.checked_sub(1) {
                        *tracked = next;
                    } else {
                        warn!("eBPF offloader tracked IP count underflow for {ip}");
                    }
                }
            }
        }
    }

    /// Plan shared-IP evictions before applying them. An IP only frees capacity
    /// when its last owner is removed. The caller rolls back a rejected owner.
    fn enforce_capacity(
        &mut self,
        observed: OwnerRef<'_>,
        affected: &mut HashSet<IpAddr>,
    ) -> bool {
        if matches!(observed, OwnerRef::DirectIp(_)) && self.max_direct_ip_owners == 0 {
            return false;
        }

        let excess_direct_ip = self
            .direct_ip_owners
            .len()
            .saturating_sub(self.max_direct_ip_owners);
        if excess_direct_ip > 0 {
            let target_direct_ip =
                excess_direct_ip.max(eviction_batch(self.max_direct_ip_owners));
            let observed_ip = match observed {
                OwnerRef::DirectIp(ip) => Some(ip),
                OwnerRef::Domain(_) => None,
            };
            let mut direct_candidates: Vec<_> = self
                .direct_ip_owners
                .iter()
                .filter_map(|(&ip, owner)| {
                    (observed_ip != Some(ip)).then_some((owner.last_seen, ip))
                })
                .collect();
            let evict_count = target_direct_ip.min(direct_candidates.len());
            if evict_count < direct_candidates.len() {
                direct_candidates.select_nth_unstable_by_key(evict_count, |(seen, _)| *seen);
            }
            for (_, ip) in direct_candidates.into_iter().take(evict_count) {
                self.remove_direct_ip_owner(ip, affected);
            }
            if self.direct_ip_owners.len() > self.max_direct_ip_owners {
                return false;
            }
        }

        let fits = |owners: usize, v4: usize, v6: usize| {
            owners <= self.max_owners
                && v4 <= self.max_v4_ips
                && v6 <= self.max_v6_ips
        };
        if fits(self.total_owners(), self.tracked_v4, self.tracked_v6) {
            return true;
        }

        let (obs_v4, obs_v6) = match observed {
            OwnerRef::Domain(domain) => {
                let Some(owner) = self.domain_owners.get(domain) else {
                    return false;
                };
                (owner.v4_ips.len(), owner.v6_ips.len())
            }
            OwnerRef::DirectIp(ip) => {
                if !self.direct_ip_owners.contains_key(&ip) {
                    return false;
                }
                if ip.is_ipv4() { (1, 0) } else { (0, 1) }
            }
        };
        if self.max_owners == 0 || obs_v4 > self.max_v4_ips || obs_v6 > self.max_v6_ips {
            return false;
        }

        let excess_owners = self.total_owners().saturating_sub(self.max_owners);
        let target_owners = if excess_owners > 0 {
            excess_owners.max(eviction_batch(self.max_owners))
        } else {
            0
        };
        let excess_v4 = self.tracked_v4.saturating_sub(self.max_v4_ips);
        let excess_v6 = self.tracked_v6.saturating_sub(self.max_v6_ips);
        if excess_v4 == 0 && excess_v6 == 0 {
            let mut candidates: Vec<_> = self
                .domain_owners
                .iter()
                .filter(|(domain, _)| {
                    !matches!(observed, OwnerRef::Domain(obs) if obs == domain.as_ref())
                })
                .map(|(domain, owner)| (owner.last_seen, EvictCandidate::Domain(domain, owner)))
                .chain(
                    self.direct_ip_owners
                        .iter()
                        .filter(|(ip, _)| {
                            !matches!(observed, OwnerRef::DirectIp(obs) if obs == **ip)
                        })
                        .map(|(&ip, owner)| {
                            (owner.last_seen, EvictCandidate::DirectIp(ip, owner))
                        }),
                )
                .collect();
            if candidates.len() < target_owners {
                return false;
            }
            candidates
                .select_nth_unstable_by_key(target_owners - 1, |(seen, _)| *seen);
            let evictions: Vec<_> = candidates[..target_owners]
                .iter()
                .map(|(_, candidate)| candidate.to_evict_key())
                .collect();
            for key in evictions {
                self.remove_evict_key(&key, affected);
            }
            return true;
        }
        let batch_v4 = eviction_batch(self.max_v4_ips);
        let batch_v6 = eviction_batch(self.max_v6_ips);
        let target_v4 = if excess_v4 > 0 {
            excess_v4.max(batch_v4)
        } else {
            0
        };
        let target_v6 = if excess_v6 > 0 {
            excess_v6.max(batch_v6)
        } else {
            0
        };
        let Some(evictions) =
            self.plan_evictions(Some(observed), target_owners, target_v4, target_v6)
        else {
            return false;
        };
        for key in evictions {
            self.remove_evict_key(&key, affected);
        }
        true
    }

    fn plan_evictions(
        &self,
        protected: Option<OwnerRef<'_>>,
        target_owners: usize,
        target_v4: usize,
        target_v6: usize,
    ) -> Option<Vec<EvictKey>> {
        let fits = |owners: usize, v4: usize, v6: usize| {
            owners <= self.max_owners
                && v4 <= self.max_v4_ips
                && v6 <= self.max_v6_ips
        };
        let mut candidates: Vec<_> = self
            .domain_owners
            .iter()
            .filter(|(domain, _)| {
                !matches!(protected, Some(OwnerRef::Domain(prot)) if prot == domain.as_ref())
            })
            .map(|(domain, owner)| EvictCandidate::Domain(domain, owner))
            .chain(
                self.direct_ip_owners
                    .iter()
                    .filter(|(ip, _)| {
                        !matches!(protected, Some(OwnerRef::DirectIp(prot)) if prot == **ip)
                    })
                    .map(|(&ip, owner)| EvictCandidate::DirectIp(ip, owner)),
            )
            .collect();
        candidates.sort_unstable_by_key(EvictCandidate::last_seen);

        let mut remaining_owners = self.total_owners();
        let mut remaining_v4 = self.tracked_v4;
        let mut remaining_v6 = self.tracked_v6;
        let mut remaining_counts = HashMap::<IpAddr, usize>::new();
        let mut evictions = Vec::new();
        loop {
            let mut deferred = Vec::new();
            let mut progressed = false;
            for candidate in candidates.drain(..) {
                let need_owner = evictions.len() < target_owners;
                let need_v4 =
                    self.tracked_v4.saturating_sub(remaining_v4) < target_v4;
                let need_v6 =
                    self.tracked_v6.saturating_sub(remaining_v6) < target_v6;
                if fits(remaining_owners, remaining_v4, remaining_v6)
                    && !need_owner
                    && !need_v4
                    && !need_v6
                {
                    break;
                }
                let frees_needed_ip = !need_owner
                    && candidate.any_ip(|ip| {
                        ((ip.is_ipv4() && need_v4) || (ip.is_ipv6() && need_v6))
                            && remaining_counts.get(&ip).copied().unwrap_or_else(
                                || {
                                    self.ip_action_counts
                                        .get(&ip)
                                        .map(|counts| {
                                            usize::from(counts.direct)
                                                + usize::from(counts.proxy)
                                        })
                                        .unwrap_or(0)
                                },
                            ) == 1
                    });
                if !frees_needed_ip
                    && !need_owner
                    && remaining_owners <= self.max_owners
                {
                    deferred.push(candidate);
                    continue;
                }
                candidate.for_each_ip(|ip| {
                    let remaining =
                        remaining_counts.entry(ip).or_insert_with(|| {
                            self.ip_action_counts
                                .get(&ip)
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
                });
                remaining_owners = remaining_owners.saturating_sub(1);
                evictions.push(candidate.to_evict_key());
                progressed = true;
            }
            if !progressed {
                break;
            }
            candidates = deferred;
        }

        if fits(remaining_owners, remaining_v4, remaining_v6) {
            Some(evictions)
        } else {
            None
        }
    }

    /// Reclaim room after a successful kernel flush, outside DNS observation processing.
    pub(super) fn reclaim_headroom(&mut self) {
        let batch_v4 = eviction_batch(self.max_v4_ips);
        let batch_v6 = eviction_batch(self.max_v6_ips);
        let free_v4 = self.max_v4_ips.saturating_sub(self.tracked_v4);
        let free_v6 = self.max_v6_ips.saturating_sub(self.tracked_v6);
        if free_v4 >= batch_v4 {
            self.reclaim_armed_v4 = true;
        }
        if free_v6 >= batch_v6 {
            self.reclaim_armed_v6 = true;
        }
        let target_v4 = if free_v4 < batch_v4 && self.reclaim_armed_v4 {
            self.reclaim_armed_v4 = false;
            batch_v4
        } else {
            0
        };
        let target_v6 = if free_v6 < batch_v6 && self.reclaim_armed_v6 {
            self.reclaim_armed_v6 = false;
            batch_v6
        } else {
            0
        };
        if target_v4 == 0 && target_v6 == 0 {
            return;
        }

        // Keep the most recently observed owner so cleanup cannot undo its fresh update.
        let latest_domain = self
            .domain_owners
            .iter()
            .max_by_key(|(_, owner)| owner.last_seen)
            .map(|(domain, owner)| (owner.last_seen, OwnerRef::Domain(domain.as_ref())));
        let latest_ip = self
            .direct_ip_owners
            .iter()
            .max_by_key(|(_, owner)| owner.last_seen)
            .map(|(&ip, owner)| (owner.last_seen, OwnerRef::DirectIp(ip)));
        let protected = match (latest_domain, latest_ip) {
            (Some(d), Some(i)) => Some(if d.0 >= i.0 { d.1 } else { i.1 }),
            (Some(d), None) => Some(d.1),
            (None, Some(i)) => Some(i.1),
            (None, None) => None,
        };
        let Some(evictions) =
            self.plan_evictions(protected, 0, target_v4, target_v6)
        else {
            return;
        };
        let mut affected = HashSet::new();
        for key in evictions {
            self.remove_evict_key(&key, &mut affected);
        }
        self.recompute_ips(affected);
        if self.max_v4_ips.saturating_sub(self.tracked_v4) >= batch_v4 {
            self.reclaim_armed_v4 = true;
        }
        if self.max_v6_ips.saturating_sub(self.tracked_v6) >= batch_v6 {
            self.reclaim_armed_v6 = true;
        }
    }

    pub(super) fn recompute_ips(&mut self, ips: impl IntoIterator<Item = IpAddr>) {
        for ip in ips {
            let direct = self
                .ip_action_counts
                .get(&ip)
                .is_some_and(|counts| counts.direct > 0 && counts.proxy == 0);
            let changed = if direct {
                self.desired.insert(ip)
            } else {
                self.desired.remove(&ip)
            };
            if changed {
                self.dirty_ips.insert(ip);
            }
        }
    }
}

#[derive(Debug)]
pub(super) enum Observation {
    Dns(DnsObservation),
    RouteDomain(RouteDomainObservation),
    RouteIp(RouteIpObservation),
}

impl Observation {
    pub(super) fn route_reconcile_key(&self) -> Option<(&Arc<str>, RoutingAction)> {
        match self {
            Self::Dns(obs) if obs.rule_offloadable => {
                obs.outbound.as_ref().map(|outbound| (outbound, obs.action))
            }
            Self::RouteDomain(obs) if obs.rule_offloadable => {
                Some((&obs.outbound, obs.action))
            }
            Self::RouteIp(obs) if obs.rule_offloadable => {
                Some((&obs.outbound, obs.action))
            }
            _ => None,
        }
    }

    pub(super) fn set_action(&mut self, action: RoutingAction) {
        match self {
            Self::Dns(obs) => obs.action = action,
            Self::RouteDomain(obs) => obs.action = action,
            Self::RouteIp(obs) => obs.action = action,
        }
    }
}

#[derive(Debug)]
pub(super) struct DnsObservation {
    pub(super) domain: DomainKey,
    pub(super) ips: Vec<IpAddr>,
    pub(super) action: RoutingAction,
    pub(super) outbound: Option<Arc<str>>,
    pub(super) rule_offloadable: bool,
}

#[derive(Debug)]
pub(super) struct RouteDomainObservation {
    pub(super) domain: DomainKey,
    pub(super) ip: IpAddr,
    pub(super) action: RoutingAction,
    pub(super) outbound: Arc<str>,
    pub(super) rule_offloadable: bool,
}

#[derive(Debug)]
pub(super) struct RouteIpObservation {
    pub(super) ip: IpAddr,
    pub(super) action: RoutingAction,
    pub(super) outbound: Arc<str>,
    pub(super) rule_offloadable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    impl OffloadDesiredState {
        fn observe_batch(&mut self, observations: impl IntoIterator<Item = Observation>) {
            let mut affected = HashSet::new();
            for observation in observations {
                self.observe(observation, &mut affected);
            }
            self.recompute_ips(affected);
        }
    }

    fn domain_key(domain: &str) -> DomainKey {
        domain.into()
    }

    fn observe(
        state: &mut OffloadDesiredState,
        domain: &str,
        ips: &[IpAddr],
        action: RoutingAction,
    ) {
        state.observe_batch([Observation::Dns(DnsObservation {
            domain: domain.into(),
            ips: ips.to_vec(),
            action,
            outbound: None,
            rule_offloadable: true,
        })]);
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
        let last_seen = state.domain_owners.get(&domain_key("a.com")).unwrap().last_seen;

        observe(&mut state, "a.com", &[a, b], RoutingAction::Direct);
        assert!(state.dirty_ips.is_empty());
        assert_eq!(state.tracked_v4, 2);
        assert_eq!(state.ip_action_counts.get(&a).unwrap().direct, 1);
        assert!(state.domain_owners.get(&domain_key("a.com")).unwrap().last_seen > last_seen);
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
    fn shared_ip_capacity_skips_oldest_owner_when_it_cannot_release_ip() {
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
        assert!(state.domain_owners.contains_key(&domain_key("a.com")));
        assert!(!state.domain_owners.contains_key(&domain_key("b.com")));
        assert!(state.domain_owners.contains_key(&domain_key("c.com")));
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
        assert!(state.domain_owners.contains_key(&domain_key("a.com")));
        assert!(state.domain_owners.contains_key(&domain_key("b.com")));
        assert!(!state.domain_owners.contains_key(&domain_key("c.com")));
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
    fn dns_update_only_touches_changed_addresses() {
        let mut state = OffloadDesiredState::new();
        let [shared, retained, added, v6]: [IpAddr; 4] =
            ["1.1.1.1", "1.1.1.2", "1.1.1.3", "2001:db8::1"]
                .map(|ip| ip.parse().unwrap());
        observe(&mut state, "a.com", &[shared, retained, v6], RoutingAction::Direct);
        observe(&mut state, "b.com", &[shared], RoutingAction::Direct);
        state.dirty_ips.clear();

        let mut affected = HashSet::new();
        state.observe(
            Observation::Dns(DnsObservation {
                domain: "a.com".into(),
                ips: vec![added, retained],
                action: RoutingAction::Direct,
                outbound: None,
                rule_offloadable: true,
            }),
            &mut affected,
        );

        assert_eq!(affected, HashSet::from([shared, added]));
        assert_eq!(state.ip_action_counts[&shared].direct, 1);
        let owner = &state.domain_owners[&domain_key("a.com")];
        assert_eq!(owner.v4_ips, [retained, added]);
        assert_eq!(owner.v6_ips, [v6]);
        state.recompute_ips(affected);
        assert_eq!(state.dirty_ips, HashSet::from([added]));
    }

    #[test]
    fn rejected_update_restores_existing_domain() {
        let mut state = OffloadDesiredState::with_capacity(1, 1, 3);
        let shared: IpAddr = "1.1.1.1".parse().unwrap();
        let new_ip: IpAddr = "2.2.2.2".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        observe(&mut state, "a.com", &[shared], RoutingAction::Direct);
        observe(&mut state, "b.com", &[shared, v6], RoutingAction::Direct);
        state.dirty_ips.clear();

        observe(
            &mut state,
            "b.com",
            &[shared, new_ip],
            RoutingAction::Direct,
        );
        assert_eq!(state.desired, HashSet::from([shared, v6]));
        assert!(state.domain_owners.contains_key(&domain_key("a.com")));
        assert!(state.domain_owners.contains_key(&domain_key("b.com")));
        assert!(!state.domain_owners.get(&domain_key("b.com")).unwrap().v4_ips.contains(&new_ip));
        assert_eq!(state.domain_owners[&domain_key("b.com")].v6_ips, [v6]);
        assert_eq!(state.ip_action_counts[&shared].direct, 2);
        assert_eq!(state.ip_action_counts[&v6].direct, 1);
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
        assert_eq!(state.total_owners(), 1);
        assert!(state.domain_owners.contains_key(&domain_key("large.com")));
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
        assert_eq!(state.total_owners(), 1);
        assert!(state.domain_owners.contains_key(&domain_key("old.com")));
        assert_eq!(state.desired, HashSet::from([old]));
        assert_eq!(state.tracked_v4, 1);
        assert!(state.dirty_ips.is_empty());
    }

    #[test]
    fn ip_capacity_evicts_oldest_before_newer_larger_owner() {
        let mut state = OffloadDesiredState::with_capacity(4, 4, 5);
        let old: IpAddr = "1.1.1.1".parse().unwrap();
        let newer: [IpAddr; 2] =
            ["2.2.2.1", "2.2.2.2"].map(|ip| ip.parse().unwrap());
        let filler: IpAddr = "3.3.3.3".parse().unwrap();
        let incoming: [IpAddr; 2] =
            ["4.4.4.1", "4.4.4.2"].map(|ip| ip.parse().unwrap());
        observe(&mut state, "old.com", &[old], RoutingAction::Direct);
        observe(&mut state, "newer.com", &newer, RoutingAction::Direct);
        observe(&mut state, "filler.com", &[filler], RoutingAction::Direct);

        observe(&mut state, "incoming.com", &incoming, RoutingAction::Direct);
        assert!(!state.domain_owners.contains_key(&domain_key("old.com")));
        assert!(!state.domain_owners.contains_key(&domain_key("newer.com")));
        assert!(state.domain_owners.contains_key(&domain_key("filler.com")));
        assert!(state.domain_owners.contains_key(&domain_key("incoming.com")));
    }

    #[test]
    fn ip_capacity_scales_batch_for_small_maps() {
        let mut state = OffloadDesiredState::with_capacity(1024, 1, 1025);
        for i in 0..1024u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            observe(
                &mut state,
                &format!("d{i}.com"),
                &[ip],
                RoutingAction::Direct,
            );
        }
        let incoming = IpAddr::V4(std::net::Ipv4Addr::from(0x0b00_0000));
        observe(
            &mut state,
            "incoming.com",
            &[incoming],
            RoutingAction::Direct,
        );

        let scaled_batch = eviction_batch(1024);
        assert_eq!(state.tracked_v4, 1025 - scaled_batch);
        assert_eq!(state.total_owners(), 1025 - scaled_batch);
        assert!(!state.domain_owners.contains_key(&domain_key("d0.com")));
        assert!(!state.domain_owners.contains_key(&domain_key("d101.com")));
        assert!(state.domain_owners.contains_key(&domain_key("d102.com")));
        assert!(state.domain_owners.contains_key(&domain_key("incoming.com")));
    }

    #[test]
    fn default_ip_capacity_evicts_ten_percent_as_a_batch() {
        let mut state = OffloadDesiredState::with_capacity(DEFAULT_MAX_V4_IPS, 1, 3);
        let batch = eviction_batch(DEFAULT_MAX_V4_IPS);
        assert_eq!(batch, 1638);
        let old: Vec<_> = (0..batch as u32)
            .map(|i| IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i)))
            .collect();
        let recent: Vec<_> = (batch as u32..DEFAULT_MAX_V4_IPS as u32)
            .map(|i| IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i)))
            .collect();
        observe(&mut state, "old.com", &old, RoutingAction::Direct);
        observe(&mut state, "recent.com", &recent, RoutingAction::Direct);
        let incoming = IpAddr::V4(std::net::Ipv4Addr::from(0x0b00_0000));

        observe(
            &mut state,
            "incoming.com",
            &[incoming],
            RoutingAction::Direct,
        );
        assert!(!state.domain_owners.contains_key(&domain_key("old.com")));
        assert!(state.domain_owners.contains_key(&domain_key("recent.com")));
        assert!(state.domain_owners.contains_key(&domain_key("incoming.com")));
        assert_eq!(state.tracked_v4, DEFAULT_MAX_V4_IPS + 1 - batch);
    }

    #[test]
    fn successful_flush_reclaims_headroom_before_ip_capacity_is_full() {
        let mut state = OffloadDesiredState::with_capacity(64, 64, 64);
        for i in 0..58u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            observe(
                &mut state,
                &format!("d{i}.com"),
                &[ip],
                RoutingAction::Direct,
            );
        }
        state.dirty_ips.clear();
        state.reclaim_headroom();
        assert_eq!(state.tracked_v4, 58);
        assert!(state.dirty_ips.is_empty());

        let next = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_003a));
        observe(&mut state, "d58.com", &[next], RoutingAction::Direct);
        state.dirty_ips.clear();
        state.reclaim_headroom();
        assert_eq!(state.tracked_v4, 53);
        assert_eq!(state.dirty_ips.len(), 6);
        assert!(!state.domain_owners.contains_key(&domain_key("d0.com")));
        assert!(!state.domain_owners.contains_key(&domain_key("d5.com")));
        assert!(state.domain_owners.contains_key(&domain_key("d6.com")));
        assert!(state.domain_owners.contains_key(&domain_key("d58.com")));
    }

    #[test]
    fn default_capacity_reclaims_when_fewer_than_ten_percent_slots_remain() {
        let mut state = OffloadDesiredState::with_capacity(DEFAULT_MAX_V4_IPS, 1, 3);
        let batch = eviction_batch(DEFAULT_MAX_V4_IPS);
        let old: Vec<_> = (0..batch as u32)
            .map(|i| IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i)))
            .collect();
        let recent: Vec<_> = (batch as u32..(DEFAULT_MAX_V4_IPS - batch + 1) as u32)
            .map(|i| IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i)))
            .collect();
        observe(&mut state, "old.com", &old, RoutingAction::Direct);
        observe(&mut state, "recent.com", &recent, RoutingAction::Direct);
        assert_eq!(state.tracked_v4, DEFAULT_MAX_V4_IPS - batch + 1);
        state.dirty_ips.clear();

        state.reclaim_headroom();
        assert!(!state.domain_owners.contains_key(&domain_key("old.com")));
        assert!(state.domain_owners.contains_key(&domain_key("recent.com")));
        assert_eq!(state.tracked_v4, DEFAULT_MAX_V4_IPS - 2 * batch + 1);
        assert_eq!(state.dirty_ips.len(), batch);
    }

    #[test]
    fn incomplete_headroom_reclaim_does_not_repeat_until_capacity_recovers() {
        let mut state = OffloadDesiredState::with_capacity(64, 64, 3);
        let old: IpAddr = "1.1.1.1".parse().unwrap();
        let recent: Vec<_> = (0..61u32)
            .map(|i| IpAddr::V4(std::net::Ipv4Addr::from(0x0b00_0000 + i)))
            .collect();
        observe(&mut state, "old.com", &[old], RoutingAction::Direct);
        observe(&mut state, "recent.com", &recent, RoutingAction::Direct);
        state.dirty_ips.clear();

        state.reclaim_headroom();
        assert_eq!(state.tracked_v4, 61);
        assert!(!state.reclaim_armed_v4);
        assert_eq!(state.dirty_ips, HashSet::from([old]));

        state.dirty_ips.clear();
        state.reclaim_headroom();
        assert_eq!(state.tracked_v4, 61);
        assert!(state.dirty_ips.is_empty());

        observe(
            &mut state,
            "recent.com",
            &recent[..58],
            RoutingAction::Direct,
        );
        state.reclaim_headroom();
        assert!(state.reclaim_armed_v4);
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
        assert_eq!(state.total_owners(), 1);
        assert!(state.domain_owners.contains_key(&domain_key("large.com")));
        assert_eq!(state.desired, HashSet::from(new));
        assert_eq!(state.tracked_v4, 3);
    }

    #[test]
    fn default_owner_limit_evicts_ten_percent_as_a_batch() {
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
        let owner_batch = eviction_batch(DEFAULT_MAX_OWNERS);
        assert_eq!(owner_batch, 819);
        assert_eq!(state.total_owners(), 8193 - owner_batch);
        assert_eq!(state.desired.len(), 8193 - owner_batch);
        assert!(!state.domain_owners.contains_key(&domain_key("d0.com")));
        assert!(!state.domain_owners.contains_key(&domain_key("d818.com")));
        assert!(state.domain_owners.contains_key(&domain_key("d819.com")));
        assert!(state.domain_owners.contains_key(&domain_key("d8192.com")));
    }

    #[test]
    fn simultaneous_owner_and_ip_overflow_evicts_ten_percent() {
        let mut state = OffloadDesiredState::with_capacity(100, 1, 100);
        for i in 0..100u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            observe(
                &mut state,
                &format!("d{i}.com"),
                &[ip],
                RoutingAction::Direct,
            );
        }
        let incoming = IpAddr::V4(std::net::Ipv4Addr::from(0x0b00_0000));
        observe(
            &mut state,
            "incoming.com",
            &[incoming],
            RoutingAction::Direct,
        );
        assert_eq!(state.total_owners(), 91);
        assert_eq!(state.tracked_v4, 91);
        assert!(!state.domain_owners.contains_key(&domain_key("d9.com")));
        assert!(state.domain_owners.contains_key(&domain_key("d10.com")));
        assert!(state.domain_owners.contains_key(&domain_key("incoming.com")));
    }

    #[test]
    fn owner_only_limit_evicts_oldest_when_capacity_is_small() {
        let mut state = OffloadDesiredState::with_capacity(10, 10, 2);
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        observe(&mut state, "a.com", &[ip], RoutingAction::Direct);
        observe(&mut state, "b.com", &[ip], RoutingAction::Direct);
        state.dirty_ips.clear();

        observe(&mut state, "c.com", &[ip], RoutingAction::Direct);
        assert!(!state.domain_owners.contains_key(&domain_key("a.com")));
        assert!(state.domain_owners.contains_key(&domain_key("b.com")));
        assert!(state.domain_owners.contains_key(&domain_key("c.com")));
        assert_eq!(state.desired, HashSet::from([ip]));
        assert!(state.dirty_ips.is_empty());
    }

    #[test]
    fn route_domain_incrementally_merges_and_caps_per_family() {
        let mut state = OffloadDesiredState::new();
        let dns_ip: IpAddr = "1.1.1.1".parse().unwrap();
        let route_ip: IpAddr = "1.1.1.2".parse().unwrap();
        observe(&mut state, "cdn.example", &[dns_ip], RoutingAction::Direct);
        state.dirty_ips.clear();

        state.observe_batch([Observation::RouteDomain(RouteDomainObservation {
            domain: "cdn.example".into(),
            ip: route_ip,
            action: RoutingAction::Direct,
            outbound: "DIRECT".into(),
            rule_offloadable: true,
        })]);

        assert!(state.desired.contains(&dns_ip));
        assert!(state.desired.contains(&route_ip));
        assert_eq!(state.dirty_ips, HashSet::from([route_ip]));
        state.dirty_ips.clear();

        // Cap at MAX_ROUTE_IPS_PER_FAMILY without unbounded growth.
        for i in 0..(MAX_ROUTE_IPS_PER_FAMILY + 4) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i as u32));
            state.observe_batch([Observation::RouteDomain(RouteDomainObservation {
                domain: "cap.example".into(),
                ip,
                action: RoutingAction::Direct,
                outbound: "DIRECT".into(),
                rule_offloadable: true,
            })]);
        }
        let cap_owner = state.domain_owners.get(&domain_key("cap.example")).unwrap();
        assert_eq!(cap_owner.v4_ips.len(), MAX_ROUTE_IPS_PER_FAMILY);
        let previous_first_ip = cap_owner.v4_ips[0];
        let lower_ip = "9.255.255.255".parse().unwrap();
        state.observe_batch([Observation::RouteDomain(RouteDomainObservation {
            domain: "cap.example".into(),
            ip: lower_ip,
            action: RoutingAction::Direct,
            outbound: "DIRECT".into(),
            rule_offloadable: true,
        })]);
        let cap_owner = &state.domain_owners[&domain_key("cap.example")];
        assert_eq!(cap_owner.v4_ips.len(), MAX_ROUTE_IPS_PER_FAMILY);
        assert_eq!(cap_owner.v4_ips[0], lower_ip);
        assert!(!cap_owner.v4_ips.contains(&previous_first_ip));
        assert!(cap_owner.v4_ips.is_sorted());
    }

    #[test]
    fn route_ip_direct_and_cross_path_proxy_veto() {
        let mut state = OffloadDesiredState::new();
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        let untracked_proxy_ip: IpAddr = "203.0.113.99".parse().unwrap();

        // Untracked pure-IP proxy traffic does not consume owner slots.
        state.observe_batch([Observation::RouteIp(RouteIpObservation {
            ip: untracked_proxy_ip,
            action: RoutingAction::Proxy,
            outbound: "PROXY".into(),
            rule_offloadable: true,
        })]);
        assert!(!state.direct_ip_owners.contains_key(&untracked_proxy_ip));

        // Pure-IP direct route installs DirectIp owner.
        state.observe_batch([Observation::RouteIp(RouteIpObservation {
            ip,
            action: RoutingAction::Direct,
            outbound: "DIRECT".into(),
            rule_offloadable: true,
        })]);
        assert!(state.desired.contains(&ip));
        assert!(state.dirty_ips.remove(&ip));

        // Domain proxy sharing the same IP vetoes it immediately.
        observe(&mut state, "blocked.example", &[ip], RoutingAction::Proxy);
        assert!(!state.desired.contains(&ip));
        assert!(state.dirty_ips.contains(&ip));
    }

    #[test]
    fn direct_ip_quota_evicts_only_direct_ips_without_touching_domains() {
        let mut state = OffloadDesiredState::with_limits(100, 100, 10, 2);
        let dom_ip: IpAddr = "1.1.1.1".parse().unwrap();
        observe(&mut state, "keep.example", &[dom_ip], RoutingAction::Direct);

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();
        for ip in [ip1, ip2, ip3] {
            state.observe_batch([Observation::RouteIp(RouteIpObservation {
                ip,
                action: RoutingAction::Direct,
                outbound: "DIRECT".into(),
                rule_offloadable: true,
            })]);
        }

        assert!(state.domain_owners.contains_key(&domain_key("keep.example")));
        assert!(!state.direct_ip_owners.contains_key(&ip1));
        assert!(state.direct_ip_owners.contains_key(&ip2));
        assert!(state.direct_ip_owners.contains_key(&ip3));
    }

    #[test]
    fn reconcile_outbounds_handles_group_switches_and_preserves_unoffloadable() {
        let mut state = OffloadDesiredState::new();
        let dom_ip: IpAddr = "198.51.100.1".parse().unwrap();
        let raw_ip: IpAddr = "198.51.100.2".parse().unwrap();
        let unsafe_ip: IpAddr = "198.51.100.3".parse().unwrap();

        state.observe_batch([
            Observation::Dns(DnsObservation {
                domain: "group.example".into(),
                ips: vec![dom_ip],
                action: RoutingAction::Direct,
                outbound: Some("AUTO".into()),
                rule_offloadable: true,
            }),
            Observation::RouteIp(RouteIpObservation {
                ip: raw_ip,
                action: RoutingAction::Direct,
                outbound: "AUTO".into(),
                rule_offloadable: true,
            }),
            Observation::Dns(DnsObservation {
                domain: "port-only.example".into(),
                ips: vec![unsafe_ip],
                action: RoutingAction::Proxy,
                outbound: Some("AUTO".into()),
                rule_offloadable: false,
            }),
        ]);
        assert!(state.desired.contains(&dom_ip));
        assert!(state.desired.contains(&raw_ip));
        assert!(!state.desired.contains(&unsafe_ip));
        state.dirty_ips.clear();

        // Switch group AUTO -> Proxy: withdraws dom_ip and raw_ip.
        let mut to_proxy = HashMap::new();
        to_proxy.insert(Arc::from("AUTO"), RoutingAction::Proxy);
        state.reconcile_outbounds(&to_proxy);
        assert!(!state.desired.contains(&dom_ip));
        assert!(!state.desired.contains(&raw_ip));
        assert!(!state.direct_ip_owners.contains_key(&raw_ip));
        assert_eq!(state.dirty_ips, HashSet::from([dom_ip, raw_ip]));
        state.dirty_ips.clear();

        // Switch group AUTO -> Direct: restores dom_ip, keeps port-only.example as Proxy.
        let mut to_direct = HashMap::new();
        to_direct.insert(Arc::from("AUTO"), RoutingAction::Direct);
        state.reconcile_outbounds(&to_direct);
        assert!(state.desired.contains(&dom_ip));
        assert!(!state.desired.contains(&unsafe_ip));
        assert_eq!(state.dirty_ips, HashSet::from([dom_ip]));
    }

    #[test]
    fn global_capacity_evicts_across_domain_and_direct_ip_owners_by_last_seen() {
        let mut state = OffloadDesiredState::with_limits(2, 2, 2, 2);
        let shared: IpAddr = "1.1.1.1".parse().unwrap();
        let ip_a: IpAddr = "2.2.2.2".parse().unwrap();
        let ip_b: IpAddr = "3.3.3.3".parse().unwrap();

        // Oldest owner is a DirectIp, followed by a domain owner.
        state.observe_batch([Observation::RouteIp(RouteIpObservation {
            ip: ip_a,
            action: RoutingAction::Direct,
            outbound: "DIRECT".into(),
            rule_offloadable: true,
        })]);
        observe(&mut state, "mid.example", &[shared], RoutingAction::Direct);

        // Adding a third owner (DirectIp) exceeds both max_owners and max_v4_ips;
        // oldest DirectIp (ip_a) is evicted while mid.example and ip_b stay.
        state.observe_batch([Observation::RouteIp(RouteIpObservation {
            ip: ip_b,
            action: RoutingAction::Direct,
            outbound: "DIRECT".into(),
            rule_offloadable: true,
        })]);
        assert!(!state.direct_ip_owners.contains_key(&ip_a));
        assert!(state.domain_owners.contains_key(&domain_key("mid.example")));
        assert!(state.direct_ip_owners.contains_key(&ip_b));
        assert_eq!(state.total_owners(), 2);
        assert_eq!(state.tracked_v4, 2);
    }

    #[test]
    fn owner_only_limit_evicts_oldest_domain_before_newer_direct_ip() {
        let mut state = OffloadDesiredState::with_limits(10, 10, 2, 2);
        let dom_ip: IpAddr = "1.1.1.1".parse().unwrap();
        let raw_ip_a: IpAddr = "2.2.2.2".parse().unwrap();
        let raw_ip_b: IpAddr = "3.3.3.3".parse().unwrap();

        // Oldest owner is a domain, followed by a newer DirectIp.
        observe(&mut state, "old.example", &[dom_ip], RoutingAction::Direct);
        state.observe_batch([Observation::RouteIp(RouteIpObservation {
            ip: raw_ip_a,
            action: RoutingAction::Direct,
            outbound: "DIRECT".into(),
            rule_offloadable: true,
        })]);

        // Adding another DirectIp exceeds only max_owners (not max_v4_ips);
        // the oldest domain owner must be evicted while both DirectIps remain.
        state.observe_batch([Observation::RouteIp(RouteIpObservation {
            ip: raw_ip_b,
            action: RoutingAction::Direct,
            outbound: "DIRECT".into(),
            rule_offloadable: true,
        })]);
        assert!(!state.domain_owners.contains_key(&domain_key("old.example")));
        assert!(state.direct_ip_owners.contains_key(&raw_ip_a));
        assert!(state.direct_ip_owners.contains_key(&raw_ip_b));
        assert_eq!(state.total_owners(), 2);
        assert_eq!(state.tracked_v4, 2);
        assert!(!state.desired.contains(&dom_ip));
        assert!(state.desired.contains(&raw_ip_a));
        assert!(state.desired.contains(&raw_ip_b));
    }
}
