//! Single-table decisions with whole-record routes and sparse plain activity writes.
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};
use aya_ebpf_bindings::{bindings::BPF_NOEXIST,
    helpers::{bpf_get_prandom_u32, bpf_ktime_get_ns}};
use clash_ebpf_common::{DaeEventType, FlowTrackEntry, RedirectEntry, RedirectTuple,
    tracking::{self, DIRECT, CLOSING, MAX_GENERATION, expired, incarnation, token, word}};
use crate::{maps::FLOW_TRACK, send_dae_event};

#[derive(Clone, Copy, Default)]
pub struct Decision {
    pub activity: u64,
    route: RedirectEntry,
    _pad: [u8; 4],
}
impl Decision {
    pub fn is_direct(&self) -> bool { token(self.activity) & DIRECT != 0 }
    pub fn is_redirect(&self) -> bool { self.activity != 0 && !self.is_direct() }
    pub fn matches_route(&self, route: &RedirectEntry) -> bool { self.is_redirect() && self.route == *route }
    pub fn route(&self) -> Option<RedirectEntry> { self.is_redirect().then_some(self.route) }
}

// Like packet parsing scratch, this is owned by the current non-sleepable TC
// invocation on its CPU. It avoids nesting large stack-resident route copies.
#[repr(C)]
pub struct Scratch { pub observed: Decision, pub result: Decision }

#[inline(always)]
fn now() -> u32 { (unsafe { bpf_ktime_get_ns() } / 1_000_000_000) as u32 }

/// The kernel guarantees map-pointer memory safety during TC execution, not
/// immutable contents after element recycling. No pointer escapes this call.
#[inline(always)]
fn current(tuple: &RedirectTuple) -> Option<(*mut FlowTrackEntry, u64)> {
    let ptr = FLOW_TRACK.get_ptr_mut(tuple)?;
    let activity = unsafe { sample(ptr) };
    Some((ptr, activity))
}

#[inline(always)]
unsafe fn sample(ptr: *const FlowTrackEntry) -> u64 {
    unsafe { word(read_volatile(addr_of!((*ptr).state)),
        read_volatile(addr_of!((*ptr).last_seen_seconds))) }
}

#[inline(always)]
unsafe fn refresh(ptr: *mut FlowTrackEntry, observed: u64, stamp: u32) {
    if stamp.wrapping_sub(tracking::seconds(observed)) as i32 > 0
        && unsafe { read_volatile(addr_of!((*ptr).state)) } == token(observed) {
        // Best-effort recheck, not a conditional atomic store. A replacement
        // may race with this write; timestamp error is accepted.
        unsafe { write_volatile(addr_of_mut!((*ptr).last_seen_seconds), stamp); }
    }
}

pub const FOUND: u32 = 1;
pub const REFRESH_DUE: u32 = 2;

#[inline(never)]
pub fn lookup_into(tuple: &RedirectTuple, reset: bool, finish: bool, out: &mut Decision) -> u32 {
    *out = Decision::default();
    let mut control_incarnation = 0;
    for _ in 0..3 {
        let Some((ptr, activity)) = current(tuple) else { return 0; };
        let id = token(activity);
        let needs_activity = tuple.proto == 17 || id & CLOSING != 0;
        let stamp = if needs_activity || reset || finish { now() } else { 0 };
        let due = needs_activity && stamp.wrapping_sub(tracking::seconds(activity)) as i32 > 0;
        let flags = FOUND | if due { REFRESH_DUE } else { 0 };
        if control_incarnation == 0 { control_incarnation = incarnation(activity); }
        else if (reset || finish) && incarnation(activity) != control_incarnation {
            // Retry a concurrent refresh or close, never a replacement SYN or
            // metadata incarnation. The caller can follow its current decision.
            return 0;
        }
        if reset || expired(activity, stamp, tuple.proto == 17) {
            if retire(tuple, ptr, activity) { return 0; }
            continue;
        }
        if id & DIRECT != 0 {
            if finish {
                if !retire(tuple, ptr, activity) { continue; }
            } else if needs_activity { unsafe { refresh(ptr, activity, stamp); } }
            out.activity = activity;
            return flags;
        }
        let route = unsafe { read_volatile(addr_of!((*ptr).route)) };
        // Catch ordinary replacement/recycling without reader registration.
        // This is best-effort validation, not a leased snapshot protocol.
        if unsafe { read_volatile(addr_of!((*ptr).state)) } != id { continue; }
        if finish && id & CLOSING == 0 {
            let latest = if stamp.wrapping_sub(tracking::seconds(activity)) as i32 > 0 {
                stamp
            } else { tracking::seconds(activity) };
            let closing = word(id | CLOSING, latest);
            if unsafe { read_volatile(addr_of!((*ptr).state)) } != id { continue; }
            unsafe {
                write_volatile(addr_of_mut!((*ptr).last_seen_seconds), latest);
                write_volatile(addr_of_mut!((*ptr).state), id | CLOSING);
            }
            out.activity = closing;
        } else {
            if needs_activity { unsafe { refresh(ptr, activity, stamp); } }
            out.activity = activity;
        }
        out.route = route;
        return flags;
    }
    0
}

/// Recheck before deleting, accepting the remaining check/delete race.
#[inline(never)]
fn retire(tuple: &RedirectTuple, ptr: *mut FlowTrackEntry, observed: u64) -> bool {
    if unsafe { sample(ptr) } != observed { return false; }
    FLOW_TRACK.remove(tuple).is_ok()
}

/// New flows arbitrate with NOEXIST. Metadata changes replace the complete
/// allocation; concurrent publishers may win in either order. Readers accept
/// rare replacement/recycling windows rather than registering on every packet.
#[inline(never)]
pub fn publish_into(tuple: &RedirectTuple, observed: &Decision, route: Option<&RedirectEntry>, out: &mut Decision) -> bool {
    *out = Decision::default();
    let stamp = now();
    // Best-effort incarnation discrimination, not a globally leased identity.
    let generation = (unsafe { bpf_get_prandom_u32() } & MAX_GENERATION as u32).max(1);
    let id = generation | if route.is_none() { DIRECT } else { 0 }
        | (token(observed.activity) & CLOSING);
    let new = word(id, stamp);
    let initial = FlowTrackEntry { last_seen_seconds: stamp, state: id,
        route: route.copied().unwrap_or_default() };
    let flags = if observed.activity == 0 { BPF_NOEXIST as u64 } else { 0 };
    let accepted = FLOW_TRACK.insert(tuple, &initial, flags).is_ok();
    if accepted {
        out.activity = new;
        if let Some(route) = route { out.route = *route; }
        true
    } else if lookup_into(tuple, false, false, out) & FOUND != 0 { true }
    else {
        send_dae_event(if tuple.proto == 6 { DaeEventType::TcpConnOverflow as u32 }
            else { DaeEventType::UdpConnOverflow as u32 }, 0, None, 0, tuple.proto,
            None, None, 0, 0);
        false
    }
}
