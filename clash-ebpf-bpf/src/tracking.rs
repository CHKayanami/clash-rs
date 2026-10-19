//! Atomic activity reads and serialized lifecycle changes, including collection.
use core::ptr::{addr_of, null, read_volatile};
use aya_ebpf_bindings::{bindings::BPF_NOEXIST, helpers::bpf_ktime_get_ns};
use clash_ebpf_common::{DaeEventType, FlowTrackEntry, RedirectEntry, RedirectTuple,
    TrackingGcRequest, tracking::{self, DIRECT, CLOSING, MAX_GENERATION, expired,
        token, word, transition, Transition, load_activity, store_activity, gate::try_lock}};
use crate::{gate, maps::FLOW_TRACK, send_dae_event};

#[derive(Clone, Copy, Default)]
pub struct Decision {
    pub activity: u64,
    pub generation: u64,
    route: RedirectEntry,
    _pad: [u8; 4],
}
impl Decision {
    pub fn is_direct(&self) -> bool { token(self.activity) & DIRECT != 0 }
    pub fn is_redirect(&self) -> bool { self.activity != 0 && !self.is_direct() }
    pub fn matches_route(&self, route: &RedirectEntry) -> bool { self.is_redirect() && self.route == *route }
}

#[repr(C)]
pub struct Scratch { pub observed: Decision, pub result: Decision }

#[inline(always)]
fn now() -> u32 { (unsafe { bpf_ktime_get_ns() } / 1_000_000_000) as u32 }

pub const FOUND: u32 = 1;
pub const BUSY: u32 = 4;
pub const DIRECT_HIT: u32 = DIRECT;
const RESET: u32 = 1;
const FINISH: u32 = 2;
const UDP: u32 = 4;

/// Copy only when a caller needs an owned decision for publication. The
/// allocation is RCU protected for this invocation; route/generation never
/// change in place, and activity must be read with one aligned atomic load.
///
/// # Safety
/// `ptr` must be a non-null FLOW_TRACK allocation borrowed by this invocation.
#[inline(always)]
pub unsafe fn read_into(ptr: *const FlowTrackEntry, out: &mut Decision) {
    unsafe {
        out.activity = load_activity(ptr);
        out.generation = read_volatile(addr_of!((*ptr).generation));
        out.route = if token(out.activity) & DIRECT != 0 { RedirectEntry::default() }
            else { read_volatile(addr_of!((*ptr).route)) };
        out._pad = [0; 4];
    }
}

/// # Safety
/// `ptr` must be a non-null FLOW_TRACK allocation borrowed by this invocation.
#[inline(always)]
pub unsafe fn route_matches(ptr: *const FlowTrackEntry, route: &RedirectEntry) -> bool {
    unsafe { read_volatile(addr_of!((*ptr).route)) == *route }
}

/// # Safety
/// Same invocation-scoped RCU lifetime as route_matches. No pointer is retained.
#[inline(always)]
pub unsafe fn route(ptr: *const FlowTrackEntry) -> RedirectEntry {
    unsafe { read_volatile(addr_of!((*ptr).route)) }
}

/// Return only a borrowed map pointer and compact status on the hot path.
/// No pointer may escape this BPF invocation or be written through by a caller.
/// Misses and BUSY both return null; callers must check status before treating
/// null as permission to classify a new flow. DIRECT_HIT belongs to this
/// allocation, whose decision is immutable even if the map key is replaced.
#[inline(never)]
pub fn lookup_ref(tuple: &RedirectTuple, reset: bool, finish: bool, packet_now: u64,
    status: &mut u32,
) -> *const FlowTrackEntry {
    *status = 0;
    let Some(ptr) = FLOW_TRACK.get_ptr_mut(tuple) else { return null(); };
    let activity = unsafe { load_activity(ptr) };
    let id = token(activity);
    let udp = tuple.proto == 17;
    let needs_activity = udp || id & CLOSING != 0;
    let stamp = if packet_now != 0 { (packet_now / 1_000_000_000) as u32 }
        else if needs_activity || reset || finish { now() } else { 0 };
    let due = needs_activity && stamp.wrapping_sub(tracking::seconds(activity)) as i32 > 0;
    if !reset && !finish && !due && !expired(activity, stamp, udp) {
        *status = FOUND | (id & DIRECT);
        return ptr;
    }
    let options = if reset { RESET } else { 0 } | if finish { FINISH } else { 0 }
        | if udp { UDP } else { 0 };
    lookup_slow(tuple, ptr, options, stamp, status)
}

#[inline(never)]
fn lookup_slow(tuple: &RedirectTuple, observed: *const FlowTrackEntry, options: u32,
    stamp: u32, status: &mut u32,
) -> *const FlowTrackEntry {
    let expected = unsafe { read_volatile(addr_of!((*observed).generation)) };
    let activity = unsafe { load_activity(observed) };
    *status = BUSY;
    let Some(epoch) = gate::word(gate::bucket(tuple)) else { return null(); };
    let Some(_guard) = try_lock(epoch) else {
        // Optional activity refresh may defer; identity changes fail closed.
        if options & (RESET | FINISH) == 0 && !expired(activity, stamp, options & UDP != 0) {
            *status = FOUND | (token(activity) & DIRECT);
            return observed;
        }
        return null();
    };
    let Some(ptr) = FLOW_TRACK.get_ptr_mut(tuple) else {
        *status = 0;
        return null();
    };
    let generation = unsafe { read_volatile(addr_of!((*ptr).generation)) };
    let mut activity = unsafe { load_activity(ptr) };
    match transition(activity, generation, expected, stamp, options & UDP != 0,
        options & RESET != 0, options & FINISH != 0) {
        Transition::Keep => {}
        Transition::Retire => {
            if FLOW_TRACK.remove(tuple).is_err() { return null(); }
            *status = 0;
            return null();
        }
        Transition::Activity(next) => {
            unsafe { store_activity(ptr, next); }
            activity = next;
        }
    }
    *status = FOUND | (token(activity) & DIRECT);
    ptr
}

/// Cold/full-parser callers still need an owned snapshot for publication.
#[inline(never)]
pub fn lookup_into(tuple: &RedirectTuple, reset: bool, finish: bool, packet_now: u64, out: &mut Decision) -> u32 {
    let mut status = 0;
    let ptr = lookup_ref(tuple, reset, finish, packet_now, &mut status);
    if ptr.is_null() { *out = Decision::default(); }
    else { unsafe { read_into(ptr, out); } }
    status
}

#[inline(never)]
pub fn publish_into(tuple: &RedirectTuple, observed: &Decision, route: Option<&RedirectEntry>, out: &mut Decision) -> bool {
    *out = Decision::default();
    let Some(epoch) = gate::word(gate::bucket(tuple)) else { return false; };
    let Some(guard) = try_lock(epoch) else { return false; };
    let current = FLOW_TRACK.get_ptr_mut(tuple);
    if let Some(ptr) = current {
        unsafe { read_into(ptr, out); }
        // NOEXIST losers and delayed publishers adopt the winner; they cannot
        // replace a newer incarnation with a decision made from an old one.
        if observed.generation == 0 || out.generation != observed.generation { return true; }
    }
    let stamp = now();
    let generation = guard.generation();
    let id = ((generation as u32) & MAX_GENERATION as u32).max(1)
        | if route.is_none() { DIRECT } else { 0 }
        | (token(out.activity) & CLOSING);
    let initial = FlowTrackEntry { last_seen_seconds: stamp, state: id,
        route: route.copied().unwrap_or_default(), _pad: [0; 4], generation };
    let flags = if current.is_none() { BPF_NOEXIST as u64 } else { 0 };
    if FLOW_TRACK.insert(tuple, &initial, flags).is_ok() {
        out.activity = word(id, stamp);
        out.generation = generation;
        out.route = initial.route;
        true
    } else {
        send_dae_event(if tuple.proto == 6 { DaeEventType::TcpConnOverflow as u32 }
            else { DaeEventType::UdpConnOverflow as u32 }, 0, None, 0, tuple.proto,
            None, None, 0, 0);
        false
    }
}

#[inline(never)]
pub fn collect(request: &TrackingGcRequest) -> i32 {
    let Some(epoch) = gate::word(gate::bucket(&request.tuple)) else { return 0; };
    let Some(_guard) = try_lock(epoch) else { return 0; };
    let Some(ptr) = FLOW_TRACK.get_ptr_mut(&request.tuple) else { return 0; };
    let generation = unsafe { read_volatile(addr_of!((*ptr).generation)) };
    let activity = unsafe { load_activity(ptr) };
    if generation != request.generation || activity != request.activity
        || !expired(activity, (request.now_ns / 1_000_000_000) as u32, request.tuple.proto == 17) {
        return 0;
    }
    // No packet writer can refresh or republish this bucket until deletion
    // completes and the guard publishes its next version.
    FLOW_TRACK.remove(&request.tuple).is_ok() as i32
}
