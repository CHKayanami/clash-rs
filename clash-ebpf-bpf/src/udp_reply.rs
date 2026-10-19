//! Client return routing uses the same bucket protocol as its collector.
use core::ptr::{addr_of, addr_of_mut, read_volatile};
use aya_ebpf_bindings::{bindings::BPF_NOEXIST, helpers::bpf_ktime_get_ns};
use clash_ebpf_bpf::policy::{UDP_CONN_TIMEOUT_NS, REDIRECT_REFRESH_NS, udp_reply_expired, udp_reply_route, udp_reply_update_into};
use clash_ebpf_common::{DaeEventType, RedirectEntry, RedirectTuple, TrackingGcRequest,
    UdpReplyEntry, UdpReplyKey, tracking::gate::{load_u64, store_u64, try_lock}};
use crate::{gate, maps::UDP_REPLY_TRACK, send_dae_event};

#[inline(always)]
unsafe fn refresh(ptr: *mut UdpReplyEntry, observed: u64, now: u64) {
    if now.saturating_sub(observed) >= REDIRECT_REFRESH_NS {
        // Every mutation and deletion holds the client bucket. A stale clock
        // sample can neither rewind activity nor touch a replacement instance.
        unsafe { store_u64(addr_of_mut!((*ptr).last_seen_ns), now); }
    }
}

/// Only the atomic timestamp changes in place. Route and generation
/// are immutable for this RCU-protected allocation. No pointer escapes the
/// invocation, and mutations always re-lookup under the writer gate.
#[inline(always)]
fn expired_at(activity: u64, now: u64) -> bool {
    now.saturating_sub(activity) > UDP_CONN_TIMEOUT_NS + REDIRECT_REFRESH_NS
}

#[inline(never)]
pub fn publish(tuple: &RedirectTuple, route: RedirectEntry, now: u64) -> bool {
    let key = UdpReplyKey::from_request(tuple);
    // Only activity is mutable in this invocation-scoped RCU allocation.
    // Generation belongs to writers/GC and is not read on a stable hit.
    let refresh_only = if let Some(ptr) = UDP_REPLY_TRACK.get_ptr_mut(&key) {
        let activity = unsafe { load_u64(addr_of!((*ptr).last_seen_ns)) };
        if !expired_at(activity, now) && unsafe { read_volatile(addr_of!((*ptr).route)) } == route {
            if now.saturating_sub(activity) < REDIRECT_REFRESH_NS { return true; }
            true
        } else { false }
    } else { false };
    let Some(epoch) = gate::word(gate::reply_bucket(&key)) else { return false; };
    let Some(guard) = try_lock(epoch) else { return refresh_only; };
    let ptr = UDP_REPLY_TRACK.get_ptr_mut(&key);
    let old = ptr.map(|ptr| unsafe { read_volatile(ptr) });
    if let (Some(ptr), Some(old)) = (ptr, old.as_ref()) {
        if !udp_reply_expired(old, now) && old.route == route {
            unsafe { refresh(ptr, old.last_seen_ns, now); }
            return true;
        }
    }
    let mut state = UdpReplyEntry::default();
    if let Some(old) = old.as_ref() {
        if !udp_reply_expired(old, now) && old.route != route { return false; }
    }
    if !udp_reply_update_into(old.as_ref(), route, now, &mut state) { return true; }
    state.generation = guard.generation();
    let flags = if old.is_some() { 0 } else { BPF_NOEXIST as u64 };
    if UDP_REPLY_TRACK.insert(&key, &state, flags).is_ok() { return true; }
    send_dae_event(DaeEventType::UdpConnOverflow as u32, 0, None,
        0, 17, None, None, 0, 0);
    false
}

/// Scalar status avoids Rust aggregate-return pointers in the BPF ABI.
/// 1 = found (out initialized), 0 = missing/expired, -1 = gate unavailable.
#[inline(never)]
pub fn lookup_into(key: &UdpReplyKey, now: u64, out: &mut RedirectEntry) -> i32 {
    let Some(ptr) = UDP_REPLY_TRACK.get_ptr_mut(key) else { return 0; };
    let activity = unsafe { load_u64(addr_of!((*ptr).last_seen_ns)) };
    if expired_at(activity, now) { return 0; }
    let route = unsafe { read_volatile(addr_of!((*ptr).route)) };
    if now.saturating_sub(activity) < REDIRECT_REFRESH_NS { *out = route; return 1; }
    let Some(epoch) = gate::word(gate::reply_bucket(key)) else { return -1; };
    let Some(_guard) = try_lock(epoch) else { *out = route; return 1; };
    let Some(ptr) = UDP_REPLY_TRACK.get_ptr_mut(key) else { return 0; };
    let state = unsafe { read_volatile(ptr) };
    let now = unsafe { bpf_ktime_get_ns() };
    let Some(route) = udp_reply_route(&state, now) else { return 0; };
    unsafe { refresh(ptr, state.last_seen_ns, now); }
    *out = route;
    1
}

#[inline(never)]
pub fn collect(request: &TrackingGcRequest) -> i32 {
    let key = UdpReplyKey::from_request(&request.tuple);
    let Some(epoch) = gate::word(gate::reply_bucket(&key)) else { return 0; };
    let Some(_guard) = try_lock(epoch) else { return 0; };
    let Some(ptr) = UDP_REPLY_TRACK.get_ptr_mut(&key) else { return 0; };
    let state = unsafe { read_volatile(ptr) };
    if state.generation != request.generation || state.last_seen_ns != request.activity
        || !udp_reply_expired(&state, request.now_ns) { return 0; }
    UDP_REPLY_TRACK.remove(&key).is_ok() as i32
}
