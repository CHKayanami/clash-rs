//! Per-client return routing with sparse in-place activity refreshes.
use core::ptr::{addr_of_mut, read_volatile, write_volatile};
use aya_ebpf_bindings::{bindings::BPF_NOEXIST, helpers::bpf_ktime_get_ns};
use clash_ebpf_bpf::policy::{REDIRECT_REFRESH_NS, UDP_CONN_TIMEOUT_NS, udp_reply_expired, udp_reply_route, udp_reply_update_into};
use clash_ebpf_common::{DaeEventType, RedirectEntry, RedirectTuple, UdpReplyEntry, UdpReplyKey};
use crate::{maps::UDP_REPLY_TRACK, send_dae_event};

/// Only the aligned timestamp is mutated in place. Concurrent refresh/recycling
/// may lose a write; no pointer escapes this non-sleepable TC invocation.
#[inline(always)]
unsafe fn refresh(ptr: *mut UdpReplyEntry, observed: u64, now: u64) {
    if now.saturating_sub(observed) >= REDIRECT_REFRESH_NS {
        unsafe { write_volatile(addr_of_mut!((*ptr).last_seen_ns), now); }
    }
}

// Keep the unit-returning update in its caller: LLVM may leave a temporary
// stack address in R0 on an early return, which BPF subprogram exits reject.
#[inline(always)]
pub fn publish(tuple: &RedirectTuple, route: RedirectEntry, now: u64) {
    let key = UdpReplyKey::from_request(tuple);
    let ptr = UDP_REPLY_TRACK.get_ptr_mut(&key);
    let old = ptr.map(|ptr| unsafe { read_volatile(ptr) });
    if let (Some(ptr), Some(old)) = (ptr, old.as_ref()) {
        if !udp_reply_expired(old, now) && old.route == route {
            unsafe { refresh(ptr, old.last_seen_ns, now); }
            return;
        }
    }
    let mut state = UdpReplyEntry::default();
    if !udp_reply_update_into(old.as_ref(), route, now, &mut state) { return; }
    let flags = if old.is_some() { 0 } else { BPF_NOEXIST as u64 };
    if UDP_REPLY_TRACK.insert(&key, &state, flags).is_ok() { return; }
    // First-request conflicts merge with the winning route. Ordinary activity
    // uses only a timestamp store; changed metadata publishes a complete value.
    if let Some(ptr) = UDP_REPLY_TRACK.get_ptr_mut(&key) {
        let old = unsafe { read_volatile(ptr) };
        if !udp_reply_expired(&old, now) && old.route == route {
            unsafe { refresh(ptr, old.last_seen_ns, now); }
        } else if udp_reply_update_into(Some(&old), route, now, &mut state) {
            let _ = UDP_REPLY_TRACK.insert(&key, &state, 0);
        }
    } else {
        // Userspace cleanup owns scans; never walk a full table on a packet.
        send_dae_event(DaeEventType::UdpConnOverflow as u32, 0, None,
            0, 17, None, None, 0, 0);
    }
}

#[inline(never)]
pub fn lookup(reversed: &RedirectTuple) -> Option<RedirectEntry> {
    let key = UdpReplyKey::from_request(reversed);
    let ptr = UDP_REPLY_TRACK.get_ptr_mut(&key)?;
    let state = unsafe { read_volatile(ptr) };
    let now = unsafe { bpf_ktime_get_ns() };
    let route = udp_reply_route(&state, now)?;
    unsafe { refresh(ptr, state.last_seen_ns, now); }
    Some(route)
}

/// Exact flow hits need only renew the client record, not copy its route.
#[inline(never)]
pub fn touch(reversed: &RedirectTuple) {
    let key = UdpReplyKey::from_request(reversed);
    let Some(ptr) = UDP_REPLY_TRACK.get_ptr_mut(&key) else { return; };
    let now = unsafe { bpf_ktime_get_ns() };
    unsafe {
        let stamp = read_volatile(core::ptr::addr_of!((*ptr).last_seen_ns));
        let ambiguous = read_volatile(core::ptr::addr_of!((*ptr).ambiguous));
        if ambiguous == 0 && now.saturating_sub(stamp) <= UDP_CONN_TIMEOUT_NS + REDIRECT_REFRESH_NS {
            refresh(ptr, stamp, now);
        }
    }
}
