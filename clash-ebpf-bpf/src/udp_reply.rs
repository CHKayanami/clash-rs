//! Per-client return routing, with serialized metadata and activity updates.
use core::{ffi::c_void, ptr::{addr_of_mut, from_ref}};
use aya_ebpf_bindings::{bindings::{BPF_NOEXIST, bpf_spin_lock as SpinLock},
    helpers::{bpf_for_each_map_elem, bpf_ktime_get_ns, bpf_spin_lock, bpf_spin_unlock}};
use clash_ebpf_bpf::policy::{REDIRECT_REFRESH_NS, udp_reply_retire, udp_reply_route, udp_reply_update};
use clash_ebpf_common::{DaeEventType, RedirectEntry, RedirectTuple, UdpReplyEntry, UdpReplyKey};
use crate::{maps::{UDP_REPLY_GC_NS, UDP_REPLY_TRACK}, send_dae_event};

/// The kernel lock is recognized by BTF and never copied after publication.
/// All state reads/writes hold it; no helper or subprogram is called while held.
/// Entries are inserted only with NOEXIST, never replaced under a held lock.
#[repr(C)]
pub struct ReplyValue {
    lock: SpinLock,
    _pad: u32,
    state: UdpReplyEntry,
}

unsafe extern "C" fn collect_one(_map: *mut c_void, key: *mut UdpReplyKey,
    value: *mut ReplyValue, context: *mut u64,
) -> i64 {
    unsafe {
        let lock = addr_of_mut!((*value).lock);
        bpf_spin_lock(lock);
        let retired = udp_reply_retire(&mut (*value).state, *context);
        bpf_spin_unlock(lock);
        // A tombstone prevents a publisher from reviving this value between
        // unlock and delete. Only its claiming collector may delete the key.
        if retired { let _ = UDP_REPLY_TRACK.remove(&*key); }
    }
    0
}

#[inline(never)]
fn collect_expired(mut now: u64) -> bool {
    let Some(last) = UDP_REPLY_GC_NS.get_ptr_mut(0) else { return false; };
    // Per-CPU storage is used only by non-sleepable TC programs. Throttle the
    // expensive scan before calling helpers, independently on each CPU.
    unsafe {
        if now.saturating_sub(*last) < REDIRECT_REFRESH_NS { return false; }
        *last = now;
        bpf_for_each_map_elem(from_ref(&UDP_REPLY_TRACK).cast_mut().cast(), collect_one as *mut c_void,
            addr_of_mut!(now).cast(), 0);
    }
    true
}

#[inline(never)]
pub fn publish(tuple: &RedirectTuple, route: RedirectEntry, now: u64) {
    let key = UdpReplyKey::from_request(tuple);
    let mut value = UDP_REPLY_TRACK.get_ptr_mut(&key);
    if value.is_none() {
        let Some(state) = udp_reply_update(None, route, now) else { return; };
        let initial = ReplyValue { lock: SpinLock { val: 0 }, _pad: 0, state };
        if UDP_REPLY_TRACK.insert(&key, &initial, BPF_NOEXIST as u64).is_ok() { return; }
        value = UDP_REPLY_TRACK.get_ptr_mut(&key);
        if value.is_none() {
            if collect_expired(now) {
                if UDP_REPLY_TRACK.insert(&key, &initial, BPF_NOEXIST as u64).is_ok() { return; }
                value = UDP_REPLY_TRACK.get_ptr_mut(&key);
                if value.is_none() {
                    send_dae_event(DaeEventType::UdpConnOverflow as u32, 0, None,
                        0, 17, None, None, 0, 0);
                }
            }
        }
    }
    let Some(value) = value else { return; };
    unsafe {
        let lock = addr_of_mut!((*value).lock);
        bpf_spin_lock(lock);
        if let Some(state) = udp_reply_update(Some(&(*value).state), route, now) {
            (*value).state = state;
        }
        bpf_spin_unlock(lock);
    }
}

#[inline(never)]
pub fn lookup(reversed: &RedirectTuple) -> Option<RedirectEntry> {
    let key = UdpReplyKey::from_request(reversed);
    let value = UDP_REPLY_TRACK.get_ptr_mut(&key)?;
    let now = unsafe { bpf_ktime_get_ns() };
    unsafe {
        let lock = addr_of_mut!((*value).lock);
        bpf_spin_lock(lock);
        let route = udp_reply_route(&(*value).state, now);
        if let Some(route) = route
            && let Some(state) = udp_reply_update(Some(&(*value).state), route, now) {
            (*value).state = state;
        }
        bpf_spin_unlock(lock);
        route
    }
}
