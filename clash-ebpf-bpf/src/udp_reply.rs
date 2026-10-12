//! Return routing for UDP associations, independent of remote peer tuples.
use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;
use clash_ebpf_bpf::policy::{udp_reply_route, udp_reply_update};
use clash_ebpf_common::{RedirectEntry, RedirectTuple, UdpReplyKey};
use crate::maps::UDP_REPLY_TRACK;

#[inline(never)]
pub fn publish(tuple: &RedirectTuple, route: RedirectEntry, now: u64) {
    let key = UdpReplyKey::from_request(tuple);
    // Copy before insert: replacing an LRU value invalidates borrowed pointers.
    let old = unsafe { UDP_REPLY_TRACK.get(&key).copied() };
    if let Some(entry) = udp_reply_update(old.as_ref(), route, now) {
        let _ = UDP_REPLY_TRACK.insert(&key, &entry, 0);
    }
}

#[inline(never)]
pub fn lookup(reversed: &RedirectTuple) -> Option<RedirectEntry> {
    let key = UdpReplyKey::from_request(reversed);
    let old = unsafe { UDP_REPLY_TRACK.get(&key).copied() }?;
    let now = unsafe { bpf_ktime_get_ns() };
    let route = udp_reply_route(&old, now)?;
    if let Some(entry) = udp_reply_update(Some(&old), route, now) {
        let _ = UDP_REPLY_TRACK.insert(&key, &entry, 0);
    }
    Some(route)
}
