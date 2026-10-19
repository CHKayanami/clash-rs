//! Shared flow state and timeout interpretation for BPF and userspace cleanup.
use crate::FlowTrackEntry;

pub mod gate;
pub const DIRECT: u32 = 1 << 31;
pub const CLOSING: u32 = 1 << 29;
pub const MAX_GENERATION: u64 = CLOSING as u64 - 1;
pub const UDP_TIMEOUT: u32 = 121;
pub const TCP_CLOSING_TIMEOUT: u32 = 10;

#[inline(always)]
pub fn word(token: u32, seconds: u32) -> u64 { ((token as u64) << 32) | seconds as u64 }
#[inline(always)]
pub fn token(value: u64) -> u32 { (value >> 32) as u32 }
#[inline(always)]
pub fn seconds(value: u64) -> u32 { value as u32 }
#[inline(always)]
pub fn incarnation(value: u64) -> u32 { token(value) & MAX_GENERATION as u32 }

#[inline(always)]
pub fn expired(value: u64, stamp: u32, udp: bool) -> bool {
    // Signed modular age handles the seconds counter wrapping after 136 years
    // and a packet timestamp sampled before another CPU's newer refresh.
    let age = stamp.wrapping_sub(seconds(value)) as i32;
    if udp { age > UDP_TIMEOUT as i32 }
    else { token(value) & CLOSING != 0 && age > TCP_CLOSING_TIMEOUT as i32 }
}

/// The first eight bytes of FlowTrackEntry are an aligned atomic activity
/// word. All live BPF accesses must use this width; userspace fixture writes
/// are permitted only while packet execution is stopped.
///
/// # Safety
/// `ptr` must address a live, eight-byte aligned FlowTrackEntry allocation.
#[inline(always)]
pub unsafe fn load_activity(ptr: *const FlowTrackEntry) -> u64 {
    let raw = unsafe { gate::load_u64(ptr.cast()) };
    if cfg!(target_endian = "little") { raw } else { raw.rotate_left(32) }
}

/// # Safety
/// `ptr` must address a live, eight-byte aligned FlowTrackEntry allocation.
/// The caller must own its writer gate and preserve the record's generation.
#[inline(always)]
pub unsafe fn store_activity(ptr: *mut FlowTrackEntry, activity: u64) {
    let raw = if cfg!(target_endian = "little") { activity } else { activity.rotate_left(32) };
    unsafe { gate::store_u64(ptr.cast(), raw); }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition { Keep, Retire, Activity(u64) }

/// Called only after re-reading the entry under its writer gate. An operation
/// that observed an older incarnation must not refresh, close or retire it.
#[inline(always)]
pub fn transition(activity: u64, generation: u64, observed: u64,
    stamp: u32, udp: bool, reset: bool, finish: bool,
) -> Transition {
    if generation != observed { return Transition::Keep; }
    if reset || expired(activity, stamp, udp) { return Transition::Retire; }
    let id = token(activity);
    if !finish && !udp && id & CLOSING == 0 { return Transition::Keep; }
    let latest = if stamp.wrapping_sub(seconds(activity)) as i32 > 0 {
        stamp
    } else { seconds(activity) };
    let next = word(id | if finish { CLOSING } else { 0 }, latest);
    if next == activity { Transition::Keep } else { Transition::Activity(next) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn activity_atomic_access_preserves_the_public_field_layout() {
        let mut entry = FlowTrackEntry { last_seen_seconds: 100, state: 7 | DIRECT,
            ..FlowTrackEntry::default() };
        assert_eq!(unsafe { load_activity(&entry) }, entry.activity());
        let next = word(9 | CLOSING, 200);
        unsafe { store_activity(&mut entry, next); }
        assert_eq!(entry.activity(), next);
        assert_eq!(unsafe { load_activity(&entry) }, next);
        assert_eq!(entry.generation, 0);
    }

    #[test]
    fn age_handles_stale_samples_and_seconds_wrap() {
        assert!(!expired(word(1, 100), 99, true));
        assert!(!expired(word(1, u32::MAX - 10), 20, true));
        assert!(expired(word(1, u32::MAX - 200), 20, true));
    }
    #[test]
    fn tcp_active_survives_and_closing_expires() {
        assert!(!expired(word(1 | DIRECT, 10), 100000, false));
        assert!(!expired(word(1 | CLOSING, 10), 20, false));
        assert!(expired(word(1 | CLOSING, 10), 21, false));
    }
    #[test]
    fn state_flags_do_not_change_the_generation() {
        assert_eq!(incarnation(word(1, 10)), incarnation(word(1 | CLOSING | DIRECT, 11)));
        assert_ne!(incarnation(word(1, 10)), incarnation(word(2, 10)));
    }

    #[test]
    fn delayed_fin_reset_and_expiry_cannot_change_a_new_incarnation() {
        let active = word(2 | DIRECT, 100);
        for (reset, finish) in [(true, false), (false, true), (true, true)] {
            assert_eq!(transition(active, 4, 2, 200, false, reset, finish), Transition::Keep);
        }
        assert_eq!(transition(word(2, 1), 4, 2, 200, true, false, false), Transition::Keep);
        assert_eq!(transition(word(2 | CLOSING, 1), 4, 2, 200, false, false, true), Transition::Keep);
    }

    #[test]
    fn current_incarnation_closes_refreshes_and_expires_without_rewinding() {
        let active = word(1 | DIRECT, 100);
        let closing = word(1 | DIRECT | CLOSING, 101);
        assert_eq!(transition(active, 2, 2, 101, false, false, true), Transition::Activity(closing));
        assert_eq!(transition(closing, 2, 2, 100, false, false, true), Transition::Keep);
        assert_eq!(transition(closing, 2, 2, 112, false, false, false), Transition::Retire);
        assert_eq!(transition(active, 2, 2, 101, false, true, false), Transition::Retire);
        assert_eq!(transition(word(1, 100), 2, 2, 101, true, false, false),
            Transition::Activity(word(1, 101)));
    }
}
