//! Shared flow state and timeout interpretation for BPF and userspace cleanup.
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

#[cfg(test)]
mod tests {
    use super::*;
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
}
