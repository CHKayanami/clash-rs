//! Versioned bucket gates shared by packet writers and the BPF collector.
use core::sync::atomic::AtomicU64;
#[cfg(not(target_arch = "bpf"))]
use core::sync::atomic::Ordering;
#[cfg(target_arch = "bpf")]
use core::arch::asm;

use crate::{RedirectTuple, UdpReplyKey};

pub const BUCKETS: u32 = 4096;

#[inline(always)]
fn hash(ip: &[u8; 16], seed: u32) -> u32 {
    let mut value = seed;
    for index in 0..4 {
        let offset = index * 4;
        let word = u32::from_ne_bytes([ip[offset], ip[offset + 1], ip[offset + 2], ip[offset + 3]]);
        value = value.rotate_left(5) ^ word;
    }
    value
}

#[inline(always)]
fn finish(mut value: u32) -> u32 {
    value ^= value >> 16;
    value = value.wrapping_mul(0x7feb352d);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846ca68b);
    (value ^ (value >> 16)) & (BUCKETS - 1)
}

#[inline(always)]
pub fn bucket(tuple: &RedirectTuple) -> u32 {
    let seed = tuple.src_port as u32 ^ ((tuple.dst_port as u32) << 16)
        ^ tuple.proto as u32 ^ tuple.ip_version as u32;
    finish(hash(&tuple.dst_ip, hash(&tuple.src_ip, seed)))
}

#[inline(always)]
pub fn reply_bucket(key: &UdpReplyKey) -> u32 {
    finish(hash(&key.client_ip, key.client_port as u32
        ^ ((key.ip_version as u32) << 16) ^ 0x9e3779b9))
}

pub struct Guard<'a> {
    word: &'a AtomicU64,
    version: u64,
}

impl Guard<'_> {
    /// Unique for this bucket until its counter is exhausted. The gate never
    /// wraps, so a reused tuple cannot inherit an earlier incarnation.
    #[inline(always)]
    pub fn generation(&self) -> u64 { self.version + 2 }
}

impl Drop for Guard<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        // Use an RMW, not a plain BPF store: its CPU ordering also publishes
        // all map writes on weakly ordered architectures.
        compare_exchange(self.word, self.version + 1, self.version + 2);
    }
}

#[inline(always)]
pub fn try_lock(word: &AtomicU64) -> Option<Guard<'_>> {
    let version = load(word);
    if version & 1 != 0 || version >= u64::MAX - 2 { return None; }
    if compare_exchange(word, version, version + 1) == version {
        Some(Guard { word, version })
    } else { None }
}

#[inline(always)]
fn load(word: &AtomicU64) -> u64 {
    #[cfg(not(target_arch = "bpf"))]
    { word.load(Ordering::Relaxed) }
    #[cfg(target_arch = "bpf")]
    {
        let value;
        // Aligned BPF scalar memory accesses are indivisible. LLVM does not
        // lower Rust atomic loads for this target, so spell out the load.
        unsafe { asm!("{value} = *(u64 *)({ptr} + 0)",
            value = out(reg) value, ptr = in(reg) word.as_ptr(),
            options(nostack, readonly)); }
        value
    }
}

/// # Safety
/// `ptr` must address live, eight-byte aligned atomic storage.
#[inline(always)]
pub unsafe fn load_u64(ptr: *const u64) -> u64 {
    unsafe { load(&*ptr.cast::<AtomicU64>()) }
}

/// # Safety
/// `ptr` must address live, eight-byte aligned atomic storage.
#[inline(always)]
pub unsafe fn store_u64(ptr: *mut u64, value: u64) {
    #[cfg(not(target_arch = "bpf"))]
    { unsafe { (&*ptr.cast::<AtomicU64>()).store(value, Ordering::Relaxed); } }
    #[cfg(target_arch = "bpf")]
    unsafe { asm!("*(u64 *)({ptr} + 0) = {value}",
        ptr = in(reg) ptr, value = in(reg) value, options(nostack)); }
}

#[inline(always)]
fn compare_exchange(word: &AtomicU64, expected: u64, next: u64) -> u64 {
    #[cfg(not(target_arch = "bpf"))]
    { word.compare_exchange(expected, next, Ordering::SeqCst, Ordering::SeqCst)
        .unwrap_or_else(|actual| actual) }
    #[cfg(target_arch = "bpf")]
    {
        let previous;
        // Rust's BPF target does not expose CAS in AtomicU64's API. Emit the
        // native BPF CMPXCHG directly. No nomem/readonly: this is also a compiler
        // memory barrier. The JIT must implement the atomic RMW ordering.
        unsafe { asm!("r0 = cmpxchg_64({ptr} + 0, r0, {next})",
            ptr = in(reg) word.as_ptr(), next = in(reg) next,
            inout("r0") expected => previous, options(nostack)); }
        previous
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_writer_excludes_retirement_and_advances_the_generation() {
        let word = AtomicU64::new(0);
        let version = word.load(Ordering::SeqCst);
        let writer = try_lock(&word).unwrap();
        assert!(try_lock(&word).is_none());
        assert_eq!(word.load(Ordering::SeqCst) & 1, 1);
        let first = writer.generation();
        drop(writer);
        assert_eq!(word.load(Ordering::SeqCst), version + 2);
        assert!(try_lock(&word).unwrap().generation() > first);
    }

    #[test]
    fn exhaustion_never_reuses_an_incarnation() {
        let word = AtomicU64::new(u64::MAX - 3);
        let last = try_lock(&word).unwrap();
        assert_eq!(last.generation(), u64::MAX - 1);
        drop(last);
        assert!(try_lock(&word).is_none());
        assert_eq!(word.load(Ordering::SeqCst), u64::MAX - 1);
    }
}
