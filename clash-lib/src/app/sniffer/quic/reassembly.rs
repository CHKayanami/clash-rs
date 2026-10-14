use std::collections::BTreeMap;

const MAX_CRYPTO_STREAM: usize = 64 * 1024;
const MAX_CRYPTO_FRAGMENTS: usize = 256;

#[derive(Debug, Clone, Default)]
pub struct CryptoReassembly {
    fragments: BTreeMap<u64, Vec<u8>>,
    assembled: Vec<u8>,
    pending_bytes: usize,
    overflowed: bool,
}

impl CryptoReassembly {
    pub fn new() -> Self { Self::default() }

    pub fn insert(&mut self, offset: u64, data: &[u8]) {
        if self.overflowed || data.is_empty() { return; }
        if offset > MAX_CRYPTO_STREAM as u64
            || data.len() > MAX_CRYPTO_STREAM.saturating_sub(offset as usize)
        {
            self.overflow();
            return;
        }
        let offset = offset as usize;
        let skip = self.assembled.len().saturating_sub(offset).min(data.len());
        let data = &data[skip..];
        if data.is_empty() { return; }
        let offset = offset + skip;
        if offset == self.assembled.len() {
            // The common in-order case needs no intermediate fragment allocation.
            self.assembled.extend_from_slice(data);
        } else {
            let existing = self.fragments.get(&(offset as u64))
                .map_or(0, Vec::len);
            let added = data.len().saturating_sub(existing);
            if added == 0 { return; }
            if self.assembled.len() + self.pending_bytes + added > MAX_CRYPTO_STREAM
                || existing == 0 && self.fragments.len() >= MAX_CRYPTO_FRAGMENTS
            {
                self.overflow();
                return;
            }
            self.fragments.entry(offset as u64).or_default()
                .extend_from_slice(&data[existing..]);
            self.pending_bytes += added;
        }
        while let Some((&offset, _)) = self.fragments.first_key_value() {
            if offset > self.assembled.len() as u64 { break; }
            let data = self.fragments.remove(&offset).unwrap();
            self.pending_bytes -= data.len();
            let skip = (self.assembled.len() - offset as usize).min(data.len());
            self.assembled.extend_from_slice(&data[skip..]);
        }
        if self.assembled.len() + self.pending_bytes > MAX_CRYPTO_STREAM {
            self.overflow();
        }
    }

    fn overflow(&mut self) {
        *self = Self { overflowed: true, ..Self::default() };
    }

    pub fn assembled(&self) -> &[u8] { &self.assembled }

    pub fn is_overflowed(&self) -> bool { self.overflowed }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_offsets_and_total_pending_bytes() {
        for offset in [MAX_CRYPTO_STREAM as u64, u64::MAX] {
            let mut state = CryptoReassembly::new();
            state.insert(offset, b"x");
            assert!(state.is_overflowed());
        }
        let mut state = CryptoReassembly::new();
        state.insert(1, &vec![0; MAX_CRYPTO_STREAM - 1]);
        state.insert(2, b"xx");
        assert!(state.is_overflowed());
        assert!(state.fragments.is_empty());
        assert_eq!(state.assembled.capacity(), 0);
    }

    #[test]
    fn bounds_fragment_count_and_releases_storage() {
        let mut state = CryptoReassembly::new();
        for offset in 1..=MAX_CRYPTO_FRAGMENTS {
            state.insert(offset as u64, b"x");
        }
        assert!(!state.is_overflowed());
        state.insert(MAX_CRYPTO_FRAGMENTS as u64 + 1, b"x");
        assert!(state.is_overflowed());
        assert!(state.fragments.is_empty());
    }

    #[test]
    fn contiguous_data_and_overlaps_do_not_require_pending_fragments() {
        let mut state = CryptoReassembly::new();
        state.insert(0, b"abcd");
        state.insert(2, b"cdef");
        assert_eq!(state.assembled(), b"abcdef");
        assert!(state.fragments.is_empty());
        assert_eq!(state.pending_bytes, 0);
    }
}
