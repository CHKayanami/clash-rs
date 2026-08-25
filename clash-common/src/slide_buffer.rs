//! Zero-allocation sliding buffer for streaming data
//!
//! This module provides a fixed-capacity sliding buffer optimized for
//! streaming protocols where data is written at one end and read from another.
//! Unlike a true ring buffer, this uses a linear layout with lazy compaction
//! via `copy_within()`, which is optimal for use cases requiring contiguous
//! slices (like TLS record processing, packet sniffing, protocol headers).

use std::fmt;
use std::io::{BufRead, Read};

/// A sliding buffer with linear slice and lazy compaction via `copy_within()`.
pub struct SlideBuffer {
    /// Pre-allocated buffer storage
    data: Box<[u8]>,
    /// Start offset of valid data (inclusive)
    start: usize,
    /// End offset of valid data (exclusive)
    end: usize,
}

impl Clone for SlideBuffer {
    fn clone(&self) -> Self {
        let mut new_buf = Self::new(self.data.len());
        new_buf.extend_from_slice(self.as_slice());
        new_buf
    }
}

impl fmt::Debug for SlideBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlideBuffer")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .field("remaining_capacity", &self.remaining_capacity())
            .field("data", &self.as_slice())
            .finish()
    }
}

impl Default for SlideBuffer {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl SlideBuffer {
    /// Create a new slide buffer with the specified capacity.
    #[inline]
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            data: crate::allocate_boxed_slice(cap),
            start: 0,
            end: 0,
        }
    }

    /// Total capacity of the underlying buffer.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// Returns the number of bytes currently stored in the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Returns true if the buffer contains no data.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    /// Returns the remaining space available for writing at the end of the buffer.
    /// To reclaim space consumed from the front, call `compact()`.
    #[inline]
    pub fn remaining_capacity(&self) -> usize {
        self.data.len() - self.end
    }

    /// Get a slice of the readable data.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.start..self.end]
    }

    /// Get a mutable slice of the readable data.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[self.start..self.end]
    }

    /// Get a mutable slice for writing new data at the end.
    #[inline]
    pub fn write_slice(&mut self) -> &mut [u8] {
        &mut self.data[self.end..]
    }

    /// Mark n bytes as written (after writing to `write_slice()`).
    #[inline]
    pub fn advance_write(&mut self, n: usize) {
        debug_assert!(
            self.end + n <= self.data.len(),
            "SlideBuffer advance_write overflow: end={}, n={}, capacity={}",
            self.end,
            n,
            self.data.len()
        );
        self.end += n;
    }

    /// Ensure the buffer has at least `min_capacity` total storage.
    pub fn ensure_capacity(&mut self, min_capacity: usize) {
        if self.data.len() < min_capacity {
            let new_cap = min_capacity.next_power_of_two();
            let mut new_data = crate::allocate_boxed_slice(new_cap);
            let len = self.len();
            if len > 0 {
                new_data[..len].copy_from_slice(self.as_slice());
            }
            self.data = new_data;
            self.start = 0;
            self.end = len;
        }
    }

    /// Reserve at least `additional` writable space.
    pub fn reserve(&mut self, additional: usize) {
        if self.remaining_capacity() < additional {
            self.compact();
            if self.remaining_capacity() < additional {
                let required = self.len() + additional;
                self.ensure_capacity(required);
            }
        }
    }

    /// Extend the buffer with data from a slice.
    #[inline]
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        if self.remaining_capacity() < data.len() {
            self.reserve(data.len());
        }
        let end = self.end;
        self.data[end..end + data.len()].copy_from_slice(data);
        self.end += data.len();
    }

    /// Consume n bytes from the front of the buffer.
    #[inline]
    pub fn consume(&mut self, n: usize) {
        debug_assert!(
            n <= self.len(),
            "SlideBuffer consume underflow: n={}, len={}",
            n,
            self.len()
        );
        self.start += n;

        // Reset offsets if buffer is now empty
        if self.start >= self.end {
            self.start = 0;
            self.end = 0;
        }
    }

    /// Clear all data in the buffer, resetting offsets to 0.
    #[inline]
    pub fn clear(&mut self) {
        self.start = 0;
        self.end = 0;
    }

    /// Truncate the buffer length to `len` bytes from the start.
    #[inline]
    pub fn truncate(&mut self, len: usize) {
        if self.len() > len {
            self.end = self.start + len;
        }
    }

    /// Compact the buffer by moving data to the front.
    #[inline]
    pub fn compact(&mut self) {
        if self.start > 0 && self.start < self.end {
            self.data.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        } else if self.start >= self.end {
            self.start = 0;
            self.end = 0;
        }
    }

    /// Compact only if we've consumed more than the threshold.
    #[inline]
    pub fn maybe_compact(&mut self, threshold: usize) {
        if self.start > threshold {
            self.compact();
        }
    }

    /// Returns a two-byte value at the given offset as big-endian u16.
    #[inline]
    pub fn get_u16_be(&self, offset: usize) -> Option<u16> {
        if offset + 2 <= self.len() {
            let idx = self.start + offset;
            Some(u16::from_be_bytes([self.data[idx], self.data[idx + 1]]))
        } else {
            None
        }
    }

    /// Get a mutable slice of the readable data for in-place modification.
    #[inline]
    pub fn slice_mut(&mut self, range: std::ops::Range<usize>) -> &mut [u8] {
        &mut self.data[self.start + range.start..self.start + range.end]
    }
}

impl Read for SlideBuffer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let available = self.len();
        if available == 0 {
            return Ok(0);
        }
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.data[self.start..self.start + to_read]);
        self.consume(to_read);
        Ok(to_read)
    }
}

impl BufRead for SlideBuffer {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        Ok(self.as_slice())
    }

    fn consume(&mut self, amt: usize) {
        SlideBuffer::consume(self, amt);
    }
}

impl std::io::Write for SlideBuffer {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::ops::Index<usize> for SlideBuffer {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.data[self.start + index]
    }
}

impl std::ops::IndexMut<usize> for SlideBuffer {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[self.start + index]
    }
}

impl std::ops::Index<std::ops::Range<usize>> for SlideBuffer {
    type Output = [u8];

    #[inline]
    fn index(&self, range: std::ops::Range<usize>) -> &Self::Output {
        &self.data[self.start + range.start..self.start + range.end]
    }
}

impl std::ops::IndexMut<std::ops::Range<usize>> for SlideBuffer {
    #[inline]
    fn index_mut(&mut self, range: std::ops::Range<usize>) -> &mut Self::Output {
        &mut self.data[self.start + range.start..self.start + range.end]
    }
}

impl std::ops::Index<std::ops::RangeFrom<usize>> for SlideBuffer {
    type Output = [u8];

    #[inline]
    fn index(&self, range: std::ops::RangeFrom<usize>) -> &Self::Output {
        &self.data[self.start + range.start..self.end]
    }
}

impl std::ops::IndexMut<std::ops::RangeFrom<usize>> for SlideBuffer {
    #[inline]
    fn index_mut(&mut self, range: std::ops::RangeFrom<usize>) -> &mut Self::Output {
        &mut self.data[self.start + range.start..self.end]
    }
}

impl std::ops::Index<std::ops::RangeTo<usize>> for SlideBuffer {
    type Output = [u8];

    #[inline]
    fn index(&self, range: std::ops::RangeTo<usize>) -> &Self::Output {
        &self.data[self.start..self.start + range.end]
    }
}

impl std::ops::IndexMut<std::ops::RangeTo<usize>> for SlideBuffer {
    #[inline]
    fn index_mut(&mut self, range: std::ops::RangeTo<usize>) -> &mut Self::Output {
        &mut self.data[self.start..self.start + range.end]
    }
}

impl std::ops::Index<std::ops::RangeFull> for SlideBuffer {
    type Output = [u8];

    #[inline]
    fn index(&self, _range: std::ops::RangeFull) -> &Self::Output {
        &self.data[self.start..self.end]
    }
}

impl std::ops::IndexMut<std::ops::RangeFull> for SlideBuffer {
    #[inline]
    fn index_mut(&mut self, _range: std::ops::RangeFull) -> &mut Self::Output {
        &mut self.data[self.start..self.end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_buffer() {
        let buf = SlideBuffer::new(1024);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert_eq!(buf.remaining_capacity(), 1024);
    }

    #[test]
    fn test_is_empty() {
        let mut buf = SlideBuffer::new(1024);
        assert!(buf.is_empty());

        buf.extend_from_slice(b"hello");
        assert!(!buf.is_empty());

        buf.consume(3);
        assert!(!buf.is_empty());

        buf.consume(2);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_extend_from_slice() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_slice(), b"hello");
        assert_eq!(buf.remaining_capacity(), 1024 - 5);
    }

    #[test]
    fn test_consume() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello world");
        buf.consume(6);
        assert_eq!(buf.as_slice(), b"world");
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn test_consume_all_resets() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello");
        buf.consume(5);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.remaining_capacity(), 1024);
    }

    #[test]
    fn test_compact() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello world");
        buf.consume(6);
        assert_eq!(buf.remaining_capacity(), 1024 - 11);

        buf.compact();
        assert_eq!(buf.as_slice(), b"world");
        assert_eq!(buf.remaining_capacity(), 1024 - 5);
    }

    #[test]
    fn test_maybe_compact() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"0123456789");
        buf.consume(5);

        // Threshold not met
        buf.maybe_compact(10);
        assert_eq!(buf.remaining_capacity(), 1024 - 10);

        // Threshold met
        buf.maybe_compact(4);
        assert_eq!(buf.remaining_capacity(), 1024 - 5);
    }

    #[test]
    fn test_write_slice() {
        let mut buf = SlideBuffer::new(1024);
        let write_buf = buf.write_slice();
        write_buf[..5].copy_from_slice(b"hello");
        buf.advance_write(5);

        assert_eq!(buf.as_slice(), b"hello");
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn test_read_trait() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello world");

        let mut output = [0u8; 5];
        let n = buf.read(&mut output).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&output, b"hello");

        let n = buf.read(&mut output).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&output, b" worl");

        let n = buf.read(&mut output).unwrap();
        assert_eq!(n, 1);
        assert_eq!(&output[..1], b"d");
    }

    #[test]
    fn test_bufread_trait() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello world");

        {
            let slice = buf.fill_buf().unwrap();
            assert_eq!(slice, b"hello world");
        }

        buf.consume(6);

        {
            let slice = buf.fill_buf().unwrap();
            assert_eq!(slice, b"world");
        }
    }

    #[test]
    fn test_indexing() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello world");

        assert_eq!(buf[0], b'h');
        assert_eq!(buf[6], b'w');
        assert_eq!(&buf[0..5], b"hello");
        assert_eq!(&buf[6..], b"world");
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(&buf[..], b"hello world");
    }

    #[test]
    fn test_indexing_after_consume() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello world");
        buf.consume(6);

        assert_eq!(buf[0], b'w');
        assert_eq!(&buf[0..5], b"world");
    }

    #[test]
    fn test_get_u16_be() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);

        assert_eq!(buf.get_u16_be(0), Some(0x1234));
        assert_eq!(buf.get_u16_be(2), Some(0x5678));
        assert_eq!(buf.get_u16_be(3), None);
    }

    #[test]
    fn test_slice_mut() {
        let mut buf = SlideBuffer::new(100);
        buf.extend_from_slice(b"hello world");

        let slice = buf.slice_mut(6..11);
        assert_eq!(slice, b"world");
        slice[0] = b'W';
        slice[4] = b'D';

        assert_eq!(buf.as_slice(), b"hello WorlD");

        buf.consume(6);
        let slice = buf.slice_mut(0..5);
        slice.copy_from_slice(b"EARTH");
        assert_eq!(buf.as_slice(), b"EARTH");
    }

    #[test]
    fn test_dynamic_reserve() {
        let mut buf = SlideBuffer::new(10);
        buf.extend_from_slice(b"0123456789");
        assert_eq!(buf.len(), 10);
        buf.extend_from_slice(b"abcdefghij");
        assert_eq!(buf.len(), 20);
        assert_eq!(buf.as_slice(), b"0123456789abcdefghij");
    }
}
