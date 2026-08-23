use bytes::BytesMut;
use std::{
    cell::{RefCell, UnsafeCell},
    ops::{Deref, DerefMut},
    sync::{
        LazyLock, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

static MAX_POOLED_BUFFERS: AtomicUsize = AtomicUsize::new(128);

pub fn set_max_pooled_buffers(limit: usize) {
    MAX_POOLED_BUFFERS.store(limit, Ordering::Relaxed);
}

pub fn max_pooled_buffers() -> usize {
    MAX_POOLED_BUFFERS.load(Ordering::Relaxed)
}

const LOCAL_POOL_CAPACITY: usize = 16;

thread_local! {
    static LOCAL_POOL: RefCell<Vec<BytesMut>> = const { RefCell::new(Vec::new()) };
}

static BUFFER_POOL: LazyLock<Mutex<Vec<BytesMut>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// Pooled buffer that returns to pool on drop instead of deallocating.
#[derive(Debug)]
pub struct PooledBuffer {
    buffer: BytesMut,
}

impl PooledBuffer {
    /// Get a buffer from the pool or create a new one with requested working capacity.
    pub fn with_capacity(cap: usize) -> Self {
        // 1. Try thread-local pool first (lock-free)
        let from_local = LOCAL_POOL.with_borrow_mut(|local| local.pop());
        if let Some(mut buffer) = from_local {
            if buffer.capacity() < cap {
                buffer.reserve(cap - buffer.capacity());
            }
            buffer.resize(cap, 0);
            return Self { buffer };
        }

        // 2. Fall back to global pool
        if let Ok(mut pool) = BUFFER_POOL.lock() {
            if let Some(mut buffer) = pool.pop() {
                if buffer.capacity() < cap {
                    buffer.reserve(cap - buffer.capacity());
                }
                buffer.resize(cap, 0);
                return Self { buffer };
            }
        }
        let mut buffer = BytesMut::with_capacity(cap);
        buffer.resize(cap, 0);
        Self { buffer }
    }

    /// Acquire a clear buffer from the pool with at least `cap` capacity.
    pub fn acquire(cap: usize) -> Self {
        // 1. Try thread-local pool first (lock-free)
        let from_local = LOCAL_POOL.with_borrow_mut(|local| local.pop());
        if let Some(mut buffer) = from_local {
            buffer.clear();
            if buffer.capacity() < cap {
                buffer.reserve(cap - buffer.capacity());
            }
            return Self { buffer };
        }

        // 2. Fall back to global pool
        if let Ok(mut pool) = BUFFER_POOL.lock() {
            if let Some(mut buffer) = pool.pop() {
                buffer.clear();
                if buffer.capacity() < cap {
                    buffer.reserve(cap - buffer.capacity());
                }
                return Self { buffer };
            }
        }
        Self {
            buffer: BytesMut::with_capacity(cap),
        }
    }

    #[inline]
    pub fn extend_from_slice(&mut self, extend: &[u8]) {
        self.buffer.extend_from_slice(extend);
    }

    pub fn into_bytes(mut self) -> bytes::Bytes {
        let mut empty = BytesMut::new();
        std::mem::swap(&mut self.buffer, &mut empty);
        empty.freeze()
    }

    #[inline]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    #[inline]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buffer.as_mut_ptr()
    }

    #[inline]
    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const u8 {
        self.buffer.as_ptr()
    }
}

impl Deref for PooledBuffer {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.buffer[..]
    }
}

impl DerefMut for PooledBuffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer[..]
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        let mut buffer = std::mem::replace(&mut self.buffer, BytesMut::new());
        buffer.clear();

        // 1. Try returning to thread-local pool first (lock-free)
        let unreturned = LOCAL_POOL.with_borrow_mut(|local| {
            if local.len() < LOCAL_POOL_CAPACITY {
                local.push(buffer);
                None
            } else {
                Some(buffer)
            }
        });

        // 2. If thread-local pool is full, return to global pool
        if let Some(buffer) = unreturned {
            if let Ok(mut pool) = BUFFER_POOL.lock() {
                if pool.len() < max_pooled_buffers() {
                    pool.push(buffer);
                }
            }
        }
    }
}

pub fn acquire_vec(capacity: usize) -> Vec<u8> {
    vec![0u8; capacity]
}

pub struct LockFreeRingBuffer {
    buffer: UnsafeCell<Option<PooledBuffer>>,
    raw_ptr: *mut u8,
    capacity: usize,
    write_pos: AtomicUsize, // Only TCP thread writes
    read_pos: AtomicUsize,  // Only app thread reads
}

unsafe impl Send for LockFreeRingBuffer {}
unsafe impl Sync for LockFreeRingBuffer {}

impl LockFreeRingBuffer {
    pub fn new(capacity: usize) -> Self {
        let mut buffer = PooledBuffer::with_capacity(capacity);
        let raw_ptr = buffer.as_mut_ptr();
        Self {
            buffer: UnsafeCell::new(Some(buffer)),
            raw_ptr,
            capacity,
            write_pos: AtomicUsize::new(0),
            read_pos: AtomicUsize::new(0),
        }
    }

    // TCP thread calls this (single producer)
    pub fn enqueue_slice(&self, data: &[u8]) -> usize {
        let write_pos = self.write_pos.load(Ordering::Relaxed);
        let read_pos = self.read_pos.load(Ordering::Acquire);

        // Calculate available space
        let available = if read_pos <= write_pos {
            self.capacity - write_pos + read_pos - 1
        } else {
            read_pos - write_pos - 1
        };

        let to_write = std::cmp::min(data.len(), available);
        if to_write == 0 {
            return 0;
        }

        unsafe {
            let buffer = std::slice::from_raw_parts_mut(self.raw_ptr, self.capacity);

            // Handle wrap-around
            if write_pos + to_write <= self.capacity {
                // No wrap
                buffer[write_pos..write_pos + to_write]
                    .copy_from_slice(&data[..to_write]);
            } else {
                // Wrap around
                let first_part = self.capacity - write_pos;
                buffer[write_pos..].copy_from_slice(&data[..first_part]);
                buffer[..to_write - first_part]
                    .copy_from_slice(&data[first_part..to_write]);
            }
        }

        // Update write position
        let new_write_pos = (write_pos + to_write) % self.capacity;
        self.write_pos.store(new_write_pos, Ordering::Release);

        to_write
    }

    // App thread calls this (single consumer)
    pub fn dequeue_slice(&self, buf: &mut [u8]) -> usize {
        let read_pos = self.read_pos.load(Ordering::Relaxed);
        let write_pos = self.write_pos.load(Ordering::Acquire);

        // Calculate available data
        let available = if write_pos >= read_pos {
            write_pos - read_pos
        } else {
            self.capacity - read_pos + write_pos
        };

        let to_read = std::cmp::min(buf.len(), available);
        if to_read == 0 {
            return 0;
        }

        unsafe {
            let buffer = std::slice::from_raw_parts(self.raw_ptr, self.capacity);

            // Handle wrap-around
            if read_pos + to_read <= self.capacity {
                // No wrap
                buf[..to_read]
                    .copy_from_slice(&buffer[read_pos..read_pos + to_read]);
            } else {
                // Wrap around
                let first_part = self.capacity - read_pos;
                buf[..first_part].copy_from_slice(&buffer[read_pos..]);
                buf[first_part..to_read]
                    .copy_from_slice(&buffer[..to_read - first_part]);
            }
        }

        // Update read position
        let new_read_pos = (read_pos + to_read) % self.capacity;
        self.read_pos.store(new_read_pos, Ordering::Release);

        to_read
    }

    pub fn is_empty(&self) -> bool {
        self.read_pos.load(Ordering::Acquire)
            == self.write_pos.load(Ordering::Acquire)
    }

    pub fn is_full(&self) -> bool {
        let read_pos = self.read_pos.load(Ordering::Acquire);
        let write_pos = self.write_pos.load(Ordering::Acquire);
        ((write_pos + 1) % self.capacity) == read_pos
    }
}

impl Drop for LockFreeRingBuffer {
    fn drop(&mut self) {
        unsafe {
            let _ = (*self.buffer.get()).take();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer_pooling() {
        let rb = LockFreeRingBuffer::new(64 * 1024);
        assert_eq!(rb.enqueue_slice(b"hello world"), 11);
        let mut out = [0u8; 11];
        assert_eq!(rb.dequeue_slice(&mut out), 11);
        assert_eq!(&out, b"hello world");
        drop(rb);

        // Next allocation should reuse pooled buffer
        let rb2 = LockFreeRingBuffer::new(64 * 1024);
        assert_eq!(rb2.enqueue_slice(b"reused"), 6);
        let mut out2 = [0u8; 6];
        assert_eq!(rb2.dequeue_slice(&mut out2), 6);
        assert_eq!(&out2, b"reused");
    }

    #[test]
    fn test_pooled_buffer_thread_local() {
        let mut buf = PooledBuffer::acquire(1024);
        buf.extend_from_slice(b"test-data");
        assert_eq!(&buf[..], b"test-data");
        drop(buf);

        // Should be acquired from local pool with 0 allocations
        let mut buf2 = PooledBuffer::acquire(512);
        assert!(buf2.is_empty());
        assert!(buf2.buffer.capacity() >= 1024);
        buf2.extend_from_slice(b"new-data");
        assert_eq!(&buf2[..], b"new-data");
    }
}
