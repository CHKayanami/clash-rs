use bytes::{Bytes, BytesMut};
use std::{
    cell::RefCell,
    ops::{Deref, DerefMut},
    sync::{
        LazyLock, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

static MAX_POOLED_BUFFERS: AtomicUsize = AtomicUsize::new(128);

#[allow(dead_code)]
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
    #[allow(dead_code)]
    pub fn with_capacity(cap: usize) -> Self {
        let from_local = LOCAL_POOL.with_borrow_mut(|local| local.pop());
        if let Some(mut buffer) = from_local {
            if buffer.capacity() < cap {
                buffer.reserve(cap - buffer.capacity());
            }
            buffer.resize(cap, 0);
            return Self { buffer };
        }

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
        let from_local = LOCAL_POOL.with_borrow_mut(|local| local.pop());
        if let Some(mut buffer) = from_local {
            buffer.clear();
            if buffer.capacity() < cap {
                buffer.reserve(cap - buffer.capacity());
            }
            return Self { buffer };
        }

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
            buffer: BytesMut::with_capacity(cap.max(2048)),
        }
    }

    #[inline]
    pub fn extend_from_slice(&mut self, extend: &[u8]) {
        self.buffer.extend_from_slice(extend);
    }

    /// Wrap this `PooledBuffer` into a standard `bytes::Bytes` using `Bytes::from_owner`.
    /// When the resulting `Bytes` is dropped, this `PooledBuffer` will be dropped and
    /// automatically returned to the memory pool!
    pub fn into_bytes(self) -> Bytes {
        Bytes::from_owner(self)
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
    #[allow(dead_code)]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buffer.as_mut_ptr()
    }

    #[inline]
    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const u8 {
        self.buffer.as_ptr()
    }
}

impl AsRef<[u8]> for PooledBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..]
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
        if buffer.capacity() == 0 || buffer.capacity() > 65536 * 4 {
            return;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pooled_buffer_thread_local() {
        let mut buf = PooledBuffer::acquire(1024);
        buf.extend_from_slice(b"test-data");
        assert_eq!(&buf[..], b"test-data");
        drop(buf);

        // Should be acquired from local pool
        let mut buf2 = PooledBuffer::acquire(512);
        assert!(buf2.is_empty());
        assert!(buf2.buffer.capacity() >= 1024);
        buf2.extend_from_slice(b"new-data");
        assert_eq!(&buf2[..], b"new-data");
    }

    #[test]
    fn test_pooled_buffer_into_bytes_returns_to_pool_on_drop() {
        {
            let mut buf = PooledBuffer::acquire(1024);
            buf.extend_from_slice(b"hello world");
            let bytes = buf.into_bytes();
            assert_eq!(&bytes[..], b"hello world");
        }

        // The buffer was returned to pool when `Bytes` dropped!
        let buf2 = PooledBuffer::acquire(512);
        assert!(buf2.is_empty());
        assert!(buf2.buffer.capacity() >= 1024);
    }
}
