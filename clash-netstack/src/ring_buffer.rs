use std::{
    cell::UnsafeCell,
    sync::{
        LazyLock, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

const MAX_POOLED_BUFFERS: usize = 128;

static BOXED_BUFFER_POOL: LazyLock<Mutex<Vec<Box<[u8]>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

pub(crate) fn acquire_boxed_slice(capacity: usize) -> Box<[u8]> {
    if let Ok(mut pool) = BOXED_BUFFER_POOL.lock() {
        if let Some(buf) = pool.pop() {
            if buf.len() == capacity {
                return buf;
            }
        }
    }
    vec![0u8; capacity].into_boxed_slice()
}

pub(crate) fn release_boxed_slice(buf: Box<[u8]>) {
    if let Ok(mut pool) = BOXED_BUFFER_POOL.lock() {
        if pool.len() < MAX_POOLED_BUFFERS {
            pool.push(buf);
        }
    }
}

static VEC_BUFFER_POOL: LazyLock<Mutex<Vec<Vec<u8>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

pub fn acquire_vec(capacity: usize) -> Vec<u8> {
    if let Ok(mut pool) = VEC_BUFFER_POOL.lock() {
        if let Some(mut v) = pool.pop() {
            if v.capacity() >= capacity {
                v.resize(capacity, 0);
                return v;
            }
        }
    }
    vec![0u8; capacity]
}

#[allow(dead_code)]
pub fn release_vec(mut v: Vec<u8>) {
    if let Ok(mut pool) = VEC_BUFFER_POOL.lock() {
        if pool.len() < MAX_POOLED_BUFFERS {
            v.clear();
            pool.push(v);
        }
    }
}

pub struct LockFreeRingBuffer {
    buffer: UnsafeCell<Option<Box<[u8]>>>,
    raw_ptr: *mut u8,
    capacity: usize,
    write_pos: AtomicUsize, // Only TCP thread writes
    read_pos: AtomicUsize,  // Only app thread reads
}

unsafe impl Send for LockFreeRingBuffer {}
unsafe impl Sync for LockFreeRingBuffer {}

impl LockFreeRingBuffer {
    pub fn new(capacity: usize) -> Self {
        let mut buffer = acquire_boxed_slice(capacity);
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
            if let Some(buf) = (*self.buffer.get()).take() {
                release_boxed_slice(buf);
            }
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
    }
}
