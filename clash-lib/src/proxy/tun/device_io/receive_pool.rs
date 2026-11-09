//! Receive allocations follow packet ownership and return only after its final
//! Bytes reference is dropped. The bounded cache belongs to one device reader.
use std::sync::{Arc, Weak};
use parking_lot::Mutex;

#[cfg(test)]
const FRAME_CAPACITY: usize = 65535 + 80;

#[derive(Clone)]
pub(super) struct Pool {
    cached: Arc<Mutex<Vec<Vec<u8>>>>,
    capacity: usize,
}
#[cfg(test)]
impl Default for Pool {
    fn default() -> Self { Self::new(FRAME_CAPACITY) }
}

pub(super) struct Buffer {
    bytes: Vec<u8>,
    length: usize,
    pool: Weak<Mutex<Vec<Vec<u8>>>>,
}
impl Pool {
    pub fn new(capacity: usize) -> Self { Self { cached: Arc::default(), capacity } }
    pub fn acquire(&self) -> Buffer {
        let cached = self.cached.lock().pop();
        let bytes = cached.unwrap_or_else(|| vec![0; self.capacity]);
        Buffer { bytes, length: self.capacity, pool: Arc::downgrade(&self.cached) }
    }
}
impl Buffer {
    pub fn truncate(&mut self, length: usize) { self.length = length; }
    pub fn reset(&mut self) { self.length = self.bytes.len(); }
}
impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] { &self.bytes[..self.length] }
}
impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] { &mut self.bytes[..self.length] }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.upgrade() {
            let mut pool = pool.lock();
            if pool.len() < 2 {
                pool.push(std::mem::take(&mut self.bytes));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reset_restores_initialized_capacity_without_clearing_received_data() {
        let pool = Pool::new(1501);
        let mut buffer = pool.acquire();
        buffer.as_mut()[0] = 0x45;
        buffer.truncate(40);
        assert_eq!(buffer.as_ref().len(), 40);
        buffer.reset();
        assert_eq!(buffer.as_ref().len(), 1501);
        assert_eq!(buffer.as_ref()[0], 0x45);
    }
}
