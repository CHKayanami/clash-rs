pub mod pooled_buffer;
pub mod ring_buffer;
pub mod slide_buffer;

pub use pooled_buffer::{
    PooledBuffer, max_pooled_buffers, set_max_pooled_buffers,
};
pub use ring_buffer::{LockFreeRingBuffer, acquire_vec};
pub use slide_buffer::SlideBuffer;

/// Allocate an uninitialized `Vec<T>` without zero-filling.
///
/// # Safety / Invariants
/// The caller must ensure that elements are properly initialized before being read.
#[inline]
#[allow(clippy::uninit_vec)]
pub fn allocate_vec<T>(len: usize) -> Vec<T> {
    let mut ret = Vec::with_capacity(len);
    unsafe {
        ret.set_len(len);
    }
    ret
}

/// Allocate an uninitialized `Box<[u8]>` without zero-filling.
#[inline]
pub fn allocate_boxed_slice(len: usize) -> Box<[u8]> {
    allocate_vec::<u8>(len).into_boxed_slice()
}
