//! Owner-local receive slots. A slot is writable only after every Bytes view
//! has gone away; retained datagrams never borrow the next receive operation.
use std::{mem::MaybeUninit, sync::Arc};
use bytes::Bytes;
use super::MAX_DATAGRAM_SIZE;
struct Slot(Box<[MaybeUninit<u8>]>);
pub(crate) struct Loan(Arc<Slot>);
struct View { slot: Arc<Slot>, length: usize }
impl AsRef<[u8]> for View {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: freeze exposes only the prefix initialized by the receive
        // syscall. Shared ownership prevents reuse until the final view drops.
        unsafe { std::slice::from_raw_parts(self.slot.0.as_ptr().cast(), self.length) }
    }
}
impl Loan {
    pub fn pointer(&mut self) -> *mut MaybeUninit<u8> {
        Arc::get_mut(&mut self.0).expect("exclusive UDP receive slot").0.as_mut_ptr()
    }
    /// The caller must have initialized this entire prefix through pointer().
    pub unsafe fn freeze(&self, length: usize) -> Bytes {
        assert!(length <= MAX_DATAGRAM_SIZE);
        Bytes::from_owner(View { slot: self.0.clone(), length })
    }
}
#[derive(Default)]
pub(crate) struct ReceiveSlots { cached: Vec<Option<Loan>> }
impl ReceiveSlots {
    pub fn acquire<const N: usize>(&mut self, limit: usize) -> [Option<Loan>; N] {
        assert!(limit <= N);
        if self.cached.len() < limit { self.cached.resize_with(limit, || None); }
        let mut slots = std::array::from_fn(|_| None);
        for (index, slot) in slots[..limit].iter_mut().enumerate() {
            // Cache one owner per actual receive position. A retained view
            // keeps the old allocation alive by itself; it does not occupy an
            // extra cache entry or prevent caching its replacement.
            *slot = Some(self.cached[index].take()
                .filter(|slot| Arc::strong_count(&slot.0) == 1)
                .unwrap_or_else(|| Loan(Arc::new(Slot(Box::new_uninit_slice(MAX_DATAGRAM_SIZE))))));
        }
        slots
    }
    pub fn keep(&mut self, index: usize, slot: Loan) {
        assert!(self.cached[index].is_none(), "UDP receive position already returned");
        self.cached[index] = Some(slot);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn released_slots_are_reused_and_retained_views_survive_replacement() {
        let mut pool = ReceiveSlots::default();
        let mut first = pool.acquire::<1>(1)[0].take().unwrap();
        let pointer = first.pointer();
        // SAFETY: the exclusive loan initializes its first byte before exposing it.
        unsafe { pointer.write(MaybeUninit::new(7)); }
        let view = unsafe { first.freeze(1) };
        pool.keep(0, first);
        drop(view);
        let mut reused = pool.acquire::<1>(1)[0].take().unwrap();
        assert_eq!(reused.pointer(), pointer);
        // SAFETY: the initialized prefix remains intact across reuse.
        let retained = unsafe { reused.freeze(1) };
        pool.keep(0, reused);
        let mut replacement = pool.acquire::<1>(1)[0].take().unwrap();
        assert_ne!(replacement.pointer(), pointer);
        pool.keep(0, replacement);
        drop(pool);
        assert_eq!(&retained[..], &[7]);
    }
    #[test]
    fn cache_follows_batch_demand_instead_of_accumulating_retained_owners() {
        let mut pool = ReceiveSlots::default();
        let mut views = Vec::new();
        for _ in 0..10 {
            for (index, slot) in pool.acquire::<8>(8).into_iter().enumerate() {
                let mut slot = slot.unwrap();
                // SAFETY: initialize the complete prefix before retaining it.
                unsafe { slot.pointer().write(MaybeUninit::new(9)); }
                views.push(unsafe { slot.freeze(1) });
                pool.keep(index, slot);
            }
            assert_eq!(pool.cached.len(), 8);
        }
        drop(pool);
        assert!(views.iter().all(|view| view.as_ref() == [9]));
    }
}
