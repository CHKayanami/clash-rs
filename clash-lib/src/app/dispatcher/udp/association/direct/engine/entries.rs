//! Stable local slots are validated against the association ID before use.
//! The ID prevents an ingress packet from addressing a recycled session slot.
use std::{collections::HashMap, sync::atomic::Ordering};
use super::Entry;
#[cfg(test)]
use std::ops::Index;

#[derive(Default)]
pub(super) struct Entries {
    slots: Vec<Option<Entry>>,
    free: Vec<usize>,
    ids: HashMap<u64, usize>,
}
impl Entries {
    pub fn insert(&mut self, id: u64, entry: Entry) {
        assert!(!self.ids.contains_key(&id), "duplicate UDP session");
        let slot = self.free.pop().unwrap_or_else(|| { self.slots.push(None); self.slots.len() - 1 });
        entry.session.location.store(slot, Ordering::Release);
        self.slots[slot] = Some(entry);
        self.ids.insert(id, slot);
    }
    pub fn at_mut(&mut self, slot: usize, id: u64) -> Option<&mut Entry> {
        self.slots.get_mut(slot)?.as_mut().filter(|entry| entry.session.id == id)
    }
    pub fn get(&self, id: &u64) -> Option<&Entry> { self.slots[*self.ids.get(id)?].as_ref() }
    pub fn get_mut(&mut self, id: &u64) -> Option<&mut Entry> {
        let slot = *self.ids.get(id)?;
        self.slots[slot].as_mut()
    }
    pub fn remove(&mut self, id: &u64) -> Option<Entry> {
        let slot = self.ids.remove(id)?;
        let entry = self.slots[slot].take()?;
        entry.session.location.store(usize::MAX, Ordering::Release);
        self.free.push(slot);
        Some(entry)
    }
    #[cfg(test)]
    pub fn is_empty(&self) -> bool { self.ids.is_empty() }
}
#[cfg(test)]
impl Index<&u64> for Entries {
    type Output = Entry;
    fn index(&self, id: &u64) -> &Entry { self.get(id).unwrap() }
}
