//! An owner-only FIFO with O(1) deduplication and removal. Removed connections
//! leave no tombstones behind, including while the output link is blocked.
use std::collections::HashMap;
use super::super::connections::SocketHandle;

struct Links {
    previous: Option<SocketHandle>,
    next: Option<SocketHandle>,
}

#[derive(Default)]
pub(super) struct ReadyList {
    links: HashMap<SocketHandle, Links>,
    first: Option<SocketHandle>,
    last: Option<SocketHandle>,
}

impl ReadyList {
    pub fn is_empty(&self) -> bool { self.first.is_none() }

    pub fn push_back(&mut self, handle: SocketHandle) {
        if self.links.contains_key(&handle) { return; }
        if let Some(last) = self.last { self.links.get_mut(&last).unwrap().next = Some(handle); }
        else { self.first = Some(handle); }
        self.links.insert(handle, Links { previous: self.last, next: None });
        self.last = Some(handle);
    }

    pub fn push_front(&mut self, handle: SocketHandle) {
        if self.links.contains_key(&handle) { return; }
        if let Some(first) = self.first { self.links.get_mut(&first).unwrap().previous = Some(handle); }
        else { self.last = Some(handle); }
        self.links.insert(handle, Links { previous: None, next: self.first });
        self.first = Some(handle);
    }

    pub fn remove(&mut self, handle: SocketHandle) {
        let Some(links) = self.links.remove(&handle) else { return; };
        if let Some(previous) = links.previous { self.links.get_mut(&previous).unwrap().next = links.next; }
        else { self.first = links.next; }
        if let Some(next) = links.next { self.links.get_mut(&next).unwrap().previous = links.previous; }
        else { self.last = links.previous; }
    }

    pub fn pop_front(&mut self) -> Option<SocketHandle> {
        let handle = self.first?;
        self.remove(handle);
        Some(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn removal_and_requeue_match_fifo_model_without_tombstones() {
        let mut ready = ReadyList::default();
        let mut expected = VecDeque::new();
        let mut seed = 1u64;
        for _ in 0..20000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let handle = SocketHandle((seed >> 32) % 64);
            match seed % 4 {
                0 => {
                    ready.push_back(handle);
                    if !expected.contains(&handle) { expected.push_back(handle); }
                }
                1 => {
                    ready.push_front(handle);
                    if !expected.contains(&handle) { expected.push_front(handle); }
                }
                2 => { ready.remove(handle); expected.retain(|entry| *entry != handle); }
                _ => assert_eq!(ready.pop_front(), expected.pop_front()),
            }
            assert_eq!(ready.links.len(), expected.len());
            assert_eq!(ready.is_empty(), expected.is_empty());
        }
        while let Some(handle) = expected.pop_front() { assert_eq!(ready.pop_front(), Some(handle)); }
        assert!(ready.links.is_empty());
    }
}
