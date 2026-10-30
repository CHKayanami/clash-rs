//! Indexed minimum heap: one deadline per connection, with in-place updates.
//! Storage is reused after cancellation; no lazy nodes or tree-node churn.
use std::collections::HashMap;
use smoltcp::time::Instant;
use super::super::connections::SocketHandle;

#[derive(Default)]
pub(super) struct Timers {
    heap: Vec<(Instant, SocketHandle)>,
    positions: HashMap<SocketHandle, usize>,
}

impl Timers {
    pub fn set(&mut self, handle: SocketHandle, deadline: Instant) {
        if let Some(&index) = self.positions.get(&handle) {
            if self.heap[index].0 == deadline { return; }
            self.heap[index].0 = deadline;
            let index = self.sift_up(index);
            self.sift_down(index);
        } else {
            let index = self.heap.len();
            self.heap.push((deadline, handle));
            self.positions.insert(handle, index);
            self.sift_up(index);
        }
    }

    pub fn remove(&mut self, handle: SocketHandle) {
        let Some(index) = self.positions.remove(&handle) else { return; };
        let last = self.heap.pop().expect("indexed timer");
        if index == self.heap.len() { return; }
        self.heap[index] = last;
        self.positions.insert(last.1, index);
        let index = self.sift_up(index);
        self.sift_down(index);
    }

    pub fn first(&self) -> Option<Instant> { self.heap.first().map(|(deadline, _)| *deadline) }

    pub fn pop_due(&mut self, now: Instant) -> Option<SocketHandle> {
        let &(deadline, handle) = self.heap.first()?;
        if deadline > now { return None; }
        self.remove(handle);
        Some(handle)
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        self.positions.insert(self.heap[a].1, a);
        self.positions.insert(self.heap[b].1, b);
    }

    fn sift_up(&mut self, mut index: usize) -> usize {
        while index > 0 {
            let parent = (index - 1) / 2;
            if self.heap[parent] <= self.heap[index] { break; }
            self.swap(parent, index);
            index = parent;
        }
        index
    }

    fn sift_down(&mut self, mut index: usize) {
        loop {
            let left = index * 2 + 1;
            if left >= self.heap.len() { break; }
            let right = left + 1;
            let child = if right < self.heap.len() && self.heap[right] < self.heap[left] {
                right
            } else { left };
            if self.heap[index] <= self.heap[child] { break; }
            self.swap(index, child);
            index = child;
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize { self.heap.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updating_and_cancelling_deadlines_matches_reference_order() {
        let mut timers = Timers::default();
        let mut reference = HashMap::new();
        let mut seed = 1u64;
        for _ in 0..20000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let handle = SocketHandle((seed >> 32) % 64);
            let time = Instant::from_millis(((seed >> 16) % 1000) as i64);
            match seed % 3 {
                0 => { timers.set(handle, time); reference.insert(handle, time); }
                1 => { timers.remove(handle); reference.remove(&handle); }
                _ => {
                    let expected = reference.iter().map(|(handle, deadline)| (*deadline, *handle))
                        .filter(|(deadline, _)| *deadline <= time).min();
                    assert_eq!(timers.pop_due(time), expected.map(|(_, handle)| handle));
                    if let Some((_, handle)) = expected { reference.remove(&handle); }
                }
            }
            assert_eq!(timers.len(), reference.len());
            assert_eq!(timers.positions.len(), reference.len());
            assert_eq!(timers.first(), reference.values().copied().min());
        }
    }
}
