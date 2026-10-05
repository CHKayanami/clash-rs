use super::{Node, WILDCARD, WILDCARD_LABEL, node_index};

pub(super) const HASH_THRESHOLD: usize = 64;
pub(super) const HASH_LABEL_BIT: u32 = 1 << 31;
const EMPTY_SLOT: u32 = u32::MAX;

#[derive(Default)]
pub(super) struct WideIndex {
    nodes: Box<[IndexNode]>,
    slots: Box<[u32]>,
}

struct IndexNode {
    label: u32,
    start: u32,
    mask: u32,
}

pub(super) fn table_size(children: usize) -> usize {
    children.checked_mul(4).map(|count| count.div_ceil(3))
        .and_then(usize::checked_next_power_of_two)
        .expect("domain hash table size overflow")
}

impl WideIndex {
    pub(super) fn build(nodes: &mut [Node], labels: &[u8]) -> Self {
        let mut descriptors = Vec::new();
        let mut total = 0usize;
        for pair in nodes.windows(2) {
            let start = pair[0].first_child()
                + usize::from(pair[0].flags() & WILDCARD != 0);
            let children = pair[1].first_child() - start;
            if children < HASH_THRESHOLD { continue; }
            let size = table_size(children);
            let base = total;
            total = total.checked_add(size).expect("domain hash index size overflow");
            u32::try_from(total).expect("domain hash index exceeds 32-bit offsets");
            descriptors.push(IndexNode {
                label: pair[0].label, start: base as u32, mask: (size - 1) as u32,
            });
        }
        let mut slots = vec![EMPTY_SLOT; total];
        let mut indexed = 0;
        for node in 0..nodes.len().saturating_sub(1) {
            let start = nodes[node].first_child()
                + usize::from(nodes[node].flags() & WILDCARD != 0);
            let end = nodes[node + 1].first_child();
            if end - start < HASH_THRESHOLD { continue; }
            let descriptor = &descriptors[indexed];
            let base = descriptor.start as usize;
            let mask = descriptor.mask as usize;
            for child in start..end {
                let bytes = &labels[nodes[child].label as usize..];
                let len = bytes.iter().position(|&byte| byte == b'.')
                    .expect("domain label terminator missing");
                let mut slot = hash_label(&bytes[..len]) & mask;
                while slots[base + slot] != EMPTY_SLOT {
                    slot = (slot + 1) & mask;
                }
                slots[base + slot] = node_index(child);
            }
            // BFS places children after their parent. Its table reads their
            // original labels before those children's labels become tagged.
            nodes[node].label = HASH_LABEL_BIT | node_index(indexed);
            indexed += 1;
        }
        Self { nodes: descriptors.into_boxed_slice(), slots: slots.into_boxed_slice() }
    }

    // Tables contain only child IDs; labels stay in the trie arena. Capacity
    // and all offsets are checked during construction, with at least 25% empty
    // slots. Linear probing therefore terminates, and full label comparison
    // resolves collisions without changing membership or wildcard semantics.
    pub(super) fn child(
        &self, tagged_label: u32, label: &[u8], matches: impl Fn(usize) -> bool,
    ) -> Option<usize> {
        let descriptor = &self.nodes[(tagged_label & !HASH_LABEL_BIT) as usize];
        let mask = descriptor.mask as usize;
        let base = descriptor.start as usize;
        let mut slot = hash_label(label) & mask;
        loop {
            let child = self.slots[base + slot];
            if child == EMPTY_SLOT { return None; }
            if matches(child as usize) { return Some(child as usize); }
            slot = (slot + 1) & mask;
        }
    }

    pub(super) fn is_indexed(label: u32) -> bool {
        label & HASH_LABEL_BIT != 0 && label != WILDCARD_LABEL
    }

    pub(super) fn label_offset(&self, label: u32) -> u32 {
        if Self::is_indexed(label) {
            self.nodes[(label & !HASH_LABEL_BIT) as usize].label
        } else { label }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize { self.nodes.len() }
}

pub(super) fn hash_label(bytes: &[u8]) -> usize {
    let mut state = 0x9e3779b97f4a7c15u64 ^ bytes.len() as u64;
    let (chunks, rest) = bytes.as_chunks::<8>();
    for chunk in chunks {
        state = (state.rotate_left(29) ^ u64::from_le_bytes(*chunk))
            .wrapping_mul(0x9e3779b97f4a7c15);
    }
    let mut tail = [0u8; 8];
    tail[..rest.len()].copy_from_slice(rest);
    state = (state.rotate_left(29) ^ u64::from_le_bytes(tail))
        .wrapping_mul(0x9e3779b97f4a7c15);
    state ^= state >> 33;
    state = state.wrapping_mul(0xff51afd7ed558ccd);
    state ^= state >> 33;
    state as usize
}
