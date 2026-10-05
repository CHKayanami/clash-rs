//! idea: https://github.com/openacid/succinct
//! impl: https://github.com/MetaCubeX/mihomo/blob/Meta/component/trie/domain_set.go
//! Temporary MRS decoding trie encoded in breadth-first order: each node stores its
//! outgoing labels as zero bits followed by a one-bit terminator.

use std::ops::Range;

#[cfg(test)]
use std::collections::VecDeque;
#[cfg(test)]
use crate::common::trie::StringTrie;

const DEAD: u32 = 1 << 31;

#[derive(Default)]
pub(crate) struct MrsDomainTrie {
    pub(super) leaves: Box<[u64]>,
    #[cfg(test)]
    pub(super) label_bit_map: Box<[u64]>,
    pub(super) labels: Box<[u8]>,
    starts: Box<[u32]>,
    node_capacity: usize,
    source_capacity: usize,
}

impl MrsDomainTrie {
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.leaves.iter().map(|x| x.count_ones() as usize).sum()
    }

    pub(super) fn children(&self, node: usize) -> Range<usize> {
        (self.starts[node] & !DEAD) as usize..(self.starts[node + 1] & !DEAD) as usize
    }

    pub(super) fn live(&self, node: usize) -> bool {
        self.starts.get(node).is_some_and(|start| start & DEAD == 0)
    }

    pub(super) fn capacities(&self) -> (usize, usize) {
        (self.node_capacity, self.source_capacity)
    }

    pub(super) fn terminal(&self, node: usize) -> bool {
        get_bit(&self.leaves, node as isize)
    }

    /// Validate topology and child order while constructing direct edge ranges.
    /// The high bit marks subtrees without terminals; edge offsets fit 31 bits.
    pub(crate) fn from_mrs_parts(
        leaves: Vec<u64>, label_bit_map: Vec<u64>, labels: Vec<u8>,
    ) -> Result<Self, &'static str> {
        if leaves.is_empty() && label_bit_map.is_empty() && labels.is_empty() {
            return Ok(Self::default());
        }
        let nodes = labels.len().checked_add(1).ok_or("too many labels")?;
        let bits = labels.len().checked_add(nodes).ok_or("too many nodes")?;
        if bits > i32::MAX as usize || label_bit_map.len() != bits.div_ceil(64) {
            return Err("invalid label bitmap length");
        }
        if leaves.len() > nodes.div_ceil(64) { return Err("invalid leaves length"); }
        for bit in bits..label_bit_map.len() * 64 {
            if get_bit(&label_bit_map, bit as isize) {
                return Err("nonzero label bitmap padding");
            }
        }
        for bit in nodes..leaves.len() * 64 {
            if get_bit(&leaves, bit as isize) { return Err("leaf outside tree"); }
        }
        let mut starts = Vec::with_capacity(nodes + 1);
        starts.push(0);
        let mut edges = 0;
        let mut previous = None;
        for bit in 0..bits {
            if get_bit(&label_bit_map, bit as isize) {
                let node = starts.len();
                if node < nodes && edges < node { return Err("unreachable node"); }
                starts.push(edges as u32);
                previous = None;
            } else {
                let label = *labels.get(edges).ok_or("too many edges")?;
                if previous.is_some_and(|p| p >= label) {
                    return Err("unsorted or duplicate child labels");
                }
                previous = Some(label);
                edges += 1;
            }
        }
        if starts.len() != nodes + 1 || edges != labels.len()
            || !get_bit(&label_bit_map, (bits - 1) as isize)
        { return Err("invalid tree topology"); }
        let (node_capacity, source_capacity) = mark_live_nodes(&leaves, &labels, &mut starts);
        Ok(Self {
            leaves: leaves.into_boxed_slice(),
            #[cfg(test)]
            label_bit_map: label_bit_map.into_boxed_slice(),
            labels: labels.into_boxed_slice(), starts: starts.into_boxed_slice(),
            node_capacity, source_capacity,
        })
    }

    #[cfg(test)]
    fn from_parts(leaves: Vec<u64>, bitmap: Vec<u64>, labels: Vec<u8>) -> Self {
        Self::from_mrs_parts(leaves, bitmap, labels).unwrap()
    }
}

// The validated BFS topology places every child after its parent. Walk backward
// to prune dead subtrees and count label endpoints before case-folding merges.
fn mark_live_nodes(leaves: &[u64], labels: &[u8], starts: &mut [u32]) -> (usize, usize) {
    let nodes = labels.len() + 1;
    let mut endpoints = 0usize;
    let mut sources = 1usize;
    for node in (0..nodes).rev() {
        let start = (starts[node] & !DEAD) as usize;
        let end = (starts[node + 1] & !DEAD) as usize;
        let terminal = get_bit(&leaves, node as isize);
        let mut live = terminal;
        let mut dot = false;
        for edge in start..end {
            let child = edge + 1;
            if starts[child] & DEAD != 0 { continue; }
            live = true;
            dot |= labels[edge] == b'.';
            // A terminal single '+' segment is a flag on its parent,
            // unless it also has ordinary rules below another dot.
            if labels[edge] == b'+' && get_bit(&leaves, child as isize)
                && (node == 0 || labels[node - 1] == b'.')
            {
                let first = (starts[child] & !DEAD) as usize;
                let last = (starts[child + 1] & !DEAD) as usize;
                if !(first..last).any(|e| labels[e] == b'.' && starts[e + 1] & DEAD == 0) {
                    endpoints -= 1;
                }
            }
        }
        if !live { starts[node] |= DEAD; }
        if dot { sources += 1; }
        if node != 0 && (dot || terminal) { endpoints += 1; }
    }
    (endpoints + 2, sources)
}

#[cfg(test)]
struct QElt {
    s: usize,
    e: usize,
    col: usize,
}

/// Convert a `StringTrie` to a `MrsDomainTrie`.
/// Keys use MRS character reversal and ASCII case folding, then byte indexing.
#[cfg(test)]
impl<T> From<StringTrie<T>> for MrsDomainTrie {
    fn from(value: StringTrie<T>) -> Self {
        let mut keys = vec![];
        value.traverse(|key, _| {
            let mut bytes = key.chars().rev().collect::<String>().into_bytes();
            bytes.make_ascii_lowercase();
            keys.push(bytes);
            true
        });
        drop(value);
        keys.sort();
        keys.dedup();
        if keys.is_empty() {
            return Self::default();
        }

        let mut leaves = Vec::new();
        let mut label_bit_map = Vec::new();
        let mut labels = Vec::new();

        let mut l_idx = 0;

        let mut queue = VecDeque::from([QElt {
            s: 0,
            e: keys.len(),
            col: 0,
        }]);

        let mut i = 0;
        while let Some(mut elt) = queue.pop_front() {
            if elt.col == keys[elt.s].len() {
                elt.s += 1;
                set_bit(&mut leaves, i, true);
            }

            let mut j = elt.s;
            let e = elt.e;
            let col = elt.col;
            while j < e {
                let frm = j;
                while j < e && keys[j][col] == keys[frm][col] {
                    j += 1;
                }

                queue.push_back(QElt {
                    s: frm,
                    e: j,
                    col: col + 1,
                });
                labels.push(keys[frm][col]);
                set_bit(&mut label_bit_map, l_idx, false);
                l_idx += 1;
            }

            set_bit(&mut label_bit_map, l_idx, true);
            l_idx += 1;

            i += 1;
        }

        Self::from_parts(leaves, label_bit_map, labels)
    }
}

#[inline(always)]
fn get_bit(bm: &[u64], i: isize) -> bool {
    if i < 0 {
        return false;
    }
    let word_idx = (i >> 6) as usize;
    if let Some(&word) = bm.get(word_idx) {
        (word & (1u64 << ((i as usize) & 63))) != 0
    } else {
        false
    }
}

#[cfg(test)]
#[inline]
fn set_bit(bm: &mut Vec<u64>, i: usize, v: bool) {
    let word_idx = i >> 6;
    if word_idx >= bm.len() {
        bm.resize(word_idx + 1, 0);
    }
    if v {
        bm[word_idx] |= 1u64 << (i & 63);
    } else {
        bm[word_idx] &= !(1u64 << (i & 63));
    }
}
