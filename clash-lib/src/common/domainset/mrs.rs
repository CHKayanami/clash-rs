//! idea: https://github.com/openacid/succinct
//! impl: https://github.com/MetaCubeX/mihomo/blob/Meta/component/trie/domain_set.go
//! Temporary MRS decoding trie encoded in breadth-first order: each node stores its
//! outgoing labels as zero bits followed by a one-bit terminator.

use std::str;

#[cfg(test)]
use std::collections::VecDeque;

#[cfg(test)]
use crate::common::trie::StringTrie;
use super::compact::{DomainKey, EXACT, SUFFIX};
use crate::common::domain::has_valid_domain_labels;

#[derive(Default)]
pub(crate) struct MrsDomainTrie {
    pub(super) leaves: Box<[u64]>,
    pub(super) label_bit_map: Box<[u64]>,
    pub(super) labels: Box<[u8]>,
    ranks: Box<[i32]>,
    selects: Box<[i32]>,
}

impl MrsDomainTrie {
    /// Consume validated MRS data; release the byte trie before freezing labels.
    pub(super) fn into_domain_keys(self) -> Result<Vec<DomainKey>, &'static str> {
        let mut keys = Vec::with_capacity(self.len());
        if self.label_bit_map.is_empty() { return Ok(keys); }
        let mut path = Vec::new();
        let mut pending = vec![(0usize, self.node_start(0), 0usize)];
        while let Some((node, edge, depth)) = pending.pop() {
            path.truncate(depth);
            if edge == self.node_start(node) && get_bit(&self.leaves, node as isize) {
                let reversed = str::from_utf8(&path)
                    .map_err(|_| "invalid UTF-8 domain in MRS")?;
                let mut domain = String::with_capacity(reversed.len());
                domain.extend(reversed.chars().rev());
                domain.make_ascii_lowercase();
                let flags = if domain == "+" {
                    domain.clear();
                    SUFFIX
                } else if domain.starts_with("+.") {
                    drop(domain.drain(..2));
                    SUFFIX
                } else {
                    EXACT
                };
                if !(domain.is_empty() && flags == SUFFIX)
                    && !has_valid_domain_labels(&domain)
                {
                    return Err("invalid domain in MRS");
                }
                keys.push(DomainKey { domain, flags });
            }
            if get_bit(&self.label_bit_map, edge as isize) { continue; }
            pending.push((node, edge + 1, depth));
            path.push(self.labels[edge - node]);
            let child = edge - node + 1;
            pending.push((child, self.node_start(child), depth + 1));
        }
        Ok(keys)
    }

    fn node_start(&self, node: usize) -> usize {
        if node == 0 {
            0
        } else {
            select_ith_one(&self.label_bit_map, &self.ranks, &self.selects, node - 1) + 1
        }
    }

    /// Number of keys in the set. Each key terminates at exactly one node, and
    /// each such node sets one bit in `leaves`.
    pub fn len(&self) -> usize {
        self.leaves.iter().map(|x| x.count_ones() as usize).sum()
    }
}

impl MrsDomainTrie {
    /// Validate the LOUDS tree before converting its domain rules.
    pub(crate) fn from_mrs_parts(
        leaves: Vec<u64>,
        label_bit_map: Vec<u64>,
        labels: Vec<u8>,
    ) -> Result<Self, &'static str> {
        if leaves.is_empty() && label_bit_map.is_empty() && labels.is_empty() {
            return Ok(Self::default());
        }
        let nodes = labels.len().checked_add(1).ok_or("too many labels")?;
        let bits = labels.len().checked_add(nodes).ok_or("too many nodes")?;
        if bits > i32::MAX as usize || label_bit_map.len() != bits.div_ceil(64) {
            return Err("invalid label bitmap length");
        }
        if leaves.len() > nodes.div_ceil(64) {
            return Err("invalid leaves length");
        }
        for bit in bits..label_bit_map.len() * 64 {
            if get_bit(&label_bit_map, bit as isize) {
                return Err("nonzero label bitmap padding");
            }
        }
        for bit in nodes..leaves.len() * 64 {
            if get_bit(&leaves, bit as isize) {
                return Err("leaf outside tree");
            }
        }
        let mut node = 0;
        let mut edges = 0;
        let mut previous = None;
        for bit in 0..bits {
            if get_bit(&label_bit_map, bit as isize) {
                node += 1;
                if node < nodes && edges < node {
                    return Err("unreachable node");
                }
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
        if node != nodes || edges != labels.len()
            || !get_bit(&label_bit_map, (bits - 1) as isize)
        {
            return Err("invalid tree topology");
        }
        Ok(Self::from_parts(leaves, label_bit_map, labels))
    }

    fn from_parts(
        leaves: Vec<u64>,
        label_bit_map: Vec<u64>,
        labels: Vec<u8>,
    ) -> Self {
        let (ranks, selects) = Self::compute_ranks_and_selects(&label_bit_map);
        Self {
            leaves: leaves.into_boxed_slice(),
            label_bit_map: label_bit_map.into_boxed_slice(),
            labels: labels.into_boxed_slice(),
            ranks,
            selects,
        }
    }

    fn compute_ranks_and_selects(label_bit_map: &[u64]) -> (Box<[i32]>, Box<[i32]>) {
        let mut ranks = Vec::with_capacity(label_bit_map.len() + 1);
        ranks.push(0);

        let mut total_ones: usize = 0;
        for &word in label_bit_map {
            let n = word.count_ones() as usize;
            total_ones += n;
            ranks.push(total_ones as i32);
        }

        let select_cap = (total_ones + 63) / 64;
        let mut selects = Vec::with_capacity(select_cap);

        let mut ones_count: usize = 0;
        for (word_idx, &word) in label_bit_map.iter().enumerate() {
            let mut w = word;
            let base_bit = (word_idx * 64) as i32;
            while w != 0 {
                let bit_idx = w.trailing_zeros() as i32;
                if ones_count & 63 == 0 {
                    selects.push(base_bit + bit_idx);
                }
                ones_count += 1;
                w &= w - 1; // Clear lowest set bit
            }
        }

        (ranks.into_boxed_slice(), selects.into_boxed_slice())
    }
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

#[inline]
fn select_ith_one(bm: &[u64], ranks: &[i32], selects: &[i32], i: usize) -> usize {
    let base = (selects[i >> 6] & !63) as usize >> 6;
    let mut find_ith_one = i as isize - ranks[base] as isize;

    for (word_idx, &w) in bm.iter().enumerate().skip(base) {
        let ones = w.count_ones() as isize;
        if find_ith_one >= ones {
            find_ith_one -= ones;
            continue;
        }

        let mut w = w;
        while w > 0 {
            let bit_idx = w.trailing_zeros() as usize;
            if find_ith_one == 0 {
                return (word_idx << 6) + bit_idx;
            }
            find_ith_one -= 1;
            w &= w - 1; // Clear lowest set bit
        }
    }

    unreachable!("invalid data");
}
