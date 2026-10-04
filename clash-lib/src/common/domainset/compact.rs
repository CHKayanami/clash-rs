#[path = "wideindex.rs"]
mod wideindex;
#[path = "keys.rs"]
mod keys;

use std::{collections::{HashMap, VecDeque}, cmp::Ordering};

use super::{Cursor, CursorStack};
use wideindex::{WideIndex, HASH_LABEL_BIT};
use keys::PreparedKeys;

pub(super) const EXACT: u8 = 1;
pub(super) const SUFFIX: u8 = 2;
const WILDCARD: u8 = 4;
const MASK_SHIFT: u32 = 29;
const CHILD_MASK: u32 = (1 << MASK_SHIFT) - 1;
const WILDCARD_LABEL: u32 = u32::MAX;
const LINEAR_CHILDREN: usize = 4;

#[derive(Default)]
pub(super) struct CompactDomainSet {
    nodes: Box<[Node]>,
    labels: Box<[u8]>,
    keys: usize,
    index: WideIndex,
}

#[derive(Default)]
struct Node {
    label: u32,
    child_flags: u32,
}

impl Node {
    fn first_child(&self) -> usize { (self.child_flags & CHILD_MASK) as usize }

    fn flags(&self) -> u8 { (self.child_flags >> MASK_SHIFT) as u8 }

    fn add_flags(&mut self, flags: u8) {
        self.child_flags |= u32::from(flags) << MASK_SHIFT;
    }
}

pub(super) struct DomainKey {
    pub(super) domain: String,
    pub(super) flags: u8,
}

struct PendingNode {
    node: u32,
    start: u32,
    end: u32,
    depth: u32,
}

// BFS children are contiguous in parent order. The next node's first-child
// index closes the current run; a trailing sentinel closes the last run.
// Three high bits hold EXACT/SUFFIX/WILDCARD, leaving 29 bits for node indices.
// Labels are dot-terminated (labels cannot contain dots), with checked u32
// offsets below 2 GiB. The label high bit tags a wide-node descriptor index;
// its original offset lives in that descriptor. Node size remains eight bytes.
// No pointer arithmetic or unsafe access is used.
fn node_index(value: usize) -> u32 {
    let value = u32::try_from(value).expect("domain set exceeds 32-bit indices");
    assert!(value <= CHILD_MASK, "domain set exceeds 29-bit node indices");
    value
}

impl CompactDomainSet {
    pub(super) fn from_keys(keys: Vec<DomainKey>) -> Self {
        if keys.is_empty() { return Self::default(); }
        let prepared = PreparedKeys::new(keys);
        let paths = &prepared.paths;
        let key_count = paths.iter().map(|path| path.flags.count_ones() as usize).sum();

        let mut nodes = vec![Node::default()];
        let mut labels = Vec::new();
        let mut interned: HashMap<&[u8], u32> = HashMap::new();
        let mut pending = VecDeque::from([PendingNode {
            node: 0, start: 0, end: u32::try_from(paths.len())
                .expect("domain path count exceeds 32-bit indices"), depth: 0,
        }]);
        while let Some(PendingNode { node, start, end, depth }) = pending.pop_front() {
            let node = node as usize;
            let mut start = start as usize;
            let end = end as usize;
            let depth = depth as usize;
            while start < end && paths[start].len() == depth {
                nodes[node].add_flags(paths[start].flags);
                start += 1;
            }
            let first_child = node_index(nodes.len());
            nodes[node].child_flags |= first_child;
            while start < end {
                let label = prepared.label(start, depth);
                let group_start = start;
                start += 1;
                while start < end && prepared.label(start, depth) == label {
                    start += 1;
                }
                let child = node_index(nodes.len());
                nodes.push(Node::default());
                pending.push_back(PendingNode {
                    node: child, start: group_start as u32, end: start as u32,
                    // A child exists only when the path has another label;
                    // path lengths and arena offsets are checked as u32.
                    depth: u32::try_from(depth + 1)
                        .expect("domain depth exceeds 32-bit indices"),
                });
                // Wildcards sort first, so their child index is implicit.
                // Ordinary siblings retain byte order for binary search.
                let offset = if label == b"*" {
                    nodes[node].add_flags(WILDCARD);
                    WILDCARD_LABEL
                } else {
                    *interned.entry(label).or_insert_with(|| {
                        let offset = u32::try_from(labels.len())
                            .expect("domain label pool exceeds 32-bit offsets");
                        let end = labels.len().checked_add(label.len())
                            .and_then(|end| end.checked_add(1))
                            .expect("domain label pool size overflow");
                        assert!(end <= HASH_LABEL_BIT as usize,
                            "domain label pool exceeds 31-bit offsets");
                        labels.extend_from_slice(label);
                        labels.push(b'.');
                        offset
                    })
                };
                nodes[child as usize].label = offset;
            }
        }
        let end = node_index(nodes.len());
        nodes.push(Node { label: 0, child_flags: end });
        drop(interned);
        drop(prepared);
        let index = WideIndex::build(&mut nodes, &labels);
        Self { nodes: nodes.into_boxed_slice(),
            labels: labels.into_boxed_slice(), keys: key_count, index }
    }

    pub(super) fn len(&self) -> usize { self.keys }

    #[cfg(test)]
    fn label(&self, node: &Node) -> &[u8] {
        let offset = self.index.label_offset(node.label);
        if offset == WILDCARD_LABEL { return b"*"; }
        let bytes = &self.labels[offset as usize..];
        &bytes[..bytes.iter().position(|&byte| byte == b'.').unwrap()]
    }

    fn compare_label(&self, node: &Node, query: &[u8]) -> Ordering {
        let offset = self.index.label_offset(node.label);
        let stored = &self.labels[offset as usize..];
        for (i, &byte) in query.iter().enumerate() {
            if stored[i] == b'.' { return Ordering::Less; }
            match stored[i].cmp(&byte) {
                Ordering::Equal => {}
                order => return order,
            }
        }
        if stored[query.len()] == b'.' { Ordering::Equal }
        else { Ordering::Greater }
    }

    fn children(&self, node: usize) -> (usize, &[Node]) {
        let start = self.nodes[node].first_child();
        let end = self.nodes[node + 1].first_child();
        (start, &self.nodes[start..end])
    }

    fn child(&self, node: usize, label: &[u8]) -> Option<usize> {
        let current = &self.nodes[node];
        if WideIndex::is_indexed(current.label) {
            return self.index.child(current.label, label, |child| {
                self.compare_label(&self.nodes[child], label) == Ordering::Equal
            });
        }
        let (mut start, mut children) = self.children(node);
        if self.nodes[node].flags() & WILDCARD != 0 {
            start += 1;
            children = &children[1..];
        }
        let found = if children.len() <= LINEAR_CHILDREN {
            children.iter().position(|child| self.compare_label(child, label) == Ordering::Equal)
        } else {
            children.binary_search_by(|child| self.compare_label(child, label)).ok()
        };
        found.map(|i| start + i)
    }

    /// The caller provides a nonempty set and validated, ASCII-normalized domain.
    /// Label slices borrow the query; normal lookups and up to eight alternatives
    /// allocate nothing, independently of a node's fan-out.
    pub(super) fn has(&self, key: &str) -> bool {
        let mut cursor = Cursor { node: 0, index: key.len() };
        let mut pending = CursorStack::default();
        loop {
            let node = &self.nodes[cursor.node];
            if cursor.index == 0 {
                if node.flags() & EXACT != 0 { return true; }
            } else {
                if node.flags() & SUFFIX != 0 { return true; }
                let rest = &key[..cursor.index];
                let split = rest.rfind('.');
                let start = split.map_or(0, |i| i + 1);
                let next_index = split.unwrap_or(0);
                let exact = self.child(cursor.node, &rest.as_bytes()[start..]);
                if let Some(child) = exact {
                    if node.flags() & WILDCARD != 0 {
                        pending.push(Cursor {
                            node: node.first_child(), index: next_index,
                        });
                    }
                    cursor = Cursor { node: child, index: next_index };
                    continue;
                }
                if node.flags() & WILDCARD != 0 {
                    cursor = Cursor {
                        node: node.first_child(), index: next_index,
                    };
                    continue;
                }
            }
            match pending.pop() {
                Some(next) => cursor = next,
                None => return false,
            }
        }
    }

    #[cfg(test)]
    pub(super) fn traverse<F: FnMut(&String) -> bool>(&self, mut f: F) {
        fn visit<F: FnMut(&String) -> bool>(
            set: &CompactDomainSet, node: usize, path: &mut Vec<String>, f: &mut F,
        ) -> bool {
            let current = &set.nodes[node];
            let key = path.iter().rev().map(String::as_str).collect::<Vec<_>>().join(".");
            if current.flags() & EXACT != 0 && !f(&key) { return false; }
            if current.flags() & SUFFIX != 0 {
                let suffix = if key.is_empty() { "+".to_owned() } else { format!("+.{key}") };
                if !f(&suffix) { return false; }
            }
            let (start, children) = set.children(node);
            for (i, child) in children.iter().enumerate() {
                path.push(String::from_utf8(set.label(child).to_vec()).unwrap());
                if !visit(set, start + i, path, f) { return false; }
                path.pop();
            }
            true
        }
        if !self.nodes.is_empty() { visit(self, 0, &mut Vec::new(), &mut f); }
    }
}

#[cfg(test)]
#[path = "compacttests.rs"]
mod tests;
