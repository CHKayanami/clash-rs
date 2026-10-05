//! Fold validated MRS byte subtrees into label edges without expanding domains.

use std::str;

use super::{CompactDomainSet, Node, EXACT, SUFFIX, WILDCARD,
    WILDCARD_LABEL, node_index, CHILD_MASK};
use super::keys::compare_labels;
use super::wideindex::{WideIndex, HASH_LABEL_BIT, hash_label, table_size};
use crate::common::domainset::mrs::MrsDomainTrie;

const NONE: u32 = u32::MAX;
const LABEL_CHUNK: usize = 64 * 1024;

struct Span {
    chunk: u32,
    start: u32,
    len: u32,
}

#[derive(Default)]
struct LabelPool {
    chunks: Vec<Vec<u8>>,
    chunk_size: usize,
    bytes: usize,
    spans: Vec<Span>,
    slots: Vec<u32>,
}

impl LabelPool {
    fn label(&self, id: u32) -> &[u8] {
        let span = &self.spans[id as usize];
        let end = span.start as usize + span.len as usize;
        &self.chunks[span.chunk as usize][span.start as usize..end]
    }

    // Fixed open-addressed slots contain only intern IDs. The endpoint count
    // bounds unique labels and guarantees at least 25% empty slots. Compare
    // full bytes on collisions; neither keys nor individual labels allocate.
    fn intern(&mut self, label: &[u8]) -> Result<u32, &'static str> {
        let mask = self.slots.len() - 1;
        let mut slot = hash_label(label) & mask;
        while self.slots[slot] != NONE {
            let id = self.slots[slot];
            if self.label(id) == label { return Ok(id); }
            slot = (slot + 1) & mask;
        }
        let size = label.len().checked_add(1).ok_or("too many domain label bytes")?;
        let end = self.bytes.checked_add(size)
            .filter(|&n| n <= HASH_LABEL_BIT as usize).ok_or("too many domain label bytes")?;
        if self.chunks.last().is_none_or(|chunk| chunk.capacity() - chunk.len() < size) {
            self.chunks.push(Vec::with_capacity(self.chunk_size.max(size)));
        }
        let chunk_id = self.chunks.len() - 1;
        let chunk = &mut self.chunks[chunk_id];
        let id = u32::try_from(self.spans.len()).map_err(|_| "too many domain labels")?;
        self.spans.push(Span {
            chunk: chunk_id as u32, start: chunk.len() as u32, len: label.len() as u32,
        });
        chunk.extend_from_slice(label);
        chunk.push(b'.');
        self.bytes = end;
        self.slots[slot] = id;
        Ok(id)
    }

    // Chunked scratch storage never copies old labels when growing. The final
    // arena is allocated once at its exact byte count, after releasing LOUDS;
    // copied chunks are dropped progressively.
    fn freeze(self, nodes: &mut [Node]) -> Box<[u8]> {
        drop(self.slots);
        let mut labels = Vec::with_capacity(self.bytes);
        let mut offsets = Vec::with_capacity(self.chunks.len());
        for chunk in self.chunks {
            offsets.push(labels.len() as u32);
            labels.extend_from_slice(&chunk);
        }
        // Node labels temporarily hold intern IDs. Root and sentinel have no
        // label; ordinary nodes now receive offsets in the exact-sized arena.
        let end = nodes.len() - 1;
        for node in &mut nodes[1..end] {
            if node.label == WILDCARD_LABEL { continue; }
            let span = &self.spans[node.label as usize];
            node.label = offsets[span.chunk as usize] + span.start;
        }
        labels.into_boxed_slice()
    }
}

struct Candidate {
    label: u32,
    source: u32,
    flags: u8,
}

#[derive(Default)]
struct Scratch {
    reversed: Vec<u8>,
    normalized: Vec<u8>,
    stack: Vec<(u32, u32, u32, u32)>,
    candidates: Vec<Candidate>,
}

impl Scratch {
    fn label(&mut self, pool: &mut LabelPool) -> Result<u32, &'static str> {
        if self.reversed.is_empty() { return Err("invalid domain in MRS"); }
        self.normalized.clear();
        if self.reversed.is_ascii() {
            self.normalized.extend(self.reversed.iter().rev().map(u8::to_ascii_lowercase));
        } else {
            let text = str::from_utf8(&self.reversed).map_err(|_| "invalid UTF-8 domain in MRS")?;
            let mut bytes = [0u8; 4];
            for ch in text.chars().rev() {
                self.normalized.extend_from_slice(ch.encode_utf8(&mut bytes).as_bytes());
            }
            self.normalized.make_ascii_lowercase();
        }
        pool.intern(&self.normalized)
    }

    fn collect(
        &mut self, trie: &MrsDomainTrie, source: usize, pool: &mut LabelPool,
    ) -> Result<u8, &'static str> {
        if trie.terminal(source) { return Err("invalid domain in MRS"); }
        self.reversed.clear();
        self.stack.clear();
        self.stack.push((
            source as u32, trie.children(source).start as u32, 0, NONE,
        ));
        let mut flags = 0;
        while let Some((node, edge, depth, mut cached)) = self.stack.pop() {
            let node = node as usize;
            let edge = edge as usize;
            let depth = depth as usize;
            self.reversed.truncate(depth);
            let range = trie.children(node);
            if edge == range.start && trie.terminal(node) {
                if self.reversed == b"+" { flags |= SUFFIX; }
                else {
                    let label = self.label(pool)?;
                    cached = label;
                    self.candidates.push(Candidate { label, source: NONE, flags: EXACT });
                }
            }
            if edge == range.end { continue; }
            self.stack.push((node as u32, (edge + 1) as u32, depth as u32, cached));
            let child = edge + 1;
            if !trie.live(child) { continue; }
            let byte = trie.labels[edge];
            if byte == b'.' {
                // A dot closes a label and starts the next byte subtree.
                if trie.terminal(child) { return Err("invalid domain in MRS"); }
                let label = if cached == NONE { self.label(pool)? } else { cached };
                self.candidates.push(Candidate { label, source: child as u32, flags: 0 });
            } else {
                self.reversed.push(byte);
                self.stack.push((
                    child as u32, trie.children(child).start as u32,
                    (depth + 1) as u32, NONE,
                ));
            }
        }
        Ok(flags)
    }
}

impl CompactDomainSet {
    pub(in crate::common::domainset) fn from_mrs(
        trie: MrsDomainTrie,
    ) -> Result<Self, &'static str> {
        if !trie.live(0) { return Ok(Self::default()); }
        let (node_capacity, source_capacity) = trie.capacities();
        if node_capacity.max(source_capacity) > CHILD_MASK as usize {
            return Err("too many MRS label nodes");
        }
        let mut pool = LabelPool {
            chunk_size: LABEL_CHUNK.min(trie.labels.len().max(1)),
            spans: Vec::with_capacity(node_capacity - 2),
            slots: vec![NONE; table_size((node_capacity - 2).max(1))],
            ..LabelPool::default()
        };
        let mut scratch = Scratch::default();
        let mut nodes = Vec::with_capacity(node_capacity);
        nodes.push(Node { label: 0, child_flags: 1 });
        let mut sources = Vec::with_capacity(source_capacity);
        sources.push(0u32);
        let mut source_start = 0;
        let mut parent = 0;
        while parent < nodes.len() {
            scratch.candidates.clear();
            let source_end = nodes[parent].first_child();
            for i in source_start..source_end {
                let flags = scratch.collect(&trie, sources[i] as usize, &mut pool)?;
                nodes[parent].add_flags(flags);
            }
            scratch.candidates.sort_unstable_by(|a, b| {
                compare_labels(pool.label(a.label), pool.label(b.label))
            });
            source_start = source_end;
            // Until processed, the child index stores the source-range end.
            // BFS processes parents in order, so a single cursor gives its start.
            nodes[parent].child_flags = (nodes[parent].child_flags & !CHILD_MASK)
                | node_index(nodes.len());
            let mut i = 0;
            while i < scratch.candidates.len() {
                let label = scratch.candidates[i].label;
                let mut flags = 0;
                while i < scratch.candidates.len() && scratch.candidates[i].label == label {
                    let candidate = &scratch.candidates[i];
                    flags |= candidate.flags;
                    if candidate.source != NONE { sources.push(candidate.source); }
                    i += 1;
                }
                let offset = if pool.label(label) == b"*" {
                    nodes[parent].add_flags(WILDCARD);
                    WILDCARD_LABEL
                } else { label };
                let mut child = Node { label: offset, child_flags: node_index(sources.len()) };
                child.add_flags(flags);
                nodes.push(child);
            }
            parent += 1;
        }
        let keys = nodes.iter()
            .map(|node| (node.flags() & (EXACT | SUFFIX)).count_ones() as usize).sum();
        nodes.push(Node { label: 0, child_flags: node_index(nodes.len()) });
        // Freeze into exact-sized arrays only after releasing the input trie and
        // all workspaces. The temporary intern table borrows no final storage.
        drop(trie);
        drop(scratch);
        drop(sources);
        let labels = pool.freeze(&mut nodes);
        let mut nodes = nodes.into_boxed_slice();
        let index = WideIndex::build(&mut nodes, &labels);
        Ok(Self { nodes, labels, keys, index })
    }
}
