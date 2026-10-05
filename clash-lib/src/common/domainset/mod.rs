//! Immutable domain membership sets backed by a compact label trie.
//! MRS files are validated and converted during loading.

mod compact;
mod mrs;

use std::{borrow::Cow, cell::OnceCell};

use compact::{CompactDomainSet, DomainKey, EXACT, SUFFIX};
use mrs::MrsDomainTrie;
use super::{domain::has_valid_domain_labels, trie::StringTrie};

#[derive(Default)]
pub struct DomainSet {
    storage: CompactDomainSet,
}

impl DomainSet {
    pub fn has(&self, key: &str) -> bool {
        if self.is_empty() { return false; }
        self.matches_query(&DomainSetQuery::new(key))
    }

    pub(crate) fn has_query(&self, query: &DomainSetQuery<'_>) -> bool {
        !self.is_empty() && self.matches_query(query)
    }

    fn matches_query(&self, query: &DomainSetQuery<'_>) -> bool {
        !query.is_empty() && self.storage.has(query.normalized())
    }

    pub fn len(&self) -> usize { self.storage.len() }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub(crate) fn from_mrs_parts(
        leaves: Vec<u64>, bitmap: Vec<u64>, labels: Vec<u8>,
    ) -> Result<Self, &'static str> {
        let set = MrsDomainTrie::from_mrs_parts(leaves, bitmap, labels)?;
        Ok(Self { storage: CompactDomainSet::from_mrs(set)? })
    }

    #[cfg(test)]
    pub fn traverse<F: FnMut(&String) -> bool>(&self, f: F) {
        self.storage.traverse(f);
    }
}

impl<T> From<StringTrie<T>> for DomainSet {
    fn from(value: StringTrie<T>) -> Self {
        let mut keys = Vec::new();
        value.traverse_parts(|parts, _| {
            let suffix = parts.last() == Some(&"");
            let parts = if suffix { &parts[..parts.len() - 1] } else { parts };
            let capacity = parts.iter().map(|part| part.len()).sum::<usize>()
                + parts.len().saturating_sub(1);
            let mut domain = String::with_capacity(capacity);
            for part in parts.iter().rev() {
                if !domain.is_empty() { domain.push('.'); }
                domain.push_str(part);
            }
            domain.make_ascii_lowercase();
            keys.push(DomainKey { domain, flags: if suffix { SUFFIX } else { EXACT } });
            true
        });
        drop(value);
        Self { storage: CompactDomainSet::from_keys(keys) }
    }
}

/// Build text patterns without an intermediate HashMap-based StringTrie.
#[derive(Default)]
pub struct DomainSetBuilder {
    keys: Vec<DomainKey>,
}

impl DomainSetBuilder {
    pub fn new() -> Self { Self::default() }

    /// Follow StringTrie pattern validation and '+' base expansion.
    pub fn insert(&mut self, key: &str) -> bool {
        let body = key.strip_prefix('.').unwrap_or(key);
        if !has_valid_domain_labels(body) { return false; }
        let (domain, flags) = if key == "+" {
            ("", SUFFIX)
        } else if let Some(suffix) = key.strip_prefix("+.") {
            (suffix, EXACT | SUFFIX)
        } else if let Some(suffix) = key.strip_prefix('.') {
            (suffix, SUFFIX)
        } else {
            (key, EXACT)
        };
        self.keys.push(DomainKey { domain: domain.to_ascii_lowercase(), flags });
        true
    }

    pub fn build(self) -> DomainSet {
        DomainSet { storage: CompactDomainSet::from_keys(self.keys) }
    }
}

/// Share lazy normalization across domain sets for one query.
pub(crate) struct DomainSetQuery<'a> {
    key: &'a str,
    normalized: OnceCell<Cow<'a, str>>,
}

impl<'a> DomainSetQuery<'a> {
    pub(crate) fn new(key: &'a str) -> Self {
        Self {
            key: if has_valid_domain_labels(key) { key } else { "" },
            normalized: OnceCell::new(),
        }
    }

    fn is_empty(&self) -> bool { self.key.is_empty() }

    fn normalized(&self) -> &str {
        self.normalized.get_or_init(|| {
            if self.key.bytes().any(|byte| byte.is_ascii_uppercase()) {
                Cow::Owned(self.key.to_ascii_lowercase())
            } else { Cow::Borrowed(self.key) }
        })
    }
}

#[derive(Clone, Copy, Default)]
struct Cursor {
    node: usize,
    index: usize,
}

#[derive(Default)]
struct CursorStack {
    inline: [Cursor; 8],
    len: usize,
    overflow: Vec<Cursor>,
}

impl CursorStack {
    fn push(&mut self, cursor: Cursor) {
        if self.len < self.inline.len() && self.overflow.is_empty() {
            self.inline[self.len] = cursor;
            self.len += 1;
        } else {
            self.overflow.push(cursor);
        }
    }

    fn pop(&mut self) -> Option<Cursor> {
        self.overflow.pop().or_else(|| {
            if self.len == 0 {
                None
            } else {
                self.len -= 1;
                Some(self.inline[self.len])
            }
        })
    }
}

#[cfg(test)]
mod tests;
