use std::{mem::size_of, sync::Arc};

use super::{CompactDomainSet, DomainKey, Node, PendingNode, EXACT};
use super::wideindex::{HASH_THRESHOLD, hash_label};
use crate::common::{domainset::{DomainSet, DomainSetBuilder}, trie::StringTrie};

#[test]
fn test_compact_layout_and_label_sharing() {
    assert_eq!(size_of::<Node>(), 8);
    assert_eq!(size_of::<PendingNode>(), 16);
    let set = CompactDomainSet::from_keys(vec![
        DomainKey { domain: "a.x".into(), flags: EXACT },
        DomainKey { domain: "a.y".into(), flags: EXACT },
    ]);
    assert_eq!(set.labels.len(), 6);
    assert!(set.has("a.x"));
    assert!(set.has("a.y"));
}

#[test]
fn test_builder_expansion_dedup_and_boundaries() {
    let mut builder = DomainSetBuilder::new();
    for key in ["+.EXAMPLE", "example", ".example", "*.x", "foo.a.x"] {
        assert!(builder.insert(key));
    }
    for key in ["", ".", "..example", "a..x", "a.x."] {
        assert!(!builder.insert(key));
    }
    let set = builder.build();
    assert_eq!(set.len(), 4);
    for query in ["example", "a.EXAMPLE", "a.b.example", "a.x", "foo.a.x"] {
        assert!(set.has(query), "{query}");
    }
    for query in ["badexample", "a.b.x", "", ".example", "a..example", "example."] {
        assert!(!set.has(query), "{query}");
    }
}

#[test]
fn test_literal_plus_labels_survive_expansion_and_conversion() {
    for pattern in ["+.+", "+.+.example", ".+", "a.+.example"] {
        let mut trie = StringTrie::new();
        let mut copy = StringTrie::new();
        let mut builder = DomainSetBuilder::new();
        trie.insert(pattern, Arc::new(()));
        copy.insert(pattern, Arc::new(()));
        assert!(builder.insert(pattern));
        let built = builder.build();
        let converted: DomainSet = copy.into();
        for query in ["+", "x", "a.+", "a.b.+", "+.example",
            "a.+.example", "x.example", "a.x.example"]
        {
            let expected = trie.search(query).is_some();
            assert_eq!(built.has(query), expected, "{pattern}: {query}");
            assert_eq!(converted.has(query), expected, "{pattern}: {query}");
        }
    }
}

#[test]
fn test_hash_collision_chain_and_absent_key() {
    let mut candidates = Vec::new();
    for i in 0..1_000_000 {
        let label = format!("collision{i}");
        if hash_label(label.as_bytes()) & 511 == 0 {
            candidates.push(label);
        }
        if candidates.len() == 129 { break; }
    }
    assert_eq!(candidates.len(), 129);
    let set = CompactDomainSet::from_keys(candidates[..128].iter().map(|label| {
        DomainKey { domain: format!("{label}.example"), flags: EXACT }
    }).collect());
    assert!(set.index.len() > 0);
    for label in &candidates[..128] { assert!(set.has(&format!("{label}.example"))); }
    assert!(!set.has(&format!("{}.example", candidates[128])));
}

#[test]
fn test_hash_wide_wildcard_backtracking_matches_string_trie() {
    let mut labels: Vec<_> = (0..256).map(|i| format!("label{i}")).collect();
    labels.extend(["!", "$", "é", "a*", "+"].into_iter().map(str::to_owned));
    let mut patterns: Vec<_> = labels.iter().map(|label| format!("b.{label}.example")).collect();
    patterns.push("a.*.example".to_owned());
    patterns.push("c.*.*.example".to_owned());
    let set = CompactDomainSet::from_keys(patterns.iter().map(|domain| {
        DomainKey { domain: domain.clone(), flags: EXACT }
    }).collect());
    let mut trie = StringTrie::new();
    for pattern in patterns { assert!(trie.insert(&pattern, Arc::new(()))); }
    assert!(set.index.len() > 0);
    for label in labels {
        for query in [format!("a.{label}.example"), format!("b.{label}.example"),
            format!("d.{label}.example"), format!("c.x.{label}.example")]
        {
            assert_eq!(set.has(&query), trie.search(&query).is_some(), "{query}");
        }
    }
    assert!(!set.has("a.foo.bar.example"));
}

#[test]
fn test_hash_threshold_excludes_wildcard_and_ignores_depth() {
    for suffix in ["example", "deep.sub.example"] {
        for count in [HASH_THRESHOLD - 1, HASH_THRESHOLD] {
            let mut keys: Vec<_> = (0..count).map(|i| DomainKey {
                domain: format!("b.label{i}.{suffix}"), flags: EXACT,
            }).collect();
            keys.push(DomainKey { domain: format!("a.*.{suffix}"), flags: EXACT });
            let set = CompactDomainSet::from_keys(keys);
            assert_eq!(set.index.len(), usize::from(count == HASH_THRESHOLD));
            for i in 0..count {
                assert!(set.has(&format!("b.label{i}.{suffix}")));
                assert!(set.has(&format!("a.label{i}.{suffix}")));
            }
            assert!(set.has(&format!("a.unknown.{suffix}")));
            assert!(!set.has(&format!("b.unknown.{suffix}")));
        }
    }
}

#[test]
fn test_direct_index_preserves_nested_and_wildcard_labels() {
    let mut patterns = Vec::new();
    for i in 0..HASH_THRESHOLD {
        patterns.push(format!("tld{i}"));
        patterns.push(format!("hit.label{i}.example"));
        patterns.push(format!("b.label{i}.*.example"));
    }
    patterns.push("example".to_owned());
    let set = CompactDomainSet::from_keys(patterns.iter().map(|domain| DomainKey {
        domain: domain.clone(), flags: EXACT,
    }).collect());
    assert_eq!(set.index.len(), 3);
    for i in 0..HASH_THRESHOLD {
        assert!(set.has(&format!("tld{i}")));
        assert!(set.has(&format!("hit.label{i}.example")));
        assert!(set.has(&format!("b.label{i}.x.example")));
    }
    assert!(set.has("example"));
    assert!(!set.has("hit.unknown.example"));
    assert!(!set.has("b.unknown.x.example"));
    let mut restored = Vec::new();
    set.traverse(|key| { restored.push(key.clone()); true });
    patterns.sort_unstable();
    restored.sort_unstable();
    assert_eq!(restored, patterns);
}
