use std::sync::Arc;

use super::{DomainSet, DomainSetBuilder, DomainSetQuery, MrsDomainTrie, StringTrie};

#[test]
fn test_domain_set_complex_wildcard() {
    let mut tree = StringTrie::new();
    let domains = vec![
        "baidu.com",
        "google.com",
        "www.google.com",
        "test.a.net",
        "test.a.oc",
        "mijia cloud",
        ".qq.com",
        "+.cn",
    ];

    for d in domains {
        tree.insert(d, Arc::new(true));
    }

    let mut key_src = vec![];
    tree.traverse(|key, _| {
        key_src.push(key.to_owned());
        true
    });
    key_src.sort();

    let set = DomainSet::from(tree);
    assert!(set.has("test.cn"));
    assert!(set.has("cn"));
    assert!(set.has("mijia cloud"));
    assert!(set.has("test.a.net"));
    assert!(set.has("www.qq.com"));
    assert!(set.has("google.com"));
    assert!(!set.has("qq.com"));
    assert!(!set.has("www.baidu.com"));

    test_dump(&key_src, &set);
}

#[test]
fn test_domain_set_wildcard() {
    let mut tree = StringTrie::new();
    let domains = vec![
        "*.*.*.baidu.com",
        "www.baidu.*",
        "stun.*.*",
        "*.*.qq.com",
        "test.*.baidu.com",
        "*.apple.com",
    ];

    for d in domains {
        tree.insert(d, Arc::new(true));
    }

    let mut key_src = vec![];
    tree.traverse(|key, _| {
        key_src.push(key.to_owned());
        true
    });
    key_src.sort();

    let set = DomainSet::from(tree);

    assert!(set.has("www.baidu.com"));
    assert!(set.has("test.test.baidu.com"));
    assert!(set.has("test.test.qq.com"));
    assert!(set.has("stun.ab.cd"));
    assert!(!set.has("test.baidu.com"));
    assert!(!set.has("www.google.com"));
    assert!(!set.has("a.www.google.com"));
    assert!(!set.has("test.qq.com"));
    assert!(!set.has("test.test.test.qq.com"));

    test_dump(&key_src, &set);
}

fn build(rules: &[&str]) -> DomainSet {
    let mut tree = StringTrie::new();
    for rule in rules {
        assert!(tree.insert(rule, Arc::new(true)));
    }
    tree.into()
}

#[test]
fn test_empty_and_normalization() {
    let set = build(&[]);
    assert_eq!(set.len(), 0);
    assert!(!set.has("example.com"));
    set.traverse(|_| panic!("empty set"));
    let set = build(&["EXAMPLE.COM", "example.com", "é.com"]);
    assert_eq!(set.len(), 2);
    assert!(set.has("EXAMPLE.COM"));
    assert!(set.has("é.com"));
    assert!(!set.has("e.com"));
    test_dump(&vec!["example.com".to_owned(), "é.com".to_owned()], &set);
    assert!(!set.has(""));
    assert!(!set.has("example.com."));
    let long = format!("{}.com", "a".repeat(300));
    assert!(build(&[&long]).has(&long));
}

#[test]
fn test_backtracking_and_label_boundaries() {
    assert!(build(&["*.example.com", "ab.example.com"]).has("b.example.com"));
    assert!(build(&["*.x", "foo.a.x"]).has("a.x"));
    let set = build(&["*.x", "a+b.com", "a*.com", ".example.com"]);
    assert!(!set.has("a.b.x"));
    assert!(!set.has("a..x"));
    assert!(!set.has(".x"));
    assert!(set.has("a+b.com"));
    assert!(!set.has("aZZb.com"));
    assert!(!set.has("abc.com"));
    assert!(!set.has("badexample.com"));
    assert!(!set.has("example.com"));
    assert!(set.has("a.b.example.com"));
}

#[test]
fn test_matches_label_reference() {
    // Deliberately overlapping exact and wildcard branches, including
    // multiple labels to exercise nested alternatives.
    let rules = ["*.x", "a.b.x", "b.*.x", "+.a.x", ".b.x", "*.*.*.x"];
    let set = build(&rules);
    fn matches(rule: &str, query: &str) -> bool {
        if let Some(suffix) = rule.strip_prefix("+.") {
            return query == suffix || query.ends_with(&format!(".{suffix}"));
        }
        if rule.starts_with('.') {
            return query.ends_with(rule);
        }
        let r: Vec<_> = rule.split('.').collect();
        let q: Vec<_> = query.split('.').collect();
        r.len() == q.len() && r.iter().zip(q).all(|(r, q)| *r == "*" || *r == q)
    }
    for depth in 1..=6 {
        for mask in 0..(1usize << depth) {
            let mut parts = Vec::new();
            for bit in 0..depth {
                parts.push(if mask & (1 << bit) == 0 { "a" } else { "b" });
            }
            parts.push("x");
            let query = parts.join(".");
            assert_eq!(
                set.has(&query), rules.iter().any(|r| matches(r, &query)),
                "{query}",
            );
        }
    }
    let mut deep = Vec::new();
    for depth in 1..=12 {
        deep.push(format!("*.{}x", "a.".repeat(depth)));
    }
    deep.push(format!("z.{}x", "a.".repeat(12)));
    let refs: Vec<_> = deep.iter().map(String::as_str).collect();
    let query = format!("a.{}x", "a.".repeat(12));
    assert!(build(&refs).has(&query));
}

#[test]
fn test_mrs_structure_validation() {
    let mut trie = StringTrie::new();
    for key in ["*.x", "+.example.com", "foo.com"] {
        trie.insert(key, Arc::new(()));
    }
    let set = MrsDomainTrie::from(trie);
    let loaded = DomainSet::from_mrs_parts(
        set.leaves.to_vec(),
        set.label_bit_map.to_vec(),
        set.labels.to_vec(),
    ).unwrap();
    assert!(loaded.has("a.x"));
    assert!(loaded.has("a.example.com"));
    assert!(loaded.has("example.com"));
    // A handcrafted MRS path for "é": UTF-8 bytes remain in order.
    let unicode = DomainSet::from_mrs_parts(
        vec![4], vec![26], vec![0xc3, 0xa9],
    ).unwrap();
    assert!(unicode.has("é"));
    for (leaves, bitmap, labels) in [
        (vec![0], vec![0], vec![b'a']),
        (vec![4], vec![6], vec![b'a']),
        (vec![0], vec![7], vec![b'a']),
        (vec![0], vec![13], vec![b'a']),
        (vec![0], vec![28], vec![b'b', b'a']),
    ] {
        assert!(DomainSet::from_mrs_parts(
            leaves, bitmap, labels,
        ).is_err());
    }
    assert!(DomainSet::from_mrs_parts(vec![], vec![1], vec![]).is_ok());
    assert!(DomainSet::from_mrs_parts(vec![], vec![], vec![]).is_ok());
}

#[test]
fn test_mrs_conversion_preserves_branches_and_wildcard_backtracking() {
    let patterns = [
        "a.*.example", "b.!a.example", "c.#a.example", "d.$a.example",
        "e.%a.example", "f.&a.example", "g.za.example", "h.é.example",
        "+.suffix.example", "prefix.example", "prefixlong.example",
    ];
    let mut trie = StringTrie::new();
    let mut source = StringTrie::new();
    let mut builder = DomainSetBuilder::new();
    for pattern in patterns {
        trie.insert(pattern, Arc::new(()));
        source.insert(pattern, Arc::new(()));
        assert!(builder.insert(pattern));
    }
    let encoded = MrsDomainTrie::from(source);
    let converted = DomainSet::from_mrs_parts(
        encoded.leaves.to_vec(), encoded.label_bit_map.to_vec(),
        encoded.labels.to_vec(),
    ).unwrap();
    let direct = builder.build();
    for query in [
        "a.!a.example", "a.za.example", "a.é.example", "a.any.example",
        "b.!a.example", "c.#a.example", "d.$a.example", "e.%a.example",
        "f.&a.example", "g.za.example", "h.é.example", "suffix.example",
        "x.y.suffix.example", "prefix.example", "prefixlong.example",
        "prefixlonger.example", "prefixlon.example", "a.x.y.example",
        "q.!a.example", "example", "unknown",
    ] {
        let expected = trie.search(query).is_some();
        assert_eq!(direct.has(query), expected, "direct: {query}");
        assert_eq!(converted.has(query), expected, "MRS: {query}");
    }
    assert!(converted.has("A.!A.EXAMPLE"));
    assert_eq!(converted.len(), direct.len());
}

#[test]
fn test_mrs_conversion_rejects_invalid_domain_bytes() {
    for label in [0xff, b'.'] {
        assert!(DomainSet::from_mrs_parts(vec![2], vec![6], vec![label]).is_err());
    }
    let mut trie = StringTrie::new();
    trie.insert("+", Arc::new(()));
    let encoded = MrsDomainTrie::from(trie);
    let all = DomainSet::from_mrs_parts(
        encoded.leaves.to_vec(), encoded.label_bit_map.to_vec(),
        encoded.labels.to_vec(),
    ).unwrap();
    assert!(all.has("example"));
    assert!(all.has("a.b.example"));
    assert!(!all.has("a..example"));
}

#[test]
fn test_rank_select_boundaries() {
    let rules: Vec<_> = (0..256)
        .map(|i| format!("host{i}.example.com")).collect();
    let refs: Vec<_> = rules.iter().map(String::as_str).collect();
    let mut trie = StringTrie::new();
    for key in refs { trie.insert(key, Arc::new(())); }
    let set = MrsDomainTrie::from(trie);
    assert_eq!(set.len(), rules.len());
    let set = DomainSet::from_mrs_parts(
        set.leaves.to_vec(),
        set.label_bit_map.to_vec(),
        set.labels.to_vec(),
    ).unwrap();
    for rule in rules {
        assert!(set.has(&rule), "{rule}");
    }
    assert!(!set.has("host256.example.com"));
}

#[test]
fn test_shared_query_and_root_wildcard() {
    let first = build(&["unrelated.example"]);
    let second = build(&["+.example", "é.test"]);
    for domain in ["A.EXAMPLE", "é.test"] {
        let query = DomainSetQuery::new(domain);
        assert!(!first.has_query(&query));
        assert!(second.has_query(&query));
    }
    let all = build(&["+"]);
    assert!(all.has("example"));
    assert!(all.has("a.b.example"));
    for domain in ["", ".example", "a..example", "example."] {
        let query = DomainSetQuery::new(domain);
        assert!(!all.has_query(&query));
    }
    test_dump(&vec!["+".to_owned()], &all);
}

fn test_dump(data_src: &Vec<String>, set: &DomainSet) {
    let mut data_set = vec![];
    set.traverse(|key| {
        data_set.push(key.to_owned());
        true
    });
    data_set.sort();

    assert_eq!(data_src, &data_set);
}
