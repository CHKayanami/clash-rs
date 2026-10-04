use std::cmp::Ordering;

use super::DomainKey;

pub(super) struct PreparedKeys {
    domains: Vec<u8>,
    labels: Vec<LabelSpan>,
    pub(super) paths: Vec<Path>,
}

struct LabelSpan {
    start: u32,
    end: u32,
}

impl LabelSpan {
    fn bytes<'a>(&self, domains: &'a [u8]) -> &'a [u8] {
        &domains[self.start as usize..self.end as usize]
    }
}

pub(super) struct Path {
    start: u32,
    len: u32,
    pub(super) flags: u8,
}

impl Path {
    pub(super) fn len(&self) -> usize { self.len as usize }

    fn labels<'a>(&self, labels: &'a [LabelSpan]) -> &'a [LabelSpan] {
        let start = self.start as usize;
        &labels[start..start + self.len()]
    }

    fn compare(&self, other: &Self, labels: &[LabelSpan], domains: &[u8]) -> Ordering {
        self.labels(labels).iter().zip(other.labels(labels))
            .map(|(a, b)| compare_labels(a.bytes(domains), b.bytes(domains)))
            .find(|order| *order != Ordering::Equal)
            .unwrap_or_else(|| self.len.cmp(&other.len))
    }
}

fn compare_labels(a: &[u8], b: &[u8]) -> Ordering {
    match (a == b"*", b == b"*") {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => a.cmp(b),
    }
}

fn offset(value: usize) -> u32 {
    u32::try_from(value).expect("domain construction arena exceeds 32-bit offsets")
}

impl PreparedKeys {
    pub(super) fn new(mut keys: Vec<DomainKey>) -> Self {
        // MRS commonly emits exact/suffix terminals for the same name next
        // to each other. Merge those in linear time before allocating spans;
        // the single sort below still merges duplicates anywhere in the input.
        keys.dedup_by(|a, b| {
            if a.domain == b.domain {
                b.flags |= a.flags;
                true
            } else { false }
        });
        let mut byte_count = 0usize;
        let mut label_count = 0usize;
        for key in &keys {
            byte_count = byte_count.checked_add(key.domain.len())
                .expect("domain construction byte size overflow");
            if !key.domain.is_empty() {
                let count = key.domain.bytes().filter(|&byte| byte == b'.').count() + 1;
                label_count = label_count.checked_add(count)
                    .expect("domain construction label count overflow");
            }
        }
        offset(byte_count);
        offset(label_count);
        let mut domains = Vec::with_capacity(byte_count);
        let mut labels = Vec::with_capacity(label_count);
        let mut paths = Vec::with_capacity(keys.len());
        // Consume strings into one arena. Labels are byte ranges on UTF-8
        // boundaries from rsplit; only byte comparisons are needed below.
        // Each path indexes the shared label array rather than owning a Vec.
        for key in keys {
            let base = domains.len();
            let start = labels.len();
            domains.extend_from_slice(key.domain.as_bytes());
            if !key.domain.is_empty() {
                let mut end = base + key.domain.len();
                for label in key.domain.rsplit('.') {
                    let begin = end - label.len();
                    labels.push(LabelSpan { start: offset(begin), end: offset(end) });
                    end = if begin > base { begin - 1 } else { begin };
                }
            }
            paths.push(Path {
                start: offset(start), len: offset(labels.len() - start), flags: key.flags,
            });
        }
        paths.sort_unstable_by(|a, b| a.compare(b, &labels, &domains));
        paths.dedup_by(|a, b| {
            if a.compare(b, &labels, &domains) == Ordering::Equal {
                b.flags |= a.flags;
                true
            } else { false }
        });
        Self { domains, labels, paths }
    }

    pub(super) fn label(&self, path: usize, depth: usize) -> &[u8] {
        let label = self.paths[path].start as usize + depth;
        self.labels[label].bytes(&self.domains)
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::{PreparedKeys, Path, LabelSpan};
    use crate::common::domainset::compact::{DomainKey, EXACT, SUFFIX};

    #[test]
    fn test_shared_labels_sort_prefixes_and_merge_flags() {
        assert_eq!(size_of::<Path>(), 12);
        assert_eq!(size_of::<LabelSpan>(), 8);
        let keys = PreparedKeys::new(vec![
            DomainKey { domain: "a.é.x".into(), flags: EXACT },
            DomainKey { domain: "*.é.x".into(), flags: EXACT },
            DomainKey { domain: "a.é.x".into(), flags: SUFFIX },
            DomainKey { domain: "!a.é.x".into(), flags: EXACT },
            DomainKey { domain: "é.x".into(), flags: EXACT },
            DomainKey { domain: String::new(), flags: SUFFIX },
        ]);
        assert_eq!(keys.paths.len(), 5);
        assert_eq!(keys.paths[0].len(), 0);
        assert_eq!(keys.paths[0].flags, SUFFIX);
        assert_eq!(keys.paths[1].len(), 2);
        assert_eq!(keys.label(1, 0), b"x");
        assert_eq!(keys.label(1, 1), "é".as_bytes());
        assert_eq!(keys.label(2, 2), b"*");
        assert_eq!(keys.label(3, 2), b"!a");
        assert_eq!(keys.label(4, 2), b"a");
        assert_eq!(keys.paths[4].flags, EXACT | SUFFIX);
    }
}
