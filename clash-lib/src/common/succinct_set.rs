//! idea: https://github.com/openacid/succinct
//! impl: https://github.com/MetaCubeX/mihomo/blob/Meta/component/trie/domain_set.go
//! I have no idea what's going on here, just copy the code from above link.

use super::trie::StringTrie;

static COMPLEX_WILDCARD: u8 = b'+';
static WILDCARD: u8 = b'*';
static DOMAIN_STEP: u8 = b'.';

#[derive(Default)]
pub struct DomainSet {
    leaves: Box<[u64]>,
    label_bit_map: Box<[u64]>,
    labels: Box<[u8]>,
    ranks: Box<[i32]>,
    selects: Box<[i32]>,
}

impl DomainSet {
    pub fn has(&self, key: &str) -> bool {
        let key_bytes = key.as_bytes();
        let mut stack_buf = [0u8; 256];
        let heap_buf;
        let rev_key: &[u8] = if key_bytes.len() <= 256 {
            let slice = &mut stack_buf[..key_bytes.len()];
            for (i, &b) in key_bytes.iter().rev().enumerate() {
                slice[i] = b.to_ascii_lowercase();
            }
            slice
        } else {
            heap_buf = key_bytes
                .iter()
                .rev()
                .map(|b| b.to_ascii_lowercase())
                .collect::<Vec<u8>>();
            &heap_buf
        };
        let key = rev_key;
        let mut node_id = 0;
        let mut bm_idx = 0;

        #[derive(Clone, Copy)]
        struct Cursor {
            bm_idx: usize,
            index: usize,
        }

        let mut stack_inline = [Cursor {
            bm_idx: 0,
            index: 0,
        }; 8];
        let mut stack_len = 0;
        let mut stack_heap: Vec<Cursor> = Vec::new();

        #[derive(PartialEq)]
        enum State {
            Restart,
            Done,
        }

        let mut i: usize = 0;

        while i < key.len() {
            let mut state = State::Restart;

            'ctrl: while state == State::Restart {
                state = State::Done;

                let c = key[i];
                loop {
                    if get_bit(&self.label_bit_map, bm_idx) {
                        let cursor_opt = if !stack_heap.is_empty() {
                            stack_heap.pop()
                        } else if stack_len > 0 {
                            stack_len -= 1;
                            Some(stack_inline[stack_len])
                        } else {
                            None
                        };

                        if let Some(cursor) = cursor_opt {
                            let next_node_id = count_zeros(
                                &self.label_bit_map,
                                &self.ranks,
                                cursor.bm_idx + 1,
                            );
                            let mut next_bm_idx = select_ith_one(
                                &self.label_bit_map,
                                &self.ranks,
                                &self.selects,
                                next_node_id - 1,
                            ) + 1;

                            let j = cursor.index
                                + key[cursor.index..]
                                    .iter()
                                    .position(|&b| b == DOMAIN_STEP)
                                    .unwrap_or(key.len() - cursor.index);
                            if j == key.len() {
                                if get_bit(&self.leaves, next_node_id as isize) {
                                    return true;
                                } else {
                                    state = State::Restart;
                                    continue 'ctrl;
                                }
                            }

                            while next_bm_idx - next_node_id < self.labels.len() {
                                if self.labels[next_bm_idx - next_node_id]
                                    == DOMAIN_STEP
                                {
                                    bm_idx = next_bm_idx as isize;
                                    node_id = next_node_id;
                                    i = j;

                                    state = State::Restart;
                                    continue 'ctrl;
                                }
                                next_bm_idx += 1;
                            }
                        }
                        return false;
                    }

                    if self.labels.is_empty() {
                        return false;
                    }

                    if self.labels[bm_idx as usize - node_id] == COMPLEX_WILDCARD {
                        return true;
                    } else if self.labels[bm_idx as usize - node_id] == WILDCARD {
                        let cursor = Cursor {
                            bm_idx: bm_idx as usize,
                            index: i,
                        };
                        if stack_len < 8 && stack_heap.is_empty() {
                            stack_inline[stack_len] = cursor;
                            stack_len += 1;
                        } else {
                            stack_heap.push(cursor);
                        }
                    } else if self.labels[bm_idx as usize - node_id] == c {
                        break;
                    }

                    bm_idx += 1;
                }

                node_id = count_zeros(
                    &self.label_bit_map,
                    &self.ranks,
                    bm_idx as usize + 1,
                );
                bm_idx = select_ith_one(
                    &self.label_bit_map,
                    &self.ranks,
                    &self.selects,
                    node_id - 1,
                ) as isize
                    + 1;

                i += 1;
            }
        }

        get_bit(&self.leaves, node_id as isize)
    }

    /// Number of keys in the set. Each key terminates at exactly one node, and
    /// each such node sets one bit in `leaves`.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.leaves.iter().map(|x| x.count_ones() as usize).sum()
    }

    #[cfg(test)]
    pub fn traverse<F>(&self, mut f: F)
    where
        F: FnMut(&String) -> bool,
    {
        self.keys(|x| f(&x.chars().rev().collect::<String>()));
    }
}

impl DomainSet {
    pub(crate) fn from_mrs_parts(
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

    #[cfg(test)]
    fn keys<F>(&self, mut f: F)
    where
        F: FnMut(&String) -> bool,
    {
        let mut current_key = vec![];

        fn traverse<F>(
            this: &DomainSet,
            current_key: &mut Vec<char>,
            node_id: isize,
            bm_idx: isize,
            f: &mut F,
        ) -> bool
        where
            F: FnMut(&String) -> bool,
        {
            if get_bit(&this.leaves, node_id) && !f(&current_key.iter().collect()) {
                return false;
            }

            let mut bm_idx = bm_idx;

            loop {
                if get_bit(&this.label_bit_map, bm_idx) {
                    return true;
                }

                let next_label = this.labels[(bm_idx - node_id) as usize];
                current_key.push(next_label as char);
                let next_node_id = count_zeros(
                    &this.label_bit_map,
                    &this.ranks,
                    bm_idx as usize + 1,
                );
                let next_bm_idx = select_ith_one(
                    &this.label_bit_map,
                    &this.ranks,
                    &this.selects,
                    next_node_id - 1,
                ) + 1;

                if !traverse(
                    this,
                    current_key,
                    next_node_id as isize,
                    next_bm_idx as isize,
                    f,
                ) {
                    return false;
                }

                current_key.pop();

                bm_idx += 1;
            }
        }

        traverse(self, &mut current_key, 0, 0, &mut f);
    }
}

struct QElt {
    s: usize,
    e: usize,
    col: usize,
}

/// Convert a `StringTrie` to a `DomainSet`.
/// TODO: support loading from a binary file.
/// e.g. the so called 'mrs' file in the MiHoMo project.
impl<T> From<StringTrie<T>> for DomainSet {
    fn from(value: StringTrie<T>) -> Self {
        let mut keys = vec![];
        value.traverse(|key, _| {
            keys.push(key.chars().rev().collect::<String>());
            true
        });
        keys.sort();

        let mut leaves = Vec::new();
        let mut label_bit_map = Vec::new();
        let mut labels = Vec::new();

        let mut l_idx = 0;

        let mut queue = vec![QElt {
            s: 0,
            e: keys.len(),
            col: 0,
        }];

        let mut i = 0;
        loop {
            let elt = &mut queue[i];
            if elt.col == keys[elt.s].len() {
                elt.s += 1;
                set_bit(&mut leaves, i, true);
            }

            let mut j = elt.s;
            let e = elt.e;
            let col = elt.col;
            while j < e {
                let frm = j;
                while j < e && keys[j].chars().nth(col) == keys[frm].chars().nth(col)
                {
                    j += 1;
                }

                queue.push(QElt {
                    s: frm,
                    e: j,
                    col: col + 1,
                });
                // Safely handle potential None if keys[frm] is shorter than col
                if let Some(char_at_col) = keys[frm].chars().nth(col) {
                    labels.push(char_at_col as u8);
                    set_bit(&mut label_bit_map, l_idx, false);
                    l_idx += 1;
                }
            }

            set_bit(&mut label_bit_map, l_idx, true);
            l_idx += 1;

            if i == queue.len() - 1 {
                break;
            }
            i += 1;
        }

        Self::from_mrs_parts(leaves, label_bit_map, labels)
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

#[inline(always)]
fn count_zeros(bm: &[u64], ranks: &[i32], i: usize) -> usize {
    let word_idx = i >> 6;
    let bit_idx = i & 63;
    let mask = if bit_idx == 0 {
        0
    } else {
        (1u64 << bit_idx) - 1
    };
    i - ranks[word_idx] as usize - (bm[word_idx] & mask).count_ones() as usize
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[test]
    fn test_domain_set_complex_wildcard() {
        let mut tree = super::StringTrie::new();
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

        let set = super::DomainSet::from(tree);
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
        let mut tree = super::StringTrie::new();
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

        let set = super::DomainSet::from(tree);

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

    fn test_dump(data_src: &Vec<String>, set: &super::DomainSet) {
        let mut data_set = vec![];
        set.traverse(|key| {
            data_set.push(key.to_owned());
            true
        });
        data_set.sort();

        assert_eq!(data_src, &data_set);
    }
}
