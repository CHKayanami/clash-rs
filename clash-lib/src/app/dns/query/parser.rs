use std::ops::Range;
use std::sync::Arc;

use bytes::Bytes;

use super::{DnsName, QueryError};

const MAX_POINTER_HOPS: usize = 128;
const STACK_PARSE_LEN: usize = 512;
// DNS compression pointers contain a 14-bit target offset.
const MAX_POINTER_TARGETS: usize = 1 << 14;

enum VisitedStorage {
    Stack([u64; STACK_PARSE_LEN / 64]),
    Heap { marks: Option<Vec<u64>>, len: usize },
}

impl VisitedStorage {
    fn new(len: usize) -> Self {
        if len <= STACK_PARSE_LEN {
            Self::Stack([0; STACK_PARSE_LEN / 64])
        } else {
            Self::Heap { marks: None, len: len.min(MAX_POINTER_TARGETS) }
        }
    }

    #[inline]
    fn word(&mut self, target: usize) -> Option<&mut u64> {
        match self {
            Self::Stack(words) => words.get_mut(target / 64),
            Self::Heap { marks, len } => {
                if target >= *len { return None; }
                marks.get_or_insert_with(|| vec![0; len.div_ceil(64)])
                    .get_mut(target / 64)
            }
        }
    }
}

pub(crate) struct NameParseState {
    visited: VisitedStorage,
    // Only successful visits need clearing before the next name. This bounds
    // cleanup by the hop limit instead of clearing the whole pointer bitmap.
    targets: [u16; MAX_POINTER_HOPS],
    pointer_hops: usize,
}

impl NameParseState {
    pub(crate) fn new(message_len: usize) -> Self {
        Self {
            visited: VisitedStorage::new(message_len),
            targets: [0; MAX_POINTER_HOPS],
            pointer_hops: 0,
        }
    }

    fn begin_name(&mut self) {
        for target in &self.targets[..self.pointer_hops] {
            let target = usize::from(*target);
            if let Some(word) = self.visited.word(target) {
                *word &= !(1_u64 << (target % 64));
            }
        }
        self.pointer_hops = 0;
    }

    fn visit_pointer(&mut self, target: usize, cursor: usize) -> Result<(), QueryError> {
        if target >= cursor || self.pointer_hops == MAX_POINTER_HOPS {
            return Err(QueryError::MalformedName);
        }
        let word = self.visited.word(target).ok_or(QueryError::MalformedName)?;
        let mask = 1_u64 << (target % 64);
        if *word & mask != 0 {
            return Err(QueryError::MalformedName);
        }
        *word |= mask;
        self.targets[self.pointer_hops] = target as u16;
        self.pointer_hops += 1;
        Ok(())
    }
}

// A validated DNS name occupies at most 255 bytes, including label lengths
// and the terminator. Its dotted domain fits in the same stack buffer.
pub(super) struct DomainBuilder {
    bytes: [u8; 255],
    len: usize,
}

impl DomainBuilder {
    pub(super) fn new() -> Self {
        Self { bytes: [0; 255], len: 0 }
    }

    pub(super) fn push_label(&mut self, label: &[u8]) {
        if label.is_empty() { return; }
        if self.len != 0 {
            self.bytes[self.len] = b'.';
            self.len += 1;
        }
        for byte in label {
            self.bytes[self.len] = byte.to_ascii_lowercase();
            self.len += 1;
        }
    }

    pub(super) fn finish(self) -> Option<Arc<str>> {
        if self.len == 0 { return None; }
        // Separators prevent UTF-8 sequences from crossing label boundaries.
        std::str::from_utf8(&self.bytes[..self.len]).ok().map(Arc::from)
    }
}

#[derive(Debug)]
pub(super) struct ResourceRecord {
    pub(super) root_name: bool,
    pub(super) rtype: u16,
    pub(super) class: u16,
    pub(super) rdata: Range<usize>,
    pub(super) end: usize,
}

pub(super) fn parse_rr(
    raw: &[u8],
    start: usize,
    state: &mut NameParseState,
) -> Result<ResourceRecord, QueryError> {
    let mut root_name = true;
    let name_end = walk_name(raw, start, state, |_, bytes| {
        if bytes != [0] { root_name = false; }
        Ok(())
    })?;
    let fields = raw.get(name_end..name_end + 10).ok_or(QueryError::TruncatedField)?;
    let rtype = u16::from_be_bytes([fields[0], fields[1]]);
    let class = u16::from_be_bytes([fields[2], fields[3]]);
    let rdlength = usize::from(u16::from_be_bytes([fields[8], fields[9]]));
    let rdata_start = name_end + 10;
    let end = rdata_start
        .checked_add(rdlength)
        .filter(|end| *end <= raw.len())
        .ok_or(QueryError::TruncatedField)?;
    Ok(ResourceRecord {
        root_name,
        rtype,
        class,
        rdata: rdata_start..end,
        end,
    })
}

pub(super) fn parse_edns(raw: &[u8], rr: &ResourceRecord) -> Result<u16, QueryError> {
    let mut cursor = rr.rdata.start;
    while cursor < rr.rdata.end {
        let fields = raw.get(cursor..cursor + 4)
            .filter(|_| cursor + 4 <= rr.rdata.end)
            .ok_or(QueryError::MalformedEdnsOption)?;
        let len = usize::from(u16::from_be_bytes([fields[2], fields[3]]));
        cursor = cursor
            .checked_add(4 + len)
            .filter(|end| *end <= rr.rdata.end)
            .ok_or(QueryError::MalformedEdnsOption)?;
    }
    if !rr.root_name {
        return Err(QueryError::MalformedName);
    }
    Ok(rr.class)
}

pub(super) fn parse_name(
    wire: &Bytes,
    start: usize,
    state: &mut NameParseState,
    decode_domain: bool,
) -> Result<(DnsName, usize, Option<Arc<str>>), QueryError> {
    let mut expanded = [0; 255];
    let mut length = 0;
    let mut compressed = false;
    let mut domain = decode_domain.then(DomainBuilder::new);
    let name_end = walk_name(wire, start, state, |offset, bytes| {
        if !compressed && offset != start + length {
            expanded[..length].copy_from_slice(&wire[start..start + length]);
            compressed = true;
        }
        if compressed {
            expanded[length..length + bytes.len()].copy_from_slice(bytes);
        }
        length += bytes.len();
        if let Some(domain) = &mut domain {
            domain.push_label(&bytes[1..]);
        }
        Ok(())
    })?;
    // A slice owns a reference to the immutable packet; compressed names own
    // their expanded bytes. Neither representation borrows parser scratch space.
    let name = if compressed {
        DnsName(Bytes::copy_from_slice(&expanded[..length]))
    } else {
        DnsName(wire.slice(start..name_end))
    };
    Ok((name, name_end, domain.and_then(DomainBuilder::finish)))
}

pub(crate) fn skip_name(
    raw: &[u8],
    start: usize,
    state: &mut NameParseState,
) -> Result<usize, QueryError> {
    walk_name(raw, start, state, |_, _| Ok(()))
}

/// Compare the expanded name without constructing a temporary DnsName.
/// All pointer, label and expanded-length checks use the common walker.
pub(crate) fn match_name(
    raw: &[u8],
    start: usize,
    state: &mut NameParseState,
    expected: &DnsName,
) -> Result<usize, QueryError> {
    let expected = expected.as_wire();
    let mut position = 0;
    let end = walk_name(raw, start, state, |_, bytes| {
        let next = position + bytes.len();
        if expected.get(position..next) != Some(bytes) {
            return Err(QueryError::MalformedName);
        }
        position = next;
        Ok(())
    })?;
    if position != expected.len() { return Err(QueryError::MalformedName); }
    Ok(end)
}

#[inline(always)]
fn walk_name<F>(
    raw: &[u8],
    start: usize,
    state: &mut NameParseState,
    mut sink: F,
) -> Result<usize, QueryError>
where F: FnMut(usize, &[u8]) -> Result<(), QueryError>,
{
    state.begin_name();
    let mut cursor = start;
    let mut end = None;
    let mut total_len = 0;
    loop {
        let octet = *raw.get(cursor).ok_or(QueryError::MalformedName)?;
        if octet & 0xc0 == 0xc0 {
            let second = *raw.get(cursor + 1).ok_or(QueryError::MalformedName)?;
            let target = usize::from((u16::from(octet & 0x3f) << 8) | u16::from(second));
            state.visit_pointer(target, cursor)?;
            if end.is_none() {
                end = Some(cursor + 2);
            }
            cursor = target;
            continue;
        }
        if octet & 0xc0 != 0 || octet > 63 {
            return Err(QueryError::MalformedName);
        }
        let label_end = cursor
            .checked_add(1 + usize::from(octet))
            .filter(|label_end| *label_end <= raw.len())
            .ok_or(QueryError::MalformedName)?;
        total_len += 1 + usize::from(octet);
        if total_len > 255 {
            return Err(QueryError::MalformedName);
        }
        sink(cursor, &raw[cursor..label_end])?;
        if octet == 0 {
            return Ok(end.unwrap_or(label_end));
        }
        cursor = label_end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparison_matches_decoding_for_plain_and_compressed_names() {
        let base = DnsName::from_domain("example.test").unwrap();
        let mut wire = base.as_wire().to_vec();
        let compressed = wire.len();
        wire.extend_from_slice(&[0xc0, 0]);
        let prefixed = wire.len();
        wire.extend_from_slice(&[3, b'w', b'w', b'w', 0xc0, 0]);
        let www = DnsName::from_domain("www.example.test").unwrap();
        for (start, expected) in [(0, &base), (compressed, &base), (prefixed, &www)] {
            let mut state = NameParseState::new(wire.len());
            let (decoded, end, _) = parse_name(&Bytes::copy_from_slice(&wire), start, &mut state, false).unwrap();
            assert_eq!(&decoded, expected);
            assert_eq!(match_name(&wire, start, &mut state, expected).unwrap(), end);
            let mismatch = DnsName::from_domain("other.test").unwrap();
            assert_eq!(match_name(&wire, start, &mut state, &mismatch), Err(QueryError::MalformedName));
        }
        for end in 0..base.as_wire().len() {
            let raw = &base.as_wire()[..end];
            assert!(match_name(raw, 0, &mut NameParseState::new(raw.len()), &base).is_err());
        }
        for mismatch in ["example.test.extra", "example", "Example.test"] {
            let expected = DnsName::from_domain(mismatch).unwrap();
            assert!(match_name(&wire, 0, &mut NameParseState::new(wire.len()), &expected).is_err());
        }
    }

    #[test]
    fn names_share_plain_wire_and_decode_domains_during_expansion() {
        let expected = DnsName::from_domain("MiXeD.é.Example").unwrap();
        let mut raw = expected.as_wire().to_vec();
        let compressed = raw.len();
        raw.extend_from_slice(&[0xc0, 0]);
        let wire = Bytes::from(raw);
        let mut state = NameParseState::new(wire.len());
        let (plain, end, domain) = parse_name(&wire, 0, &mut state, true).unwrap();
        assert_eq!(end, compressed);
        assert_eq!(plain.as_wire().as_ptr(), wire.as_ptr());
        assert_eq!(domain.as_deref(), Some("mixed.é.example"));
        let (expanded, end, domain) = parse_name(&wire, compressed, &mut state, true).unwrap();
        assert_eq!(end, wire.len());
        assert_eq!(expanded, plain);
        assert_ne!(expanded.as_wire().as_ptr(), wire.as_ptr());
        assert_eq!(domain.as_deref(), Some("mixed.é.example"));
        let (_, _, domain) = parse_name(&wire, compressed, &mut state, false).unwrap();
        assert!(domain.is_none());
        drop(wire);
        assert_eq!(plain, expected);
        assert_eq!(expanded, expected);
        // Binary labels remain valid DNS names without a routable UTF-8 domain.
        for raw in [vec![1, 0xc3, 1, 0xa9, 0], vec![1, 0xff, 0], vec![0]] {
            let wire = Bytes::from(raw);
            let (_, _, domain) = parse_name(&wire, 0, &mut NameParseState::new(wire.len()), true).unwrap();
            assert!(domain.is_none());
        }
    }

    #[test]
    fn pointer_bitmap_is_reusable_after_cycles_and_hop_limit_errors() {
        let wire = [1, b'x', 0xc0, 0, 0, 0xc0, 4];
        let mut state = NameParseState::new(wire.len());
        for _ in 0..2 {
            assert_eq!(skip_name(&wire, 0, &mut state), Err(QueryError::MalformedName));
            assert_eq!(skip_name(&wire, 5, &mut state), Ok(7));
        }
        let mut chain = vec![0];
        let mut start = 0;
        for _ in 0..MAX_POINTER_HOPS + 1 {
            let target = start;
            start = chain.len();
            chain.extend_from_slice(&(0xc000 | target as u16).to_be_bytes());
        }
        let mut state = NameParseState::new(chain.len());
        assert_eq!(skip_name(&chain, start, &mut state), Err(QueryError::MalformedName));
        assert_eq!(skip_name(&chain, start - 2, &mut state), Ok(start));
        assert_eq!(skip_name(&chain, start - 2, &mut state), Ok(start));
    }

    #[test]
    fn comparison_rejects_invalid_pointers_and_overlong_names() {
        let expected = DnsName::from_domain("x").unwrap();
        for wire in [vec![0xc0, 0], vec![0xc0, 2, 0], vec![0x40, 0],
            vec![1, b'x', 0xc0, 0]] {
            let mut state = NameParseState::new(wire.len());
            assert!(match_name(&wire, 0, &mut state, &expected).is_err());
            assert!(skip_name(&wire, 0, &mut state).is_err());
        }
        let root = DnsName::from_domain("").unwrap();
        let mut chain = vec![0];
        let mut start = 0;
        for hops in 1..=MAX_POINTER_HOPS + 1 {
            let target = start;
            start = chain.len();
            chain.extend_from_slice(&(0xc000 | target as u16).to_be_bytes());
            let mut state = NameParseState::new(chain.len());
            assert_eq!(match_name(&chain, start, &mut state, &root).is_ok(), hops <= MAX_POINTER_HOPS);
        }
        for (last_len, valid) in [(61, true), (62, false)] {
            let mut wire = Vec::new();
            for len in [63, 63, 63, last_len] {
                wire.push(len as u8);
                wire.extend(std::iter::repeat_n(b'x', len));
            }
            wire.push(0);
            let expected = DnsName(Bytes::from(wire));
            let wire = expected.as_wire();
            let mut state = NameParseState::new(wire.len());
            assert_eq!(match_name(wire, 0, &mut state, &expected).is_ok(), valid);
            assert_eq!(parse_name(&expected.0, 0, &mut state, true).is_ok(), valid);
        }
    }

    #[test]
    fn large_messages_allocate_pointer_marks_only_when_needed() {
        let mut wire = vec![0; 65535];
        let start = wire.len() - 2;
        let mut state = NameParseState::new(wire.len());
        assert_eq!(skip_name(&wire, 0, &mut state).unwrap(), 1);
        assert!(matches!(&state.visited, VisitedStorage::Heap { marks: None, .. }));
        // Exercise the largest encodable target and bitmap reuse between names.
        wire[start..].copy_from_slice(&[0xff, 0xff]);
        assert_eq!(skip_name(&wire, start, &mut state).unwrap(), wire.len());
        match &state.visited {
            VisitedStorage::Heap { marks: Some(marks), .. } => assert_eq!(marks.len(), MAX_POINTER_TARGETS / 64),
            _ => panic!("compression must allocate pointer marks"),
        }
        assert_eq!(skip_name(&wire, start, &mut state).unwrap(), wire.len());
        // A maximum-offset target beyond a smaller message remains invalid.
        let mut shorter = vec![0; 1024];
        shorter[1022..].copy_from_slice(&[0xff, 0xff]);
        assert!(skip_name(&shorter, 1022, &mut NameParseState::new(shorter.len())).is_err());
    }
}
