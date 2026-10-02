use std::ops::Range;

use super::{DnsName, EdnsMetadata, QueryError};

const MAX_POINTER_HOPS: usize = 128;
const STACK_PARSE_LEN: usize = 512;
// DNS compression pointers contain a 14-bit target offset.
const MAX_POINTER_TARGETS: usize = 1 << 14;

enum VisitedStorage {
    Stack([u32; STACK_PARSE_LEN]),
    Heap { marks: Option<Vec<u32>>, len: usize },
}

impl VisitedStorage {
    fn new(len: usize) -> Self {
        if len <= STACK_PARSE_LEN {
            Self::Stack([0; STACK_PARSE_LEN])
        } else {
            Self::Heap { marks: None, len: len.min(MAX_POINTER_TARGETS) }
        }
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> Option<&mut u32> {
        match self {
            Self::Stack(arr) => arr.get_mut(idx),
            Self::Heap { marks, len } => {
                if idx >= *len { return None; }
                marks.get_or_insert_with(|| vec![0; *len]).get_mut(idx)
            }
        }
    }

    #[inline]
    fn fill(&mut self, val: u32) {
        match self {
            Self::Stack(arr) => arr.fill(val),
            Self::Heap { marks, .. } => {
                if let Some(marks) = marks { marks.fill(val); }
            }
        }
    }
}

pub(crate) struct NameParseState {
    visited: VisitedStorage,
    epoch: u32,
    pointer_hops: usize,
}

impl NameParseState {
    pub(crate) fn new(message_len: usize) -> Self {
        Self {
            visited: VisitedStorage::new(message_len),
            epoch: 0,
            pointer_hops: 0,
        }
    }

    fn begin_name(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        if self.epoch == 0 {
            self.visited.fill(0);
            self.epoch = 1;
        }
        self.pointer_hops = 0;
    }

    fn visit_pointer(&mut self, target: usize, cursor: usize) -> Result<(), QueryError> {
        if target >= cursor {
            return Err(QueryError::MalformedName);
        }
        self.pointer_hops += 1;
        if self.pointer_hops > MAX_POINTER_HOPS {
            return Err(QueryError::MalformedName);
        }
        let mark = self
            .visited
            .get_mut(target)
            .ok_or(QueryError::MalformedName)?;
        if *mark == self.epoch {
            return Err(QueryError::MalformedName);
        }
        *mark = self.epoch;
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct ResourceRecord {
    pub(super) name: DnsName,
    pub(super) rtype: u16,
    pub(super) class: u16,
    pub(super) ttl: u32,
    pub(super) rdata: Range<usize>,
    pub(super) end: usize,
}

pub(super) fn parse_rr(
    raw: &[u8],
    start: usize,
    state: &mut NameParseState,
) -> Result<ResourceRecord, QueryError> {
    let (name, name_end) = parse_name(raw, start, state)?;
    let rtype = read_u16(raw, name_end)?;
    let class = read_u16(raw, name_end + 2)?;
    let ttl = read_u32(raw, name_end + 4)?;
    let rdlength = usize::from(read_u16(raw, name_end + 8)?);
    let rdata_start = name_end + 10;
    let end = rdata_start
        .checked_add(rdlength)
        .filter(|end| *end <= raw.len())
        .ok_or(QueryError::TruncatedField)?;
    Ok(ResourceRecord {
        name,
        rtype,
        class,
        ttl,
        rdata: rdata_start..end,
        end,
    })
}

pub(super) fn parse_edns(raw: &[u8], rr: &ResourceRecord) -> Result<EdnsMetadata, QueryError> {
    let mut cursor = rr.rdata.start;
    let mut option_codes = Vec::new();
    while cursor < rr.rdata.end {
        let code = read_u16(raw, cursor).map_err(|_| QueryError::MalformedEdnsOption)?;
        let len =
            usize::from(read_u16(raw, cursor + 2).map_err(|_| QueryError::MalformedEdnsOption)?);
        cursor = cursor
            .checked_add(4 + len)
            .filter(|end| *end <= rr.rdata.end)
            .ok_or(QueryError::MalformedEdnsOption)?;
        option_codes.push(code);
    }
    if rr.name.0.as_ref() != [0] {
        return Err(QueryError::MalformedName);
    }
    let flags = u16::try_from(rr.ttl & 0xffff).map_err(|_| QueryError::TruncatedField)?;
    Ok(EdnsMetadata {
        advertised_size: rr.class,
        extended_rcode: u8::try_from(rr.ttl >> 24).map_err(|_| QueryError::TruncatedField)?,
        version: u8::try_from((rr.ttl >> 16) & 0xff).map_err(|_| QueryError::TruncatedField)?,
        dnssec_ok: flags & 0x8000 != 0,
        option_codes,
        flags,
    })
}

pub(crate) fn parse_name(
    raw: &[u8],
    start: usize,
    state: &mut NameParseState,
) -> Result<(DnsName, usize), QueryError> {
    let mut wire = Vec::with_capacity(64);
    let name_end = walk_name(raw, start, state, |bytes| {
        wire.extend_from_slice(bytes);
        Ok(())
    })?;
    Ok((DnsName(wire.into_boxed_slice()), name_end))
}

pub(crate) fn skip_name(
    raw: &[u8],
    start: usize,
    state: &mut NameParseState,
) -> Result<usize, QueryError> {
    walk_name(raw, start, state, |_| Ok(()))
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
    let end = walk_name(raw, start, state, |bytes| {
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
where F: FnMut(&[u8]) -> Result<(), QueryError>,
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
        sink(&[octet])?;
        total_len += 1;
        if total_len > 255 {
            return Err(QueryError::MalformedName);
        }
        cursor += 1;
        if octet == 0 {
            return Ok(end.unwrap_or(cursor));
        }
        let label_end = cursor
            .checked_add(usize::from(octet))
            .filter(|label_end| *label_end <= raw.len())
            .ok_or(QueryError::MalformedName)?;
        sink(&raw[cursor..label_end])?;
        total_len += usize::from(octet);
        if total_len > 255 {
            return Err(QueryError::MalformedName);
        }
        cursor = label_end;
    }
}

pub(super) fn read_u16(raw: &[u8], offset: usize) -> Result<u16, QueryError> {
    let bytes = raw
        .get(offset..offset + 2)
        .ok_or(QueryError::TruncatedField)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(raw: &[u8], offset: usize) -> Result<u32, QueryError> {
    let bytes = raw
        .get(offset..offset + 4)
        .ok_or(QueryError::TruncatedField)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
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
            let (decoded, end) = parse_name(&wire, start, &mut state).unwrap();
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
            let domain = ["x".repeat(63), "x".repeat(63), "x".repeat(63), "x".repeat(last_len)].join(".");
            let expected = DnsName::from_domain(&domain).unwrap();
            let wire = expected.as_wire();
            let mut state = NameParseState::new(wire.len());
            assert_eq!(match_name(wire, 0, &mut state, &expected).is_ok(), valid);
            assert_eq!(parse_name(wire, 0, &mut state).is_ok(), valid);
        }
    }

    #[test]
    fn large_messages_allocate_pointer_marks_only_when_needed() {
        let mut wire = vec![0; 65535];
        let start = wire.len() - 2;
        let mut state = NameParseState::new(wire.len());
        assert_eq!(skip_name(&wire, 0, &mut state).unwrap(), 1);
        assert!(matches!(&state.visited, VisitedStorage::Heap { marks: None, .. }));
        // Exercise the largest encodable target, including epoch rollover.
        wire[start..].copy_from_slice(&[0xff, 0xff]);
        assert_eq!(skip_name(&wire, start, &mut state).unwrap(), wire.len());
        match &state.visited {
            VisitedStorage::Heap { marks: Some(marks), .. } => assert_eq!(marks.len(), MAX_POINTER_TARGETS),
            _ => panic!("compression must allocate pointer marks"),
        }
        state.epoch = u32::MAX;
        assert_eq!(skip_name(&wire, start, &mut state).unwrap(), wire.len());
        // A maximum-offset target beyond a smaller message remains invalid.
        let mut shorter = vec![0; 1024];
        shorter[1022..].copy_from_slice(&[0xff, 0xff]);
        assert!(skip_name(&shorter, 1022, &mut NameParseState::new(shorter.len())).is_err());
    }
}
