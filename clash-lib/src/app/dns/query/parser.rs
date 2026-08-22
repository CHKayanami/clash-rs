use std::ops::Range;

use super::{DnsName, EdnsMetadata, QueryError};

const MAX_POINTER_HOPS: usize = 128;
const STACK_PARSE_LEN: usize = 512;

enum VisitedStorage {
    Stack([u32; STACK_PARSE_LEN]),
    Heap(Vec<u32>),
}

impl VisitedStorage {
    fn new(len: usize) -> Self {
        if len <= STACK_PARSE_LEN {
            Self::Stack([0; STACK_PARSE_LEN])
        } else {
            Self::Heap(vec![0; len])
        }
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> Option<&mut u32> {
        match self {
            Self::Stack(arr) => arr.get_mut(idx),
            Self::Heap(vec) => vec.get_mut(idx),
        }
    }

    #[inline]
    fn fill(&mut self, val: u32) {
        match self {
            Self::Stack(arr) => arr.fill(val),
            Self::Heap(vec) => vec.fill(val),
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
    state.begin_name();
    let mut cursor = start;
    let mut end = None;
    let mut wire = Vec::new();
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
        wire.push(octet);
        if wire.len() > 255 {
            return Err(QueryError::MalformedName);
        }
        cursor += 1;
        if octet == 0 {
            return Ok((DnsName(wire.into_boxed_slice()), end.unwrap_or(cursor)));
        }
        let label_end = cursor
            .checked_add(usize::from(octet))
            .filter(|label_end| *label_end <= raw.len())
            .ok_or(QueryError::MalformedName)?;
        wire.extend_from_slice(
            raw.get(cursor..label_end)
                .ok_or(QueryError::MalformedName)?,
        );
        if wire.len() > 255 {
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
