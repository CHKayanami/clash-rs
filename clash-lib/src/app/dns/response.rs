use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;
use std::sync::Arc;

use bytes::Bytes;
use thiserror::Error;

use super::query::{
    IngressProfile, NameParseState, QType, QueryContext, TxId, match_name, skip_name,
};

const HEADER_LEN: usize = 12;
const MIN_RECORD_WIRE_LEN: usize = 11;
const QR: u16 = 0x8000;
const TC: u16 = 0x0200;
const OPCODE_MASK: u16 = 0x7800;
const RA: u16 = 0x0080;
const QUERY_ECHO_MASK: u16 = OPCODE_MASK | 0x0110;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResponseError {
    #[error("DNS response is shorter than its header")]
    HeaderTruncated,
    #[error("DNS response has QR clear")]
    QueryMessage,
    #[error("DNS response opcode does not match the request")]
    OpcodeMismatch,
    #[error("DNS response question does not match the request")]
    QuestionMismatch,
    #[error("DNS response contains a malformed record")]
    MalformedRecord,
    #[error("DNS response has trailing bytes")]
    TrailingBytes,
    #[error("truncated response is incompatible with the request ingress profile")]
    IncompatibleProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Answer,
    Authority,
    Additional,
}

#[derive(Debug, Clone)]
struct RecordBoundary {
    section: Section,
    wire: Range<usize>,
    // Zero denotes OPT, whose EDNS state must never be rewritten as a TTL.
    ttl_offset: usize,
}

#[derive(Debug)]
pub(crate) struct ResponseMetadata {
    pub cache_ttl: Option<u32>,
    pub negative: bool,
}

#[cfg(test)]
impl ResponseMetadata {
    pub fn parse(wire: &[u8]) -> Option<Self> {
        Some(validate_layout(None, wire).ok()?.metadata)
    }
}

struct ValidatedLayout {
    question_end: usize,
    records: Vec<RecordBoundary>,
    answer_records: Vec<usize>,
    metadata: ResponseMetadata,
    answer_ttl: Option<u32>,
    negative_ttl: Option<u32>,
    max_answer_ttl: u32,
    max_other_ttl: u32,
}

impl ValidatedLayout {
    fn needs_ttl_rewrite(&self, ttl: u32) -> bool {
        self.answer_ttl.is_some_and(|minimum| minimum != ttl || self.max_answer_ttl != ttl)
            || self.max_other_ttl > ttl
    }
}

pub(crate) struct RenderedResponse {
    pub wire: Vec<u8>,
    pub answer_ips: Arc<[IpAddr]>,
}

impl RenderedResponse {
    pub(crate) fn empty(wire: Vec<u8>) -> Self {
        Self { wire, answer_ips: Arc::from([]) }
    }
}

#[derive(Debug, Clone)]
pub struct ResponseTemplate {
    domain: Arc<str>,
    qtype: QType,
    wire: Bytes,
    question_end: usize,
    records: Vec<RecordBoundary>,
    answer_ips: Arc<[IpAddr]>,
    // Retain only the rendered response TTL needed by singleflight followers.
    cache_ttl: Option<u32>,
    answer_ip_ends: Vec<usize>,
}

impl ResponseTemplate {
    pub fn validate(request: &QueryContext, response: &[u8]) -> Result<Self, ResponseError> {
        let layout = validate_layout(Some(request), response)?;
        Ok(Self::from_layout(request, Bytes::copy_from_slice(response), layout))
    }

    fn from_layout(request: &QueryContext, wire: Bytes, layout: ValidatedLayout) -> Self {
        let answer_ips = decode_answer_ips(&wire, &layout);
        let cache_ttl = layout.metadata.cache_ttl;
        // Reuse the index buffer as record ends for UDP prefix selection.
        let mut answer_ip_ends = layout.answer_records;
        for index in &mut answer_ip_ends {
            *index = layout.records[*index].wire.end;
        }
        let domain = request
            .qdomain_arc()
            .unwrap_or_else(|| Arc::from(""));
        let qtype = request.qtype().unwrap_or(QType::A);
        Self {
            domain,
            qtype,
            wire,
            question_end: layout.question_end,
            records: layout.records,
            answer_ips,
            cache_ttl,
            answer_ip_ends,
        }
    }

    pub(crate) fn answer_ips(&self) -> Arc<[IpAddr]> {
        Arc::clone(&self.answer_ips)
    }

    pub(crate) fn cache_ttl(&self) -> Option<u32> {
        self.cache_ttl
    }

    /// Rewrite the original response through validated offsets before freezing
    /// the template. No record names or RDATA are parsed again.
    pub(crate) fn validate_with_ttl<F>(
        request: &QueryContext,
        wire: &mut [u8],
        effective_ttl: F,
    ) -> Result<(Self, bool, u32), ResponseError>
    where F: FnOnce(&ResponseMetadata) -> u32,
    {
        let mut layout = validate_layout(Some(request), wire)?;
        let ttl = effective_ttl(&layout.metadata);
        if layout.metadata.cache_ttl.is_some() && layout.needs_ttl_rewrite(ttl) {
            patch_ttls(wire, &layout.records, ttl)?;
            layout.metadata.cache_ttl = if layout.metadata.negative {
                layout.negative_ttl.map(|old| old.min(ttl))
            } else {
                Some(ttl)
            };
        }
        // Only the negative flag is needed by the caller's retention policy.
        // All SOA and rewrite statistics are discarded with the layout.
        let negative = layout.metadata.negative;
        let template = Self::from_layout(request, Bytes::copy_from_slice(wire), layout);
        Ok((template, negative, ttl))
    }

    pub(crate) fn render_with_ips(&self, caller: &QueryContext) -> Result<RenderedResponse, ResponseError> {
        let wire = self.render(caller)?;
        let answer_ips = self.visible_answer_ips(wire.len());
        Ok(RenderedResponse { wire, answer_ips })
    }

    fn visible_answer_ips(&self, wire_len: usize) -> Arc<[IpAddr]> {
        let visible = self.answer_ip_ends.partition_point(|end| *end <= wire_len);
        if visible == self.answer_ips.len() {
            Arc::clone(&self.answer_ips)
        } else {
            Arc::from(&self.answer_ips[..visible])
        }
    }

    /// Patch only validated TTL offsets and reuse decoded answer IPs. UDP
    /// rendering emits a prefix of whole records, so record ends identify
    /// exactly which cached addresses remain visible in the rendered wire.
    pub(crate) fn render_cached(
        &self,
        caller: &QueryContext,
        ttl: u32,
    ) -> Result<RenderedResponse, ResponseError> {
        let mut wire = self.render(caller)?;
        patch_ttls(&mut wire, &self.records, ttl)?;
        let answer_ips = self.visible_answer_ips(wire.len());
        Ok(RenderedResponse { wire, answer_ips })
    }

    pub fn render(&self, caller: &QueryContext) -> Result<Vec<u8>, ResponseError> {
        if caller.qdomain() != Some(&self.domain) || caller.qtype() != Some(self.qtype) {
            return Err(ResponseError::QuestionMismatch);
        }
        match caller.ingress() {
            IngressProfile::Udp { advertised_size } => {
                self.render_udp(caller, usize::from(advertised_size))
            }
            IngressProfile::Tcp | IngressProfile::Api | IngressProfile::Internal => {
                self.render_full(caller)
            }
        }
    }

    fn render_full(&self, caller: &QueryContext) -> Result<Vec<u8>, ResponseError> {
        let mut response = self.wire.to_vec();
        set_txid(&mut response, caller.txid())?;
        if let Some(qw) = caller.question_wire() {
            if 12 + qw.len() == self.question_end && response.len() >= self.question_end {
                response[12..self.question_end].copy_from_slice(qw);
            }
        }
        Ok(response)
    }

    fn render_udp(&self, caller: &QueryContext, limit: usize) -> Result<Vec<u8>, ResponseError> {
        if self.wire.len() <= limit {
            return self.render_full(caller);
        }
        let prefix = self
            .wire
            .get(..self.question_end)
            .ok_or(ResponseError::MalformedRecord)?;
        let mut response = Vec::with_capacity(limit.max(prefix.len()));
        response.extend_from_slice(prefix);
        if let Some(qw) = caller.question_wire() {
            if 12 + qw.len() == self.question_end && response.len() >= self.question_end {
                response[12..self.question_end].copy_from_slice(qw);
            }
        }
        let mut counts = [0u16; 3];
        for record in &self.records {
            let record_wire = self
                .wire
                .get(record.wire.clone())
                .ok_or(ResponseError::MalformedRecord)?;
            if response.len().saturating_add(record_wire.len()) > limit {
                break;
            }
            response.extend_from_slice(record_wire);
            let index = match record.section {
                Section::Answer => 0,
                Section::Authority => 1,
                Section::Additional => 2,
            };
            counts[index] = counts[index].saturating_add(1);
        }
        set_txid(&mut response, caller.txid())?;
        let flags = read_u16(&response, 2)? | TC;
        write_u16(&mut response, 2, flags)?;
        write_u16(&mut response, 6, counts[0])?;
        write_u16(&mut response, 8, counts[1])?;
        write_u16(&mut response, 10, counts[2])?;
        Ok(response)
    }
}

fn decode_answer_ips(wire: &[u8], layout: &ValidatedLayout) -> Arc<[IpAddr]> {
    // SliceIter::map has a trusted exact length: Arc collects directly into
    // its final allocation, without an intermediate Vec<IpAddr>.
    layout.answer_records.iter().map(|index| {
        let record = &layout.records[*index];
        let data = &wire[record.ttl_offset + 6..record.wire.end];
        // Only correctly sized Answer A/AAAA records enter this index list.
        // The immutable wire keeps the validated bounds valid.
        if data.len() == 4 {
            let mut octets = [0; 4];
            octets.copy_from_slice(data);
            IpAddr::V4(Ipv4Addr::from(octets))
        } else {
            let mut octets = [0; 16];
            octets.copy_from_slice(data);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }).collect()
}

fn patch_ttls(wire: &mut [u8], records: &[RecordBoundary], ttl: u32) -> Result<(), ResponseError> {
    for record in records {
        if record.wire.end > wire.len() { break; }
        if record.ttl_offset == 0 { continue; }
        let field = wire.get_mut(record.ttl_offset..record.ttl_offset + 4)
            .ok_or(ResponseError::MalformedRecord)?;
        let new_ttl = match record.section {
            Section::Answer => ttl,
            Section::Authority | Section::Additional => {
                let old_ttl = u32::from_be_bytes(field.try_into().map_err(|_| ResponseError::MalformedRecord)?);
                old_ttl.min(ttl)
            }
        };
        field.copy_from_slice(&new_ttl.to_be_bytes());
    }
    Ok(())
}

fn validate_layout(
    request: Option<&QueryContext>,
    response: &[u8],
) -> Result<ValidatedLayout, ResponseError> {
    let header = response.get(..HEADER_LEN).ok_or(ResponseError::HeaderTruncated)?;
    let flags = u16::from_be_bytes([header[2], header[3]]);
    if flags & QR == 0 {
        return Err(ResponseError::QueryMessage);
    }
    let qdcount = u16::from_be_bytes([header[4], header[5]]);
    if let Some(request) = request {
        if flags & OPCODE_MASK != request.flags() & OPCODE_MASK {
            return Err(ResponseError::OpcodeMismatch);
        }
        if flags & TC != 0 && !matches!(request.ingress(), IngressProfile::Udp { .. }) {
            return Err(ResponseError::IncompatibleProfile);
        }
        if usize::from(qdcount) != request.questions().len() {
            return Err(ResponseError::QuestionMismatch);
        }
    }
    let mut name_state = NameParseState::new(response.len());
    let mut cursor = HEADER_LEN;
    let mut requested_type = None;
    let mut expected = request.map(|request| request.questions());
    for _ in 0..qdcount {
        let expected_question = if let Some(expected) = expected.as_mut() {
            Some(expected.next().ok_or(ResponseError::QuestionMismatch)?)
        } else {
            None
        };
        let name_end = if let Some((name, _, _)) = expected_question {
            match_name(response, cursor, &mut name_state, name)
                .map_err(|_| ResponseError::QuestionMismatch)?
        } else {
            skip_name(response, cursor, &mut name_state).map_err(|_| ResponseError::QuestionMismatch)?
        };
        let fields = response.get(name_end..name_end + 4).ok_or(ResponseError::MalformedRecord)?;
        let qtype = u16::from_be_bytes([fields[0], fields[1]]);
        let qclass = u16::from_be_bytes([fields[2], fields[3]]);
        if let Some((_, expected_type, expected_class)) = expected_question {
            if qtype != expected_type.get() || qclass != expected_class.get() {
                return Err(ResponseError::QuestionMismatch);
            }
        }
        requested_type.get_or_insert(qtype);
        cursor = name_end + 4;
    }
    let question_end = cursor;
    let sections = [
        (Section::Answer, u16::from_be_bytes([header[6], header[7]])),
        (Section::Authority, u16::from_be_bytes([header[8], header[9]])),
        (Section::Additional, u16::from_be_bytes([header[10], header[11]])),
    ];
    let total_records = usize::from(sections[0].1)
        + usize::from(sections[1].1)
        + usize::from(sections[2].1);
    // Do not allocate metadata from counts that cannot fit in the packet.
    if total_records > response.len().saturating_sub(question_end) / MIN_RECORD_WIRE_LEN {
        return Err(ResponseError::MalformedRecord);
    }
    let mut records = Vec::with_capacity(total_records);
    let mut answer_records = Vec::new();
    let mut rcode = flags & 0xf;
    let mut has_requested_answer = false;
    let mut answer_ttl = None;
    let mut max_answer_ttl = 0;
    let mut max_other_ttl = 0;
    let mut negative_ttl = None;
    for (section, count) in sections {
        for _ in 0..count {
            let start = cursor;
            let fields = skip_name(response, cursor, &mut name_state)
                .map_err(|_| ResponseError::MalformedRecord)?;
            let data_start = fields + 10;
            let record = response.get(fields..data_start).ok_or(ResponseError::MalformedRecord)?;
            let rtype = u16::from_be_bytes([record[0], record[1]]);
            let ttl = u32::from_be_bytes([record[4], record[5], record[6], record[7]]);
            let length = usize::from(u16::from_be_bytes([record[8], record[9]]));
            let end = data_start.checked_add(length).filter(|end| *end <= response.len())
                .ok_or(ResponseError::MalformedRecord)?;
            cursor = end;
            let ttl_offset = if rtype == 41 { 0 } else { fields + 4 };
            if rtype == 41 {
                if section != Section::Additional { return Err(ResponseError::MalformedRecord); }
                rcode |= u16::from(record[4]) << 4;
            } else if section == Section::Answer {
                has_requested_answer |= requested_type == Some(rtype) || requested_type == Some(255);
                answer_ttl = Some(answer_ttl.map_or(ttl, |old: u32| old.min(ttl)));
                max_answer_ttl = max_answer_ttl.max(ttl);
                if rcode == 0 && (rtype == 1 || rtype == 28) {
                    if length != if rtype == 1 { 4 } else { 16 } {
                        return Err(ResponseError::MalformedRecord);
                    }
                    answer_records.push(records.len());
                }
            } else {
                max_other_ttl = max_other_ttl.max(ttl);
                if section == Section::Authority && rtype == 6 {
                    let minimum = soa_minimum(response, data_start..end, &mut name_state)
                        .ok_or(ResponseError::MalformedRecord)?;
                    let ttl = ttl.min(minimum);
                    negative_ttl = Some(negative_ttl.map_or(ttl, |old: u32| old.min(ttl)));
                }
            }
            records.push(RecordBoundary {
                section,
                wire: start..cursor,
                ttl_offset,
            });
        }
    }
    if cursor != response.len() {
        return Err(ResponseError::TrailingBytes);
    }
    if rcode != 0 {
        answer_records.clear();
    }
    let negative = rcode == 3 || (rcode == 0 && !has_requested_answer);
    let cache_ttl = if (rcode != 0 && rcode != 3) || flags & TC != 0 {
        None
    } else if negative {
        negative_ttl.map(|ttl| answer_ttl.map_or(ttl, |answer| answer.min(ttl)))
    } else {
        answer_ttl
    };
    let metadata = ResponseMetadata { cache_ttl, negative };
    Ok(ValidatedLayout { question_end, records, answer_records, metadata,
        answer_ttl, negative_ttl, max_answer_ttl, max_other_ttl })
}

fn soa_minimum(wire: &[u8], rdata: Range<usize>, state: &mut NameParseState) -> Option<u32> {
    let values_start = rdata.end.checked_sub(20)?;
    if values_start < rdata.start { return None; }
    let mname_end = skip_name(wire, rdata.start, state).ok()?;
    if mname_end >= values_start { return None; }
    let names_end = skip_name(wire, mname_end, state).ok()?;
    if names_end != values_start { return None; }
    let minimum = wire.get(rdata.end - 4..rdata.end)?;
    Some(u32::from_be_bytes(minimum.try_into().ok()?))
}

pub fn set_txid(response: &mut [u8], txid: TxId) -> Result<(), ResponseError> {
    write_u16(response, 0, txid.get())
}

pub fn read_u16(response: &[u8], offset: usize) -> Result<u16, ResponseError> {
    let bytes = response
        .get(offset..offset + 2)
        .ok_or(ResponseError::MalformedRecord)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub fn write_u16(response: &mut [u8], offset: usize, value: u16) -> Result<(), ResponseError> {
    response
        .get_mut(offset..offset + 2)
        .ok_or(ResponseError::MalformedRecord)?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

pub fn dns_error_flags(query: &[u8], rcode: u8) -> u16 {
    let request_flags = query
        .get(2..4)
        .map(|flags| u16::from_be_bytes([flags[0], flags[1]]))
        .unwrap_or(0x0100);
    QR | RA | (request_flags & QUERY_ECHO_MASK) | u16::from(rcode & 0x0f)
}

/// Build a minimal DNS error response while preserving the request payload (including EDNS0 OPT records).
pub fn build_dns_error_response(query: &[u8], rcode: u8) -> Vec<u8> {
    if query.len() < HEADER_LEN {
        return vec![0u8; HEADER_LEN];
    }
    let mut response = query.to_vec();
    response[2..4].copy_from_slice(&dns_error_flags(query, rcode).to_be_bytes());
    response
}

pub fn build_dns_nxdomain(query: &[u8]) -> Vec<u8> {
    build_dns_error_response(query, 3)
}

pub fn build_dns_nodata(query: &[u8]) -> Vec<u8> {
    build_dns_error_response(query, 0)
}

pub fn build_dns_servfail(query: &[u8]) -> Vec<u8> {
    build_dns_error_response(query, 2)
}

pub fn build_dns_refused(query: &[u8]) -> Vec<u8> {
    build_dns_error_response(query, 5)
}

/// Build a synthetic DNS answer for given IP addresses (e.g. for Fake-IP, Hosts).
pub fn build_dns_ip_response(query: &[u8], ips: &[IpAddr], ttl: u32) -> Option<Vec<u8>> {
    if query.len() < HEADER_LEN {
        return None;
    }
    let mut response = Vec::with_capacity(query.len() + ips.len() * 20);
    // Find the end of the question section
    let qdcount = u16::from_be_bytes([query[4], query[5]]) as usize;
    if qdcount == 0 {
        return None;
    }
    let mut pos = HEADER_LEN;
    for _ in 0..qdcount {
        if !crate::app::dns::wire::skip_dns_name(query, &mut pos) {
            return None;
        }
        pos += 4; // QTYPE + QCLASS
        if pos > query.len() {
            return None;
        }
    }
    let question_end = pos;

    // Header & Question
    response.extend_from_slice(&query[..question_end]);

    // Flags: QR=1, RA=1, preserve RD & Opcode, RCode=0 (NoError)
    let flags = dns_error_flags(query, 0);
    response[2..4].copy_from_slice(&flags.to_be_bytes());
    // Set ANCOUNT
    let ancount = ips.len() as u16;
    response[6..8].copy_from_slice(&ancount.to_be_bytes());
    // Zero NSCOUNT, ARCOUNT
    response[8..12].copy_from_slice(&[0; 4]);

    // Append answer RRs with compression pointer to offset 12 (first QNAME)
    for ip in ips {
        response.extend_from_slice(&[0xC0, 0x0C]); // Pointer to question name
        match ip {
            IpAddr::V4(v4) => {
                response.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
                response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                response.extend_from_slice(&ttl.to_be_bytes());
                response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH 4
                response.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                response.extend_from_slice(&28u16.to_be_bytes()); // TYPE AAAA
                response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                response.extend_from_slice(&ttl.to_be_bytes());
                response.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH 16
                response.extend_from_slice(&v6.octets());
            }
        }
    }

    Some(response)
}

#[cfg(test)]
#[path = "response_tests.rs"]
mod tests;
