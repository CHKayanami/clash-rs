use std::fmt::{self, Display};
use std::sync::{Arc, OnceLock};

use bytes::Bytes;

use thiserror::Error;

mod parser;

pub(crate) use parser::{NameParseState, match_name, skip_name};
use parser::{DomainBuilder, parse_edns, parse_name, parse_rr};

const HEADER_LEN: usize = 12;
const MIN_QUESTION_WIRE_LEN: usize = 5;
const OPT_TYPE: u16 = 41;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxId(u16);

impl TxId {
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QType(u16);

impl QType {
    pub const A: Self = Self(1);
    pub const NS: Self = Self(2);
    pub const CNAME: Self = Self(5);
    pub const SOA: Self = Self(6);
    pub const PTR: Self = Self(12);
    pub const MX: Self = Self(15);
    pub const TXT: Self = Self(16);
    pub const AAAA: Self = Self(28);
    pub const SRV: Self = Self(33);
    pub const SVCB: Self = Self(64);
    pub const HTTPS: Self = Self(65);
    pub const ANY: Self = Self(255);

    pub const fn get(self) -> u16 {
        self.0
    }
}

impl std::fmt::Display for QType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::A => write!(f, "A"),
            Self::NS => write!(f, "NS"),
            Self::CNAME => write!(f, "CNAME"),
            Self::SOA => write!(f, "SOA"),
            Self::PTR => write!(f, "PTR"),
            Self::MX => write!(f, "MX"),
            Self::TXT => write!(f, "TXT"),
            Self::AAAA => write!(f, "AAAA"),
            Self::SRV => write!(f, "SRV"),
            Self::SVCB => write!(f, "SVCB"),
            Self::HTTPS => write!(f, "HTTPS"),
            Self::ANY => write!(f, "ANY"),
            other => write!(f, "TYPE{}", other.0),
        }
    }
}

impl std::str::FromStr for QType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if let Ok(num) = trimmed.parse::<u16>() {
            return Ok(Self(num));
        }
        if let Some(rest) = trimmed
            .strip_prefix("TYPE")
            .or_else(|| trimmed.strip_prefix("type"))
        {
            if let Ok(num) = rest.parse::<u16>() {
                return Ok(Self(num));
            }
        }
        match trimmed.to_ascii_uppercase().as_str() {
            "A" => Ok(Self::A),
            "NS" => Ok(Self::NS),
            "CNAME" => Ok(Self::CNAME),
            "SOA" => Ok(Self::SOA),
            "PTR" => Ok(Self::PTR),
            "MX" => Ok(Self::MX),
            "TXT" => Ok(Self::TXT),
            "AAAA" => Ok(Self::AAAA),
            "SRV" => Ok(Self::SRV),
            "SVCB" => Ok(Self::SVCB),
            "HTTPS" => Ok(Self::HTTPS),
            "ANY" => Ok(Self::ANY),
            _ => Err(format!("unknown DNS QType: '{s}'")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QClass(u16);

impl QClass {
    pub const IN: Self = Self(1);

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsName(Bytes);

impl DnsName {
    pub fn from_domain(domain: &str) -> Option<Self> {
        let domain = domain.trim_end_matches('.');
        let mut wire = Vec::with_capacity(domain.len().min(253) + 2);
        if domain.is_empty() {
            wire.push(0);
            return Some(Self(Bytes::from(wire)));
        }
        for label in domain.split('.') {
            if label.is_empty() || label.len() > 63
                || wire.len() + label.len() + 2 > 255
            {
                return None;
            }
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0);
        Some(Self(Bytes::from(wire)))
    }

    pub fn as_wire(&self) -> &[u8] {
        &self.0
    }

    fn domain(&self) -> Option<Arc<str>> {
        let mut domain = DomainBuilder::new();
        let mut cursor = 0;
        loop {
            let length = usize::from(*self.0.get(cursor)?);
            cursor += 1;
            if length == 0 {
                if cursor != self.0.len() { return None; }
                return domain.finish();
            }
            let end = cursor.checked_add(length)?;
            domain.push_label(self.0.get(cursor..end)?);
            cursor = end;
        }
    }
}

/// Pre-allocates and builds a standard DNS query wire packet with randomized TxID.
pub fn build_dns_query_wire(name: &DnsName, qtype: QType) -> Vec<u8> {
    build_dns_query_wire_with_id(rand::random::<u16>(), name, qtype)
}

/// Builds a standard DNS query wire packet with a specific TxID.
pub fn build_dns_query_wire_with_id(
    tx_id: u16,
    name: &DnsName,
    qtype: QType,
) -> Vec<u8> {
    let wire_name = name.as_wire();
    let mut buf = Vec::with_capacity(12 + wire_name.len() + 4);
    buf.extend_from_slice(&tx_id.to_be_bytes());
    buf.extend_from_slice(&[
        0x01, 0x00, // Flags: RD = 1 (Recursion Desired)
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
    ]);
    buf.extend_from_slice(wire_name);
    buf.extend_from_slice(&qtype.get().to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN = 1
    buf
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IngressProfile {
    Udp {
        advertised_size: u16,
    },
    Tcp,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QuestionOffsets {
    start: u32,
    end: u32,
}

impl QuestionOffsets {
    const fn start(self) -> usize {
        self.start as usize
    }

    const fn end(self) -> usize {
        self.end as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Question {
    name: DnsName,
    qtype: QType,
    qclass: QClass,
    offsets: QuestionOffsets,
}

#[derive(Debug)]
struct QueryPacket {
    wire: Bytes,
    canonical_wire: OnceLock<Arc<[u8]>>,
}

#[derive(Debug)]
struct QueryData {
    txid: TxId,
    flags: u16,
    questions: Vec<Question>,
    cached_domain: Option<Arc<str>>,
    packet: QueryPacket,
}

#[derive(Debug, Clone)]
pub struct QueryContext {
    data: Arc<QueryData>,
    // ECS keeps the parsed questions shared, but owns its modified packet and
    // canonical key. Ordinary queries need only the single QueryData allocation.
    packet_override: Option<Arc<QueryPacket>>,
    ingress: IngressProfile,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QueryError {
    #[error("DNS message is shorter than its header")]
    HeaderTruncated,
    #[error("DNS message contains a malformed name")]
    MalformedName,
    #[error("DNS message contains a truncated field")]
    TruncatedField,
    #[error("DNS message contains a malformed EDNS option")]
    MalformedEdnsOption,
    #[error("DNS message has trailing bytes")]
    TrailingBytes,
}

impl QueryContext {
    pub fn parse(wire: Bytes, mut ingress: IngressProfile) -> Result<Self, QueryError> {
        let raw = wire.as_ref();
        if raw.len() < HEADER_LEN {
            return Err(QueryError::HeaderTruncated);
        }
        let txid = TxId(u16::from_be_bytes([raw[0], raw[1]]));
        let flags = u16::from_be_bytes([raw[2], raw[3]]);
        let qdcount = u16::from_be_bytes([raw[4], raw[5]]);
        let ancount = u16::from_be_bytes([raw[6], raw[7]]);
        let nscount = u16::from_be_bytes([raw[8], raw[9]]);
        let arcount = u16::from_be_bytes([raw[10], raw[11]]);
        let mut cursor = HEADER_LEN;
        if usize::from(qdcount) > (raw.len() - HEADER_LEN) / MIN_QUESTION_WIRE_LEN {
            return Err(QueryError::TruncatedField);
        }
        let mut name_state = NameParseState::new(raw.len());
        let mut questions = Vec::with_capacity(usize::from(qdcount));
        let mut cached_domain = None;
        for index in 0..qdcount {
            let start = cursor;
            let (name, end, domain) = parse_name(&wire, cursor, &mut name_state, index == 0)?;
            if index == 0 { cached_domain = domain; }
            cursor = end;
            let fields = raw.get(cursor..cursor + 4)
                .ok_or(QueryError::TruncatedField)?;
            let qtype = QType(u16::from_be_bytes([fields[0], fields[1]]));
            let qclass = QClass(u16::from_be_bytes([fields[2], fields[3]]));
            cursor += 4;
            questions.push(Question {
                name,
                qtype,
                qclass,
                offsets: QuestionOffsets {
                    start: u32::try_from(start)
                        .map_err(|_| QueryError::TruncatedField)?,
                    end: u32::try_from(cursor)
                        .map_err(|_| QueryError::TruncatedField)?,
                },
            });
        }
        for _ in 0..ancount {
            cursor = parse_rr(raw, cursor, &mut name_state)?.end;
        }
        for _ in 0..nscount {
            cursor = parse_rr(raw, cursor, &mut name_state)?.end;
        }
        let mut advertised_size = None;
        for _ in 0..arcount {
            let rr = parse_rr(raw, cursor, &mut name_state)?;
            cursor = rr.end;
            if rr.rtype == OPT_TYPE {
                let size = parse_edns(raw, &rr)?;
                advertised_size.get_or_insert(size);
            }
        }
        if cursor != raw.len() {
            return Err(QueryError::TrailingBytes);
        }
        if let IngressProfile::Udp { advertised_size: default_size } = ingress {
            ingress = IngressProfile::Udp {
                advertised_size: advertised_size
                    .map(|size| size.max(512)).unwrap_or(default_size),
            };
        }
        Ok(Self {
            data: Arc::new(QueryData {
                txid,
                flags,
                questions,
                cached_domain,
                packet: QueryPacket { wire, canonical_wire: OnceLock::new() },
            }),
            packet_override: None,
            ingress,
        })
    }

    pub fn new(name: DnsName, qtype: QType) -> Self {
        let txid = TxId(rand::random());
        let wire = build_dns_query_wire_with_id(txid.get(), &name, qtype);
        let end = wire.len() as u32;
        let cached_domain = name.domain();
        Self {
            data: Arc::new(QueryData {
                txid,
                flags: 0x0100,
                questions: vec![Question {
                    name, qtype, qclass: QClass::IN,
                    offsets: QuestionOffsets { start: 12, end },
                }],
                cached_domain,
                packet: QueryPacket {
                    wire: Bytes::from(wire), canonical_wire: OnceLock::new(),
                },
            }),
            packet_override: None,
            ingress: IngressProfile::Internal,
        }
    }

    /// ECS rewrites only Additional records and ARCOUNT; all question offsets,
    /// flags and TxID remain valid. The original context keeps its cache key.
    pub(crate) fn with_additional_wire(&self, wire: Bytes) -> Self {
        debug_assert_eq!(&wire[..10], &self.wire()[..10]);
        if let Some(question) = self.question_wire() {
            debug_assert_eq!(&wire[12..12 + question.len()], question);
        }
        let mut query = self.clone();
        query.packet_override = Some(Arc::new(QueryPacket {
            wire, canonical_wire: OnceLock::new(),
        }));
        query
    }

    fn packet(&self) -> &QueryPacket {
        self.packet_override.as_deref().unwrap_or(&self.data.packet)
    }

    pub fn wire(&self) -> &[u8] {
        &self.packet().wire
    }

    pub(crate) fn shared_question_wire(&self) -> Bytes {
        self.question_offsets()
            .map(|offsets| self.packet().wire.slice(offsets.start()..offsets.end()))
            .unwrap_or_default()
    }

    pub(crate) fn logged_qtype(&self) -> impl Display {
        LoggedQType(self.qtype())
    }

    pub fn txid(&self) -> TxId {
        self.data.txid
    }

    pub fn qdomain(&self) -> Option<&str> {
        self.data.cached_domain.as_deref()
    }

    pub fn qdomain_arc(&self) -> Option<Arc<str>> {
        self.data.cached_domain.clone()
    }

    pub fn qtype(&self) -> Option<QType> {
        self.data.questions.first().map(|question| question.qtype)
    }

    fn question_offsets(&self) -> Option<QuestionOffsets> {
        self.data.questions.first().map(|question| question.offsets)
    }

    pub fn question_wire(&self) -> Option<&[u8]> {
        let start = self.data.questions.first()?.offsets.start();
        let end = self.data.questions.last()?.offsets.end();
        self.wire().get(start..end)
    }

    pub const fn ingress(&self) -> IngressProfile {
        self.ingress
    }

    pub(crate) fn canonical_wire_arc(&self) -> Arc<[u8]> {
        Arc::clone(self.packet().canonical_wire.get_or_init(|| {
            let mut wire = self.wire().to_vec();
            wire[..2].fill(0);
            wire.into()
        }))
    }

    pub fn flags(&self) -> u16 {
        self.data.flags
    }

    pub fn questions(
        &self,
    ) -> impl ExactSizeIterator<Item = (&DnsName, QType, QClass)> {
        self.data.questions
            .iter()
            .map(|question| (&question.name, question.qtype, question.qclass))
    }
}

struct LoggedQType(Option<QType>);

impl Display for LoggedQType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(qtype) => Display::fmt(&qtype, f),
            None => f.write_str("<unknown>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qtype_from_str_and_display() {
        assert_eq!("A".parse::<QType>().unwrap(), QType::A);
        assert_eq!("a".parse::<QType>().unwrap(), QType::A);
        assert_eq!("AAAA".parse::<QType>().unwrap(), QType::AAAA);
        assert_eq!("aaaa".parse::<QType>().unwrap(), QType::AAAA);
        assert_eq!("HTTPS".parse::<QType>().unwrap(), QType::HTTPS);
        assert_eq!("https".parse::<QType>().unwrap(), QType::HTTPS);
        assert_eq!("svcb".parse::<QType>().unwrap(), QType::SVCB);
        assert_eq!("txt".parse::<QType>().unwrap(), QType::TXT);
        assert_eq!("TXT".parse::<QType>().unwrap(), QType::TXT);
        assert_eq!("any".parse::<QType>().unwrap(), QType::ANY);

        // Numeric string
        assert_eq!("65".parse::<QType>().unwrap(), QType::HTTPS);
        assert_eq!("64".parse::<QType>().unwrap(), QType::SVCB);
        assert_eq!("16".parse::<QType>().unwrap(), QType::TXT);
        assert_eq!("TYPE65".parse::<QType>().unwrap(), QType::HTTPS);
        assert_eq!("type28".parse::<QType>().unwrap(), QType::AAAA);

        // Display
        assert_eq!(QType::A.to_string(), "A");
        assert_eq!(QType::HTTPS.to_string(), "HTTPS");
        assert_eq!(QType(999).to_string(), "TYPE999");

        // Invalid
        assert!("invalid_qtype".parse::<QType>().is_err());
    }

    #[test]
    fn built_context_matches_parsed_context_and_preserves_key() {
        for (domain, qtype) in [("Mixed.Example", QType::AAAA), ("MiXeD.é.Example", QType::TXT), (".", QType::A)] {
            let query = QueryContext::new(DnsName::from_domain(domain).unwrap(), qtype);
            let wire = Bytes::copy_from_slice(query.wire());
            let wire_start = wire.as_ptr();
            let parsed = QueryContext::parse(wire, IngressProfile::Internal).unwrap();
            assert_eq!(parsed.wire().as_ptr(), wire_start);
            assert_eq!(query.txid(), parsed.txid());
            assert_eq!(query.flags(), parsed.flags());
            assert_eq!(query.data.questions, parsed.data.questions);
            assert_eq!(query.qdomain(), parsed.qdomain());
            assert!(query.packet().canonical_wire.get().is_none());
            let key = query.canonical_wire_arc();
            assert_eq!(&key[..2], &[0, 0]);
            assert_eq!(&key[2..], &query.wire()[2..]);
            assert_eq!(key, parsed.canonical_wire_arc());
            let cloned = query.clone();
            assert!(Arc::ptr_eq(&query.data, &cloned.data));
            assert!(Arc::ptr_eq(&key, &cloned.canonical_wire_arc()));
            assert_eq!(query.wire().as_ptr(), cloned.wire().as_ptr());
            assert_eq!(query.shared_question_wire().as_ptr(), query.wire()[12..].as_ptr());
        }
    }

    #[test]
    fn udp_profile_uses_edns_size_and_tcp_keeps_full_response_profile() {
        let query = QueryContext::new(DnsName::from_domain("size.test").unwrap(), QType::A);
        let mut wire = query.wire().to_vec();
        wire[10..12].copy_from_slice(&1_u16.to_be_bytes());
        wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        let udp = QueryContext::parse(Bytes::copy_from_slice(&wire), IngressProfile::Udp { advertised_size: 512 }).unwrap();
        assert_eq!(udp.ingress(), IngressProfile::Udp { advertised_size: 1232 });
        let tcp = QueryContext::parse(Bytes::copy_from_slice(&wire), IngressProfile::Tcp).unwrap();
        assert_eq!(tcp.ingress(), IngressProfile::Tcp);
        let last = wire.len() - 1;
        wire[last] = 1;
        assert_eq!(QueryContext::parse(Bytes::copy_from_slice(&wire), IngressProfile::Tcp).unwrap_err(), QueryError::TruncatedField);
    }

    #[test]
    fn additional_packets_share_metadata_but_keep_independent_keys() {
        let query = QueryContext::new(DnsName::from_domain("ecs.test").unwrap(), QType::A);
        let original_key = query.canonical_wire_arc();
        let mut wire = query.wire().to_vec();
        wire[10..12].copy_from_slice(&1_u16.to_be_bytes());
        wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        let derived = query.with_additional_wire(Bytes::from(wire));
        assert!(Arc::ptr_eq(&query.data, &derived.data));
        assert_eq!(query.qdomain(), derived.qdomain());
        assert_eq!(query.question_wire(), derived.question_wire());
        assert!(Arc::ptr_eq(&original_key, &query.canonical_wire_arc()));
        let derived_key = derived.canonical_wire_arc();
        assert_ne!(original_key, derived_key);
        assert_eq!(&derived_key[2..], &derived.wire()[2..]);
        assert!(Arc::ptr_eq(&derived_key, &derived.clone().canonical_wire_arc()));
    }

    #[test]
    fn generated_names_respect_dns_wire_length_limit() {
        let label = "a".repeat(63);
        assert!(DnsName::from_domain(&format!("{label}.{label}.{label}.{label}")).is_none());
    }

}
