use std::ops::Range;

use ipnet::Ipv4Net;
use thiserror::Error;

use super::wire::skip_dns_name;

const ECS_OPTION_CODE: u16 = 8;
const OPT_RECORD_TYPE: u16 = 41;
const DEFAULT_EDNS_PAYLOAD: u16 = 1232;

#[derive(Debug, Error)]
pub enum EcsWireError {
    #[error("malformed DNS message")]
    Malformed,
    #[error("multiple EDNS OPT records")]
    MultipleOpt,
    #[error("EDNS OPT record is not final")]
    NonFinalOpt,
    #[error("unsupported EDNS OPT record")]
    UnsupportedOpt,
    #[error("DNS message is too large for ECS")]
    TooLarge,
    #[error("upstream returned EDNS state that cannot be hidden")]
    UnsupportedResponseOpt,
    #[error("upstream returned mismatched ECS")]
    MismatchedResponse,
}

pub struct EcsQuery {
    wire: Vec<u8>,
    original_had_opt: bool,
    expected: ExpectedEcs,
}

#[derive(Clone, Copy)]
struct ExpectedEcs {
    source_prefix: u8,
    address: [u8; 4],
    address_len: usize,
}

#[derive(Clone)]
struct MessageLayout {
    opt: Option<OptRecord>,
    additional_count: u16,
}

#[derive(Clone)]
struct OptRecord {
    start: usize,
    end: usize,
    rdlength_offset: usize,
    rdata: Range<usize>,
    extended_rcode: u8,
    version: u8,
}

impl EcsQuery {
    pub fn prepare(raw: &[u8], subnet: Ipv4Net) -> Result<Option<Self>, EcsWireError> {
        let layout = message_layout(raw)?;
        let (option, expected) = encode_ecs(subnet);
        let original_had_opt = layout.opt.is_some();
        let wire = if let Some(opt) = layout.opt {
            if opt.end != raw.len() {
                return Err(EcsWireError::NonFinalOpt);
            }
            if opt.version != 0 {
                return Err(EcsWireError::UnsupportedOpt);
            }
            if find_ecs(raw, &opt.rdata)?.is_some() {
                return Ok(None);
            }
            let rdlength = opt.rdata.len();
            let new_rdlength = rdlength
                .checked_add(option.len())
                .and_then(|length| u16::try_from(length).ok())
                .ok_or(EcsWireError::TooLarge)?;
            if raw
                .len()
                .checked_add(option.len())
                .is_none_or(|length| length > u16::MAX as usize)
            {
                return Err(EcsWireError::TooLarge);
            }
            let mut wire = Vec::with_capacity(raw.len() + option.len());
            wire.extend_from_slice(raw);
            wire.extend_from_slice(&option);
            wire[opt.rdlength_offset..opt.rdlength_offset + 2]
                .copy_from_slice(&new_rdlength.to_be_bytes());
            wire
        } else {
            let additional_count = layout
                .additional_count
                .checked_add(1)
                .ok_or(EcsWireError::TooLarge)?;
            let opt_len = 11_usize
                .checked_add(option.len())
                .ok_or(EcsWireError::TooLarge)?;
            if raw
                .len()
                .checked_add(opt_len)
                .is_none_or(|length| length > u16::MAX as usize)
            {
                return Err(EcsWireError::TooLarge);
            }
            let mut wire = Vec::with_capacity(raw.len() + opt_len);
            wire.extend_from_slice(raw);
            wire[10..12].copy_from_slice(&additional_count.to_be_bytes());
            wire.push(0);
            wire.extend_from_slice(&OPT_RECORD_TYPE.to_be_bytes());
            wire.extend_from_slice(&DEFAULT_EDNS_PAYLOAD.to_be_bytes());
            wire.extend_from_slice(&0_u32.to_be_bytes());
            wire.extend_from_slice(&(option.len() as u16).to_be_bytes());
            wire.extend_from_slice(&option);
            wire
        };
        Ok(Some(Self {
            wire,
            original_had_opt,
            expected,
        }))
    }

    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    pub fn restore_response(self, mut response: Vec<u8>) -> Result<Vec<u8>, EcsWireError> {
        let layout = message_layout(&response)?;
        let Some(opt) = layout.opt else {
            return Ok(response);
        };
        if opt.end != response.len() {
            return Err(EcsWireError::NonFinalOpt);
        }
        let ecs = find_ecs(&response, &opt.rdata)?;
        if let Some(ecs) = ecs.as_ref()
            && !ecs_matches(&response[ecs.clone()], self.expected)
        {
            return Err(EcsWireError::MismatchedResponse);
        }

        if !self.original_had_opt && opt.extended_rcode != 0 {
            return Err(EcsWireError::UnsupportedResponseOpt);
        }
        if !self.original_had_opt {
            let additional_count = layout
                .additional_count
                .checked_sub(1)
                .ok_or(EcsWireError::Malformed)?;
            response.truncate(opt.start);
            response[10..12].copy_from_slice(&additional_count.to_be_bytes());
        } else if let Some(ecs) = ecs {
            let option_start = ecs.start.checked_sub(4).ok_or(EcsWireError::Malformed)?;
            let option_length = ecs.len().checked_add(4).ok_or(EcsWireError::Malformed)?;
            let new_rdlength = opt
                .rdata
                .len()
                .checked_sub(option_length)
                .and_then(|length| u16::try_from(length).ok())
                .ok_or(EcsWireError::Malformed)?;
            response.drain(option_start..ecs.end);
            response[opt.rdlength_offset..opt.rdlength_offset + 2]
                .copy_from_slice(&new_rdlength.to_be_bytes());
        }
        Ok(response)
    }
}

fn encode_ecs(subnet: Ipv4Net) -> (Vec<u8>, ExpectedEcs) {
    let source_prefix = subnet.prefix_len();
    let address_len = usize::from(source_prefix).div_ceil(8);
    let address = subnet.network().octets();
    let mut option = Vec::with_capacity(8 + address_len);
    option.extend_from_slice(&ECS_OPTION_CODE.to_be_bytes());
    option.extend_from_slice(&(4_u16 + address_len as u16).to_be_bytes());
    option.extend_from_slice(&1_u16.to_be_bytes());
    option.push(source_prefix);
    option.push(0);
    option.extend_from_slice(&address[..address_len]);
    (
        option,
        ExpectedEcs {
            source_prefix,
            address,
            address_len,
        },
    )
}

fn ecs_matches(value: &[u8], expected: ExpectedEcs) -> bool {
    value.len() == 4 + expected.address_len
        && value[..2] == 1_u16.to_be_bytes()
        && value[2] == expected.source_prefix
        && value[3] <= 32
        && value[4..] == expected.address[..expected.address_len]
}

fn find_ecs(raw: &[u8], rdata: &Range<usize>) -> Result<Option<Range<usize>>, EcsWireError> {
    let mut cursor = rdata.start;
    let mut ecs = None;
    while cursor < rdata.end {
        if cursor + 4 > rdata.end {
            return Err(EcsWireError::Malformed);
        }
        let code = read_u16(raw, cursor)?;
        let length = usize::from(read_u16(raw, cursor + 2)?);
        let value_start = cursor + 4;
        let value_end = value_start
            .checked_add(length)
            .filter(|end| *end <= rdata.end)
            .ok_or(EcsWireError::Malformed)?;
        if code == ECS_OPTION_CODE {
            if ecs.is_some() {
                return Err(EcsWireError::MismatchedResponse);
            }
            ecs = Some(value_start..value_end);
        }
        cursor = value_end;
    }
    Ok(ecs)
}

fn message_layout(raw: &[u8]) -> Result<MessageLayout, EcsWireError> {
    if raw.len() < 12 {
        return Err(EcsWireError::Malformed);
    }
    let questions = usize::from(read_u16(raw, 4)?);
    let answers = usize::from(read_u16(raw, 6)?);
    let authorities = usize::from(read_u16(raw, 8)?);
    let additional_count = read_u16(raw, 10)?;
    let mut cursor = 12;
    for _ in 0..questions {
        if !skip_dns_name(raw, &mut cursor) || cursor + 4 > raw.len() {
            return Err(EcsWireError::Malformed);
        }
        cursor += 4;
    }
    for _ in 0..answers
        .checked_add(authorities)
        .ok_or(EcsWireError::Malformed)?
    {
        record(raw, &mut cursor)?;
    }

    let mut opt = None;
    for _ in 0..additional_count {
        let record = record(raw, &mut cursor)?;
        if record.0 == OPT_RECORD_TYPE {
            if opt.is_some() {
                return Err(EcsWireError::MultipleOpt);
            }
            opt = Some(record.1);
        }
    }
    if cursor != raw.len() {
        return Err(EcsWireError::Malformed);
    }
    Ok(MessageLayout {
        opt,
        additional_count,
    })
}

fn record(raw: &[u8], cursor: &mut usize) -> Result<(u16, OptRecord), EcsWireError> {
    let start = *cursor;
    if !skip_dns_name(raw, cursor) || cursor.checked_add(10).is_none_or(|end| end > raw.len()) {
        return Err(EcsWireError::Malformed);
    }
    let fields = *cursor;
    let record_type = read_u16(raw, fields)?;
    let rdlength_offset = fields + 8;
    let rdata_start = fields + 10;
    let rdlength = usize::from(read_u16(raw, rdlength_offset)?);
    let end = rdata_start
        .checked_add(rdlength)
        .filter(|end| *end <= raw.len())
        .ok_or(EcsWireError::Malformed)?;
    *cursor = end;
    if record_type == OPT_RECORD_TYPE && (fields != start + 1 || raw[start] != 0) {
        return Err(EcsWireError::UnsupportedOpt);
    }
    Ok((
        record_type,
        OptRecord {
            start,
            end,
            rdlength_offset,
            rdata: rdata_start..end,
            extended_rcode: raw.get(fields + 4).copied().unwrap_or(0),
            version: raw.get(fields + 5).copied().unwrap_or(0),
        },
    ))
}

fn read_u16(raw: &[u8], offset: usize) -> Result<u16, EcsWireError> {
    let bytes = raw.get(offset..offset + 2).ok_or(EcsWireError::Malformed)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}
