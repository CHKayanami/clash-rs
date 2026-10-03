use std::{io, ops::RangeInclusive};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, header::COOKIE};
use http_body_util::Full;
use crate::config::internal::proxy::XHttpOpt;
use super::{body::RequestBody, metadata::{Placement, append_cookie, cookie_buffer, managed_header, valid_key}, range::{invalid, range}};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DataPlacement { Body, Header, Cookie }

pub(super) struct Payload {
    pub(super) placement: DataPlacement,
    key: String,
    chunk: RangeInclusive<u32>,
}

impl Payload {
    pub(super) fn new(opts: &XHttpOpt, post_bytes: RangeInclusive<u32>) -> io::Result<Self> {
        let placement = match opts.uplink_data_placement.as_deref().unwrap_or("body") {
            "" | "body" | "auto" => DataPlacement::Body,
            "header" => DataPlacement::Header,
            "cookie" => DataPlacement::Cookie,
            other => return Err(invalid(format!("unsupported XHTTP uplink data placement: {other}"))),
        };
        let key = opts.uplink_data_key.as_deref().filter(|key| !key.is_empty())
            .unwrap_or(if placement == DataPlacement::Cookie { "x_data" } else { "X-Data" }).to_owned();
        valid_key(&key)?;
        if placement == DataPlacement::Header {
            let name = format!("{key}-0").parse::<HeaderName>().map_err(invalid)?;
            if managed_header(&name) { return Err(invalid("reserved XHTTP uplink data header")); }
        }
        let default = match placement {
            DataPlacement::Body => post_bytes,
            DataPlacement::Header => 3072..=4096,
            DataPlacement::Cookie => 2048..=3072,
        };
        let configured = range(opts.uplink_chunk_size.as_deref(), 0..=0, 0..=16_777_216, "uplink chunk size")?;
        let chunk = if *configured.end() == 0 { default }
            else { (*configured.start()).max(64)..=(*configured.end()).max(64) };
        Ok(Self { placement, key, chunk })
    }

    pub(super) fn manages(&self, placement: Placement, key: &str) -> bool {
        let separator = match (self.placement, placement) {
            (DataPlacement::Header, Placement::Header) => '-',
            (DataPlacement::Cookie, Placement::Cookie) => '_',
            _ => return false,
        };
        let Some((prefix, index)) = key.rsplit_once(separator) else { return false; };
        let matches = if placement == Placement::Header { prefix.eq_ignore_ascii_case(&self.key) }
            else { prefix == self.key };
        matches && !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
    }

    pub(super) fn body(&self, headers: &mut HeaderMap, bytes: Bytes) -> io::Result<RequestBody> {
        if self.placement == DataPlacement::Body {
            return Ok(RequestBody::Full(Full::new(bytes)));
        }
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        let mut cookies = if self.placement == DataPlacement::Cookie {
            cookie_buffer(headers)?
        } else { String::new() };
        if self.placement == DataPlacement::Cookie {
            cookies.reserve(encoded.len());
        }
        let mut offset = 0;
        let mut index = 0;
        while offset < encoded.len() {
            let length = (rand::random_range(self.chunk.clone()) as usize).min(encoded.len() - offset);
            let value = &encoded[offset..offset + length];
            match self.placement {
                DataPlacement::Header => {
                    headers.insert(format!("{}-{index}", self.key).parse::<HeaderName>().map_err(invalid)?,
                        HeaderValue::from_str(value).map_err(invalid)?);
                }
                DataPlacement::Cookie => append_cookie(&mut cookies, &format!("{}_{index}", self.key), value),
                DataPlacement::Body => unreachable!(),
            }
            offset += length;
            index += 1;
        }
        if self.placement == DataPlacement::Cookie && !cookies.is_empty() {
            headers.insert(COOKIE, HeaderValue::from_str(&cookies).map_err(invalid)?);
        }
        Ok(RequestBody::empty())
    }
}
