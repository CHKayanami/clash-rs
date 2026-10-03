use std::{io, ops::RangeInclusive};
use http::{HeaderMap, HeaderName, HeaderValue, Version};
use http::header::COOKIE;
use crate::config::internal::proxy::XHttpOpt;
use super::{
    metadata::{Metadata, Placement as MetadataPlacement, cookie, managed_header, query_set, valid_key},
    range::{invalid, range},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Placement { Header, QueryInHeader, Query, Cookie }

pub(super) struct Padding {
    bytes: RangeInclusive<u32>,
    placement: Placement,
    pub(super) key: String,
    header: HeaderName,
    tokenish: bool,
    obfuscated: bool,
}

impl Padding {
    pub(super) fn new(opts: &XHttpOpt) -> io::Result<Self> {
        let obfuscated = opts.x_padding_obfs_mode.unwrap_or(false);
        let placement = if obfuscated {
            match opts.x_padding_placement.as_deref().unwrap_or("queryInHeader") {
                "" | "queryInHeader" => Placement::QueryInHeader,
                "header" => Placement::Header,
                "query" => Placement::Query,
                "cookie" => Placement::Cookie,
                other => return Err(invalid(format!("unsupported XHTTP padding placement: {other}"))),
            }
        } else { Placement::QueryInHeader };
        let key = if obfuscated { opts.x_padding_key.as_deref().filter(|key| !key.is_empty()).unwrap_or("x_padding") }
            else { "x_padding" }.to_owned();
        valid_key(&key)?;
        let header = if obfuscated { opts.x_padding_header.as_deref().filter(|header| !header.is_empty()).unwrap_or("X-Padding") }
            else { "Referer" }.parse::<HeaderName>().map_err(invalid)?;
        if matches!(placement, Placement::Header | Placement::QueryInHeader)
            && (managed_header(&header) || header == COOKIE) {
            return Err(invalid("reserved XHTTP padding header"));
        }
        let tokenish = if obfuscated {
            match opts.x_padding_method.as_deref().unwrap_or("repeat-x") {
                "" | "repeat-x" => false,
                "tokenish" => true,
                other => return Err(invalid(format!("unsupported XHTTP padding method: {other}"))),
            }
        } else { false };
        let bytes = range(opts.x_padding_bytes.as_deref(), 100..=1000, 0..=65_536, "padding")?;
        // A zero upper bound is treated as an unset range by current Mihomo.
        let bytes = if *bytes.end() == 0 { 100..=1000 } else { bytes };
        Ok(Self { bytes, placement, key, header, tokenish, obfuscated })
    }

    pub(super) fn header(&self) -> Option<&HeaderName> {
        matches!(self.placement, Placement::Header | Placement::QueryInHeader).then_some(&self.header)
    }

    pub(super) fn cookie_key(&self) -> Option<&str> {
        (self.placement == Placement::Cookie).then_some(self.key.as_str())
    }

    pub(super) fn uses_query(&self) -> bool {
        self.placement == Placement::Query || !self.obfuscated || self.header.as_str() == "referer"
    }

    pub(super) fn conflicts(&self, metadata: &Metadata) -> bool {
        match metadata.placement {
            MetadataPlacement::Header => self.header().is_some_and(|header| header.as_str().eq_ignore_ascii_case(&metadata.key)),
            MetadataPlacement::Query => self.uses_query() && self.key == metadata.key,
            MetadataPlacement::Cookie => self.placement == Placement::Cookie && self.key == metadata.key,
            MetadataPlacement::Path => false,
        }
    }

    pub(super) fn apply(
        &self, headers: &mut HeaderMap, query: &mut String,
        base_url: &str, streaming: bool, version: Version,
    ) -> io::Result<()> {
        let length = rand::random_range(self.bytes.clone()) as usize;
        let value = if self.tokenish { tokenish(length) } else { "X".repeat(length) };
        // Default Referer padding causes Xray/Go HTTP/1.1 upload response
        // writes to drain the live request. Its native query fallback avoids it.
        let placement = if streaming && version == Version::HTTP_11
            && self.header.as_str() == "referer"
            && matches!(self.placement, Placement::Header | Placement::QueryInHeader) {
            Placement::Query
        } else { self.placement };
        match placement {
            Placement::Header => { headers.insert(self.header.clone(), HeaderValue::from_str(&value).map_err(invalid)?); }
            Placement::QueryInHeader => {
                let value = format!("{}?{}={value}", base_url.split('?').next().unwrap_or(base_url), self.key);
                headers.insert(self.header.clone(), HeaderValue::from_str(&value).map_err(invalid)?);
            }
            Placement::Query => query_set(query, &self.key, &value),
            Placement::Cookie => cookie(headers, &self.key, &value)?,
        }
        Ok(())
    }
}

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// HPACK's static Huffman lengths for the base62 alphabet (RFC 7541, Appendix B).
pub(super) fn huffman_bits(byte: u8) -> usize {
    match byte {
        b'0'..=b'2' | b'a' | b'c' | b'e' | b'i' | b'o' | b's' | b't' => 5,
        b'3'..=b'9' | b'A' | b'b' | b'd' | b'f' | b'g' | b'h' | b'l' | b'm' | b'n' | b'p' | b'r' | b'u' => 6,
        b'X' | b'Z' => 8,
        _ => 7,
    }
}

fn tokenish(length: usize) -> String {
    let mut value = String::with_capacity(length * 8 / 5 + 1);
    let mut bits: usize = 0;
    while bits.div_ceil(8) < length {
        let byte = BASE62[rand::random_range(0..BASE62.len())];
        bits += huffman_bits(byte);
        value.push(byte as char);
    }
    value
}
