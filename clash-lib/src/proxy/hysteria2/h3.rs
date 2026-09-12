use std::{
    io,
    sync::LazyLock,
};

use super::codec;

// RFC 9000 QUIC Varint
pub fn write_varint(out: &mut Vec<u8>, value: u64) {
    if value <= 63 {
        out.push(value as u8);
    } else if value <= 16383 {
        out.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes());
    } else if value <= 1_073_741_823 {
        out.extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

pub async fn read_varint_stream(recv: &mut quinn::RecvStream) -> io::Result<u64> {
    let mut first = [0u8; 1];
    recv.read_exact(&mut first)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
    let len = 1usize << (first[0] >> 6);
    let mut value = (first[0] & 0x3f) as u64;
    for _ in 1..len {
        let mut b = [0u8; 1];
        recv.read_exact(&mut b)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
        value = (value << 8) | b[0] as u64;
    }
    Ok(value)
}

pub async fn skip_bytes(recv: &mut quinn::RecvStream, mut n: u64) -> io::Result<()> {
    let mut buf = [0u8; 512];
    while n > 0 {
        let chunk = n.min(buf.len() as u64) as usize;
        recv.read_exact(&mut buf[..chunk])
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
        n -= chunk as u64;
    }
    Ok(())
}

// QPACK prefixed integers (RFC 7541 §5.1 / RFC 9204 §4.1.1)
pub fn write_prefixed_int(out: &mut Vec<u8>, prefix_bits: u32, flags: u8, value: u64) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max as u8);
    let mut remaining = value - max;
    while remaining >= 0x80 {
        out.push((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
}

pub fn take<'a>(cursor: &mut &'a [u8], n: usize) -> io::Result<&'a [u8]> {
    if cursor.len() < n {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short QPACK field section",
        ));
    }
    let (head, tail) = cursor.split_at(n);
    *cursor = tail;
    Ok(head)
}

pub fn read_prefixed_int(
    cursor: &mut &[u8],
    first: u8,
    prefix_bits: u32,
) -> io::Result<u64> {
    let mask = (1u64 << prefix_bits) - 1;
    let mut value = (first as u64) & mask;
    if value < mask {
        return Ok(value);
    }
    let mut shift = 0u32;
    loop {
        let b = take(cursor, 1)?[0];
        value += ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 56 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "QPACK prefixed integer overflow",
            ));
        }
    }
}

// HPACK Huffman coding (RFC 7541 Appendix B)
pub const HUFFMAN_TABLE: [(u32, u8); 257] = [
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x1fffdc, 21),
    (0x3fffd8, 22),
    (0x7fffe5, 23),
    (0x3fffd9, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xffffef, 24),
    (0x3fffda, 22),
    (0x1fffdd, 21),
    (0xfffe9, 20),
    (0x3fffdb, 22),
    (0x3fffdc, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x1fffde, 21),
    (0x7fffea, 23),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x1fffdf, 21),
    (0x3fffdf, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x1fffe0, 21),
    (0x1fffe1, 21),
    (0x3fffe0, 22),
    (0x1fffe2, 21),
    (0x7fffed, 23),
    (0x3fffe1, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffea, 20),
    (0x3fffe2, 22),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7ffff0, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7ffff1, 23),
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x3fffe7, 22),
    (0x7ffff2, 23),
    (0x3fffe8, 22),
    (0x1ffffec, 25),
    (0x3ffffe2, 26),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffffde, 27),
    (0x7ffffdf, 27),
    (0x3ffffe5, 26),
    (0xfffff1, 24),
    (0x1ffffed, 25),
    (0x7fff2, 19),
    (0x1fffe3, 21),
    (0x3ffffe6, 26),
    (0x7ffffe0, 27),
    (0x7ffffe1, 27),
    (0x3ffffe7, 26),
    (0x7ffffe2, 27),
    (0xfffff2, 24),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x3ffffe8, 26),
    (0x3ffffe9, 26),
    (0xffffffd, 28),
    (0x7ffffe3, 27),
    (0x7ffffe4, 27),
    (0x7ffffe5, 27),
    (0xfffec, 20),
    (0xfffff3, 24),
    (0xfffed, 20),
    (0x1fffe6, 21),
    (0x3fffe9, 22),
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x7ffff3, 23),
    (0x3fffea, 22),
    (0x3fffeb, 22),
    (0x1ffffee, 25),
    (0x1ffffef, 25),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3ffffea, 26),
    (0x7ffff4, 23),
    (0x3ffffeb, 26),
    (0x7ffffe6, 27),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x7ffffe7, 27),
    (0x7ffffe8, 27),
    (0x7ffffe9, 27),
    (0x7ffffea, 27),
    (0x7ffffeb, 27),
    (0xffffffe, 28),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x7ffffee, 27),
    (0x7ffffef, 27),
    (0x7fffff0, 27),
    (0x3ffffee, 26),
    (0x3fffffff, 30),
];

pub static HUFFMAN_TREE: LazyLock<Vec<[u16; 2]>> = LazyLock::new(|| {
    let mut tree = vec![[0u16; 2]];
    for (sym, &(code, len)) in HUFFMAN_TABLE.iter().enumerate() {
        let mut node = 0usize;
        for i in 0..len {
            let bit = ((code >> (len - 1 - i)) & 1) as usize;
            if i == len - 1 {
                tree[node][bit] = 0x8000 | sym as u16;
            } else {
                if tree[node][bit] == 0 {
                    tree.push([0; 2]);
                    tree[node][bit] = (tree.len() - 1) as u16;
                }
                node = tree[node][bit] as usize;
            }
        }
    }
    tree
});

pub fn huffman_decode(data: &[u8]) -> Option<Vec<u8>> {
    let tree = &*HUFFMAN_TREE;
    let mut out = Vec::with_capacity(data.len());
    let mut node = 0usize;
    let mut pending: u32 = 0;
    let mut pending_len: u8 = 0;
    for &byte in data {
        for i in 0..8 {
            let bit = ((byte >> (7 - i)) & 1) as usize;
            pending = (pending << 1) | bit as u32;
            pending_len += 1;
            let next = tree[node][bit];
            if next == 0 {
                return None;
            }
            if next & 0x8000 != 0 {
                let sym = next & 0x7fff;
                if sym == 256 {
                    return None;
                }
                out.push(sym as u8);
                node = 0;
                pending = 0;
                pending_len = 0;
            } else {
                node = next as usize;
            }
        }
    }
    if pending_len >= 8 || pending != (1u32 << pending_len) - 1 {
        return None;
    }
    Some(out)
}

// QPACK static table
pub const QPACK_STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

fn invalid_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn decode_string_bytes(huffman: bool, raw: &[u8]) -> io::Result<String> {
    let bytes = if huffman {
        huffman_decode(raw).ok_or_else(|| invalid_data("invalid Huffman-coded string"))?
    } else {
        raw.to_vec()
    };
    String::from_utf8(bytes).map_err(|_| invalid_data("header is not valid UTF-8"))
}

pub fn read_qpack_str(cursor: &mut &[u8]) -> io::Result<String> {
    let first = take(cursor, 1)?[0];
    let len = read_prefixed_int(cursor, first, 7)? as usize;
    let raw = take(cursor, len)?;
    decode_string_bytes(first & 0x80 != 0, raw)
}

pub fn qpack_decode_field_section(buf: &[u8]) -> io::Result<Vec<(String, String)>> {
    let mut cursor = buf;
    let first = take(&mut cursor, 1)?[0];
    let _insert_count = read_prefixed_int(&mut cursor, first, 8)?;
    let second = take(&mut cursor, 1)?[0];
    let _base = read_prefixed_int(&mut cursor, second, 7)?;

    let mut fields = Vec::new();
    while !cursor.is_empty() {
        let b = take(&mut cursor, 1)?[0];
        if b & 0x80 != 0 {
            let idx = read_prefixed_int(&mut cursor, b, 6)? as usize;
            if b & 0x40 == 0 {
                return Err(invalid_data("QPACK dynamic table reference"));
            }
            let (name, value) = QPACK_STATIC_TABLE
                .get(idx)
                .copied()
                .ok_or_else(|| invalid_data("QPACK static index out of range"))?;
            fields.push((name.to_string(), value.to_string()));
        } else if b & 0x40 != 0 {
            let idx = read_prefixed_int(&mut cursor, b, 4)? as usize;
            if b & 0x10 == 0 {
                return Err(invalid_data("QPACK dynamic table name reference"));
            }
            let name = QPACK_STATIC_TABLE
                .get(idx)
                .map(|entry| entry.0)
                .ok_or_else(|| invalid_data("QPACK static index out of range"))?;
            let value = read_qpack_str(&mut cursor)?;
            fields.push((name.to_string(), value));
        } else if b & 0x20 != 0 {
            let name_len = read_prefixed_int(&mut cursor, b, 3)? as usize;
            let raw_name = take(&mut cursor, name_len)?;
            let name = decode_string_bytes(b & 0x08 != 0, raw_name)?;
            let value = read_qpack_str(&mut cursor)?;
            fields.push((name, value));
        } else {
            return Err(invalid_data("QPACK post-base field line"));
        }
    }
    Ok(fields)
}

pub fn write_qpack_str(out: &mut Vec<u8>, value: &str) {
    write_prefixed_int(out, 7, 0x00, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

pub fn qpack_encode_request_fields(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00];
    for &(name, value) in fields {
        match (name, value) {
            (":method", "POST") => write_prefixed_int(&mut out, 6, 0xc0, 20),
            (":scheme", "https") => write_prefixed_int(&mut out, 6, 0xc0, 23),
            ("content-length", "0") => write_prefixed_int(&mut out, 6, 0xc0, 4),
            (":authority", _) => {
                write_prefixed_int(&mut out, 4, 0x50, 0);
                write_qpack_str(&mut out, value);
            }
            (":path", _) => {
                write_prefixed_int(&mut out, 4, 0x50, 1);
                write_qpack_str(&mut out, value);
            }
            _ => {
                write_prefixed_int(&mut out, 3, 0x20, name.len() as u64);
                out.extend_from_slice(name.as_bytes());
                write_qpack_str(&mut out, value);
            }
        }
    }
    out
}

// RFC 9114 HTTP/3 Constants & Framing
pub const H3_STREAM_CONTROL: u64 = 0x00;
pub const H3_STREAM_QPACK_ENCODER: u64 = 0x02;
pub const H3_STREAM_QPACK_DECODER: u64 = 0x03;

pub const H3_FRAME_HEADERS: u64 = 0x01;
pub const H3_FRAME_SETTINGS: u64 = 0x04;

pub const H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
pub const H3_SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;
pub const H3_SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

pub const MAX_FIELD_SECTION: u64 = 64 * 1024;

/// Client connection preface: control stream type + SETTINGS frame.
///
/// NOTE: H3_SETTINGS_DATAGRAM must NOT be sent to avoid server-side quic-go
/// datagram reader competing with hysteria UDP session manager.
pub fn client_preface() -> Vec<u8> {
    let mut payload = Vec::new();
    for (id, value) in [
        (H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
        (H3_SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        (H3_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
    ] {
        write_varint(&mut payload, id);
        write_varint(&mut payload, value);
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    write_varint(&mut out, H3_STREAM_CONTROL);
    write_varint(&mut out, H3_FRAME_SETTINGS);
    write_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(&payload);
    out
}

pub fn h3_headers_frame(field_section: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + field_section.len());
    write_varint(&mut out, H3_FRAME_HEADERS);
    write_varint(&mut out, field_section.len() as u64);
    out.extend_from_slice(field_section);
    out
}

pub fn auth_request_frame(passwd: &str, down_bytes: u64) -> Vec<u8> {
    let padding_bytes = codec::padding(64..=512);
    let padding_str = String::from_utf8_lossy(&padding_bytes);
    let down_str = down_bytes.to_string();

    let section = qpack_encode_request_fields(&[
        (":authority", "hysteria"),
        (":method", "POST"),
        (":path", "/auth"),
        (":scheme", "https"),
        ("hysteria-auth", passwd),
        ("hysteria-cc-rx", &down_str),
        ("hysteria-padding", &padding_str),
        ("content-length", "0"),
    ]);
    h3_headers_frame(&section)
}

pub async fn read_h3_response_headers(
    recv: &mut quinn::RecvStream,
) -> io::Result<Vec<(String, String)>> {
    loop {
        let frame_type = read_varint_stream(recv).await?;
        let len = read_varint_stream(recv).await?;
        if len > MAX_FIELD_SECTION {
            return Err(invalid_data("HTTP/3 frame too large"));
        }
        if frame_type == H3_FRAME_HEADERS {
            let mut payload = vec![0u8; len as usize];
            recv.read_exact(&mut payload)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
            return qpack_decode_field_section(&payload);
        }
        skip_bytes(recv, len).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encode() {
        let mut out = Vec::new();
        write_varint(&mut out, 25);
        assert_eq!(out, vec![25]);

        let mut out = Vec::new();
        write_varint(&mut out, 15293);
        assert_eq!(out, vec![0x7b, 0xbd]);
    }

    #[test]
    fn test_client_preface() {
        let preface = client_preface();
        // 必须以 H3_STREAM_CONTROL (0x00) 开头
        assert_eq!(preface[0], 0x00);
        // 接 H3_FRAME_SETTINGS (0x04)
        assert_eq!(preface[1], 0x04);
        // 绝对不能包含 H3_SETTINGS_DATAGRAM (0x33)
        assert!(!preface.contains(&0x33));
    }

    #[test]
    fn test_auth_request_frame() {
        let frame = auth_request_frame("my_secret", 1000000);
        // 以 H3_FRAME_HEADERS (0x01) 开头
        assert_eq!(frame[0], 0x01);
        // 包含 "my_secret"
        assert!(
            frame
                .windows("my_secret".len())
                .any(|w| w == b"my_secret")
        );
        // 包含 "hysteria"
        assert!(
            frame
                .windows("hysteria".len())
                .any(|w| w == b"hysteria")
        );
    }

    #[test]
    fn test_qpack_decode_response() {
        let mut out = vec![0x00, 0x00]; // prefix
        // 1. :status -> 233
        write_prefixed_int(&mut out, 3, 0x20, ":status".len() as u64);
        out.extend_from_slice(b":status");
        write_qpack_str(&mut out, "233");

        // 2. hysteria-cc-rx -> 12500000
        write_prefixed_int(&mut out, 3, 0x20, "hysteria-cc-rx".len() as u64);
        out.extend_from_slice(b"hysteria-cc-rx");
        write_qpack_str(&mut out, "12500000");

        // 3. hysteria-udp -> true
        write_prefixed_int(&mut out, 3, 0x20, "hysteria-udp".len() as u64);
        out.extend_from_slice(b"hysteria-udp");
        write_qpack_str(&mut out, "true");

        let fields = qpack_decode_field_section(&out).expect("decode failed");
        let get = |k: &str| fields.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());

        assert_eq!(get(":status"), Some("233"));
        assert_eq!(get("hysteria-cc-rx"), Some("12500000"));
        assert_eq!(get("hysteria-udp"), Some("true"));
    }

    #[test]
    fn test_huffman_roundtrip_ascii() {
        let input = b"www.example.com";
        let mut encoded = Vec::new();
        let mut acc: u64 = 0;
        let mut nbits: u32 = 0;
        for &b in input {
            let (code, len) = HUFFMAN_TABLE[b as usize];
            acc = (acc << len) | u64::from(code);
            nbits += u32::from(len);
            while nbits >= 8 {
                nbits -= 8;
                encoded.push((acc >> nbits) as u8);
            }
        }
        if nbits > 0 {
            encoded.push(((acc << (8 - nbits)) | ((1u64 << (8 - nbits)) - 1)) as u8);
        }

        let decoded = huffman_decode(&encoded).expect("huffman decode failed");
        assert_eq!(decoded, input);
    }
}
