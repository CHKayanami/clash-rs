/// TLS SNI (Server Name Indication) parser
/// Supports extracting SNI from TLS Record (TCP) or directly from TLS Handshake ClientHello (QUIC CRYPTO frames).

pub fn parse_tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // Check TLS Record header:
    // ContentType: 0x16 (Handshake)
    // Version: 0x03, 0x00..=0x04 (SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
    if data[0] != 0x16 || data[1] != 0x03 {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let payload = &data[5..];
    if payload.len() < record_len && payload.len() < 4 {
        // Even if the entire record isn't in buffer yet, try parsing what we have if long enough
    }

    parse_client_hello_handshake(payload)
}

/// Parse raw TLS Handshake ClientHello (starting from Handshake Type `0x01`)
pub fn parse_client_hello_handshake(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }

    // Handshake Type: 0x01 (Client Hello)
    if data[0] != 0x01 {
        return None;
    }

    let handshake_len =
        ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);
    let mut pos = 4;
    let limit = data.len().min(4 + handshake_len);

    // Client Version (2 bytes) + Random (32 bytes)
    if pos + 34 > limit {
        return None;
    }
    pos += 34;

    // Session ID length (1 byte) + Session ID
    if pos >= limit {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;
    if pos > limit {
        return None;
    }

    // Cipher Suites length (2 bytes) + Cipher Suites
    if pos + 2 > limit {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos > limit {
        return None;
    }

    // Compression Methods length (1 byte) + Compression Methods
    if pos >= limit {
        return None;
    }
    let compression_methods_len = data[pos] as usize;
    pos += 1 + compression_methods_len;
    if pos > limit {
        return None;
    }

    // Extensions length (2 bytes)
    if pos + 2 > limit {
        return None;
    }
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let ext_end = limit.min(pos + extensions_len);

    // Iterate through TLS Extensions
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > ext_end {
            break;
        }

        // Extension Type 0x0000 = server_name (SNI)
        if ext_type == 0x0000 {
            return parse_sni_extension(&data[pos..pos + ext_len]);
        }

        pos += ext_len;
    }

    None
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let limit = data.len().min(2 + list_len);

    while pos + 3 <= limit {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;

        if pos + name_len > limit {
            break;
        }

        // NameType 0x00 = host_name
        if name_type == 0x00 {
            let host_bytes = &data[pos..pos + name_len];
            if let Ok(host) = std::str::from_utf8(host_bytes) {
                let trimmed = host.trim().trim_end_matches('.');
                let lower = trimmed.to_ascii_lowercase();
                if !lower.is_empty() && is_valid_hostname(&lower) {
                    return Some(lower);
                }
            }
        }

        pos += name_len;
    }

    None
}

/// Validate that a string looks like a valid hostname according to RFC 1035 / 1123.
pub fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        let first = label.chars().next().unwrap_or('\0');
        let last = label.chars().last().unwrap_or('\0');

        if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
            return false;
        }

        for ch in label.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_sni_parsing() {
        // TLS 1.2 / 1.3 ClientHello with SNI = "example.com"
        #[rustfmt::skip]
        let sample = [
            0x16, 0x03, 0x01, 0x00, 0x43, // TLS Record Header (Handshake, TLS 1.0, len 67)
            0x01, 0x00, 0x00, 0x3f,       // ClientHello, len 63
            0x03, 0x03,                   // TLS 1.2
            // 32 bytes Random
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0x00,                         // Session ID len 0
            0x00, 0x02, 0x13, 0x01,       // Cipher Suites (len 2, TLS_AES_128_GCM_SHA256)
            0x01, 0x00,                   // Compression Methods (len 1, 0x00)
            0x00, 0x14,                   // Extensions length 20
            0x00, 0x00, 0x00, 0x10,       // Extension server_name (len 16)
            0x00, 0x0e,                   // ServerNameList len 14
            0x00, 0x00, 0x0b,             // HostName type 0, len 11
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm'
        ];

        let sni = parse_tls_sni(&sample);
        assert_eq!(sni, Some("example.com".to_string()));
    }

    #[test]
    fn test_non_tls() {
        let sample = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(parse_tls_sni(sample), None);
    }
}
