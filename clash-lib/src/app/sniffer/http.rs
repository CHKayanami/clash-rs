/// HTTP Host parser
/// Efficiently inspects the initial bytes of an HTTP request and extracts the Host header.

const HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"CONNECT ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"TRACE ",
    b"PATCH ",
    b"PRI * HTTP/2.0",
];

pub fn parse_http_host(data: &[u8]) -> Option<String> {
    if data.len() < 10 {
        return None;
    }

    // Check if the data starts with a known HTTP method
    let is_http = HTTP_METHODS.iter().any(|m| data.starts_with(m));
    if !is_http {
        return None;
    }

    // Search line by line for the `Host:` header (case-insensitive)
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => {
            // Even if whole buffer is not valid UTF-8, try converting lossily or slice up to headers
            let valid_len = match std::str::from_utf8(&data[..data.len().min(4096)])
            {
                Ok(s) => s.len(),
                Err(e) => e.valid_up_to(),
            };
            if valid_len < 10 {
                return None;
            }
            std::str::from_utf8(&data[..valid_len]).unwrap_or("")
        }
    };

    for line in s.lines() {
        if line.is_empty() {
            // End of headers
            break;
        }

        let trimmed = line.trim();
        if let Some(rest) = trimmed
            .strip_prefix("Host:")
            .or_else(|| trimmed.strip_prefix("host:"))
            .or_else(|| trimmed.strip_prefix("HOST:"))
        {
            return sanitize_host(rest);
        } else if trimmed.len() > 5 && trimmed[..5].eq_ignore_ascii_case("host:") {
            return sanitize_host(&trimmed[5..]);
        }
    }

    None
}

fn sanitize_host(raw: &str) -> Option<String> {
    let host_str = raw.trim();
    if host_str.is_empty() {
        return None;
    }

    // Handle IPv6 literal with port: [2001:db8::1]:80
    if host_str.starts_with('[') {
        if let Some(end_bracket) = host_str.find(']') {
            let ip_part = &host_str[1..end_bracket];
            return Some(ip_part.to_ascii_lowercase());
        }
    }

    // Handle host:port
    let host = match host_str.split_once(':') {
        Some((domain, _port)) => domain.trim(),
        None => host_str,
    };

    let host = host.trim_end_matches('.');
    let host_lower = host.to_ascii_lowercase();
    if host_lower.is_empty() || !super::tls::is_valid_hostname(&host_lower) {
        None
    } else {
        Some(host_lower)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_get() {
        let req = b"GET /index.html HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: curl/7.68.0\r\n\r\n";
        assert_eq!(parse_http_host(req), Some("www.google.com".to_string()));
    }

    #[test]
    fn test_parse_http_with_port() {
        let req = b"POST /api HTTP/1.1\r\nhost: api.github.com:8443\r\n\r\n";
        assert_eq!(parse_http_host(req), Some("api.github.com".to_string()));
    }

    #[test]
    fn test_parse_http_connect() {
        let req = b"CONNECT www.cloudflare.com:443 HTTP/1.1\r\nHost: www.cloudflare.com:443\r\n\r\n";
        assert_eq!(parse_http_host(req), Some("www.cloudflare.com".to_string()));
    }

    #[test]
    fn test_parse_non_http() {
        let req = b"\x16\x03\x01\x00\x05hello";
        assert_eq!(parse_http_host(req), None);
    }
}
