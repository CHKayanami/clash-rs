use super::super::endpoint::DnsEndpoint;

/// `host[:port]` authority string (brackets bare IPv6, elides default 443).
fn authority(host: &str, port: u16) -> String {
    let host_fmt = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 443 {
        host_fmt
    } else {
        format!("{host_fmt}:{port}")
    }
}

/// Build the DoH/DoH3 POST request for a DNS message. `content_length` is
/// set only on the HTTP/2 path; H3 omits it.
pub fn build_doh_request(
    endpoint: &DnsEndpoint,
    content_length: Option<usize>,
    label: &str,
) -> anyhow::Result<http::Request<()>> {
    let path = if endpoint.path.is_empty() {
        "/dns-query"
    } else {
        endpoint.path.as_str()
    };
    let uri = format!(
        "https://{}{}",
        authority(&endpoint.host, endpoint.port),
        path
    );
    let mut builder = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message");
    if let Some(len) = content_length {
        builder = builder.header("content-length", len.to_string());
    }
    builder
        .body(())
        .map_err(|e| anyhow::anyhow!("{label} request build: {e}"))
}

/// Shared DoH/DoH3 response validation: 2xx status, minimum DNS header size,
/// then restore the original query ID.
pub fn finish_doh_response(
    label: &str,
    status: http::StatusCode,
    mut body: Vec<u8>,
    orig_id: u16,
) -> anyhow::Result<Vec<u8>> {
    if !status.is_success() {
        anyhow::bail!("{label} HTTP status {status}");
    }
    if body.len() < 12 {
        anyhow::bail!("{label} response too short ({} bytes)", body.len());
    }
    body[0..2].copy_from_slice(&orig_id.to_be_bytes());
    Ok(body)
}
