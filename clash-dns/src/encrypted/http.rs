use std::{net::IpAddr, sync::Arc};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{uri::Authority, Request, Response, StatusCode, Method, header::{self, HeaderValue}};
use tokio::sync::Semaphore;
use tracing::debug;
use crate::{DnsIngress, DnsMessageExchanger};

pub(super) const MAX_DNS_SIZE: usize = 65535;

pub(super) struct Service<X> {
    pub exchanger: X,
    pub hostname: Option<Authority>,
    pub permits: Arc<Semaphore>,
}

pub(super) enum Query {
    Get(Bytes),
    Post { length: Option<usize> },
}

pub(super) struct QueryBody {
    query: Query,
    received: Vec<u8>,
}

impl QueryBody {
    pub fn new(query: Query) -> Self {
        let capacity = match &query {
            Query::Post { length } => length.unwrap_or(0),
            Query::Get(_) => 0,
        };
        Self { query, received: Vec::with_capacity(capacity) }
    }

    pub fn push(&mut self, data: &[u8]) -> Result<(), StatusCode> {
        if matches!(self.query, Query::Get(_)) {
            return if data.is_empty() { Ok(()) } else { Err(StatusCode::BAD_REQUEST) };
        }
        if let Query::Post { length: Some(length) } = &self.query
            && data.len() > length.saturating_sub(self.received.len())
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        if data.len() > MAX_DNS_SIZE - self.received.len() {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        self.received.extend_from_slice(data);
        Ok(())
    }

    pub fn finish(self) -> Result<Bytes, StatusCode> {
        match self.query {
            Query::Get(query) => Ok(query),
            Query::Post { length } => {
                if length.is_some_and(|length| length != self.received.len()) {
                    return Err(StatusCode::BAD_REQUEST);
                }
                Ok(Bytes::from(self.received))
            }
        }
    }
}

pub(super) fn failure(status: StatusCode) -> Response<Bytes> {
    let mut response = Response::new(Bytes::new());
    *response.status_mut() = status;
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if status == StatusCode::METHOD_NOT_ALLOWED {
        response.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET, POST"));
    }
    response
}

fn accepts_dns(request: &Request<()>) -> bool {
    let mut selected = None;
    for value in request.headers().get_all(header::ACCEPT) {
        let Ok(value) = value.to_str() else { return false };
        for entry in value.split(',') {
            let mut parts = entry.split(';');
            let media = parts.next().unwrap_or("").trim();
            let specificity = if media.eq_ignore_ascii_case("application/dns-message") { 2 }
                else if media.eq_ignore_ascii_case("application/*") { 1 }
                else if media == "*/*" { 0 } else { continue };
            let quality = parts.find_map(|part| part.trim().strip_prefix("q="))
                .map_or(1.0, |q| q.parse::<f32>().unwrap_or(0.0));
            let quality = if (0.0..=1.0).contains(&quality) { quality } else { 0.0 };
            if selected.is_none_or(|(s, q)| specificity > s || (specificity == s && quality > q)) {
                selected = Some((specificity, quality));
            }
        }
    }
    !request.headers().contains_key(header::ACCEPT)
        || selected.is_some_and(|(_, quality)| quality > 0.0)
}

pub(super) fn prepare(request: &Request<()>, hostname: Option<&Authority>) -> Result<Query, StatusCode> {
    if request.uri().path() != "/dns-query" {
        return Err(StatusCode::NOT_FOUND);
    }
    if let Some(expected) = hostname {
        let authority = request.uri().authority().cloned().or_else(|| {
            request.headers().get(header::HOST)?.to_str().ok()?.parse().ok()
        });
        if !authority.is_some_and(|value| value.host().trim_end_matches('.')
            .eq_ignore_ascii_case(expected.host().trim_end_matches('.')))
        {
            return Err(StatusCode::MISDIRECTED_REQUEST);
        }
    }
    if !accepts_dns(request) {
        return Err(StatusCode::NOT_ACCEPTABLE);
    }
    let length = request.headers().get(header::CONTENT_LENGTH).map(|value| {
        value.to_str().ok().and_then(|value| value.parse::<usize>().ok())
            .ok_or(StatusCode::BAD_REQUEST)
    }).transpose()?;
    if length.is_some_and(|length| length > MAX_DNS_SIZE) {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if request.headers().get(header::CONTENT_ENCODING)
        .is_some_and(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    match *request.method() {
        Method::GET => {
            if length.is_some_and(|length| length != 0) { return Err(StatusCode::BAD_REQUEST) }
            let query = request.uri().query().ok_or(StatusCode::BAD_REQUEST)?;
            // Bound URI decoding before allocating a decoded query.
            if query.len() > MAX_DNS_SIZE * 2 { return Err(StatusCode::URI_TOO_LONG) }
            let mut encoded = None;
            for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                if key == "dns" && encoded.replace(value).is_some() {
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
            let encoded = encoded.ok_or(StatusCode::BAD_REQUEST)?;
            let query = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| StatusCode::BAD_REQUEST)?;
            if query.len() > MAX_DNS_SIZE { return Err(StatusCode::PAYLOAD_TOO_LARGE) }
            Ok(Query::Get(Bytes::from(query)))
        }
        Method::POST => {
            let content_type = request.headers().get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()).and_then(|value| value.split(';').next());
            if !content_type.is_some_and(|value| value.trim().eq_ignore_ascii_case("application/dns-message")) {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            Ok(Query::Post { length })
        }
        _ => Err(StatusCode::METHOD_NOT_ALLOWED),
    }
}

impl<X: DnsMessageExchanger> Service<X> {
    pub async fn exchange(&self, query: Bytes, peer: IpAddr, ingress: DnsIngress) -> Response<Bytes> {
        if query.len() < 12 || query.len() > MAX_DNS_SIZE || query[2] & 0x80 != 0 {
            return failure(StatusCode::BAD_REQUEST);
        }
        match self.exchanger.exchange(query, Some(peer), ingress).await {
            Ok(body) if (12..=MAX_DNS_SIZE).contains(&body.len()) => {
                let mut response = Response::new(Bytes::from(body));
                response.headers_mut().insert(header::CONTENT_TYPE,
                    HeaderValue::from_static("application/dns-message"));
                // The DNS cache is authoritative; do not create a second HTTP
                // cache with a freshness lifetime longer than the DNS records.
                response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                response
            }
            Ok(_) => failure(StatusCode::BAD_GATEWAY),
            Err(error) => {
                debug!(%peer, %error, "encrypted DNS exchange failed");
                failure(StatusCode::BAD_GATEWAY)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_body_reserves_validated_length_and_rejects_mismatch() {
        let request = Request::builder().method("POST").uri("/dns-query")
            .header("content-type", "application/dns-message")
            .header("content-length", "32").body(()).unwrap();
        let mut body = QueryBody::new(prepare(&request, None).unwrap());
        assert_eq!(body.received.capacity(), 32);
        body.push(&[0; 12]).unwrap();
        assert_eq!(body.finish().err(), Some(StatusCode::BAD_REQUEST));
        let mut body = QueryBody::new(prepare(&request, None).unwrap());
        assert_eq!(body.push(&[0; 33]), Err(StatusCode::BAD_REQUEST));
        assert!(body.received.is_empty());
    }

    #[test]
    fn get_body_is_rejected_on_first_nonempty_chunk() {
        let mut body = QueryBody::new(Query::Get(Bytes::from_static(b"query")));
        body.push(&[]).unwrap();
        assert_eq!(body.push(b"x"), Err(StatusCode::BAD_REQUEST));
        assert!(body.received.is_empty());
    }
}
