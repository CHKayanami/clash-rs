use std::{io, ops::RangeInclusive};
use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Uri, Version,
    header::{CONTENT_TYPE, COOKIE, HOST}, uri::Authority,
};
use url::form_urlencoded;

use crate::config::internal::proxy::XHttpOpt;
use super::{
    body::RequestBody,
    metadata::{Metadata, Placement, managed_header},
    padding::Padding,
    payload::{DataPlacement, Payload},
    range::{invalid, range},
    session::SessionId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Mode { PacketUp, StreamUp, StreamOne }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HttpVersion { Auto, Http1, Http2 }

pub(super) struct Options {
    pub(super) mode: Mode,
    pub(super) version: HttpVersion,
    pub(super) secure: bool,
    pub(super) reality: bool,
    authority: Authority,
    host_header: HeaderValue,
    padding_url: String,
    path: String,
    query: String,
    headers: HeaderMap,
    padding: Padding,
    session: Metadata,
    sequence: Metadata,
    sessions: SessionId,
    payload: Payload,
    upload_method: Method,
    pub(super) post_bytes: RangeInclusive<u32>,
    pub(super) interval_ms: RangeInclusive<u32>,
    no_grpc_header: bool,
}

impl Options {
    pub(super) fn new(
        opts: &XHttpOpt, host: &str, secure: bool, reality: bool, alpn: Option<&[String]>,
    ) -> io::Result<Self> {
        let mode = match opts.mode.as_deref().unwrap_or("auto") {
            "auto" | "" if reality && opts.download_settings.is_some() => Mode::StreamUp,
            "auto" | "" if reality => Mode::StreamOne,
            "auto" | "" | "packet-up" => Mode::PacketUp,
            "stream-up" => Mode::StreamUp,
            "stream-one" => Mode::StreamOne,
            other => return Err(invalid(format!("unsupported XHTTP mode: {other}"))),
        };
        if mode == Mode::StreamOne && opts.download_settings.is_some() {
            return Err(invalid("XHTTP stream-one cannot use download-settings"));
        }
        if alpn.is_some_and(|protocols| protocols.iter()
            .any(|protocol| !matches!(protocol.as_str(), "h2" | "http/1.1"))) {
            return Err(invalid("XHTTP ALPN must be h2 or http/1.1"));
        }
        let version = match alpn {
            Some(protocols) if protocols.len() == 1 && protocols[0] == "h2" => HttpVersion::Http2,
            Some(protocols) if protocols.len() == 1 && protocols[0] == "http/1.1" => HttpVersion::Http1,
            _ => HttpVersion::Auto,
        };
        if version == HttpVersion::Http1 && (reality || mode == Mode::StreamOne) {
            return Err(invalid("XHTTP Reality and stream-one require HTTP/2"));
        }
        let mut headers = HeaderMap::new();
        if let Some(configured) = &opts.headers {
            for (name, value) in configured {
                headers.insert(name.parse::<HeaderName>().map_err(invalid)?,
                    HeaderValue::from_str(value).map_err(invalid)?);
            }
        }
        let authority = opts.host.as_deref().filter(|host| !host.is_empty())
            .or(headers.get(HOST).map(|value| value.to_str()).transpose().map_err(invalid)?)
            .unwrap_or(host);
        if authority.is_empty() || authority.contains('@') { return Err(invalid("invalid XHTTP host")); }
        let authority = authority.parse::<Authority>().map_err(invalid)?;
        headers.remove(HOST);
        if headers.keys().any(managed_header) { return Err(invalid("reserved XHTTP request header")); }
        let session = Metadata::new(opts.session_placement.as_deref(), opts.session_key.as_deref(), "session")?;
        let sequence = Metadata::new(opts.seq_placement.as_deref(), opts.seq_key.as_deref(), "sequence")?;
        if session.placement != Placement::Path && session.placement == sequence.placement
            && session.key.eq_ignore_ascii_case(&sequence.key) {
            return Err(invalid("XHTTP session and sequence keys must differ"));
        }
        let padding = Padding::new(opts)?;
        if padding.conflicts(&session) || padding.conflicts(&sequence) {
            return Err(invalid("XHTTP padding and metadata keys must differ"));
        }
        for metadata in [&session, &sequence] {
            if metadata.placement == Placement::Header && headers.contains_key(&metadata.key) {
                return Err(invalid("XHTTP metadata header is managed by the transport"));
            }
        }
        if padding.header().is_some_and(|header| headers.contains_key(header)) {
            return Err(invalid("XHTTP padding header is managed by the transport"));
        }
        let configured_path = opts.path.as_deref().unwrap_or("/");
        let (path, query) = configured_path.split_once('?').unwrap_or((configured_path, ""));
        for (key, _) in form_urlencoded::parse(query.as_bytes()) {
            if (padding.uses_query() && key == padding.key)
                || (session.placement == Placement::Query && key == session.key)
                || (sequence.placement == Placement::Query && key == sequence.key) {
                return Err(invalid("XHTTP path contains a transport-managed query parameter"));
            }
        }
        let mut path = path.to_owned();
        if !path.starts_with('/') { path.insert(0, '/'); }
        if (session.placement == Placement::Path || sequence.placement == Placement::Path)
            && !path.ends_with('/') { path.push('/'); }
        let post_bytes = range(opts.sc_max_each_post_bytes.as_deref(),
            1_000_000..=1_000_000, 1..=16_777_216, "upload packet size")?;
        let payload = Payload::new(opts, post_bytes.clone())?;
        if [&session, &sequence].iter().any(|metadata| payload.manages(metadata.placement, &metadata.key))
            || headers.keys().any(|header| payload.manages(Placement::Header, header.as_str()))
            || padding.header().is_some_and(|header| payload.manages(Placement::Header, header.as_str()))
            || padding.cookie_key().is_some_and(|key| payload.manages(Placement::Cookie, key)) {
            return Err(invalid("XHTTP uplink data keys conflict with configured headers or metadata"));
        }
        if let Some(cookies) = headers.get(COOKIE) {
            for part in cookies.to_str().map_err(invalid)?.split(';') {
                if let Some((key, _)) = part.trim().split_once('=')
                    && ((session.placement == Placement::Cookie && key == session.key)
                        || (sequence.placement == Placement::Cookie && key == sequence.key)
                        || padding.cookie_key() == Some(key) || payload.manages(Placement::Cookie, key)) {
                    return Err(invalid("XHTTP cookie is managed by the transport"));
                }
            }
        }
        if mode != Mode::PacketUp && payload.placement != DataPlacement::Body {
            return Err(invalid("XHTTP header/cookie uplink data requires packet-up"));
        }
        let upload_method = opts.uplink_http_method.as_deref().filter(|method| !method.is_empty())
            .unwrap_or("POST").parse::<Method>().map_err(invalid)?;
        if matches!(upload_method, Method::CONNECT | Method::HEAD | Method::TRACE | Method::OPTIONS) {
            return Err(invalid("unsupported XHTTP uplink HTTP method"));
        }
        if upload_method == Method::GET && mode != Mode::PacketUp {
            return Err(invalid("XHTTP GET uplink requires packet-up"));
        }
        let options = Self {
            host_header: HeaderValue::from_str(authority.as_str()).map_err(invalid)?,
            padding_url: format!("{}://{authority}{path}", if secure { "https" } else { "http" }),
            mode, version, secure, reality, authority, path, query: query.to_owned(), headers,
            padding, session, sequence, sessions: SessionId::new(opts)?, payload,
            upload_method, post_bytes,
            interval_ms: range(opts.sc_min_posts_interval_ms.as_deref(), 30..=30, 0..=60_000, "POST interval")?,
            no_grpc_header: opts.no_grpc_header.unwrap_or(false),
        };
        options.request("", None, None, Version::HTTP_2)?;
        Ok(options)
    }

    pub(super) fn session(&self) -> String { self.sessions.generate() }

    pub(super) fn packet_request(
        &self, session: &str, sequence: u64, bytes: Bytes, version: Version,
    ) -> io::Result<Request<RequestBody>> {
        let mut headers = self.headers.clone();
        let body = self.payload.body(&mut headers, bytes)?;
        self.build(session, Some(sequence), Some(body), version, headers)
    }

    pub(super) fn request(
        &self, session: &str, sequence: Option<u64>, body: Option<RequestBody>, version: Version,
    ) -> io::Result<Request<RequestBody>> {
        self.build(session, sequence, body, version, self.headers.clone())
    }

    fn build(
        &self, session: &str, sequence: Option<u64>, body: Option<RequestBody>,
        version: Version, mut headers: HeaderMap,
    ) -> io::Result<Request<RequestBody>> {
        let streaming = body.is_some() && sequence.is_none();
        let mut path = self.path.clone();
        let mut query = self.query.clone();
        let scheme = if self.secure { "https" } else { "http" };
        self.padding.apply(&mut headers, &mut query, &self.padding_url, streaming, version)?;
        if !session.is_empty() { self.session.apply(&mut path, &mut query, &mut headers, session)?; }
        if let Some(sequence) = sequence {
            self.sequence.apply(&mut path, &mut query, &mut headers, &sequence.to_string())?;
        }
        if !query.is_empty() { path.push('?'); path.push_str(&query); }
        let uri = Uri::builder().scheme(scheme).authority(self.authority.clone())
            .path_and_query(path).build().map_err(invalid)?;
        let mut request = Request::builder().uri(uri).version(version)
            .method(if body.is_some() { self.upload_method.clone() } else { Method::GET })
            .body(body.unwrap_or_else(RequestBody::empty)).map_err(invalid)?;
        headers.insert(HOST, self.host_header.clone());
        if streaming && !self.no_grpc_header {
            headers.entry(CONTENT_TYPE).or_insert(HeaderValue::from_static("application/grpc"));
        }
        *request.headers_mut() = headers;
        Ok(request)
    }
}
