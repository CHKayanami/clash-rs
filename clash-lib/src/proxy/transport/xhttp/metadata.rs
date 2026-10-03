use std::io;
use http::{HeaderMap, HeaderName, HeaderValue};
use http::header::COOKIE;
use url::form_urlencoded;

use super::range::invalid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Placement { Path, Query, Header, Cookie }

pub(super) struct Metadata {
    pub(super) placement: Placement,
    pub(super) key: String,
    header: Option<HeaderName>,
}

pub(super) fn cookie(headers: &mut HeaderMap, key: &str, value: &str) -> io::Result<()> {
    let mut cookies = cookie_buffer(headers)?;
    append_cookie(&mut cookies, key, value);
    headers.insert(COOKIE, HeaderValue::from_str(&cookies).map_err(invalid)?);
    Ok(())
}

pub(super) fn cookie_buffer(headers: &HeaderMap) -> io::Result<String> {
    headers.get(COOKIE).map(|value| value.to_str().map(str::to_owned))
        .transpose().map_err(invalid).map(Option::unwrap_or_default)
}

pub(super) fn append_cookie(cookies: &mut String, key: &str, value: &str) {
    if !cookies.is_empty() { cookies.push_str("; "); }
    cookies.push_str(key);
    cookies.push('=');
    cookies.push_str(value);
}

pub(super) fn query_set(query: &mut String, key: &str, value: &str) {
    let mut pairs: Vec<_> = form_urlencoded::parse(query.as_bytes())
        .filter(|(name, _)| name != key).map(|(name, value)| (name.into_owned(), value.into_owned())).collect();
    pairs.push((key.to_owned(), value.to_owned()));
    *query = form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish();
}

pub(super) fn valid_key(key: &str) -> io::Result<()> {
    if key.is_empty() || !key.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_-.$".contains(&byte)) {
        return Err(invalid("invalid XHTTP metadata/cookie key"));
    }
    Ok(())
}

impl Metadata {
    pub(super) fn new(placement: Option<&str>, key: Option<&str>, name: &str) -> io::Result<Self> {
        let placement = match placement.unwrap_or("path") {
            "" | "path" => Placement::Path,
            "query" => Placement::Query,
            "header" => Placement::Header,
            "cookie" => Placement::Cookie,
            other => return Err(invalid(format!("unsupported XHTTP {name} placement: {other}"))),
        };
        let default = match (placement, name) {
            (Placement::Header, "session") => "X-Session",
            (Placement::Header, _) => "X-Seq",
            (_, "session") => "x_session",
            _ => "x_seq",
        };
        let key = key.filter(|key| !key.is_empty()).unwrap_or(default).to_owned();
        let header = if placement == Placement::Header {
            let header = key.parse::<HeaderName>().map_err(invalid)?;
            if managed_header(&header) || header == COOKIE { return Err(invalid("reserved XHTTP metadata header")); }
            Some(header)
        } else { valid_key(&key)?; None };
        Ok(Self { placement, key, header })
    }

    pub(super) fn apply(
        &self, path: &mut String, query: &mut String, headers: &mut HeaderMap, value: &str,
    ) -> io::Result<()> {
        match self.placement {
            Placement::Path => {
                if !path.ends_with('/') { path.push('/'); }
                path.push_str(value);
            }
            Placement::Query => query_set(query, &self.key, value),
            Placement::Header => {
                headers.insert(self.header.clone().expect("compiled XHTTP metadata header"),
                    HeaderValue::from_str(value).map_err(invalid)?);
            }
            Placement::Cookie => cookie(headers, &self.key, value)?,
        }
        Ok(())
    }
}

pub(super) fn managed_header(name: &HeaderName) -> bool {
    matches!(name.as_str(), "host" | "connection" | "content-length"
        | "transfer-encoding" | "upgrade" | "te" | "trailer")
}
