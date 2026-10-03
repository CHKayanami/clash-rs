use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderMap, Uri};
use url::form_urlencoded;
use crate::config::internal::proxy::XHttpOpt;

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get("cookie")?.to_str().ok()?.split(';').find_map(|pair| {
        let (key, value) = pair.trim().split_once('=')?;
        (key == name).then(|| value.to_owned())
    })
}

fn value(placement: &str, key: &str, uri: &Uri, headers: &HeaderMap) -> Option<String> {
    match placement {
        "header" => headers.get(key)?.to_str().ok().map(str::to_owned),
        "cookie" => cookie(headers, key),
        "query" => form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
            .find_map(|(name, value)| (name == key).then(|| value.into_owned())),
        _ => None,
    }
}

pub(super) fn extract(opts: &XHttpOpt, uri: &Uri, headers: &HeaderMap) -> (String, Option<u64>) {
    let session_placement = opts.session_placement.as_deref().unwrap_or("path");
    let seq_placement = opts.seq_placement.as_deref().unwrap_or("path");
    let prefix = opts.path.as_deref().unwrap_or("/").split('?').next().unwrap().trim_matches('/');
    let path = uri.path().trim_start_matches('/').strip_prefix(prefix).unwrap().trim_start_matches('/');
    let mut parts = path.split('/').filter(|part| !part.is_empty());
    let session = if session_placement == "path" { parts.next().unwrap_or("").to_owned() }
        else { value(session_placement, opts.session_key.as_deref().unwrap_or(
            if session_placement == "header" { "X-Session" } else { "x_session" }), uri, headers).unwrap_or_default() };
    let sequence = if seq_placement == "path" { parts.next().map(str::to_owned) }
        else { value(seq_placement, opts.seq_key.as_deref().unwrap_or(
            if seq_placement == "header" { "X-Seq" } else { "x_seq" }), uri, headers) };
    (session, sequence.and_then(|value| value.parse().ok()))
}

pub(super) fn data(opts: &XHttpOpt, headers: &HeaderMap) -> Option<Vec<u8>> {
    let placement = opts.uplink_data_placement.as_deref().unwrap_or("body");
    if !matches!(placement, "header" | "cookie") { return None; }
    let key = opts.uplink_data_key.as_deref().unwrap_or(
        if opts.uplink_data_placement.as_deref() == Some("cookie") { "x_data" } else { "X-Data" });
    let mut encoded = String::new();
    for index in 0.. {
        let value = if placement == "header" {
            headers.get(format!("{key}-{index}"))
                .map(|value| value.to_str().unwrap().to_owned())
        } else { cookie(headers, &format!("{key}_{index}")) };
        let Some(value) = value else { break; };
        encoded.push_str(&value);
    }
    Some(URL_SAFE_NO_PAD.decode(encoded).unwrap())
}
