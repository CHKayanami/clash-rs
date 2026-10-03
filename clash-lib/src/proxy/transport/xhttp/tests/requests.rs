use std::collections::{HashMap, HashSet};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::Version;
use url::{Url, form_urlencoded};
use crate::config::internal::proxy::XHttpOpt;
use super::super::{options::Options, padding::huffman_bits};
use super::options;
use super::super::body::RequestBody;

fn cookie(value: &str, name: &str) -> String {
    value.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then(|| value.to_owned())
    }).unwrap()
}

#[test]
fn xhttp_metadata_placements_preserve_user_headers_and_query() {
    for session in ["path", "query", "header", "cookie"] {
        for sequence in ["path", "query", "header", "cookie"] {
            let opts = XHttpOpt {
                session_placement: Some(session.into()), session_key: Some("sid".into()),
                seq_placement: Some(sequence.into()), seq_key: Some("seq".into()),
                headers: Some(HashMap::from([("Cookie".into(), "theme=dark".into())])),
                ..options("packet-up")
            };
            let compiled = Options::new(&opts, "example.test", false, false, None).unwrap();
            let request = compiled.packet_request("abc", 7, Bytes::from_static(b"data"), Version::HTTP_2).unwrap();
            let query: HashMap<_, _> = form_urlencoded::parse(request.uri().query().unwrap().as_bytes()).collect();
            assert_eq!(query["token"], "abc");
            assert!(request.headers()["cookie"].to_str().unwrap().contains("theme=dark"));
            for (placement, key, expected) in [(session, "sid", "abc"), (sequence, "seq", "7")] {
                match placement {
                    "path" => assert!(request.uri().path().split('/').any(|part| part == expected)),
                    "query" => assert_eq!(query[key], expected),
                    "header" => assert_eq!(request.headers()[key], expected),
                    "cookie" => assert_eq!(cookie(request.headers()["cookie"].to_str().unwrap(), key), expected),
                    _ => unreachable!(),
                }
            }
        }
    }
}

#[test]
fn xhttp_padding_placements_and_tokenish_huffman_length() {
    for placement in ["header", "queryInHeader", "query", "cookie"] {
        for method in ["repeat-x", "tokenish"] {
            let opts = XHttpOpt {
                x_padding_obfs_mode: Some(true), x_padding_placement: Some(placement.into()),
                x_padding_key: Some("pad".into()), x_padding_header: Some("X-Pad".into()),
                x_padding_method: Some(method.into()), x_padding_bytes: Some("128".into()),
                ..options("packet-up")
            };
            let compiled = Options::new(&opts, "example.test", false, false, None).unwrap();
            for version in [Version::HTTP_11, Version::HTTP_2] {
                let request = compiled.packet_request("abc", 0, Bytes::from_static(b"data"), version).unwrap();
                let padding = match placement {
                    "header" => request.headers()["x-pad"].to_str().unwrap().to_owned(),
                    "queryInHeader" => Url::parse(request.headers()["x-pad"].to_str().unwrap()).unwrap()
                        .query_pairs().find(|(name, _)| name == "pad").unwrap().1.into_owned(),
                    "query" => form_urlencoded::parse(request.uri().query().unwrap().as_bytes())
                        .find(|(name, _)| name == "pad").unwrap().1.into_owned(),
                    "cookie" => cookie(request.headers()["cookie"].to_str().unwrap(), "pad"),
                    _ => unreachable!(),
                };
                assert_eq!(padding.bytes().map(huffman_bits).sum::<usize>().div_ceil(8), 128);
                if method == "repeat-x" { assert_eq!(padding, "X".repeat(128)); }
                else { assert!(padding.bytes().all(|byte| byte.is_ascii_alphanumeric())); }
            }
        }
    }
}

#[test]
fn xhttp_session_tables_and_ranges_are_validated() {
    for (table, length) in [("number", "16"), ("Base62", "16-32"), ("ABCD", "16-20")] {
        let opts = XHttpOpt { session_table: Some(table.into()), session_length: Some(length.into()), ..options("packet-up") };
        let compiled = Options::new(&opts, "example.test", false, false, None).unwrap();
        let mut ids = HashSet::new();
        for _ in 0..32 {
            let id = compiled.session();
            assert!((16..=32).contains(&id.len()));
            if table == "number" { assert!(id.bytes().all(|byte| byte.is_ascii_digit())); }
            assert!(ids.insert(id));
        }
    }
    for (table, length) in [("a", "16"), ("AB", "2"), ("中文", "32"), ("abc", "0-3")] {
        let opts = XHttpOpt { session_table: Some(table.into()), session_length: Some(length.into()), ..options("packet-up") };
        assert!(Options::new(&opts, "example.test", false, false, None).is_err());
    }
    for value in ["0", "0-0", " ", " 100 - 200 "] {
        let opts = XHttpOpt { x_padding_bytes: Some(value.into()), ..options("packet-up") };
        assert!(Options::new(&opts, "example.test", false, false, None).is_ok());
    }
    for (placement, key) in [("unknown", "id"), ("cookie", "bad;key"), ("header", "content-length")] {
        let opts = XHttpOpt { session_placement: Some(placement.into()), session_key: Some(key.into()), ..options("packet-up") };
        assert!(Options::new(&opts, "example.test", false, false, None).is_err());
    }
    let opts = XHttpOpt { uplink_data_placement: Some("cookie".into()), ..options("stream-up") };
    assert!(Options::new(&opts, "example.test", false, false, None).is_err());
}

#[test]
fn xhttp_rejects_colliding_metadata_padding_and_payload_keys() {
    let cases = [
        XHttpOpt { session_placement: Some("header".into()), session_key: Some("Referer".into()), ..options("packet-up") },
        XHttpOpt { session_placement: Some("query".into()), session_key: Some("x_padding".into()), ..options("packet-up") },
        XHttpOpt { seq_placement: Some("header".into()), seq_key: Some("X-Data-0".into()),
            uplink_data_placement: Some("header".into()), ..options("packet-up") },
        XHttpOpt { session_placement: Some("cookie".into()), session_key: Some("x_data_0".into()),
            uplink_data_placement: Some("cookie".into()), ..options("packet-up") },
        XHttpOpt { headers: Some(HashMap::from([("Cookie".into(), "x_session=fixed".into())])),
            session_placement: Some("cookie".into()), ..options("packet-up") },
        XHttpOpt { uplink_http_method: Some("GET".into()), ..options("stream-one") },
        XHttpOpt { uplink_http_method: Some("OPTIONS".into()), ..options("packet-up") },
    ];
    for opts in cases {
        assert!(Options::new(&opts, "example.test", false, false, None).is_err());
    }
}

#[test]
fn xhttp_grpc_header_preserves_metadata_padding_and_user_content_type() {
    let cases = [
        (XHttpOpt { session_placement: Some("header".into()), session_key: Some("Content-Type".into()),
            ..options("stream-up") }, "session"),
        (XHttpOpt { x_padding_obfs_mode: Some(true), x_padding_placement: Some("header".into()),
            x_padding_header: Some("Content-Type".into()), x_padding_bytes: Some("100".into()),
            ..options("stream-one") }, &"X".repeat(100)),
        (XHttpOpt { headers: Some(HashMap::from([("Content-Type".into(), "custom/type".into())])),
            ..options("stream-up") }, "custom/type"),
    ];
    for (opts, expected) in cases {
        let compiled = Options::new(&opts, "example.test", false, false, Some(&["h2".into()])).unwrap();
        let (_, receiver) = tokio::sync::mpsc::channel(1);
        let request = compiled.request("session", None, Some(RequestBody::Stream(receiver)), Version::HTTP_2).unwrap();
        assert_eq!(request.headers()["content-type"], expected);
    }
}

#[test]
fn xhttp_cookie_payload_many_chunks_preserves_cookie_and_bytes() {
    let opts = XHttpOpt {
        uplink_data_placement: Some("cookie".into()), uplink_chunk_size: Some("64".into()),
        headers: Some(HashMap::from([("Cookie".into(), "theme=dark".into())])),
        ..options("packet-up")
    };
    let compiled = Options::new(&opts, "example.test", false, false, None).unwrap();
    let bytes = Bytes::from(vec![7; 131_072]);
    let request = compiled.packet_request("session", 0, bytes.clone(), Version::HTTP_2).unwrap();
    let encoded: String = request.headers()["cookie"].to_str().unwrap().split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(key, _)| key.starts_with("x_data_"))
        .map(|(_, value)| value).collect();
    let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
    assert_eq!(decoded, bytes);
    assert!(request.headers()["cookie"].to_str().unwrap().starts_with("theme=dark; x_data_0="));
}
