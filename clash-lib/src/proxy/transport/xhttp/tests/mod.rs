mod server;
mod requests;
mod advanced;
mod pooling;

use std::{collections::HashMap, io, sync::Arc, time::Duration};
use bytes::Bytes;
use http::{Method, StatusCode, Version};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, time::timeout};
use uuid::Uuid;

use crate::{
    config::internal::proxy::XHttpOpt,
    proxy::AnyStream,
};
use super::{Client, body::RequestBody, options::{Mode, Options}};
use self::server::Server;

fn options(mode: &str) -> XHttpOpt {
    XHttpOpt {
        mode: Some(mode.into()), path: Some("test?token=abc".into()),
        sc_min_posts_interval_ms: Some("0".into()),
        sc_max_each_post_bytes: Some("32768".into()),
        ..Default::default()
    }
}

#[test]
fn xhttp_request_format_and_validation() {
    let mut opts = options("packet-up");
    opts.headers = Some(HashMap::from([("Host".into(), "cdn.example:8443".into()),
        ("User-Agent".into(), "test-agent".into())]));
    let compiled = Options::new(&opts, "fallback.example", true, false, None).unwrap();
    let request = compiled.request("session", Some(3),
        Some(RequestBody::empty()), Version::HTTP_2).unwrap();
    assert_eq!(request.uri(), "https://cdn.example:8443/test/session/3?token=abc");
    assert_eq!(request.headers()["host"], "cdn.example:8443");
    assert_eq!(request.headers()["user-agent"], "test-agent");
    assert!(!request.headers().contains_key("content-type"));
    let referer = request.headers()["referer"].to_str().unwrap();
    let padding = referer.split_once("x_padding=").unwrap().1;
    assert!((100..=1000).contains(&padding.len()));
    assert!(padding.bytes().all(|byte| byte == b'X'));
    let (_, body) = tokio::sync::mpsc::channel(1);
    let request = compiled.request("session", None,
        Some(RequestBody::Stream(body)), Version::HTTP_11).unwrap();
    assert!(!request.headers().contains_key("referer"));
    let query = request.uri().query().unwrap();
    assert!(query.starts_with("token=abc&x_padding="));
    assert!((100..=1000).contains(&query.split_once("x_padding=").unwrap().1.len()));
    opts.no_grpc_header = Some(true);
    let compiled = Options::new(&opts, "host", true, false, None).unwrap();
    let (_, body) = tokio::sync::mpsc::channel(1);
    let request = compiled.request("session", None,
        Some(RequestBody::Stream(body)), Version::HTTP_2).unwrap();
    assert!(!request.headers().contains_key("content-type"));
    assert_eq!(Options::new(&XHttpOpt::default(), "host", true, true, None).unwrap().mode, Mode::StreamOne);
    assert_eq!(Options::new(&XHttpOpt::default(), "host", false, false, None).unwrap().mode, Mode::PacketUp);
    for mode in ["bad", "stream-down"] {
        let opts = XHttpOpt { mode: Some(mode.into()), ..Default::default() };
        assert!(Client::new(&opts, "host", false, false, None).is_err());
    }
    assert!(Client::new(&options("stream-one"), "host", false, false, Some(&["http/1.1".into()])).is_err());
    for invalid in [ "4294967295", "5-1", "a-3"] {
        let opts = XHttpOpt { x_padding_bytes: Some(invalid.into()), ..Default::default() };
        assert!(Client::new(&opts, "host", false, false, None).is_err());
    }
    for name in ["connection", "content-length", "referer", "invalid\nname"] {
        let opts = XHttpOpt { headers: Some(HashMap::from([(name.into(), "value".into())])),
            ..Default::default() };
        assert!(Client::new(&opts, "host", false, false, None).is_err());
    }
    for host in ["", "host/path", "user@host", "host\n"] {
        assert!(Client::new(&XHttpOpt::default(), host, false, false, None).is_err());
    }
    for path in ["/?x_padding=bad", "/?x%5fpadding=bad"] {
        let opts = XHttpOpt { path: Some(path.into()), ..Default::default() };
        assert!(Client::new(&opts, "host", false, false, None).is_err());
    }
    let unsupported = r#"{"extra":{"downloadSettings":{}}}"#;
    assert!(serde_json::from_str::<XHttpOpt>(unsupported).is_err());
    for unsupported in [r#"{"extra":{"xPaddingBytes":"100-1000"}}"#,
        r#"{"http-version":"2"}"#, r#"{"xPaddingBytes":"100-1000"}"#] {
        assert!(serde_json::from_str::<XHttpOpt>(unsupported).is_err());
    }
}

#[tokio::test]
async fn xhttp_modes_round_trip_and_preserve_packet_sequence() {
    timeout(Duration::from_secs(15), async {
        for h2 in [false, true] {
            for mode in ["packet-up", "stream-up", "stream-one"] {
                if !h2 && mode == "stream-one" { continue; }
                let payload: Vec<u8> = (0..262_177).map(|index| (index % 251) as u8).collect();
                let mut state = Server::new(payload.len());
                state.options = options(mode);
                let server = Arc::new(state);
                let client = Client::new(&options(mode), "example.test", false, false,
                    Some(&[if h2 { "h2" } else { "http/1.1" }.into()])).unwrap();
                let mut stream = client.connect_with_factories(server.factory(h2), None).await.unwrap();
                assert!(matches!(stream, AnyStream::XHttp(_)));
                assert_eq!(stream.write(&[]).await.unwrap(), 0);
                assert_eq!(stream.read(&mut []).await.unwrap(), 0);
                let mut received = Vec::new();
                let (mut reader, mut writer) = tokio::io::split(&mut stream);
                let (read, write) = tokio::join!(
                    reader.read_to_end(&mut received),
                    async {
                        writer.write_all(&payload).await?;
                        writer.flush().await?;
                        writer.shutdown().await
                    },
                );
                read.unwrap(); write.unwrap();
                assert_eq!(received, payload, "mode={mode}, h2={h2}");
                stream.shutdown().await.unwrap();
                assert_eq!(stream.write(b"after EOF").await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
                let captures = server.captures.lock();
                let expected_version = if h2 { Version::HTTP_2 } else { Version::HTTP_11 };
                assert!(captures.iter().all(|capture| capture.version == expected_version));
                if mode == "stream-one" {
                    assert_eq!(captures.len(), 1);
                    assert_eq!(captures[0].uri.path(), "/test/");
                    assert_eq!(captures[0].headers["content-type"], "application/grpc");
                } else {
                    let download = captures.iter().find(|capture| capture.method == Method::GET).unwrap();
                    let session = download.uri.path().strip_prefix("/test/").unwrap();
                    Uuid::parse_str(session).unwrap();
                    let mut posts: Vec<_> = captures.iter().filter(|capture| capture.method == Method::POST).collect();
                    posts.sort_by_key(|post| post.sequence);
                    if mode == "stream-up" {
                        assert_eq!(posts.len(), 1);
                        assert_eq!(posts[0].uri.path(), download.uri.path());
                    } else {
                        let mut uploaded = Vec::new();
                        for (sequence, post) in posts.iter().enumerate() {
                            assert_eq!(post.uri.path(), format!("/test/{session}/{sequence}"));
                            assert!(post.body.len() <= 32_768);
                            uploaded.extend_from_slice(&post.body);
                        }
                        assert_eq!(uploaded, payload);
                    }
                }
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_rejects_non_success_responses_and_upload_errors_wake_readers() {
    timeout(Duration::from_secs(5), async {
        for h2 in [false, true] {
            for reject_download in [true, false] {
                let mut state = Server::new(1);
                if reject_download { state.get_status = StatusCode::FORBIDDEN; }
                else { state.post_status = StatusCode::CONFLICT; }
                let server = Arc::new(state);
                let client = Client::new(&options("packet-up"), "example.test", false, false,
                    Some(&[if h2 { "h2" } else { "http/1.1" }.into()])).unwrap();
                let result = client.connect_with_factories(server.factory(h2), None).await;
                if reject_download {
                    let mut stream = result.unwrap();
                    let error = stream.read(&mut [0; 1]).await.unwrap_err();
                    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
                    continue;
                }
                let mut stream = result.unwrap();
                stream.write_all(b"x").await.unwrap();
                let (mut reader, mut writer) = tokio::io::split(&mut stream);
                let mut buf = [0; 1];
                let (read, flush) = tokio::join!(reader.read(&mut buf), writer.flush());
                assert_eq!(read.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
                assert_eq!(flush.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_streaming_post_rejection_is_propagated() {
    timeout(Duration::from_secs(5), async {
        for mode in ["stream-up", "stream-one"] {
            let mut state = Server::new(1);
            state.post_status = StatusCode::CONFLICT;
            let server = Arc::new(state);
            let client = Client::new(&options(mode), "example.test", false, false,
                Some(&["h2".into()])).unwrap();
            let result = client.connect_with_factories(server.factory(true), None).await;
            let error = match result {
                Err(error) => error,
                Ok(mut stream) => {
                    let mut buf = [0; 1];
                    let error = stream.read(&mut buf).await.unwrap_err();
                    assert_eq!(stream.flush().await.unwrap_err().kind(), error.kind());
                    error
                }
            };
            assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
            assert!(error.to_string().contains("409"));
        }
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_upload_backpressure_is_bounded() {
    let mut state = Server::new(4_194_304);
    state.post_delay = Duration::from_secs(5);
    let server = Arc::new(state);
    let client = Client::new(&options("packet-up"), "example.test", false, false,
                Some(&["h2".into()])).unwrap();
    let mut stream = client.connect_with_factories(server.factory(true), None).await.unwrap();
    let payload = Bytes::from(vec![7; 4_194_304]);
    assert!(timeout(Duration::from_millis(100), stream.write_all(&payload)).await.is_err());
    drop(stream);
}

#[tokio::test]
async fn xhttp_streaming_upload_backpressure_is_bounded() {
    for mode in ["stream-up", "stream-one"] {
        let mut state = Server::new(4_194_304);
        state.post_delay = Duration::from_secs(5);
        state.options = options(mode);
        let server = Arc::new(state);
        let client = Client::new(&options(mode), "example.test", false, false,
            Some(&["h2".into()])).unwrap();
        let mut stream = client.connect_with_factories(server.factory(true), None).await.unwrap();
        let payload = vec![7; 4_194_304];
        assert!(timeout(Duration::from_millis(100), stream.write_all(&payload)).await.is_err());
        drop(stream);
    }
}
