use std::{sync::{Arc, atomic::Ordering}, time::Duration};
use http::{Method, Version};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, time::timeout};
use crate::config::internal::proxy::XHttpOpt;
use super::{Client, options, server::Server};

async fn exchange(client: &Client, server: &Arc<Server>, h2: bool, bytes: &[u8]) {
    let mut stream = client.connect_with_factories(server.factory(h2), None).await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let mut received = Vec::new();
    let (read, write) = tokio::join!(reader.read_to_end(&mut received), async {
        writer.write_all(bytes).await?;
        writer.flush().await?;
        writer.shutdown().await
    });
    read.unwrap(); write.unwrap();
    assert_eq!(received, bytes);
}

#[tokio::test]
async fn xhttp_header_cookie_upload_and_custom_methods_round_trip() {
    timeout(Duration::from_secs(15), async {
        let payload: Vec<_> = (0..8193).map(|index| (index % 251) as u8).collect();
        for h2 in [false, true] {
            for placement in ["body", "header", "cookie"] {
                for method in ["POST", "PUT", "GET", "PATCH", "DELETE"] {
                    let opts = XHttpOpt {
                        uplink_data_placement: Some(placement.into()), uplink_data_key: Some("Data".into()),
                        uplink_chunk_size: Some("64-128".into()), uplink_http_method: Some(method.into()),
                        session_placement: Some("query".into()), session_key: Some("auth".into()),
                        seq_placement: Some("header".into()), seq_key: Some("X-Offset".into()),
                        ..options("packet-up")
                    };
                    let mut state = Server::new(payload.len()); state.options = opts.clone();
                    let server = Arc::new(state);
                    let client = Client::new(&opts, "example.test", false, false,
                        Some(&[if h2 { "h2" } else { "http/1.1" }.into()])).unwrap();
                    exchange(&client, &server, h2, &payload).await;
                    let captures = server.captures.lock();
                    assert!(captures.iter().filter(|capture| capture.sequence.is_some())
                        .all(|capture| capture.method == method));
                    if placement == "header" {
                        assert!(captures.iter().any(|capture| capture.headers.contains_key("data-1")));
                    }
                }
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_parallel_packets_are_reassembled_in_sequence() {
    timeout(Duration::from_secs(10), async {
        for h2 in [false, true] {
            let payload = vec![7; 262_177];
            let mut state = Server::new(payload.len()); state.delay_first_packet = true;
            let server = Arc::new(state);
            let client = Client::new(&options("packet-up"), "example.test", false, false,
                Some(&[if h2 { "h2" } else { "http/1.1" }.into()])).unwrap();
            exchange(&client, &server, h2, &payload).await;
            assert!(server.max_uploads.load(Ordering::Acquire) > 1);
            assert!(server.max_uploads.load(Ordering::Acquire) <= 16);
        }
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_buffered_response_headers_do_not_block_upload() {
    timeout(Duration::from_secs(10), async {
        for mode in ["packet-up", "stream-up", "stream-one"] {
            let mut state = Server::new(8193); state.delay_headers = true; state.options = options(mode);
            let server = Arc::new(state);
            let client = Client::new(&options(mode), "example.test", false, false, Some(&["h2".into()])).unwrap();
            let stream = timeout(Duration::from_millis(200), client.connect_with_factories(server.factory(true), None)).await.unwrap().unwrap();
            drop(stream);
            exchange(&client, &server, true, &vec![5; 8193]).await;
        }
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_independent_download_uses_its_own_http_version_host_and_path() {
    timeout(Duration::from_secs(10), async {
        for mode in ["packet-up", "stream-up"] {
            let opts = options(mode);
            let mut upload = Server::new(131_077); upload.options = opts.clone();
            let upload = Arc::new(upload);
            let mut download = Server::new(131_077); download.options = opts.clone();
            download.options.path = Some("/download".into()); download.share_sessions(&upload);
            let download = Arc::new(download);
            let mut download_opts = opts.clone(); download_opts.path = Some("/download".into());
            download_opts.mode = Some("packet-up".into()); download_opts.host = Some("download.example".into());
            let mut client = Client::new(&opts, "upload.example", false, false, Some(&["http/1.1".into()])).unwrap();
            client.configure_download(&download_opts, "different.example".into(), 8443, None, Some(&["h2".into()])).unwrap();
            let mut stream = client.connect_with_factories(upload.factory(false), Some(download.factory(true))).await.unwrap();
            let payload = vec![9; 131_077];
            let mut received = Vec::new();
            let (mut reader, mut writer) = tokio::io::split(&mut stream);
            let (read, write) = tokio::join!(reader.read_to_end(&mut received), async {
                writer.write_all(&payload).await?; writer.shutdown().await
            });
            read.unwrap(); write.unwrap(); assert_eq!(received, payload);
            assert!(upload.captures.lock().iter().all(|capture| capture.method == Method::POST && capture.version == Version::HTTP_11));
            assert!(download.captures.lock().iter().all(|capture| capture.method == Method::GET
                && capture.version == Version::HTTP_2 && capture.headers["host"] == "download.example"
                && capture.uri.path().starts_with("/download/")));
        }
    }).await.unwrap();
}

#[tokio::test]
async fn xhttp_http1_upload_redials_after_clean_connection_close() {
    timeout(Duration::from_secs(10), async {
        let mut state = Server::new(8 * 500); state.close_post = true;
        let server = Arc::new(state);
        let client = Client::new(&options("packet-up"), "example.test", false, false, Some(&["http/1.1".into()])).unwrap();
        let mut stream = client.connect_with_factories(server.factory(false), None).await.unwrap();
        let mut received = Vec::new();
        let (mut reader, mut writer) = tokio::io::split(&mut stream);
        let (read, write) = tokio::join!(reader.read_to_end(&mut received), async {
            for _ in 0..8 { writer.write_all(&vec![3; 500]).await?; writer.flush().await?; }
            writer.shutdown().await
        });
        read.unwrap(); write.unwrap(); assert_eq!(received, vec![3; 4000]);
        assert!(server.connections.load(Ordering::Acquire) >= 9);
    }).await.unwrap();
}
