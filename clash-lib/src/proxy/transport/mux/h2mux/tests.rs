use bytes::Bytes;
use h2::{client::handshake as client_handshake, server::Builder as ServerBuilder};
use http::Response;
use std::{
    io::{self, ErrorKind},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::oneshot;
use tokio::time::timeout;

use super::{
    padding::PaddingStream, pool::H2MuxPool, protocol::*,
    session::H2MuxSession, stream::H2MuxStream,
};
use crate::{
    proxy::{AnyStream, ProxyStream, transport::mux::MuxOption},
    session::SocksAddr,
};

#[tokio::test]
async fn test_h2mux_shutdown_without_capacity_is_idempotent() {
    check_shutdown(false).await;
}

#[tokio::test]
async fn test_h2mux_shutdown_after_send_side_closed() {
    check_shutdown(true).await;
}

async fn check_shutdown(end_stream: bool) {
    let (client, peer) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut builder = ServerBuilder::new();
        builder.initial_window_size(0);
        let mut conn = builder.handshake::<_, Bytes>(peer).await.unwrap();
        let (req, mut respond) = conn.accept().await.unwrap().unwrap();
        let task = tokio::spawn(async move {
            let response = Response::builder().status(200).body(()).unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from_static(&[STATUS_SUCCESS, b'x']), false).unwrap();
            let mut recv = req.into_body();
            while let Some(data) = recv.data().await {
                assert!(data.unwrap().is_empty());
            }
            send.send_data(Bytes::from_static(b"y"), true).unwrap();
        });
        while conn.accept().await.is_some() {}
        task.await.unwrap();
    });
    let (mut sender, conn) = client_handshake(client).await.unwrap();
    let driver = tokio::spawn(conn);
    let (response, send) = sender.send_request(build_h2_connect_request().unwrap(), end_stream).unwrap();
    let mut stream = H2MuxStream::new(response, send, Bytes::new(), None);
    let mut data = [0; 1];
    stream.read_exact(&mut data).await.unwrap();
    assert_eq!(data, [b'x']);
    timeout(Duration::from_secs(1), stream.shutdown())
        .await.unwrap().unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(stream.write_all(b"closed").await.unwrap_err().kind(), ErrorKind::BrokenPipe);
    stream.read_exact(&mut data).await.unwrap();
    assert_eq!(data, [b'y']);
    assert_eq!(stream.read(&mut data).await.unwrap(), 0);
    drop((stream, sender));
    driver.abort();
    server.await.unwrap();
}

#[test]
fn test_mux_option_validation() {
    use crate::proxy::transport::mux::MuxProtocol;

    let opt_h2 = MuxOption {
        enable: true,
        protocol: MuxProtocol::H2Mux,
        ..Default::default()
    };
    assert!(opt_h2.validate().is_ok());

    let opt_smux = MuxOption {
        enable: true,
        protocol: MuxProtocol::Smux,
        ..Default::default()
    };
    assert!(opt_smux.validate().is_err());

    let opt_yamux = MuxOption {
        enable: true,
        protocol: MuxProtocol::Yamux,
        ..Default::default()
    };
    assert!(opt_yamux.validate().is_err());
}

#[test]
fn test_stream_request_encoding() {
    let req_ip =
        StreamRequest::new(SocksAddr::Ip("1.2.3.4:80".parse().unwrap()), false);
    let bytes_ip = req_ip.encode().unwrap();
    assert_eq!(&bytes_ip[..3], &[0x00, 0x00, 0x01]); // flags=0, type=1 (ipv4)

    let req_domain =
        StreamRequest::new(SocksAddr::Domain("example.com".into(), 443), false);
    let bytes_domain = req_domain.encode().unwrap();
    assert_eq!(&bytes_domain[..4], &[0x00, 0x00, 0x03, 11]); // flags=0, type=3, len=11
}

#[tokio::test]
async fn test_h2mux_session_echo_and_concurrency() {
    session_echo_and_concurrency(false).await;
}

#[tokio::test]
async fn test_h2mux_padded_session_echo_and_concurrency() {
    session_echo_and_concurrency(true).await;
}

async fn session_echo_and_concurrency(padding_enabled: bool) {
    let (client_io, mut server_io) = tokio::io::duplex(1024 * 1024);

    // Spawn mock sing-box H2Mux server
    tokio::spawn(async move {
        // 1. Read session request header (version + protocol)
        let version = server_io.read_u8().await.unwrap();
        let protocol = server_io.read_u8().await.unwrap();
        assert_eq!(protocol, PROTOCOL_H2MUX);
        if version == VERSION_1 {
            let padding = server_io.read_u8().await.unwrap();
            if padding != 0 {
                let pad_len = server_io.read_u16().await.unwrap();
                let mut pad = vec![0u8; pad_len as usize];
                server_io.read_exact(&mut pad).await.unwrap();
            }
        }

        let mut server_io = AnyStream::new(server_io);
        if padding_enabled {
            assert_eq!(version, VERSION_1);
            server_io = AnyStream::new(PaddingStream::new(server_io));
        }

        // 2. HTTP/2 handshake
        let mut server = h2::server::handshake(server_io).await.unwrap();
        while let Some(Ok((req, mut respond))) = server.accept().await {
            assert_eq!(req.method(), http::Method::CONNECT);
            assert_eq!(
                req.uri().to_string(),
                format!("{MUX_DESTINATION_HOST}:{MUX_DESTINATION_PORT}")
            );

            tokio::spawn(async move {
                let response = Response::builder().status(200).body(()).unwrap();
                let mut send_stream =
                    respond.send_response(response, false).unwrap();
                let mut recv_stream = req.into_body();

                // Send sing-box StreamResponse success (0x00)
                let _ = send_stream
                    .send_data(Bytes::from_static(&[STATUS_SUCCESS]), false);

                let mut first_frame = true;
                while let Some(Ok(chunk)) = recv_stream.data().await {
                    let len = chunk.len();
                    let _ = recv_stream.flow_control().release_capacity(len);

                    if first_frame {
                        // Skip the stream request header (flags + address) in echo test
                        first_frame = false;
                        // Minimum StreamRequest size is 2 (flags) + 1 (addr type) + 4 (ipv4) + 2 (port) = 9
                        if chunk.len() > 9 {
                            let _ = send_stream.send_data(chunk.slice(9..), false);
                        }
                    } else {
                        let _ = send_stream.send_data(chunk, false);
                    }
                }
                let _ = send_stream.send_data(Bytes::new(), true);
            });
        }
    });

    let opt = MuxOption {
        enable: true,
        max_connections: 2,
        min_streams: 2,
        max_streams: 10,
        padding: padding_enabled,
        ..Default::default()
    };

    let session = H2MuxSession::new(AnyStream::new(client_io), opt)
        .await
        .unwrap();

    let invalid = SocksAddr::Domain("x".repeat(256).into(), 80);
    let err = session.open_stream(&invalid, false).await.err().unwrap();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(!session.is_closed());
    assert_eq!(session.active_streams(), 0);

    let dst = SocksAddr::Ip("1.2.3.4:8080".parse().unwrap());

    // Test multiple concurrent streams
    let mut handles = Vec::new();
    for i in 0..5 {
        let session = session.clone();
        let dst = dst.clone();
        handles.push(tokio::spawn(async move {
            let mut stream = session.open_stream(&dst, false).await.unwrap();
            let msg = format!("hello h2mux stream {i}");
            stream.write_all(msg.as_bytes()).await.unwrap();

            let mut buf = vec![0u8; msg.len()];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(String::from_utf8(buf).unwrap(), msg);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    session.retire();
    assert!(session.is_closed());
    assert!(!session.is_available());
}

#[tokio::test]
async fn test_h2mux_pool_dispatch() {
    let opt = MuxOption {
        enable: true,
        max_connections: 2,
        min_streams: 2,
        max_streams: 4,
        padding: false,
        ..Default::default()
    };

    let pool = H2MuxPool::new(opt);

    let dialer = || async {
        let (client_io, mut server_io) = tokio::io::duplex(1024 * 1024);
        tokio::spawn(async move {
            let _version = server_io.read_u8().await.unwrap();
            let _protocol = server_io.read_u8().await.unwrap();
            let mut server = h2::server::handshake(server_io).await.unwrap();
            while let Some(Ok((req, mut respond))) = server.accept().await {
                tokio::spawn(async move {
                    let response = Response::builder().status(200).body(()).unwrap();
                    let mut send_stream =
                        respond.send_response(response, false).unwrap();
                    let mut recv_stream = req.into_body();

                    let _ = send_stream
                        .send_data(Bytes::from_static(&[STATUS_SUCCESS]), false);

                    let mut first = true;
                    while let Some(Ok(chunk)) = recv_stream.data().await {
                        let len = chunk.len();
                        let _ = recv_stream.flow_control().release_capacity(len);
                        if first {
                            first = false;
                            if chunk.len() > 9 {
                                let _ =
                                    send_stream.send_data(chunk.slice(9..), false);
                            }
                        } else {
                            let _ = send_stream.send_data(chunk, false);
                        }
                    }
                    let _ = send_stream.send_data(Bytes::new(), true);
                });
            }
        });
        Ok(AnyStream::new(client_io))
    };

    let dst = SocksAddr::Ip("1.2.3.4:9000".parse().unwrap());

    let mut stream1 = pool.open_stream(&dst, false, dialer).await.unwrap();
    stream1.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream1.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    let mut stream2 = pool.open_stream(&dst, false, dialer).await.unwrap();
    stream2.write_all(b"pong").await.unwrap();
    let mut buf2 = [0u8; 4];
    stream2.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"pong");
}

#[tokio::test]
async fn test_h2mux_pool_does_not_dial_past_connection_limit() {
    let opt = MuxOption {
        enable: true,
        max_connections: 1,
        max_streams: 1,
        padding: false,
        ..Default::default()
    };
    let pool = H2MuxPool::new(opt);
    let dials = Arc::new(AtomicUsize::new(0));
    let dialer = || {
        let dials = dials.clone();
        async move {
            dials.fetch_add(1, Ordering::SeqCst);
            let (client_io, mut server_io) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                server_io.read_u8().await.unwrap();
                server_io.read_u8().await.unwrap();
                let mut server = h2::server::handshake(server_io).await.unwrap();
                while let Some(Ok((_req, mut respond))) = server.accept().await {
                    let response = Response::builder().status(200).body(()).unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    send.send_data(Bytes::from_static(&[STATUS_SUCCESS]), false)
                        .unwrap();
                }
            });
            Ok(AnyStream::new(client_io))
        }
    };
    let dst = SocksAddr::Ip("1.2.3.4:80".parse().unwrap());
    let first = pool.open_stream(&dst, false, dialer).await.unwrap();
    let error = pool.open_stream(&dst, false, dialer).await.err().unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    drop(first);
}

#[tokio::test]
async fn test_h2mux_pool_reuses_session_during_slow_dial() {
    fn mock_carrier() -> AnyStream {
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            server_io.read_u8().await.unwrap();
            server_io.read_u8().await.unwrap();
            let mut server = h2::server::handshake(server_io).await.unwrap();
            while let Some(Ok((_req, mut respond))) = server.accept().await {
                let response = Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                send.send_data(Bytes::from_static(&[STATUS_SUCCESS]), false)
                    .unwrap();
            }
        });
        AnyStream::new(client_io)
    }

    let pool = H2MuxPool::new(MuxOption {
        enable: true,
        max_connections: 2,
        min_streams: 1,
        max_streams: 10,
        padding: false,
        ..Default::default()
    });
    let dst = SocksAddr::Ip("1.2.3.4:80".parse().unwrap());
    let first = pool
        .open_stream(&dst, false, || async { Ok(mock_carrier()) })
        .await
        .unwrap();

    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let release_after_reuse = release.clone();
    let started_wait = started.notified();
    let started_for_dial = started.clone();
    let second_pool = pool.clone();
    let second_dst = dst.clone();
    let second = tokio::spawn(async move {
        second_pool
            .open_stream(&second_dst, false, || {
                let started = started_for_dial.clone();
                let release = release.clone();
                async move {
                    started.notify_one();
                    release.notified().await;
                    Ok(mock_carrier())
                }
            })
            .await
    });
    started_wait.await;

    let third = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        pool.open_stream(&dst, false, || async {
            Err(std::io::Error::other("unexpected carrier dial"))
        }),
    )
    .await
    .expect("existing session must remain available during dial")
    .unwrap();

    release_after_reuse.notify_one();
    let second = second.await.unwrap().unwrap();
    drop((first, second, third));
}

#[tokio::test]
async fn test_h2mux_pool_keep_idle_health_check_switch_and_reselect() {
    use parking_lot::Mutex;

    fn spawn_echo_carrier(
        close_txs: &Arc<Mutex<Vec<oneshot::Receiver<()>>>>,
    ) -> AnyStream {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let (tx, rx) = oneshot::channel();
        close_txs.lock().push(rx);
        tokio::spawn(async move {
            if server_io.read_u8().await.is_err() {
                let _ = tx.send(());
                return;
            }
            if server_io.read_u8().await.is_err() {
                let _ = tx.send(());
                return;
            }
            if let Ok(mut server) = h2::server::handshake(server_io).await {
                while let Some(Ok((req, mut respond))) = server.accept().await {
                    tokio::spawn(async move {
                        let response = Response::builder().status(200).body(()).unwrap();
                        let Ok(mut send) = respond.send_response(response, false) else {
                            return;
                        };
                        let _ = send.send_data(Bytes::from_static(&[STATUS_SUCCESS]), false);
                        let mut recv = req.into_body();
                        let mut header_left = 9usize;
                        while let Some(Ok(chunk)) = recv.data().await {
                            let len = chunk.len();
                            let _ = recv.flow_control().release_capacity(len);
                            let payload = if header_left >= len {
                                header_left -= len;
                                continue;
                            } else if header_left > 0 {
                                let rest = chunk.slice(header_left..);
                                header_left = 0;
                                rest
                            } else {
                                chunk
                            };
                            let _ = send.send_data(payload, false);
                        }
                        let _ = send.send_data(Bytes::new(), true);
                    });
                }
            }
            let _ = tx.send(());
        });
        AnyStream::new(client_io)
    }

    let closed_list = Arc::new(Mutex::new(Vec::new()));
    let pool = H2MuxPool::new(MuxOption {
        enable: true,
        max_connections: 2,
        min_streams: 2,
        max_streams: 8,
        padding: false,
        ..Default::default()
    });
    let dst = SocksAddr::Ip("1.2.3.4:80".parse().unwrap());

    // 1. Health check only (keep_idle = false): carrier closes when stream drops.
    pool.set_keep_idle(false);
    let probe = pool
        .open_stream(&dst, false, || {
            let closed_list = closed_list.clone();
            async move { Ok(spawn_echo_carrier(&closed_list)) }
        })
        .await
        .unwrap();
    assert_eq!(pool.session_count_for_test(), 1);
    drop(probe);
    let closed_rx = closed_list.lock().pop().unwrap();
    timeout(Duration::from_secs(2), closed_rx).await.unwrap().unwrap();
    assert_eq!(pool.session_count_for_test(), 0);

    // 2. Active business then switch away: active carrier stays open until last
    // stream finishes, idle carrier is evicted immediately.
    pool.set_keep_idle(true);
    let mut s1 = pool
        .open_stream(&dst, false, || {
            let closed_list = closed_list.clone();
            async move { Ok(spawn_echo_carrier(&closed_list)) }
        })
        .await
        .unwrap();
    s1.write_all(b"keep-alive-msg").await.unwrap();
    let mut buf = [0u8; 14];
    s1.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"keep-alive-msg");
    assert_eq!(pool.session_count_for_test(), 1);
    let closed_rx1 = closed_list.lock().pop().unwrap();

    // Brief deselect -> reselect reuses active carrier.
    pool.set_keep_idle(false);
    assert_eq!(pool.session_count_for_test(), 1);
    pool.set_keep_idle(true);
    let s2 = pool
        .open_stream(&dst, false, || async {
            panic!("reselected active carrier must be reused");
        })
        .await
        .unwrap();

    // Deselect permanently while both streams are open.
    pool.set_keep_idle(false);
    drop(s2);
    // Still one active stream (s1), carrier must remain open.
    tokio::task::yield_now().await;
    assert_eq!(pool.session_count_for_test(), 1);

    // Final stream writes and drops: bounded graceful close flushes and closes carrier.
    s1.write_all(b"final").await.unwrap();
    s1.shutdown().await.unwrap();
    let mut final_buf = [0u8; 5];
    s1.read_exact(&mut final_buf).await.unwrap();
    assert_eq!(&final_buf, b"final");
    drop(s1);
    timeout(Duration::from_secs(2), closed_rx1).await.unwrap().unwrap();
    assert_eq!(pool.session_count_for_test(), 0);

    // 3. Concurrent dial loses route reference before completion: must not stay in pool.
    pool.set_keep_idle(true);
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let pool_dial = pool.clone();
    let dst_dial = dst.clone();
    let started_tx = started.clone();
    let release_rx = release.clone();
    let closed_dial = closed_list.clone();
    let dial_task = tokio::spawn(async move {
        pool_dial
            .open_stream(&dst_dial, false, || {
                let started = started_tx.clone();
                let release = release_rx.clone();
                let closed_list = closed_dial.clone();
                async move {
                    started.notify_one();
                    release.notified().await;
                    Ok(spawn_echo_carrier(&closed_list))
                }
            })
            .await
    });
    started.notified().await;
    pool.set_keep_idle(false);
    release.notify_one();
    let s3 = dial_task.await.unwrap().unwrap();
    assert_eq!(pool.session_count_for_test(), 1);
    let closed_rx3 = closed_list.lock().pop().unwrap();
    drop(s3);
    timeout(Duration::from_secs(2), closed_rx3).await.unwrap().unwrap();
    assert_eq!(pool.session_count_for_test(), 0);
}

#[tokio::test]
async fn test_h2mux_keep_idle_false_respects_max_connections_and_stream_limits() {
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let closed_list = Arc::new(Mutex::new(Vec::new()));
    let dial_count = Arc::new(AtomicUsize::new(0));
    let pool = H2MuxPool::new(MuxOption {
        enable: true,
        max_connections: 1,
        min_streams: 1,
        max_streams: 2,
        padding: false,
        ..Default::default()
    });
    pool.set_keep_idle(false);

    let dial = || {
        let closed_list = closed_list.clone();
        let dial_count = dial_count.clone();
        async move {
            dial_count.fetch_add(1, Ordering::SeqCst);
            let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
            let (tx, rx) = oneshot::channel();
            closed_list.lock().push(rx);
            tokio::spawn(async move {
                if server_io.read_u8().await.is_ok()
                    && server_io.read_u8().await.is_ok()
                    && let Ok(mut server) = h2::server::handshake(server_io).await
                {
                    while let Some(Ok((_req, mut respond))) = server.accept().await {
                        tokio::spawn(async move {
                            let resp = Response::builder().status(200).body(()).unwrap();
                            if let Ok(mut send) = respond.send_response(resp, false) {
                                let _ = send.send_data(Bytes::from_static(&[STATUS_SUCCESS]), false);
                                let _ = send.send_data(Bytes::new(), true);
                            }
                        });
                    }
                }
                let _ = tx.send(());
            });
            Ok(AnyStream::new(client_io))
        }
    };

    let dst = SocksAddr::Ip("1.2.3.4:80".parse().unwrap());
    let s1 = pool.open_stream(&dst, false, dial).await.unwrap();
    let s2 = pool.open_stream(&dst, false, dial).await.unwrap();
    assert_eq!(dial_count.load(Ordering::SeqCst), 1);
    assert_eq!(pool.session_count_for_test(), 1);

    // Third overlapping stream must hit max_connections=1 * max_streams=2 rather
    // than dialing a second carrier while keep_idle is false.
    let err = pool
        .open_stream(&dst, false, dial)
        .await
        .err()
        .expect("third stream must fail with WouldBlock");
    assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(dial_count.load(Ordering::SeqCst), 1);

    drop(s1);
    tokio::task::yield_now().await;
    assert_eq!(pool.session_count_for_test(), 1);

    drop(s2);
    let closed_rx = closed_list.lock().pop().unwrap();
    timeout(Duration::from_secs(2), closed_rx).await.unwrap().unwrap();
    assert_eq!(pool.session_count_for_test(), 0);
}

#[tokio::test]
async fn test_h2mux_graceful_close_is_bounded_when_peer_stalls() {
    use parking_lot::Mutex;

    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let (dropped_tx, dropped_rx) = oneshot::channel();
    let _server = tokio::spawn(async move {
        let _ = server_io.read_u8().await;
        let _ = server_io.read_u8().await;
        let mut server = h2::server::handshake(server_io).await.unwrap();
        let (_req, mut respond) = server.accept().await.unwrap().unwrap();
        let mut send = respond.send_response(Response::new(()), false).unwrap();
        let _ = send.send_data(Bytes::from_static(&[STATUS_SUCCESS]), false);
        // Deliberately keep `server` and `send` alive without closing the stream.
        futures::future::pending::<()>().await;
    });

    let pool = H2MuxPool::new(MuxOption {
        enable: true,
        max_connections: 1,
        max_streams: 4,
        ..Default::default()
    });
    let holder = Arc::new(Mutex::new(Some(AnyStream::new(client_io))));
    struct NotifyOnDrop(AnyStream, Option<oneshot::Sender<()>>);
    impl ProxyStream for NotifyOnDrop {}
    impl AsyncRead for NotifyOnDrop {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for NotifyOnDrop {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
    impl Drop for NotifyOnDrop {
        fn drop(&mut self) {
            if let Some(tx) = self.1.take() {
                let _ = tx.send(());
            }
        }
    }

    let wrapped = AnyStream::Dynamic(Box::new(NotifyOnDrop(
        holder.lock().take().unwrap(),
        Some(dropped_tx),
    )));
    let wrapped = Arc::new(Mutex::new(Some(wrapped)));
    let dst = SocksAddr::Ip("1.2.3.4:80".parse().unwrap());
    let stream = pool
        .open_stream(&dst, false, || {
            let wrapped = wrapped.clone();
            async move { Ok(wrapped.lock().take().unwrap()) }
        })
        .await
        .unwrap();
    pool.sessions_for_test()[0].set_drain_timeout_for_test(Duration::from_millis(50));
    pool.set_keep_idle(false);
    drop(stream);

    timeout(Duration::from_secs(2), dropped_rx)
        .await
        .expect("bounded drain timeout must drop underlying carrier")
        .unwrap();
}
