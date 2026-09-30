use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
use super::splice::zero_copy_bidirectional;

#[tokio::test]
async fn buffered_statistics_include_writes_before_error() {
    use crate::app::dispatcher::{StatisticsManager, TrackerInfo};
    use std::sync::{Arc, atomic::Ordering};

    let mut a = tokio_test::io::Builder::new().read(b"abcdef").build();
    let mut b = tokio_test::io::Builder::new()
        .write(b"abc")
        .write_error(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        .build();
    let info = Arc::new(TrackerInfo::default());
    let tracker = TrafficTracker::new(info.clone(), StatisticsManager::new());
    let result = copy_buf_bidirectional_with_timeout(
        &mut a,
        &mut b,
        1024,
        Duration::from_secs(10),
        Duration::from_secs(10),
        tracker,
    )
    .await;
    assert!(
        matches!(result, Err(CopyBidirectionalError::LeftClosed(err)) if err.kind() == io::ErrorKind::BrokenPipe)
    );
    assert_eq!(info.upload_total.load(Ordering::Relaxed), 3);
    assert_eq!(info.download_total.load(Ordering::Relaxed), 0);
}

async fn check_progress<S>(
    copy: impl Future<Output = Result<(u64, u64), CopyBidirectionalError>>,
    mut source: S,
    mut sink: S,
    timeout: Duration,
    reverse: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::pin!(copy);
    source.shutdown().await.unwrap();
    let mut byte = [0];
    tokio::select! {
        res = &mut copy => panic!("copy ended before half-close: {res:?}"),
        res = sink.read(&mut byte) => assert_eq!(res.unwrap(), 0),
    }

    // Keep the remaining direction active for more than twice the original
    // deadline. Each successful write must start a fresh inactivity timeout.
    for value in 0..4 {
        tokio::select! {
            res = &mut copy => panic!("active half-closed connection ended: {res:?}"),
            _ = async {
                tokio::time::sleep(timeout * 3 / 5).await;
                sink.write_all(&[value]).await.unwrap();
                source.read_exact(&mut byte).await.unwrap();
                assert_eq!(byte, [value]);
            } => (),
        }
    }

    sink.shutdown().await.unwrap();
    let counts = tokio::time::timeout(timeout, copy)
        .await
        .expect("both EOFs should release the connection immediately")
        .unwrap();
    assert_eq!(counts, if reverse { (4, 0) } else { (0, 4) });
}

#[tokio::test(start_paused = true)]
async fn buffered_half_close_progress() {
    for reverse in [false, true] {
        let (client, mut a) = tokio::io::duplex(64);
        let (mut b, server) = tokio::io::duplex(64);
        let timeout = Duration::from_secs(10);
        let copy = copy_buf_bidirectional_with_timeout(
            &mut a,
            &mut b,
            1024,
            timeout,
            timeout,
            TrafficTracker::noop(),
        );
        let (source, sink) = if reverse {
            (server, client)
        } else {
            (client, server)
        };
        check_progress(copy, source, sink, timeout, reverse).await;
    }
}

#[tokio::test(start_paused = true)]
async fn buffered_half_close_reads_do_not_extend_timeout() {
    for reverse in [false, true] {
        // Fill the remaining direction's destination, then read another byte
        // into the relay buffer without being able to write it out.
        let (client, mut a) = tokio::io::duplex(1);
        let (mut b, server) = tokio::io::duplex(1);
        let (mut source, mut sink) = if reverse {
            (server, client)
        } else {
            (client, server)
        };
        source.shutdown().await.unwrap();
        let timeout = Duration::from_secs(10);
        let mut copy = tokio_test::task::spawn(copy_buf_bidirectional_with_timeout(
            &mut a,
            &mut b,
            1024,
            timeout,
            timeout,
            TrafficTracker::noop(),
        ));
        assert!(copy.poll().is_pending());
        tokio::time::advance(Duration::from_secs(6)).await;
        sink.write_all(b"a").await.unwrap();
        assert!(copy.poll().is_pending());
        tokio::time::advance(Duration::from_secs(6)).await;
        sink.write_all(b"b").await.unwrap();
        assert!(copy.poll().is_pending());
        tokio::time::advance(Duration::from_secs(3)).await;
        assert!(copy.poll().is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        let Poll::Ready(Ok(counts)) = copy.poll() else {
            panic!("reads without successful writes must not postpone release");
        };
        assert_eq!(counts, if reverse { (1, 0) } else { (0, 1) });
    }
}

#[tokio::test(start_paused = true)]
async fn buffered_half_close_idle_timeout() {
    for reverse in [false, true] {
        let (mut client, mut a) = tokio::io::duplex(64);
        let (mut b, mut server) = tokio::io::duplex(64);
        if reverse {
            server.shutdown().await.unwrap();
        } else {
            client.shutdown().await.unwrap();
        }
        let start = tokio::time::Instant::now();
        let counts = copy_buf_bidirectional_with_timeout(
            &mut a,
            &mut b,
            1024,
            Duration::from_secs(7),
            Duration::from_secs(10),
            TrafficTracker::noop(),
        )
        .await
        .unwrap();
        assert_eq!(counts, (0, 0));
        assert_eq!(
            start.elapsed(),
            Duration::from_secs(if reverse { 7 } else { 10 })
        );
    }
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, server) = tokio::join!(
        tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept(),
    );
    (client.unwrap(), server.unwrap().0)
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
#[tokio::test]
async fn zero_copy_half_close_progress() {
    for reverse in [false, true] {
        let (client, mut a) = tcp_pair().await;
        let (mut b, server) = tcp_pair().await;
        let timeout = Duration::from_millis(500);
        let copy = zero_copy_bidirectional(
            &mut a,
            &mut b,
            DownloadTracker::new(TrafficTracker::noop()).into(),
            UploadTracker::new(TrafficTracker::noop()).into(),
            timeout,
            timeout,
        );
        let (source, sink) = if reverse {
            (server, client)
        } else {
            (client, server)
        };
        check_progress(copy, source, sink, timeout, reverse).await;
    }
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
#[tokio::test]
async fn zero_copy_half_close_idle_timeout() {
    for reverse in [false, true] {
        let (mut client, mut a) = tcp_pair().await;
        let (mut b, mut server) = tcp_pair().await;
        if reverse {
            server.shutdown().await.unwrap();
        } else {
            client.shutdown().await.unwrap();
        }
        let duration = Duration::from_millis(100);
        let counts = tokio::time::timeout(
            Duration::from_secs(2),
            zero_copy_bidirectional(
                &mut a,
                &mut b,
                DownloadTracker::new(TrafficTracker::noop()).into(),
                UploadTracker::new(TrafficTracker::noop()).into(),
                duration,
                duration,
            ),
        )
        .await
        .expect("an idle half-closed connection must be released")
        .unwrap();
        assert_eq!(counts, (0, 0));
    }
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
#[tokio::test]
async fn zero_copy_forwards_nested_prefixes_and_counts_them() {
    use crate::app::sniffer::PrefixedStream;
    use crate::proxy::ProxyStream;
    let (mut client, a) = tcp_pair().await;
    let (b, mut server) = tcp_pair().await;
    let mut inner_prefix = SlideBuffer::new(4096);
    inner_prefix.extend_from_slice(b"inner");
    let mut outer_prefix = SlideBuffer::new(4096);
    outer_prefix.extend_from_slice(b"outer");
    let mut a =
        PrefixedStream::new(outer_prefix, PrefixedStream::new(inner_prefix, a));
    assert!(a.underlying_socket().is_none());
    assert!(a.zero_copy_socket().is_some());
    let copy = copy_bidirectional(
        Box::new(a),
        Box::new(b),
        1024,
        Duration::from_secs(10),
        Duration::from_secs(10),
        TrafficTracker::noop(),
    );
    let peers = async {
        client.write_all(b"tail").await.unwrap();
        client.shutdown().await.unwrap();
        // Reply before consuming the request to exercise both directions.
        server.write_all(b"reply").await.unwrap();
        let mut request = Vec::new();
        server.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"outerinnertail");
        server.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"reply");
    };
    let (counts, ()) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(copy, peers)
    })
    .await
    .unwrap();
    assert_eq!(counts.unwrap(), (14, 5));
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
#[tokio::test]
async fn zero_copy_prefix_backpressure_does_not_block_replies() {
    use crate::app::sniffer::PrefixedStream;
    let (mut client, a) = tcp_pair().await;
    let (b, mut server) = tcp_pair().await;
    socket2::SockRef::from(&b)
        .set_send_buffer_size(8192)
        .unwrap();
    let payload = vec![0x42; 1024 * 1024];
    let mut prefix = SlideBuffer::new(payload.len());
    prefix.extend_from_slice(&payload);
    let copy = copy_bidirectional(
        Box::new(PrefixedStream::new(prefix, a)),
        Box::new(b),
        1024,
        Duration::from_secs(10),
        Duration::from_secs(10),
        TrafficTracker::noop(),
    );
    let (reply_seen, reply_seen_rx) = tokio::sync::oneshot::channel();
    let client_io = async {
        client.shutdown().await.unwrap();
        let mut reply = [0; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        reply_seen.send(()).unwrap();
        assert_eq!(client.read(&mut reply).await.unwrap(), 0);
    };
    let server_io = async {
        server.write_all(b"reply").await.unwrap();
        // Delay draining the large request until its response was delivered.
        reply_seen_rx.await.unwrap();
        let mut request = Vec::new();
        server.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, payload);
        server.shutdown().await.unwrap();
    };
    let (counts, (), ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(copy, client_io, server_io)
    })
    .await
    .unwrap();
    assert_eq!(counts.unwrap(), (1024 * 1024, 5));
}
