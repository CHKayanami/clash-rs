use super::*;
use futures::poll;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, time::{advance, pause, resume, timeout}};

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
use super::splice::zero_copy_bidirectional;

#[tokio::test]
async fn buffered_statistics_include_writes_before_error() {
    use crate::app::dispatcher::{StatisticsManager, TrackerInfo};
    use std::sync::Arc;

    let mut a = tokio_test::io::Builder::new().read(b"abcdef").build();
    let mut b = tokio_test::io::Builder::new()
        .write(b"abc")
        .write_error(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        .build();
    let info = Arc::new(TrackerInfo::default());
    let tracker = TrafficTracker::new(info.clone(), StatisticsManager::new());
    let result = copy_buf_bidirectional(
        &mut a,
        &mut b,
        1024,
        tracker,
    )
    .await;
    assert!(
        matches!(result, Err(CopyBidirectionalError::LeftClosed(err)) if err.kind() == io::ErrorKind::BrokenPipe)
    );
    assert_eq!(info.upload_total(), 3);
    assert_eq!(info.download_total(), 0);
}

async fn check_delayed_reply<S>(
    copy: impl Future<Output = Result<(u64, u64), CopyBidirectionalError>>,
    mut source: S,
    mut sink: S,
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

    // The reverse direction must stay open past the former 10-second limit.
    pause();
    advance(Duration::from_secs(30)).await;
    assert!(poll!(&mut copy).is_pending());
    resume();

    sink.write_all(b"a").await.unwrap();
    sink.shutdown().await.unwrap();
    let counts = timeout(Duration::from_secs(3), async {
        let receive = async {
            source.read_exact(&mut byte).await.unwrap();
            assert_eq!(byte, *b"a");
            assert_eq!(source.read(&mut byte).await.unwrap(), 0);
        };
        let (counts, ()) = tokio::join!(copy, receive);
        counts.unwrap()
    })
    .await
    .expect("delayed reply or shutdown stalled");
    assert_eq!(counts, if reverse { (1, 0) } else { (0, 1) });
}

#[tokio::test]
async fn buffered_half_close_allows_delayed_reply() {
    for reverse in [false, true] {
        let (client, mut a) = tokio::io::duplex(64);
        let (mut b, server) = tokio::io::duplex(64);
        let copy = copy_buf_bidirectional(&mut a, &mut b, 1024, TrafficTracker::noop());
        let (source, sink) = if reverse { (server, client) } else { (client, server) };
        check_delayed_reply(copy, source, sink, reverse).await;
    }
}

#[tokio::test]
async fn owned_copy_half_close_allows_delayed_reply() {
    use crate::proxy::AnyStream;

    for reverse in [false, true] {
        let (client, a) = tokio::io::duplex(64);
        let (b, server) = tokio::io::duplex(64);
        let copy = copy_bidirectional(
            AnyStream::dynamic(a), AnyStream::dynamic(b), 1024, TrafficTracker::noop(),
        );
        let (source, sink) = if reverse { (server, client) } else { (client, server) };
        check_delayed_reply(copy, source, sink, reverse).await;
    }
}

#[tokio::test(start_paused = true)]
async fn buffered_half_close_retains_pending_writes() {
    let (mut client, mut a) = tokio::io::duplex(1);
    let (mut b, mut server) = tokio::io::duplex(1);
    let mut copy = tokio_test::task::spawn(copy_buf_bidirectional(
        &mut a, &mut b, 1024, TrafficTracker::noop(),
    ));
    client.shutdown().await.unwrap();
    assert!(copy.poll().is_pending());
    server.write_all(b"a").await.unwrap();
    assert!(copy.poll().is_pending());
    server.write_all(b"b").await.unwrap();
    assert!(copy.poll().is_pending());

    advance(Duration::from_secs(30)).await;
    assert!(copy.poll().is_pending());
    let mut byte = [0];
    client.read_exact(&mut byte).await.unwrap();
    assert_eq!(byte, *b"a");
    server.shutdown().await.unwrap();
    assert!(matches!(copy.poll(), Poll::Ready(Ok((0, 2)))));
    client.read_exact(&mut byte).await.unwrap();
    assert_eq!(byte, *b"b");
}

async fn check_idle_timeout<S>(
    copy: impl Future<Output = Result<(u64, u64), CopyBidirectionalError>>,
    mut source: S,
    mut sink: S,
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

    pause();
    let remaining = Duration::from_secs(1);
    advance(COPY_IDLE_TIMEOUT - remaining).await;
    assert!(poll!(&mut copy).is_pending());
    advance(remaining).await;
    assert!(matches!(
        poll!(&mut copy),
        Poll::Ready(Err(CopyBidirectionalError::Other(error)))
            if error.kind() == io::ErrorKind::TimedOut
    ));
    resume();
}

#[tokio::test]
async fn buffered_half_close_uses_connection_idle_timeout() {
    let (client, mut a) = tokio::io::duplex(64);
    let (mut b, server) = tokio::io::duplex(64);
    let copy = copy_buf_bidirectional(&mut a, &mut b, 1024, TrafficTracker::noop());
    check_idle_timeout(copy, client, server).await;
}

#[tokio::test]
async fn owned_copy_half_close_uses_connection_idle_timeout() {
    use crate::proxy::AnyStream;

    let (client, a) = tokio::io::duplex(64);
    let (b, server) = tokio::io::duplex(64);
    let copy = copy_bidirectional(
        AnyStream::dynamic(a), AnyStream::dynamic(b), 1024, TrafficTracker::noop(),
    );
    check_idle_timeout(copy, client, server).await;
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
async fn zero_copy_half_close_allows_delayed_reply() {
    for reverse in [false, true] {
        let (client, mut a) = tcp_pair().await;
        let (mut b, server) = tcp_pair().await;
        let copy = zero_copy_bidirectional(&mut a, &mut b, TrafficTracker::noop());
        let (source, sink) = if reverse { (server, client) } else { (client, server) };
        check_delayed_reply(copy, source, sink, reverse).await;
    }
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
#[tokio::test]
async fn zero_copy_half_close_uses_connection_idle_timeout() {
    let (client, mut a) = tcp_pair().await;
    let (mut b, server) = tcp_pair().await;
    let copy = zero_copy_bidirectional(&mut a, &mut b, TrafficTracker::noop());
    check_idle_timeout(copy, client, server).await;
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
#[tokio::test]
async fn zero_copy_forwards_nested_prefixes_and_counts_them() {
    use std::sync::Arc;
    use crate::app::dispatcher::{StatisticsManager, TrackerInfo};
    use crate::app::sniffer::PrefixedStream;
    use crate::proxy::{AnyStream, ProxyStream};
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
    let info = Arc::new(TrackerInfo::default());
    let tracker = TrafficTracker::new(info.clone(), StatisticsManager::new());
    let copy = copy_bidirectional(
        AnyStream::Dynamic(Box::new(a)),
        AnyStream::Tcp(b),
        1024,
        tracker,
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
    assert_eq!(info.upload_total(), 14);
    assert_eq!(info.download_total(), 5);
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
#[tokio::test]
async fn zero_copy_prefix_backpressure_does_not_block_replies() {
    use crate::app::sniffer::PrefixedStream;
    use crate::proxy::AnyStream;
    let (mut client, a) = tcp_pair().await;
    let (b, mut server) = tcp_pair().await;
    socket2::SockRef::from(&b)
        .set_send_buffer_size(8192)
        .unwrap();
    let payload = vec![0x42; 1024 * 1024];
    let mut prefix = SlideBuffer::new(payload.len());
    prefix.extend_from_slice(&payload);
    let copy = copy_bidirectional(
        AnyStream::Dynamic(Box::new(PrefixedStream::new(prefix, a))),
        AnyStream::Tcp(b),
        1024,
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
