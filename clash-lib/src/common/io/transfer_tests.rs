use super::*;
use std::io;
use crate::common::io::{CopyBuffer, copy_buf_bidirectional_with_timeout};
use futures::future::poll_fn;
use tokio::{io::{AsyncReadExt, AsyncWriteExt, ReadBuf}, time::advance};

#[tokio::test]
async fn completed_shutdown_retains_counts() {
    let (_client, mut a) = tokio::io::duplex(64);
    let (mut b, _server) = tokio::io::duplex(64);
    let mut copy = CopyState::new(
        CopyBuffer::default(), CopyBuffer::default(),
        Duration::ZERO, Duration::ZERO, TrafficTracker::noop(),
    );
    copy.upload = TransferState::ShuttingDown(7);
    copy.download = TransferState::ShuttingDown(9);
    let counts = poll_fn(|cx| copy.poll(&mut a, &mut b, cx)).await.unwrap();
    assert_eq!(counts, (7, 9));
}

#[tokio::test(start_paused = true)]
async fn ready_write_refreshes_expired_half_close_deadline() {
    for reverse in [false, true] {
        let (client, mut a) = tokio::io::duplex(64);
        let (mut b, server) = tokio::io::duplex(64);
        let (mut source, mut sink) = if reverse { (server, client) } else { (client, server) };
        source.shutdown().await.unwrap();
        let timeout = Duration::from_secs(10);
        let mut copy = tokio_test::task::spawn(copy_buf_bidirectional_with_timeout(
            &mut a, &mut b, 1024, timeout, timeout, TrafficTracker::noop(),
        ));
        assert!(copy.poll().is_pending());
        advance(timeout).await;
        sink.write_all(b"a").await.unwrap();
        assert!(copy.poll().is_pending());
        let mut byte = [0];
        source.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, *b"a");
        advance(timeout - Duration::from_secs(1)).await;
        assert!(copy.poll().is_pending());
        advance(Duration::from_secs(1)).await;
        assert!(copy.is_woken());
        let Poll::Ready(Ok(counts)) = copy.poll() else { panic!("half-close did not expire"); };
        assert_eq!(counts, if reverse { (1, 0) } else { (0, 1) });
    }
}

#[tokio::test(start_paused = true)]
async fn zero_half_close_timeout_finishes_both_directions() {
    for reverse in [false, true] {
        let (mut client, mut a) = tokio::io::duplex(64);
        let (mut b, mut server) = tokio::io::duplex(64);
        if reverse { server.shutdown().await.unwrap(); } else { client.shutdown().await.unwrap(); }
        let result = copy_buf_bidirectional_with_timeout(
            &mut a, &mut b, 1024, Duration::ZERO, Duration::ZERO, TrafficTracker::noop(),
        ).await.unwrap();
        assert_eq!(result, (0, 0));
    }
}

#[tokio::test(start_paused = true)]
async fn idle_error_wins_when_both_deadlines_expire() {
    let (mut client, mut a) = tokio::io::duplex(64);
    let (mut b, _server) = tokio::io::duplex(64);
    client.shutdown().await.unwrap();
    let mut copy = tokio_test::task::spawn(copy_buf_bidirectional_with_timeout(
        &mut a, &mut b, 1024, Duration::from_secs(180), Duration::from_secs(180),
        TrafficTracker::noop(),
    ));
    assert!(copy.poll().is_pending());
    advance(Duration::from_secs(180)).await;
    let Poll::Ready(Err(CopyBidirectionalError::Other(error))) = copy.poll()
    else { panic!("idle error lost its priority"); };
    assert_eq!(error.kind(), ErrorKind::TimedOut);
}

#[tokio::test(start_paused = true)]
async fn progress_registers_updated_idle_deadline() {
    let (mut client, mut a) = tokio::io::duplex(64);
    let (mut b, mut server) = tokio::io::duplex(64);
    let timeout = Duration::from_secs(10);
    let mut copy = tokio_test::task::spawn(copy_buf_bidirectional_with_timeout(
        &mut a, &mut b, 1024, timeout, timeout, TrafficTracker::noop(),
    ));
    assert!(copy.poll().is_pending());
    advance(Duration::from_secs(179)).await;
    client.write_all(b"a").await.unwrap();
    assert!(copy.poll().is_pending());
    let mut byte = [0];
    server.read_exact(&mut byte).await.unwrap();
    advance(Duration::from_secs(179)).await;
    assert!(copy.poll().is_pending());
    advance(Duration::from_secs(1)).await;
    assert!(copy.is_woken());
    assert!(matches!(copy.poll(), Poll::Ready(Err(CopyBidirectionalError::Other(_)))));
}

struct PendingShutdown;

impl AsyncRead for PendingShutdown {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>)
        -> Poll<io::Result<()>>
    { Poll::Ready(Ok(())) }
}

impl AsyncWrite for PendingShutdown {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8])
        -> Poll<io::Result<usize>>
    { Poll::Ready(Ok(bytes.len())) }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>>
    { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>>
    { Poll::Pending }
}

#[tokio::test(start_paused = true)]
async fn pending_shutdown_does_not_rearm_expired_half_close() {
    let (mut client, mut a) = tokio::io::duplex(64);
    let mut b = PendingShutdown;
    client.shutdown().await.unwrap();
    let mut copy = tokio_test::task::spawn(copy_buf_bidirectional_with_timeout(
        &mut a, &mut b, 1024, Duration::ZERO, Duration::ZERO, TrafficTracker::noop(),
    ));
    assert!(copy.poll().is_pending());
    advance(Duration::from_secs(1)).await;
    assert!(!copy.is_woken(), "completed directions must not keep waking shutdown");
    advance(Duration::from_secs(179)).await;
    assert!(copy.is_woken());
    assert!(matches!(copy.poll(), Poll::Ready(Err(CopyBidirectionalError::Other(_)))));
}
