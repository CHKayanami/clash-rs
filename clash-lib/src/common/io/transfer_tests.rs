use super::*;
use std::{cell::RefCell, io, task::Waker, time::Duration};
use crate::common::io::{CopyBuffer, copy_buf_bidirectional};
use futures::future::poll_fn;
use tokio::{io::{AsyncReadExt, AsyncWriteExt, ReadBuf}, time::advance};

struct RecordPolls<'a>(&'a RefCell<Vec<&'static str>>);

impl<R: ?Sized, W: ?Sized> Buffer<R, W> for RecordPolls<'_> {
    fn amount_transferred(&self) -> u64 { 0 }

    fn poll_copy(
        &mut self, _: &mut Context<'_>, _: &mut R, _: &mut W, _: &mut bool,
        direction: Direction,
    ) -> Poll<Result<u64, CopyBidirectionalError>> {
        self.0.borrow_mut().push(match direction {
            Direction::Upload => "upload",
            Direction::Download => "download",
        });
        Poll::Pending
    }
}

#[tokio::test]
async fn polls_both_directions_with_alternating_priority() {
    let (_client, mut a) = tokio::io::duplex(64);
    let (mut b, _server) = tokio::io::duplex(64);
    let polls = RefCell::new(Vec::new());
    let mut copy = CopyState::new(
        RecordPolls(&polls), RecordPolls(&polls),
        TrafficTracker::noop(),
    );
    let mut cx = Context::from_waker(Waker::noop());
    for expected in [["upload", "download"], ["download", "upload"], ["upload", "download"]] {
        assert!(copy.poll(&mut a, &mut b, &mut cx).is_pending());
        assert_eq!(polls.take(), expected);
    }
}

#[tokio::test]
async fn completed_shutdown_retains_counts() {
    let (_client, mut a) = tokio::io::duplex(64);
    let (mut b, _server) = tokio::io::duplex(64);
    let mut copy = CopyState::new(
        CopyBuffer::default(), CopyBuffer::default(),
        TrafficTracker::noop(),
    );
    copy.upload = TransferState::ShuttingDown(7);
    copy.download = TransferState::ShuttingDown(9);
    let counts = poll_fn(|cx| copy.poll(&mut a, &mut b, cx)).await.unwrap();
    assert_eq!(counts, (7, 9));
}

#[tokio::test(start_paused = true)]
async fn progress_registers_updated_idle_deadline() {
    let (mut client, mut a) = tokio::io::duplex(64);
    let (mut b, mut server) = tokio::io::duplex(64);
    let mut copy = tokio_test::task::spawn(copy_buf_bidirectional(
        &mut a, &mut b, 1024, TrafficTracker::noop(),
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
async fn pending_shutdown_expires_at_the_idle_deadline() {
    let (mut client, mut a) = tokio::io::duplex(64);
    let mut b = PendingShutdown;
    client.shutdown().await.unwrap();
    let mut copy = tokio_test::task::spawn(copy_buf_bidirectional(
        &mut a, &mut b, 1024, TrafficTracker::noop(),
    ));
    assert!(copy.poll().is_pending());
    advance(Duration::from_secs(1)).await;
    assert!(!copy.is_woken(), "pending shutdown must wait for I/O or idle expiry");
    advance(Duration::from_secs(179)).await;
    assert!(copy.is_woken());
    assert!(matches!(copy.poll(), Poll::Ready(Err(CopyBidirectionalError::Other(_)))));
}
