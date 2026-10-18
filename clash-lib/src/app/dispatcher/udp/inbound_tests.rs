use super::*;
use std::{io, sync::{Arc, atomic::{AtomicUsize, Ordering}}};
use bytes::Bytes;
use futures::{Sink, StreamExt, future::poll_fn, task::{ArcWake, noop_waker_ref, waker}};
use crate::proxy::ProxyStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{timeout, Duration};

struct TestDatagram {
    incoming: mpsc::Receiver<UdpPacket>,
    permits: mpsc::Receiver<()>,
    sent: mpsc::UnboundedSender<UdpPacket>,
    pending: Option<UdpPacket>,
    attempts: Arc<AtomicUsize>,
    fail_first: bool,
}
impl Stream for TestDatagram {
    type Item = UdpPacket;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>> {
        self.incoming.poll_recv(cx)
    }
}
impl Sink<UdpPacket> for TestDatagram {
    type Error = io::Error;
    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        assert!(self.pending.is_none()); Poll::Ready(Ok(()))
    }
    fn start_send(mut self: Pin<&mut Self>, packet: UdpPacket) -> io::Result<()> {
        assert!(self.pending.is_none());
        self.attempts.fetch_add(1, Ordering::Relaxed);
        self.pending = Some(packet); Ok(())
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending.is_none() { return Poll::Ready(Ok(())); }
        match self.permits.poll_recv(cx) {
            Poll::Ready(Some(())) => {
                let packet = self.pending.take().unwrap();
                if self.fail_first {
                    self.fail_first = false;
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidInput, "bad reply")));
                }
                self.sent.send(packet).unwrap(); Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}
impl DatagramBatch for TestDatagram {}

#[tokio::test]
async fn blocked_reply_preserves_reads_and_resumes_without_new_input() {
    timeout(Duration::from_secs(3), async {
        let (incoming_tx, incoming) = mpsc::channel(4);
        let (permits_tx, permits) = mpsc::channel(4);
        let (sent, mut received) = mpsc::unbounded_channel();
        let attempts = Arc::new(AtomicUsize::new(0));
        let (reply_tx, reply_rx) = mpsc::channel(4);
        let mut io = InboundIo::new(TestDatagram { incoming, permits, sent,
            pending: None, fail_first: false, attempts: attempts.clone() }, reply_rx);
        reply_tx.send(UdpPacket { data: Bytes::from_static(b"reply"), ..Default::default() }).await.unwrap();
        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(Pin::new(&mut io).poll_next(&mut cx).is_pending());
        assert!(Pin::new(&mut io).poll_next(&mut cx).is_pending());
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        incoming_tx.send(UdpPacket { data: Bytes::from_static(b"request"), ..Default::default() }).await.unwrap();
        assert_eq!(io.next().await.unwrap().data, b"request"[..]);
        // Keep the input open but idle. Only a write readiness notification
        // may wake the owner; no additional incoming packet is available.
        let owner = tokio::spawn(async move { io.next().await });
        permits_tx.send(()).await.unwrap();
        assert_eq!(received.recv().await.unwrap().data, b"reply"[..]);
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        drop(incoming_tx);
        assert!(owner.await.unwrap().is_none());
        reply_tx.closed().await;
    }).await.unwrap();
}

#[tokio::test]
async fn reply_only_batches_keep_progressing_and_drop_on_cancellation() {
    timeout(Duration::from_secs(3), async {
        let (incoming_tx, incoming) = mpsc::channel(1);
        let (permits_tx, permits) = mpsc::channel(64);
        let (sent, mut received) = mpsc::unbounded_channel();
        let (reply_tx, reply_rx) = mpsc::channel(64);
        let mut io = InboundIo::new(TestDatagram { incoming, permits, sent,
            pending: None, fail_first: false, attempts: Arc::new(AtomicUsize::new(0)) }, reply_rx);
        // Cross both the packet-count and payload-byte batch boundaries.
        for index in 0..32 {
            reply_tx.send(UdpPacket { data: Bytes::from(vec![index; 8192]), ..Default::default() }).await.unwrap();
            permits_tx.send(()).await.unwrap();
        }
        let owner = tokio::spawn(async move {
            let mut packets = Vec::new();
            poll_fn(|cx| io.poll_recv_batch(cx, &mut packets)).await
        });
        for index in 0..32 {
            assert_eq!(received.recv().await.unwrap().data, Bytes::from(vec![index; 8192]));
        }
        owner.abort();
        assert!(owner.await.unwrap_err().is_cancelled());
        incoming_tx.closed().await;
        reply_tx.closed().await;
    }).await.unwrap();
}

#[tokio::test]
async fn failed_reply_does_not_discard_suffix_or_block_reads() {
    timeout(Duration::from_secs(3), async {
        let (incoming_tx, incoming) = mpsc::channel(1);
        let (permits_tx, permits) = mpsc::channel(2);
        let (sent, mut received) = mpsc::unbounded_channel();
        let (reply_tx, reply_rx) = mpsc::channel(2);
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut io = InboundIo::new(TestDatagram { incoming, permits, sent,
            pending: None, fail_first: true, attempts: attempts.clone() }, reply_rx);
        for payload in [b"bad".as_slice(), b"good"] {
            reply_tx.send(UdpPacket { data: Bytes::copy_from_slice(payload), ..Default::default() }).await.unwrap();
            permits_tx.send(()).await.unwrap();
        }
        incoming_tx.send(UdpPacket { data: Bytes::from_static(b"request"), ..Default::default() }).await.unwrap();
        assert_eq!(io.next().await.unwrap().data, b"request"[..]);
        let owner = tokio::spawn(async move { io.next().await });
        assert_eq!(received.recv().await.unwrap().data, b"good"[..]);
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
        drop(incoming_tx);
        assert!(owner.await.unwrap().is_none());
    }).await.unwrap();
}

struct WakeCount(AtomicUsize);
impl ArcWake for WakeCount {
    fn wake_by_ref(this: &Arc<Self>) { this.0.fetch_add(1, Ordering::Relaxed); }
}

#[tokio::test]
async fn idle_reply_writer_subscribes_to_next_reply_without_self_waking() {
    let (_incoming_tx, incoming) = mpsc::channel(1);
    let (permits_tx, permits) = mpsc::channel(2);
    let (sent, mut received) = mpsc::unbounded_channel();
    let (reply_tx, reply_rx) = mpsc::channel(2);
    let mut io = InboundIo::new(TestDatagram { incoming, permits, sent, pending: None,
        fail_first: false, attempts: Arc::new(AtomicUsize::new(0)) }, reply_rx);
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = waker(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    for _ in 0..2 {
        reply_tx.send(UdpPacket::default()).await.unwrap();
        permits_tx.send(()).await.unwrap();
        // Ignore the legitimate channel/readiness notification before polling.
        wakes.0.store(0, Ordering::Relaxed);
        assert!(Pin::new(&mut io).poll_next(&mut cx).is_pending());
        assert!(received.try_recv().is_ok());
        assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
    }
    reply_tx.send(UdpPacket::default()).await.unwrap();
    assert!(wakes.0.load(Ordering::Relaxed) > 0, "new reply must wake the subscribed receiver");
}

struct FailedStream(Arc<AtomicUsize>);
impl ProxyStream for FailedStream {}
impl AsyncRead for FailedStream {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for FailedStream {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if self.0.fetch_add(1, Ordering::Relaxed) == 0 { Poll::Ready(Ok(data.len().min(1))) }
        else { Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidInput, "write failed mid-frame"))) }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}

#[tokio::test]
async fn stream_write_failure_terminates_single_and_multi_packet_replies() {
    use crate::proxy::{AnyStream, transport::uot::OutboundDatagramUotV2};
    for count in [1, 2] {
        let calls = Arc::new(AtomicUsize::new(0));
        let datagram = OutboundDatagramUotV2::packet_mode(AnyStream::dynamic(FailedStream(calls.clone())));
        let (reply_tx, reply_rx) = mpsc::channel(4);
        for _ in 0..count { reply_tx.send(UdpPacket::default()).await.unwrap(); }
        let mut io = InboundIo::new(datagram, reply_rx);
        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(matches!(Pin::new(&mut io).poll_next(&mut cx), Poll::Ready(None)));
        let remaining = io.sending.len();
        assert!(matches!(Pin::new(&mut io).poll_next(&mut cx), Poll::Ready(None)));
        assert_eq!(io.sending.len(), remaining, "terminal writer must not retry its suffix");
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert!(reply_tx.is_closed());
    }
}
