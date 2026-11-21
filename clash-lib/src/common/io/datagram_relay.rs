use std::{io, task::{Context, Poll}};
use futures::future::poll_fn;
use crate::proxy::{OutboundDatagram, datagram::{UdpPacket,
    batch::{PacketBatch, BatchResult, MAX_BATCH_PACKETS}}};

/// State belongs to the relay task; neither direction needs a shared lock.
pub(crate) trait RelayContext {
    fn poll_outgoing(&mut self, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>>;
    fn sent(&mut self, result: io::Result<usize>) -> bool;
    fn received_batch(&mut self, packets: &mut Vec<UdpPacket>) -> bool;
    fn poll_control(&mut self, _cx: &mut Context<'_>) -> bool { true }
    /// An outstanding local write pauses remote reads while upload and
    /// control continue to be polled.
    fn poll_replies(&mut self, _cx: &mut Context<'_>) -> Poll<()> { Poll::Ready(()) }
}

/// Keep a bounded batch across Pending while still servicing reads and control.
pub(crate) async fn relay<D: OutboundDatagram, C: RelayContext>(mut datagram: D, mut context: C) {
    enum Event { Sent(BatchResult), Received, Closed }
    let mut sending = PacketBatch::default();
    let mut deferred = None;
    let mut outgoing_closed = false;
    let mut received = Vec::with_capacity(MAX_BATCH_PACKETS);
    let mut read_first = true;
    loop {
        let event = poll_fn(|cx| {
            if !context.poll_control(cx) { return Poll::Ready(Event::Closed); }
            let receive_ready = context.poll_replies(cx).is_ready();
            if sending.is_empty() {
                if let Some(packet) = deferred.take() { sending.push(packet).unwrap(); }
                while !sending.is_full() && !outgoing_closed {
                    match context.poll_outgoing(cx) {
                        Poll::Ready(Some(packet)) => {
                            if let Err(packet) = sending.push(packet) { deferred = Some(packet); break; }
                        }
                        Poll::Ready(None) => { outgoing_closed = true; break; }
                        Poll::Pending => break,
                    }
                }
            }
            if sending.is_empty() && outgoing_closed && receive_ready {
                return Poll::Ready(Event::Closed);
            }
            if !read_first && !sending.is_empty()
                && let Poll::Ready(result) = datagram.poll_send_batch(cx, &mut sending) {
                return Poll::Ready(Event::Sent(result));
            }
            if receive_ready {
                match datagram.poll_recv_batch(cx, &mut received) {
                    Poll::Ready(Some(())) => return Poll::Ready(Event::Received),
                    Poll::Ready(None) => return Poll::Ready(Event::Closed),
                    Poll::Pending => {},
                }
            }
            if read_first && !sending.is_empty() {
                datagram.poll_send_batch(cx, &mut sending).map(Event::Sent)
            } else { Poll::Pending }
        }).await;
        let mut processed = 0;
        match event {
            Event::Sent(result) => {
                assert!(result.sent > 0 || result.error.is_some(), "batch send made no progress");
                for _ in 0..result.sent {
                    let len = sending.complete();
                    if !context.sent(Ok(len)) { return; }
                    processed += 1;
                }
                if let Some(error) = result.error {
                    sending.complete();
                    if !context.sent(Err(error)) || result.fatal { return; }
                    processed += 1;
                }
            }
            Event::Received => {
                processed = received.len();
                if !context.received_batch(&mut received) { return; }
            }
            Event::Closed => return,
        }
        read_first = !read_first;
        if processed > 0 { tokio::task::consume_budget().await; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures::poll;
    use std::{future::Future, pin::{Pin, pin}, time::Duration};
    use tokio::{spawn, sync::{mpsc, oneshot}, time::timeout};
    use tokio_util::task::AbortOnDropHandle;

    use crate::proxy::datagram::ChannelDatagram;

    struct Local {
        upload: mpsc::Receiver<UdpPacket>,
        observed: mpsc::Sender<UdpPacket>,
        release: Option<oneshot::Receiver<()>>,
        blocked: bool,
    }

    impl RelayContext for Local {
        fn poll_outgoing(&mut self, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>> {
            self.upload.poll_recv(cx)
        }
        fn sent(&mut self, result: io::Result<usize>) -> bool {
            result.unwrap();
            true
        }
        fn received_batch(&mut self, packets: &mut Vec<UdpPacket>) -> bool {
            for packet in packets.drain(..) { self.observed.try_send(packet).unwrap(); }
            self.blocked = self.release.is_some();
            true
        }
        fn poll_replies(&mut self, cx: &mut Context<'_>) -> Poll<()> {
            if self.blocked && let Some(release) = &mut self.release {
                if Pin::new(release).poll(cx).is_pending() { return Poll::Pending; }
                self.blocked = false;
                self.release = None;
            }
            Poll::Ready(())
        }
    }

    #[tokio::test]
    async fn pending_local_reply_pauses_only_download() {
        let (upload, upload_rx) = mpsc::channel(4);
        let (observed, mut received) = mpsc::channel(4);
        let (outgoing, mut remote) = mpsc::channel(4);
        let (replies, reply_rx) = mpsc::channel(4);
        let (allow, release) = oneshot::channel();
        let _relay = AbortOnDropHandle::new(spawn(relay(
            ChannelDatagram::new(outgoing, reply_rx),
            Local { upload: upload_rx, observed, release: Some(release), blocked: false },
        )));
        let packet = |data| UdpPacket { data: Bytes::from_static(data), ..Default::default() };
        timeout(Duration::from_secs(2), async {
            replies.send(packet(b"one")).await.unwrap();
            assert_eq!(received.recv().await.unwrap().data.as_ref(), b"one");
            replies.send(packet(b"two")).await.unwrap();
            upload.send(packet(b"upload")).await.unwrap();
            assert_eq!(remote.recv().await.unwrap().data.as_ref(), b"upload");
            assert!(received.try_recv().is_err());
            allow.send(()).unwrap();
            assert_eq!(received.recv().await.unwrap().data.as_ref(), b"two");
        }).await.unwrap();
    }

    #[tokio::test]
    async fn upload_eof_waits_for_pending_local_reply() {
        let (upload, upload_rx) = mpsc::channel(1);
        let (observed, mut received) = mpsc::channel(1);
        let (outgoing, _remote) = mpsc::channel(1);
        let (replies, reply_rx) = mpsc::channel(1);
        let (allow, release) = oneshot::channel();
        let mut relay = pin!(relay(
            ChannelDatagram::new(outgoing, reply_rx),
            Local { upload: upload_rx, observed, release: Some(release), blocked: false },
        ));
        replies.try_send(UdpPacket::default()).unwrap();
        assert!(poll!(relay.as_mut()).is_pending());
        assert!(received.try_recv().is_ok());
        drop(upload);
        assert!(poll!(relay.as_mut()).is_pending());
        allow.send(()).unwrap();
        assert!(poll!(relay.as_mut()).is_ready());
    }
}
