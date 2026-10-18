use std::{io, task::{Context, Poll}};
use futures::future::poll_fn;
use crate::proxy::{OutboundDatagram, datagram::{UdpPacket,
    batch::{PacketBatch, BatchResult, MAX_BATCH_PACKETS}}};

/// State belongs to the relay task; neither direction needs a shared lock.
pub(crate) trait RelayContext {
    fn poll_outgoing(&mut self, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>>;
    fn sent(&mut self, result: io::Result<usize>) -> bool;
    fn received(&mut self, packet: UdpPacket) -> bool;
    fn poll_control(&mut self, _cx: &mut Context<'_>) -> bool { true }
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
            if sending.is_empty() && outgoing_closed { return Poll::Ready(Event::Closed); }
            if !read_first && !sending.is_empty()
                && let Poll::Ready(result) = datagram.poll_send_batch(cx, &mut sending) {
                return Poll::Ready(Event::Sent(result));
            }
            match datagram.poll_recv_batch(cx, &mut received) {
                Poll::Ready(Some(())) => return Poll::Ready(Event::Received),
                Poll::Ready(None) => return Poll::Ready(Event::Closed),
                Poll::Pending => {}
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
                for packet in received.drain(..) {
                    if !context.received(packet) { return; }
                    processed += 1;
                }
            }
            Event::Closed => return,
        }
        read_first = !read_first;
        for _ in 0..processed { tokio::task::consume_budget().await; }
    }
}
