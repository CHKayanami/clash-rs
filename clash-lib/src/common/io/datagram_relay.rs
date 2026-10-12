use std::{io, pin::Pin, task::{Context, Poll}};

use futures::future::poll_fn;

use crate::proxy::{OutboundDatagram, datagram::UdpPacket};

/// State belongs to the relay task; neither direction needs a shared lock.
pub(crate) trait RelayContext {
    fn poll_outgoing(&mut self, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>>;
    fn sent(&mut self, result: io::Result<usize>) -> bool;
    fn received(&mut self, packet: UdpPacket) -> bool;
    fn poll_control(&mut self, _cx: &mut Context<'_>) -> bool { true }
}

/// Retain a send across Pending while continuing reads and control messages.
pub(crate) async fn relay<D, C>(mut datagram: D, mut context: C)
where
    D: OutboundDatagram<UdpPacket>,
    C: RelayContext,
{
    enum Event {
        Sent(io::Result<usize>),
        Received(UdpPacket),
        Closed,
    }

    fn poll_send<D: OutboundDatagram<UdpPacket>, C: RelayContext>(
        datagram: &mut D,
        context: &mut C,
        queued: &mut Option<UdpPacket>,
        flushing: &mut Option<usize>,
        cx: &mut Context<'_>,
    ) -> Poll<Event> {
        if flushing.is_none() && queued.is_none() {
            match context.poll_outgoing(cx) {
                Poll::Ready(Some(packet)) => *queued = Some(packet),
                Poll::Ready(None) => return Poll::Ready(Event::Closed),
                Poll::Pending => return Poll::Pending,
            }
        }
        if let Some(packet) = queued.as_ref() {
            match Pin::new(&mut *datagram).poll_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => {
                    *queued = None;
                    return Poll::Ready(Event::Sent(Err(err)));
                }
                Poll::Pending => return Poll::Pending,
            }
            let len = packet.data.len();
            let packet = queued.take().unwrap();
            if let Err(err) = Pin::new(&mut *datagram).start_send(packet) {
                return Poll::Ready(Event::Sent(Err(err)));
            }
            *flushing = Some(len);
        }
        match Pin::new(datagram).poll_flush(cx) {
            Poll::Ready(result) => {
                let len = flushing.take().unwrap();
                Poll::Ready(Event::Sent(result.map(|()| len)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    let mut queued = None;
    let mut flushing = None;
    let mut read_first = true;
    loop {
        let event = poll_fn(|cx| {
            if !context.poll_control(cx) { return Poll::Ready(Event::Closed); }
            if !read_first {
                if let Poll::Ready(event) = poll_send(
                    &mut datagram, &mut context, &mut queued, &mut flushing, cx,
                ) {
                    return Poll::Ready(event);
                }
            }
            match Pin::new(&mut datagram).poll_next(cx) {
                Poll::Ready(Some(packet)) => return Poll::Ready(Event::Received(packet)),
                Poll::Ready(None) => return Poll::Ready(Event::Closed),
                Poll::Pending => {}
            }
            if read_first {
                poll_send(&mut datagram, &mut context, &mut queued, &mut flushing, cx)
            } else {
                Poll::Pending
            }
        }).await;
        let keep_running = match event {
            Event::Sent(result) => context.sent(result),
            Event::Received(packet) => context.received(packet),
            Event::Closed => false,
        };
        if !keep_running { break; }
        read_first = !read_first;
        tokio::task::consume_budget().await;
    }
}
