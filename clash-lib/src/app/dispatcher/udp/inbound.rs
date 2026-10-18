//! One task owns protocol state and polls both directions without a shared lock.
use std::{collections::VecDeque, pin::Pin, task::{Context, Poll}};
use futures::Stream;
use tokio::sync::mpsc;
use tracing::error;
use crate::proxy::datagram::{UdpPacket,
    batch::{DatagramBatch, PacketBatch, MAX_BATCH_PACKETS}};

pub(super) struct InboundIo<D> {
    datagram: D,
    closed: bool,
    replies: mpsc::Receiver<UdpPacket>,
    sending: PacketBatch,
    deferred: Option<UdpPacket>,
    queued: VecDeque<UdpPacket>,
    scratch: Vec<UdpPacket>,
}

impl<D: DatagramBatch> InboundIo<D> {
    pub(super) fn new(datagram: D, replies: mpsc::Receiver<UdpPacket>) -> Self {
        Self { datagram, closed: false, replies, sending: PacketBatch::default(), deferred: None,
            queued: VecDeque::with_capacity(MAX_BATCH_PACKETS),
            scratch: Vec::with_capacity(MAX_BATCH_PACKETS) }
    }

    // Make at most one bounded send attempt per poll, then give reads and the
    // caller's control events a turn. Pending writes never suspend reads.
    fn poll_replies(&mut self, cx: &mut Context<'_>) -> Option<bool> {
        if self.closed { return None; }
        if self.sending.is_empty() {
            let packet = match self.deferred.take() {
                Some(packet) => packet,
                None => match self.replies.poll_recv(cx) {
                    Poll::Ready(Some(packet)) => packet,
                    Poll::Ready(None) => return None,
                    Poll::Pending => return Some(false),
                },
            };
            self.sending.push(packet).unwrap();
            while !self.sending.is_full() {
                let Ok(packet) = self.replies.try_recv() else { break; };
                if let Err(packet) = self.sending.push(packet) {
                    self.deferred = Some(packet);
                    break;
                }
            }
        }
        if let Poll::Ready(result) = self.datagram.poll_send_batch(cx, &mut self.sending) {
            assert!(result.sent > 0 || result.error.is_some(), "batch send made no progress");
            for _ in 0..result.sent { self.sending.complete(); }
            if let Some(error) = result.error {
                self.sending.complete();
                error!("failed to send UDP packet to local: {error}");
                if result.fatal { self.closed = true; self.replies.close(); return None; }
            }
            if !self.sending.is_empty() || self.deferred.is_some() { return Some(true); }
            // Register the receiver's waker even after the last ready reply.
            // try_recv does not subscribe us to the next arrival.
            return match self.replies.poll_recv(cx) {
                Poll::Ready(Some(packet)) => { self.deferred = Some(packet); Some(true) }
                Poll::Ready(None) => None,
                Poll::Pending => Some(false),
            };
        }
        Some(false)
    }

    pub(super) fn poll_recv_batch(&mut self, cx: &mut Context<'_>, packets: &mut Vec<UdpPacket>) -> Poll<Option<()>> {
        let Some(more) = self.poll_replies(cx) else { return Poll::Ready(None); };
        let result = if !self.queued.is_empty() {
            packets.extend(self.queued.drain(..));
            Poll::Ready(Some(()))
        } else { self.datagram.poll_recv_batch(cx, packets) };
        if more && result.is_pending() { cx.waker().wake_by_ref(); }
        result
    }
}

impl<D: DatagramBatch> Stream for InboundIo<D> {
    type Item = UdpPacket;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>> {
        let this = self.get_mut();
        let Some(more) = this.poll_replies(cx) else { return Poll::Ready(None); };
        if let Some(packet) = this.queued.pop_front() { return Poll::Ready(Some(packet)); }
        match this.datagram.poll_recv_batch(cx, &mut this.scratch) {
            Poll::Ready(Some(())) => {
                this.queued.extend(this.scratch.drain(..));
                if let Some(packet) = this.queued.pop_front() { Poll::Ready(Some(packet)) }
                else { cx.waker().wake_by_ref(); Poll::Pending }
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => {
                if more { cx.waker().wake_by_ref(); }
                Poll::Pending
            }
        }
    }
}

#[cfg(test)]
#[path = "inbound_tests.rs"]
mod tests;
