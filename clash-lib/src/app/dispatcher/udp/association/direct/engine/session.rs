//! One bounded step, never an async forwarding loop. Policy state is shared
//! with ordinary proxy associations; only packet transport differs.
#[cfg(target_os = "linux")]
use crate::proxy::direct::recv::ReceiveSlots;
use std::{sync::{Arc, atomic::AtomicUsize}, collections::VecDeque, num::NonZeroU16, task::{Context, Poll}};
use futures::future::BoxFuture;
use bytes::Bytes;
use tokio::{sync::mpsc, time::Instant};
use crate::proxy::{AnyOutboundDatagram, datagram::{UdpPacket, segments::DatagramSegments,
    batch::{DatagramBatch, PacketBatch, MAX_DIRECT_BATCH_PACKETS}}};
mod borrowed;
use super::super::super::{Outgoing, DirectLifetime, state::AssociationState};

pub(in crate::app::dispatcher::udp::association) struct Session {
    pub id: u64,
    pub location: Arc<AtomicUsize>,
    datagram: AnyOutboundDatagram,
    state: AssociationState,
    cold: mpsc::Receiver<Outgoing>,
    sending: PacketBatch,
    aggregate: Option<(DatagramSegments, usize)>,
    deferred: Option<UdpPacket>,
    pub replies: VecDeque<DatagramSegments>,
    received: Vec<DatagramSegments>,
    closed: BoxFuture<'static, ()>,
    _lifetime: DirectLifetime,
}
#[derive(Default)]
pub(super) struct Work { pub frames: usize, pub bytes: usize, pub progress: bool, pub close: bool, pub again: bool }
impl Work {
    fn merge(&mut self, next: Self) {
        self.frames += next.frames; self.bytes += next.bytes;
        self.progress |= next.progress; self.close |= next.close; self.again |= next.again;
    }
}
impl Session {
    pub fn new(id: u64, mut datagram: AnyOutboundDatagram, state: AssociationState,
        cold: mpsc::Receiver<Outgoing>, closed: BoxFuture<'static, ()>, lifetime: DirectLifetime, offload: bool,
    ) -> Self {
        if offload { datagram.enable_udp_offload(); }
        Self { id, location: Arc::new(AtomicUsize::new(usize::MAX)), datagram, state, cold, sending: PacketBatch::with_limit(MAX_DIRECT_BATCH_PACKETS), aggregate: None, deferred: None,
            replies: VecDeque::new(), received: Vec::new(), closed, _lifetime: lifetime }
    }
    fn can_upload(&self, segmentation: Option<u16>) -> bool {
        // Never accept ahead of the route owner's buffered first burst.
        self.aggregate.is_none() && (segmentation.is_none() || self.sending.is_empty())
            && !self.sending.is_full() && self.deferred.is_none() && self.cold.is_empty()
    }
    pub fn upload(&mut self, outgoing: Outgoing, segmentation: Option<u16>, now: Instant) -> bool {
        if !self.can_upload(segmentation) { return false; }
        if let Some(packet) = self.state.outgoing(outgoing, now) {
            if let Some(size) = segmentation.and_then(NonZeroU16::new) {
                self.aggregate = Some((DatagramSegments { packet, size: Some(size) }, 0));
                return true;
            }
            if let Err(packet) = self.sending.push(packet) { self.deferred = Some(packet); }
        }
        true
    }
    pub(super) fn has_buffered_upload(&self) -> bool {
        self.aggregate.is_some() || !self.sending.is_empty() || self.deferred.is_some()
    }
    pub(super) fn has_upload(&self) -> bool {
        self.aggregate.is_some() || !self.sending.is_empty() || self.deferred.is_some() || !self.cold.is_empty()
    }
    pub(super) fn upload_full(&self) -> bool { self.sending.is_full() || self.deferred.is_some() }
    pub(super) fn compact_pending(&mut self) {
        // Only retained sends copy: a successful synchronous batch releases
        // its shared TUN receive storage without allocating per datagram.
        for packet in self.sending.packets_mut() { compact(packet); }
        if let Some(packet) = &mut self.deferred { compact(packet); }
        if let Some((group, _)) = &mut self.aggregate { compact(&mut group.packet); }
    }
    pub(super) fn has_aggregate(&self) -> bool { self.aggregate.is_some() }
    pub(super) fn poll_control(&mut self, cx: &mut Context<'_>) -> bool {
        self.closed.as_mut().poll(cx).is_pending() && self.state.poll_control(cx)
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>, receive: bool, checked: bool, now: Instant,
        #[cfg(target_os = "linux")] slots: &mut ReceiveSlots) -> Work {
        // The engine may skip control only when no event has advanced this
        // session's readiness generation since the previous control poll.
        if !checked && !self.poll_control(cx) { return Work { close: true, ..Work::default() }; }
        let mut work = if checked && !self.has_upload() { Work::default() } else { self.poll_send(cx, now) };
        if work.close { return work; }
        if receive && self.replies.is_empty() {
            #[cfg(target_os = "linux")]
            let receive = self.datagram.poll_recv_segments_in(cx, &mut self.received, slots);
            #[cfg(not(target_os = "linux"))]
            let receive = self.datagram.poll_recv_segments(cx, &mut self.received);
            match receive {
                Poll::Ready(Some(())) => {
                    for mut group in self.received.drain(..) {
                        work.frames += 1; work.bytes += group.packet.data.len();
                        if self.state.map_received(&mut group.packet, now) { self.replies.push_back(group); }
                    }
                    work.progress = true;
                    if self.replies.is_empty() { work.again = true; }
                },
                Poll::Ready(None) => work.close = true,
                Poll::Pending => {},
            }
        }
        work
    }
    pub(super) fn poll_send(&mut self, cx: &mut Context<'_>, now: Instant) -> Work {
        let mut work = Work::default();
        if let Some((group, offset)) = &mut self.aggregate {
            if let Poll::Ready(result) = self.datagram.poll_send_segments(cx, group, *offset) {
                assert!(result.bytes > 0 || result.error.is_some(), "UDP aggregate send made no progress");
                *offset += result.bytes;
                work.frames += 1; work.bytes += result.bytes; work.progress = true;
                if result.bytes > 0 { self.state.sent_part(result.bytes, now); }
                if let Some(error) = result.error {
                    *offset += result.failed;
                    if !self.state.send_error(error) || result.fatal { work.close = true; return work; }
                }
                if *offset >= group.packet.data.len() {
                    self.aggregate = None; self.state.finish_send();
                }
                if self.has_upload() { work.again = true; }
            }
            return work;
        }
        if let Some(packet) = self.deferred.take() && let Err(packet) = self.sending.push(packet) {
            self.deferred = Some(packet);
        }
        for _ in 0..MAX_DIRECT_BATCH_PACKETS {
            if self.sending.is_full() || self.deferred.is_some() { break; }
            match self.cold.poll_recv(cx) {
                Poll::Ready(Some(outgoing)) => if let Some(packet) = self.state.outgoing(outgoing, now)
                    && let Err(packet) = self.sending.push(packet) { self.deferred = Some(packet); },
                Poll::Ready(None) => { work.close = true; return work; },
                Poll::Pending => break,
            }
        }
        if !self.sending.is_empty() && let Poll::Ready(result) = self.datagram.poll_send_batch(cx, &mut self.sending) {
            assert!(result.sent > 0 || result.error.is_some(), "DIRECT UDP send made no progress");
            self.state.sent_batch((0..result.sent).map(|_| {
                let bytes = self.sending.complete(); work.bytes += bytes; bytes
            }), now);
            work.frames += result.sent;
            // Accounting is combined per consecutive flow, including actual
            // prefix completion when the socket only accepts part of a batch.

            if let Some(error) = result.error {
                self.sending.complete(); work.frames += 1;
                if !self.state.sent(Err(error), now) || result.fatal { work.close = true; return work; }
            }
            work.progress = true;
            // A short syscall result need not register write readiness.
            if !self.sending.is_empty() || self.deferred.is_some() || !self.cold.is_empty() {
                work.again = true;
            }
        }
        work
    }
}

fn compact(packet: &mut UdpPacket) {
    // try_into_mut is deliberately avoided: payloads may share a receive slab.
    if !packet.data.is_unique() { packet.data = Bytes::copy_from_slice(&packet.data); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_payload_releases_shared_slab_and_is_not_copied_again() {
        let slab = Bytes::from(vec![0x5a; 128 * 1024]);
        let mut packet = UdpPacket { data: slab.slice(100..200), ..Default::default() };
        let shared = packet.data.as_ptr();
        compact(&mut packet);
        assert_ne!(packet.data.as_ptr(), shared);
        assert_eq!(packet.data.as_ref(), &[0x5a; 100]);
        let compacted = packet.data.as_ptr();
        compact(&mut packet);
        assert_eq!(packet.data.as_ptr(), compacted);
        assert_eq!(&slab[100..200], &[0x5a; 100]);
    }
}
