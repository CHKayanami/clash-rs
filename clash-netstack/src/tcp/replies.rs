//! Bounded storage for immediate TCP control replies, independent of egress slots.
use std::collections::VecDeque;
use crate::link::output::Output;
use crate::Packet;

pub(super) const MAX_PENDING_REPLIES: usize = 32;
const MAX_CONTROL_BYTES: usize = 128;

#[derive(Default)]
pub(super) struct Replies {
    pending: VecDeque<Packet>,
}

impl Replies {
    pub fn has_capacity(&self) -> bool { self.pending.len() < MAX_PENDING_REPLIES }

    pub fn is_empty(&self) -> bool { self.pending.is_empty() }

    #[cfg(test)]
    pub fn len(&self) -> usize { self.pending.len() }

    /// The caller checks capacity before mutating an incoming TCP socket.
    /// Replies have no payload; their IPv4/IPv6 and TCP headers fit in 128 bytes.
    /// Previously queued replies always go first.
    pub fn send(&mut self, packet: Packet, output: &mut Output) {
        assert!(self.has_capacity(), "TCP reply queue was not reserved");
        assert!(packet.data().len() <= MAX_CONTROL_BYTES, "TCP control reply too large");
        let packet = if self.pending.is_empty() {
            match output.send(packet) {
                Ok(()) => return,
                Err(packet) => packet,
            }
        } else { packet };
        self.pending.push_back(packet);
    }

    /// Reserve before removing a packet: full/closed output never loses a reply.
    /// At most MAX_PENDING_REPLIES small control packets are drained per call.
    pub fn flush(&mut self, output: &mut Output) -> (usize, usize) {
        let mut packets = 0;
        let mut bytes = 0;
        while !self.pending.is_empty() {
            let Some(permit) = output.reserve() else { break; };
            let packet = self.pending.pop_front().unwrap();
            packets += 1;
            bytes += packet.data().len();
            permit.send(packet);
        }
        (packets, bytes)
    }
}
