//! Per-connection, demand-driven TCP protocol storage.
mod sender;
mod receiver;
mod growth;
use super::protocol::{Socket, SocketBuffer};
use tokio::time::{Duration, Instant};
use receiver::{Observation as ReceiveObservation, Receiver};
use sender::{Observation, Sender};

pub(super) const INITIAL_CAPACITY: usize = 16 * 1024;
const MAX_CAPACITY: usize = 4 * 1024 * 1024;

pub(crate) struct Buffers {
    acknowledged: u64,
    receiver: Receiver,
    sender: Sender,
}

impl Buffers {
    pub fn new() -> (Self, Socket<'static>) {
        let now = Instant::now();
        let buffers = Self { acknowledged: 0,
            receiver: Receiver::new(now, MAX_CAPACITY),
            sender: Sender::new(now, MAX_CAPACITY) };
        let mut socket = Socket::new(SocketBuffer::new(vec![0; INITIAL_CAPACITY]),
            SocketBuffer::new(vec![0; INITIAL_CAPACITY]));
        socket.set_receive_capacity_limit(MAX_CAPACITY);
        (buffers, socket)
    }

    pub fn grow(&mut self, socket: &mut Socket<'_>, consumed: usize, send_limited: bool, output_ready: bool, now: Instant) -> bool {
        let (rtt, acknowledged) = socket.buffer_delivery();
        self.grow_at(socket, consumed, Duration::from(rtt), acknowledged,
            now, send_limited, output_ready)
    }

    fn grow_at(&mut self, socket: &mut Socket<'_>, consumed: usize, rtt: Duration,
        acknowledged: u64, now: Instant, send_limited: bool, output_ready: bool) -> bool {
        let delivered = acknowledged.wrapping_sub(self.acknowledged);
        self.acknowledged = acknowledged;
        let receive_state = socket.take_receive_state();
        let receive = self.receiver.target(ReceiveObservation { now, rtt, state: receive_state,
            consumed, output_ready });
        let state = socket.transmit_state();
        let send = self.sender.target(Observation { now, rtt, capacity: state.capacity,
            queued: state.queued, unsent: state.unsent, delivered, filled: send_limited });
        let receive_grown = Self::grow_one(socket, true, receive);
        if receive_grown {
            self.receiver.grew(now);
        }
        let send_grown = Self::grow_one(socket, false, send);
        if send_grown {
            self.sender.grew(now);
        }
        receive_grown || send_grown
    }

    pub fn idle_deadline(&self, socket: &Socket<'_>) -> Option<Instant> {
        let state = socket.receive_state();
        let receive = self.receiver.idle_deadline(state.capacity, state.stored);
        let send = self.sender.idle_deadline(socket.send_capacity(), socket.send_queue());
        receive.into_iter().chain(send).min()
    }

    /// RX reclaim honors outstanding advertised credit and reassembly. TX
    /// reclaim honors every accepted byte. Exclusive ownership keeps borrowed
    /// slices from surviving either replacement; wire sequence state is intact.
    pub fn reclaim(&mut self, socket: &mut Socket<'_>, now: Instant) -> bool {
        let mut changed = false;
        let receive = socket.receive_state();
        if let Some(capacity) = self.receiver.reclaim_request(now, receive) {
            // Keep backing storage while the peer may still legally fill its
            // old grant. New ACKs stop extending that grant until it drains.
            // Resumed bulk traffic completes this reclaim before probing up
            // from the initial capacity again; several RTTs of ramp-up are
            // an intentional tradeoff for retiring the old receive grant.
            changed |= socket.limit_receive_admission(capacity);
            if receive.required <= capacity {
                socket.shrink_receive_buffer(SocketBuffer::new(vec![0; capacity]));
                self.receiver.reclaimed(now);
                changed = true;
            }
        }
        if let Some(capacity) = self.sender.reclaim_target(now, socket.send_capacity(), socket.send_queue()) {
            socket.shrink_send_buffer(SocketBuffer::new(vec![0; capacity]));
            self.sender.reclaimed(now);
            changed = true;
        }
        changed
    }

    fn grow_one(socket: &mut Socket<'_>, receive: bool, target: usize) -> bool {
        let old = if receive { socket.recv_capacity() } else { socket.send_capacity() };
        let limit = if receive { socket.receive_capacity_limit() } else { MAX_CAPACITY };
        let next = target.min(limit);
        if next <= old { return false; }
        let storage = SocketBuffer::new(vec![0; next]);
        if receive { socket.grow_receive_buffer(storage); }
        else { socket.grow_send_buffer(storage); }
        true
    }
}

#[cfg(test)]
mod tests;
