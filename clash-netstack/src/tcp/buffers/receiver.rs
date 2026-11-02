//! RX observation adapter. All capacity decisions live in growth.rs.
use tokio::time::{Duration, Instant};
use super::growth::{Growth, Observation as GrowthObservation, Pressure};
use crate::tcp::protocol::ReceiveState;

pub(super) struct Observation {
    pub now: Instant,
    pub rtt: Duration,
    pub state: ReceiveState,
    pub consumed: usize,
    pub output_ready: bool,
}

pub(super) struct Receiver { growth: Growth }
impl Receiver {
    pub fn new(now: Instant, maximum: usize) -> Self { Self { growth: Growth::new(now, maximum) } }
    pub fn target(&mut self, o: Observation) -> usize {
        self.growth.target(GrowthObservation { now: o.now, rtt: o.rtt,
            capacity: o.state.capacity, queued: o.state.stored, progress: o.consumed as u64,
            pressure: Pressure::Receive { storage_limited: o.state.storage_limited,
                credit_limited: o.state.credit_limited, output_ready: o.output_ready } })
    }
    pub fn grew(&mut self, now: Instant) { self.growth.grew(now); }
    /// The protocol owner still validates all advertised credit and reassembly.
    pub fn reclaim_request(&mut self, now: Instant, state: ReceiveState) -> Option<usize> {
        self.growth.reclaim_request(now, state.capacity, state.stored)
    }
    pub fn idle_deadline(&self, capacity: usize, queued: usize) -> Option<Instant> {
        self.growth.idle_deadline(capacity, queued)
    }
    pub fn reclaimed(&mut self, now: Instant) { self.growth.reclaimed(now); }
}
#[cfg(test)]
mod tests;
