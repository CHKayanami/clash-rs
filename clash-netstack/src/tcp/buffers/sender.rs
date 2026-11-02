//! TX observation adapter. All capacity decisions live in growth.rs.
use tokio::time::{Duration, Instant};
use super::growth::{Growth, Observation as GrowthObservation, Pressure};

pub(super) struct Observation {
    pub now: Instant,
    pub rtt: Duration,
    pub capacity: usize,
    pub queued: usize,
    pub unsent: usize,
    pub delivered: u64,
    pub filled: bool,
}

pub(super) struct Sender { growth: Growth }
impl Sender {
    pub fn new(now: Instant, maximum: usize) -> Self { Self { growth: Growth::new(now, maximum) } }
    pub fn reclaim_target(&mut self, now: Instant, capacity: usize, queued: usize) -> Option<usize> {
        self.growth.reclaim_ready(now, capacity, queued)
    }
    pub fn idle_deadline(&self, capacity: usize, queued: usize) -> Option<Instant> {
        self.growth.idle_deadline(capacity, queued)
    }
    pub fn reclaimed(&mut self, now: Instant) { self.growth.reclaimed(now); }
    pub fn target(&mut self, o: Observation) -> usize {
        self.growth.target(GrowthObservation { now: o.now, rtt: o.rtt,
            capacity: o.capacity, queued: o.queued, progress: o.delivered,
            pressure: Pressure::Send { filled: o.filled, unsent: o.unsent } })
    }
    pub fn grew(&mut self, now: Instant) { self.growth.grew(now); }
}
#[cfg(test)]
mod tests;
