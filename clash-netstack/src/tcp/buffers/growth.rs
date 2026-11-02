//! Central buffer policy. Direction adapters supply signals, never capacities.
use tokio::time::{Duration, Instant};
use super::INITIAL_CAPACITY;

pub(super) const IDLE: Duration = Duration::from_secs(30);
const INTERVAL: Duration = Duration::from_millis(10);
const SEND_PROBE_CAPACITY: usize = 64 * 1024;

#[derive(Clone, Copy)]
pub(super) enum Pressure {
    Send { filled: bool, unsent: usize },
    Receive { storage_limited: bool, credit_limited: bool, output_ready: bool },
}

pub(super) struct Observation {
    pub now: Instant,
    pub rtt: Duration,
    pub capacity: usize,
    pub queued: usize,
    pub progress: u64,
    pub pressure: Pressure,
}

pub(super) struct Growth {
    start: Instant,
    bytes: u64,
    pressure_count: u8,
    send_backlog: Option<(Instant, usize)>,
    first_pressure: Option<Instant>,
    last_pressure: Option<Instant>,
    last_delivery: Instant,
    reclaim: Option<usize>,
    maximum: usize,
}

impl Growth {
    pub fn new(now: Instant, maximum: usize) -> Self {
        Self { start: now, bytes: 0, pressure_count: 0, send_backlog: None, first_pressure: None,
            last_pressure: None, last_delivery: now, reclaim: None, maximum }
    }

    fn reset(&mut self, now: Instant) {
        self.start = now;
        self.bytes = 0;
        self.pressure_count = 0;
        self.send_backlog = None;
        self.first_pressure = None;
        self.last_pressure = None;
    }

    fn observe(&mut self, now: Instant, progress: u64, pressure: bool) {
        self.bytes = self.bytes.saturating_add(progress);
        if pressure {
            self.first_pressure.get_or_insert(now);
            self.last_pressure = Some(now);
        }
    }

    pub fn idle_deadline(&self, capacity: usize, queued: usize) -> Option<Instant> {
        (capacity > INITIAL_CAPACITY && queued == 0 && self.reclaim.is_none())
            .then_some(self.last_delivery + IDLE)
    }

    pub fn reclaim_request(&mut self, now: Instant, capacity: usize, queued: usize) -> Option<usize> {
        if queued == 0 && now.duration_since(self.last_delivery) >= IDLE && capacity > INITIAL_CAPACITY {
            self.reclaim = Some(INITIAL_CAPACITY);
        }
        self.reclaim.filter(|&limit| limit < capacity)
    }

    pub fn reclaim_ready(&mut self, now: Instant, capacity: usize, queued: usize) -> Option<usize> {
        self.reclaim_request(now, capacity, queued).filter(|&limit| queued <= limit)
    }

    pub fn reclaimed(&mut self, now: Instant) {
        self.reclaim = None;
        self.last_delivery = now;
        self.reset(now);
    }

    pub fn target(&mut self, o: Observation) -> usize {
        if o.progress > 0 {
            self.last_delivery = o.now;
            // TX can resume immediately. RX must first retire already
            // advertised credit before releasing its larger backing storage.
            if matches!(o.pressure, Pressure::Send { .. }) { self.reclaim = None; }
        }
        self.reclaim_request(o.now, o.capacity, o.queued);
        if self.reclaim.is_some() || o.rtt.is_zero() || o.capacity >= self.maximum {
            self.reset(o.now);
            return 0;
        }
        let target = match o.pressure {
            Pressure::Send { filled, unsent } => self.send_target(&o, filled, unsent),
            Pressure::Receive { storage_limited, credit_limited, output_ready } => {
                if !output_ready {
                    self.reset(o.now);
                    return 0;
                }
                self.receive_target(&o, storage_limited || credit_limited)
            },
        };
        if target > o.capacity {
            target.min(o.capacity.saturating_mul(2)).min(self.maximum)
        } else { 0 }
    }

    /// Normalize TX ACK progress by actual observation time,
    /// with an independent bounded probe to escape a small initial WAN window.
    fn send_target(&mut self, o: &Observation, filled: bool, unsent: usize) -> usize {
        self.bytes = self.bytes.saturating_add(o.progress);
        let elapsed = o.now.duration_since(self.start);
        let interval = o.rtt.max(INTERVAL);
        // Post-pump observations include newly accepted data. Require a large
        // backlog across time, without net drainage, rather than one fill.
        if unsent < o.capacity / 2 {
            self.send_backlog = None;
        } else {
            self.send_backlog.get_or_insert((o.now, unsent));
        }
        let mut target = 0;
        if elapsed >= interval {
            let estimate = ((self.bytes as u128) * o.rtt.as_nanos() * 2 / elapsed.as_nanos())
                .min(self.maximum as u128) as usize;
            let next = o.capacity.saturating_mul(2).min(self.maximum);
            let backed_up = self.send_backlog.is_some_and(|(since, initial)|
                o.now.duration_since(since) >= interval / 2 && unsent >= initial);
            // Allow 1/8 headroom for ACK batching and sampling phase delay.
            // Keep the bounded startup probe independent of this backlog gate.
            if estimate >= next - next / 8 && (o.capacity < SEND_PROBE_CAPACITY || !backed_up) {
                target = next;
            }
            let repeated = self.pressure_count >= 2 && self.bytes >= o.capacity as u64;
            let partial_refill = o.capacity >= SEND_PROBE_CAPACITY / 2 && self.pressure_count >= 1
                && self.bytes >= (o.capacity + o.capacity / 2) as u64;
            if o.capacity < SEND_PROBE_CAPACITY && (repeated || partial_refill) {
                target = target.max(o.capacity.saturating_mul(2).min(SEND_PROBE_CAPACITY));
            }
            self.reset(o.now);
            if unsent >= o.capacity / 2 { self.send_backlog = Some((o.now, unsent)); }
        }
        // Completed epochs discard old fills. Record this boundary fill in
        // the new epoch; a successful replacement clears it via grew().
        if filled { self.pressure_count = (self.pressure_count + 1).min(2); }
        target
    }

    /// Keep RX's batch-aware pressure evidence and bounded delivery epoch.
    fn receive_target(&mut self, o: &Observation, pressure: bool) -> usize {
        let interval = o.rtt.max(INTERVAL);
        if o.now.duration_since(self.start) > interval * 2 { self.reset(o.now); }
        self.observe(o.now, o.progress, pressure);
        if o.now.duration_since(self.start) < interval { return 0; }
        let pressure_span = self.first_pressure.zip(self.last_pressure)
            .map_or(Duration::ZERO, |(first, last)| last.duration_since(first));
        let sustained = pressure_span >= interval / 2;
        let grow = sustained && self.bytes >= (o.capacity + o.capacity / 2) as u64;
        self.reset(o.now);
        if grow {
            o.capacity.saturating_mul(2)
        } else {
            self.observe(o.now, 0, pressure);
            0
        }
    }

    pub fn grew(&mut self, now: Instant) { self.reset(now); }
}

#[cfg(test)]
mod tests;
