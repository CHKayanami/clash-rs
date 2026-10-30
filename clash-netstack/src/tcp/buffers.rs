//! Per-connection, demand-driven TCP protocol storage.
use super::protocol::{Socket, SocketBuffer};
use tokio::time::{Duration, Instant};

const INITIAL_CAPACITY: usize = 16 * 1024;
const SEND_PROBE_CAPACITY: usize = 64 * 1024;
const MAX_CAPACITY: usize = 4 * 1024 * 1024;
const SAMPLE_INTERVAL: Duration = Duration::from_millis(10);

struct Sample {
    start: Instant,
    bytes: u64,
}

impl Sample {
    fn target(&mut self, now: Instant, rtt: Duration, total: u64, limit: usize) -> Option<(usize, u64)> {
        if rtt.is_zero() {
            // Do not attribute progress before the first RTT measurement to
            // the first valid sample. No delivery estimate means no growth.
            self.start = now;
            self.bytes = total;
            return None;
        }
        let elapsed = now.duration_since(self.start);
        if elapsed < rtt.max(SAMPLE_INTERVAL) { return None; }
        let progress = total.wrapping_sub(self.bytes);
        self.start = now;
        self.bytes = total;
        // Normalize delayed observations by actual elapsed time. The minimum
        // sampling interval smooths batches; it is not the path's RTT.
        let target = ((progress as u128) * rtt.as_nanos() * 2 / elapsed.as_nanos())
            .min(limit as u128) as usize;
        Some((target, progress))
    }
}

pub(crate) struct Buffers {
    received: u64,
    send_pressure: u8,
    receive: Sample,
    send: Sample,
}

impl Buffers {
    pub fn new() -> (Self, Socket<'static>) {
        let now = Instant::now();
        let buffers = Self { received: 0, send_pressure: 0, receive: Sample { start: now, bytes: 0 },
            send: Sample { start: now, bytes: 0 } };
        let mut socket = Socket::new(SocketBuffer::new(vec![0; INITIAL_CAPACITY]),
            SocketBuffer::new(vec![0; INITIAL_CAPACITY]));
        socket.set_receive_capacity_limit(MAX_CAPACITY);
        (buffers, socket)
    }

    pub fn grow(&mut self, socket: &mut Socket<'_>, consumed: usize, send_limited: bool) -> bool {
        let (rtt, acknowledged) = socket.buffer_delivery();
        self.grow_at(socket, consumed, Duration::from(rtt), acknowledged, Instant::now(), send_limited)
    }

    fn grow_at(&mut self, socket: &mut Socket<'_>, consumed: usize, rtt: Duration,
        acknowledged: u64, now: Instant, send_limited: bool) -> bool {
        self.received = self.received.wrapping_add(consumed as u64);
        let receive = self.receive.target(now, rtt, self.received, socket.receive_capacity_limit())
            .map_or(0, |(target, _)| target);
        let send = match self.send.target(now, rtt, acknowledged, MAX_CAPACITY) {
            Some((mut target, progress)) => {
                let capacity = socket.send_capacity();
                // A WAN burst slightly below 64 KiB fills 32 KiB only once.
                // Allow its acknowledged partial refill to prove turnover;
                // one full buffer alone must not trigger a second probe.
                let repeated = self.send_pressure >= 2 && progress >= capacity as u64;
                let partial_refill = capacity >= SEND_PROBE_CAPACITY / 2
                    && self.send_pressure >= 1
                    && progress >= (capacity + capacity / 2) as u64;
                if capacity < SEND_PROBE_CAPACITY && (repeated || partial_refill) {
                    target = target.max((capacity * 2).min(SEND_PROBE_CAPACITY));
                }
                self.send_pressure = 0;
                target
            },
            None => {
                if rtt.is_zero() { self.send_pressure = 0; }
                0
            },
        };
        let receive_grown = Self::grow_one(socket, true, receive);
        let send_grown = Self::grow_one(socket, false, send);
        // A fresh fill belongs to the next sample if this call closed one.
        // Do not erase it at a WAN burst boundary before its ACK arrives, or
        // carry pressure against an old capacity across actual TX growth.
        if send_limited && !rtt.is_zero() && !send_grown {
            self.send_pressure = (self.send_pressure + 1).min(2);
        }
        receive_grown || send_grown
    }

    fn grow_one(socket: &mut Socket<'_>, receive: bool, target: usize) -> bool {
        let old = if receive { socket.recv_capacity() } else { socket.send_capacity() };
        let limit = if receive { socket.receive_capacity_limit() } else { MAX_CAPACITY };
        let next = target.min(old * 2).min(limit);
        if next <= old { return false; }
        let storage = SocketBuffer::new(vec![0; next]);
        if receive { socket.grow_receive_buffer(storage); }
        else { socket.grow_send_buffer(storage); }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wan_bursts_probe_small_send_buffers_despite_low_bdp_target() {
        let (mut buffers, mut socket) = Buffers::new();
        let start = buffers.send.start;
        let rtt = Duration::from_millis(1);
        let interval = Duration::from_millis(20);
        let mut acknowledged = 0;
        for round in 1..=3 {
            // One initial WAN window fills 16 KiB repeatedly, but 32 KiB
            // only once. BDP remains below 16 KiB in both stages.
            buffers.send_pressure = if round == 1 { 2 } else { 1 };
            acknowledged += 62_464;
            let grown = buffers.grow_at(&mut socket, 0, rtt,
                acknowledged, start + interval * round, false);
            assert_eq!(grown, round <= 2);
            assert_eq!(socket.send_capacity(), (INITIAL_CAPACITY << round).min(SEND_PROBE_CAPACITY));
            assert_eq!(socket.recv_capacity(), INITIAL_CAPACITY);
            assert_eq!(buffers.send_pressure, 0);
            // No new interval means no chained growth, even after a refill.
            buffers.send_pressure = 2;
            assert!(!buffers.grow_at(&mut socket, 0, rtt,
                acknowledged, start + interval * round, false));
        }
    }

    #[test]
    fn probe_requires_repeated_pressure_and_fresh_delivery_in_each_interval() {
        for (pressure, progress) in [(0, 60 * 1024), (1, 60 * 1024),
            (2, 0), (2, INITIAL_CAPACITY - 1)] {
            let (mut buffers, mut socket) = Buffers::new();
            let now = buffers.send.start + Duration::from_millis(20);
            buffers.send_pressure = pressure;
            assert!(!buffers.grow_at(&mut socket, 0, Duration::from_millis(1),
                progress as u64, now, false));
            assert_eq!(socket.send_capacity(), INITIAL_CAPACITY);
            assert_eq!(buffers.send_pressure, 0);
        }
        let (mut buffers, mut socket) = Buffers::new();
        let now = buffers.send.start + Duration::from_millis(20);
        buffers.send_pressure = 2;
        let acknowledged = INITIAL_CAPACITY as u64;
        assert!(buffers.grow_at(&mut socket, 0, Duration::from_millis(1), acknowledged, now, false));
        buffers.send_pressure = 2;
        assert!(!buffers.grow_at(&mut socket, 0, Duration::from_millis(1),
            acknowledged, now + Duration::from_millis(20), false));
        // New ACKs alone cannot reuse pressure from the previous interval.
        assert!(!buffers.grow_at(&mut socket, 0, Duration::from_millis(1),
            acknowledged + 60 * 1024, now + Duration::from_millis(40), false));
    }

    #[test]
    fn partial_refill_probe_requires_pressure_and_enough_new_acks() {
        for (pressure, progress, expected) in [
            (0, 62_464, false),
            (1, 32_768, false),
            (1, 49_151, false),
            (1, 49_152, true),
            (1, 62_464, true),
        ] {
            let (mut buffers, mut socket) = Buffers::new();
            Buffers::grow_one(&mut socket, false, 32_768);
            buffers.send_pressure = pressure;
            let now = buffers.send.start + Duration::from_millis(20);
            assert_eq!(buffers.grow_at(&mut socket, 0, Duration::from_millis(1),
                progress, now, false), expected);
            assert_eq!(socket.send_capacity(), if expected { 65_536 } else { 32_768 });
            assert_eq!(buffers.send_pressure, 0);
            // Neither old ACK credit nor the old pressure carries forward.
            assert!(!buffers.grow_at(&mut socket, 0, Duration::from_millis(1),
                progress, now + Duration::from_millis(20), false));
        }
    }

    #[test]
    fn burst_boundary_preserves_new_pressure_until_its_acks_arrive() {
        let (mut buffers, mut socket) = Buffers::new();
        Buffers::grow_one(&mut socket, false, 32_768);
        let start = buffers.send.start;
        let rtt = Duration::from_millis(1);
        // Idle ends exactly at a sample boundary: the first 32 KiB is
        // filled but no data from this burst has been ACKed yet.
        assert!(!buffers.grow_at(&mut socket, 0, rtt, 0,
            start + Duration::from_millis(20), true));
        assert_eq!(buffers.send_pressure, 1);
        // Remaining 29,696 bytes never fill the buffer again.
        assert!(!buffers.grow_at(&mut socket, 0, rtt, 62_464,
            start + Duration::from_micros(20_600), false));
        assert_eq!(buffers.send_pressure, 1);
        // The next WAN arrival settles the previous burst and probes 64 KiB.
        assert!(buffers.grow_at(&mut socket, 0, rtt, 62_464,
            start + Duration::from_millis(40), true));
        assert_eq!(socket.send_capacity(), SEND_PROBE_CAPACITY);
        assert_eq!(buffers.send_pressure, 0);
    }

    #[test]
    fn sample_boundary_expires_old_pressure_and_retains_only_a_new_fill() {
        let (mut buffers, mut socket) = Buffers::new();
        let start = buffers.send.start;
        let rtt = Duration::from_millis(1);
        assert!(!buffers.grow_at(&mut socket, 0, rtt, 0,
            start + Duration::from_millis(1), true));
        assert!(!buffers.grow_at(&mut socket, 0, rtt, 0,
            start + Duration::from_millis(20), true));
        // The old stalled fill expired, only this call's new fill remains.
        assert_eq!(buffers.send_pressure, 1);
        assert!(!buffers.grow_at(&mut socket, 0, rtt, 0,
            start + Duration::from_millis(40), false));
        assert_eq!(buffers.send_pressure, 0);
        assert!(!buffers.grow_at(&mut socket, 0, rtt, 62_464,
            start + Duration::from_millis(60), false));
        assert_eq!(socket.send_capacity(), INITIAL_CAPACITY);
    }

    #[test]
    fn missing_rtt_and_no_delivery_do_not_grow() {
        let (mut buffers, mut socket) = Buffers::new();
        let now = buffers.receive.start;
        for i in 1..20 {
            assert!(!buffers.grow_at(&mut socket, INITIAL_CAPACITY,
                Duration::ZERO, 0, now + SAMPLE_INTERVAL * i, false));
        }
        assert!(!buffers.grow_at(&mut socket, 0, Duration::from_millis(1),
            0, now + SAMPLE_INTERVAL * 20, false));
        assert_eq!(socket.recv_capacity(), INITIAL_CAPACITY);
        assert_eq!(socket.send_capacity(), INITIAL_CAPACITY);
    }

    #[test]
    fn bursts_cannot_grow_repeatedly_within_one_sample() {
        let (mut buffers, mut socket) = Buffers::new();
        let now = buffers.receive.start;
        let rtt = SAMPLE_INTERVAL;
        assert!(!buffers.grow_at(&mut socket, INITIAL_CAPACITY, rtt, 0,
            now + Duration::from_millis(1), false));
        assert!(buffers.grow_at(&mut socket, 0, rtt, INITIAL_CAPACITY as u64,
            now + SAMPLE_INTERVAL, false));
        assert_eq!(socket.recv_capacity(), INITIAL_CAPACITY * 2);
        assert_eq!(socket.send_capacity(), INITIAL_CAPACITY * 2);
        assert!(!buffers.grow_at(&mut socket, INITIAL_CAPACITY * 4, rtt,
            INITIAL_CAPACITY as u64 * 5, now + SAMPLE_INTERVAL, false));
        // Even a new complete interval without new progress cannot reuse the
        // earlier sample that caused the first expansion.
        let (mut buffers, mut socket) = Buffers::new();
        let now = buffers.receive.start;
        assert!(buffers.grow_at(&mut socket, INITIAL_CAPACITY, rtt,
            INITIAL_CAPACITY as u64, now + SAMPLE_INTERVAL, false));
        assert!(!buffers.grow_at(&mut socket, 0, rtt,
            INITIAL_CAPACITY as u64, now + SAMPLE_INTERVAL * 2, false));
    }

    #[test]
    fn short_rtt_and_delayed_observations_use_actual_bandwidth_delay_product() {
        for (elapsed, progress, rtt, expected) in [
            (10, 100_000, 1, 20_000),
            (100, 100_000, 1, INITIAL_CAPACITY),
            (100, 100_000, 10, 20_000),
        ] {
            let (mut buffers, mut socket) = Buffers::new();
            let now = buffers.receive.start + Duration::from_millis(elapsed);
            buffers.grow_at(&mut socket, progress, Duration::from_millis(rtt),
                progress as u64, now, false);
            assert_eq!(socket.recv_capacity(), expected);
            assert_eq!(socket.send_capacity(), expected);
        }
    }

    #[test]
    fn long_rtt_waits_a_complete_round_and_growth_respects_limits() {
        let (mut buffers, mut socket) = Buffers::new();
        let now = buffers.receive.start;
        let rtt = Duration::from_millis(100);
        assert!(!buffers.grow_at(&mut socket, MAX_CAPACITY, rtt,
            MAX_CAPACITY as u64, now + SAMPLE_INTERVAL, false));
        assert!(buffers.grow_at(&mut socket, 0, rtt,
            MAX_CAPACITY as u64, now + rtt, false));
        assert_eq!(socket.recv_capacity(), INITIAL_CAPACITY * 2);
        assert_eq!(socket.send_capacity(), INITIAL_CAPACITY * 2);
        for _ in 0..20 {
            Buffers::grow_one(&mut socket, true, usize::MAX);
            Buffers::grow_one(&mut socket, false, usize::MAX);
        }
        assert_eq!(socket.recv_capacity(), MAX_CAPACITY);
        assert_eq!(socket.send_capacity(), MAX_CAPACITY);
        assert!(!Buffers::grow_one(&mut socket, true, usize::MAX));
        assert!(!Buffers::grow_one(&mut socket, false, usize::MAX));
    }
}
