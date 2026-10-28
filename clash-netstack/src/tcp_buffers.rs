//! Per-connection, demand-driven TCP protocol storage.
use smoltcp::socket::tcp::{Socket, SocketBuffer};
use tokio::time::{Duration, Instant};

const INITIAL_CAPACITY: usize = 16 * 1024;
const MAX_CAPACITY: usize = 4 * 1024 * 1024;
const SAMPLE_INTERVAL: Duration = Duration::from_millis(10);

pub(crate) struct Buffers {
    received: usize,
    sent: usize,
    send_sample_start: Instant,
    sample_start: Instant,
}

impl Buffers {
    pub fn new() -> (Self, Socket<'static>) {
        let buffers = Self { received: 0, sent: 0, sample_start: Instant::now(),
            send_sample_start: Instant::now() };
        let mut socket = Socket::new(SocketBuffer::new(vec![0; INITIAL_CAPACITY]),
            SocketBuffer::new(vec![0; INITIAL_CAPACITY]));
        socket.set_receive_capacity_limit(MAX_CAPACITY);
        (buffers, socket)
    }

    pub fn grow(&mut self, socket: &mut Socket<'_>, queued_receive: usize, consumed: usize, sent: usize) -> bool {
        self.grow_at(socket, queued_receive, consumed, sent, Instant::now())
    }

    fn grow_at(&mut self, socket: &mut Socket<'_>, queued_receive: usize, consumed: usize, sent: usize,
        now: Instant) -> bool {
        self.received = self.received.saturating_add(consumed);
        let elapsed = now.duration_since(self.sample_start);
        let rx = socket.recv_capacity();
        // Occupancy catches window-limited bursts; measured consumption catches
        // busy DIRECT flows that drain every ingress batch before occupancy builds.
        let sustained = elapsed >= SAMPLE_INTERVAL
            && (self.received as u128) * SAMPLE_INTERVAL.as_nanos() * 2
                >= (rx as u128) * elapsed.as_nanos();
        let receive_busy = consumed > 0 && (queued_receive >= rx / 2 || sustained);
        let receive_grown = receive_busy && Self::grow_one(socket, true);
        if receive_grown || elapsed >= SAMPLE_INTERVAL {
            self.received = 0;
            self.sample_start = now;
        }
        let tx = socket.send_capacity();
        self.sent = self.sent.saturating_add(sent);
        let send_elapsed = now.duration_since(self.send_sample_start);
        let sustained_send = send_elapsed >= SAMPLE_INTERVAL && sent > 0
            && (self.sent as u128) * SAMPLE_INTERVAL.as_nanos() * 2
                >= (tx as u128) * send_elapsed.as_nanos();
        let send_grown = (socket.send_queue() >= tx * 3 / 4 || sustained_send)
            && Self::grow_one(socket, false);
        if send_grown || send_elapsed >= SAMPLE_INTERVAL {
            self.sent = 0;
            self.send_sample_start = now;
        }
        receive_grown || send_grown
    }

    fn grow_one(socket: &mut Socket<'_>, receive: bool) -> bool {
        let old = if receive { socket.recv_capacity() } else { socket.send_capacity() };
        let limit = if receive { socket.receive_capacity_limit() } else { MAX_CAPACITY };
        if old >= limit { return false; }
        let next = (old * 2).min(limit);
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
    fn idle_connections_allocate_only_initial_storage() {
        let (_buffers, socket) = Buffers::new();
        assert_eq!(socket.recv_capacity(), INITIAL_CAPACITY);
        assert_eq!(socket.send_capacity(), INITIAL_CAPACITY);
    }

    #[test]
    fn growth_stops_at_per_direction_limit_and_stalled_receive_does_not_grow() {
        let (mut allocation, mut socket) = Buffers::new();
        assert!(!allocation.grow(&mut socket, INITIAL_CAPACITY, 0, 0));
        while socket.recv_capacity() < MAX_CAPACITY {
            let size = socket.recv_capacity();
            assert!(allocation.grow(&mut socket, size, size, 0));
        }
        assert!(!allocation.grow(&mut socket, MAX_CAPACITY, MAX_CAPACITY, 0));
        while Buffers::grow_one(&mut socket, false) {}
        assert_eq!(socket.send_capacity(), MAX_CAPACITY);
    }

    #[test]
    fn sustained_consumption_grows_even_when_each_ingress_batch_is_small() {
        let (mut allocation, mut socket) = Buffers::new();
        allocation.received = INITIAL_CAPACITY * 4;
        let now = allocation.sample_start + SAMPLE_INTERVAL;
        assert!(allocation.grow_at(&mut socket, 1024, 1024, 0, now));
        assert_eq!(socket.recv_capacity(), 2 * INITIAL_CAPACITY);
        assert!(!allocation.grow_at(&mut socket, 1, 1, 0, now + SAMPLE_INTERVAL));
        assert_eq!(socket.recv_capacity(), 2 * INITIAL_CAPACITY);
    }

    #[test]
    fn occupancy_growth_does_not_reuse_burst_for_next_rate_sample() {
        let (mut allocation, mut socket) = Buffers::new();
        let burst = allocation.sample_start + Duration::from_millis(1);
        assert!(allocation.grow_at(&mut socket, INITIAL_CAPACITY, INITIAL_CAPACITY, 0, burst));
        assert_eq!(socket.recv_capacity(), 2 * INITIAL_CAPACITY);
        assert_eq!(allocation.received, 0);
        assert_eq!(allocation.sample_start, burst);
        assert!(!allocation.grow_at(&mut socket, 1, 1, 0, burst + SAMPLE_INTERVAL));
        assert_eq!(socket.recv_capacity(), 2 * INITIAL_CAPACITY);
    }

    #[test]
    fn transmit_rate_grows_with_small_batches_and_does_not_reuse_samples() {
        let (mut allocation, mut socket) = Buffers::new();
        allocation.sent = INITIAL_CAPACITY * 4;
        let now = allocation.send_sample_start + SAMPLE_INTERVAL;
        assert_eq!(socket.send_queue(), 0);
        assert!(allocation.grow_at(&mut socket, 0, 0, 1024, now));
        assert_eq!(socket.send_capacity(), 2 * INITIAL_CAPACITY);
        assert_eq!(socket.recv_capacity(), INITIAL_CAPACITY);
        assert_eq!(allocation.sent, 0);
        assert!(!allocation.grow_at(&mut socket, 0, 0, 1, now + SAMPLE_INTERVAL));
        assert_eq!(socket.send_capacity(), 2 * INITIAL_CAPACITY);
    }

}
