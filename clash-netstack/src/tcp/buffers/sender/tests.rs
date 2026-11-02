use super::*;
use super::super::{INITIAL_CAPACITY, growth::IDLE};
const SAMPLE_INTERVAL: Duration = Duration::from_millis(10);
fn observation(now: Instant, capacity: usize, delivered: u64, filled: bool) -> Observation {
    Observation { now, rtt: Duration::from_millis(1), capacity, queued: capacity, unsent: 0, delivered, filled }
}
#[test]
fn wan_bursts_escape_small_buffers_with_a_partial_second_refill() {
    let now = Instant::now();
    let mut sender = Sender::new(now, 4 * 1024 * 1024);
    assert_eq!(sender.target(observation(now, INITIAL_CAPACITY, 0, true)), 0);
    assert_eq!(sender.target(observation(now + Duration::from_millis(1), INITIAL_CAPACITY, 0, true)), 0);
    assert_eq!(sender.target(observation(now + Duration::from_millis(20), INITIAL_CAPACITY, 62_464, false)), 32 * 1024);
    sender.grew(now + Duration::from_millis(20));
    assert_eq!(sender.target(observation(now + Duration::from_millis(21), 32 * 1024, 0, true)), 0);
    assert_eq!(sender.target(observation(now + Duration::from_millis(40), 32 * 1024, 62_464, false)), 64 * 1024);
    sender.grew(now + Duration::from_millis(40));
    assert_eq!(sender.target(observation(now + Duration::from_millis(60), 64 * 1024, 62_464, true)), 0);
}
#[test]
fn a_boundary_fill_without_ack_is_preserved_until_delivery_arrives() {
    let now = Instant::now();
    let mut sender = Sender::new(now, 4 * 1024 * 1024);
    assert_eq!(sender.target(observation(now + Duration::from_millis(20), 32 * 1024, 0, true)), 0);
    assert_eq!(sender.target(observation(now + Duration::from_micros(20600), 32 * 1024, 62_464, false)), 0);
    assert_eq!(sender.target(observation(now + Duration::from_millis(40), 32 * 1024, 0, true)), 64 * 1024);
    sender.grew(now + Duration::from_millis(40));
    assert_eq!(sender.target(observation(now + Duration::from_millis(60), 64 * 1024, 0, true)), 0);
}
#[test]
fn delivery_estimate_is_normalized_by_actual_elapsed_time() {
    let now = Instant::now();
    for (ms, expected) in [(10, 0), (100, 0)] {
        let mut sender = Sender::new(now, 4 * 1024 * 1024);
        assert_eq!(sender.target(observation(now + Duration::from_millis(ms), INITIAL_CAPACITY, 100_000, false)), expected);
    }
}
#[test]
fn larger_buffers_grow_by_one_step_when_delivery_supports_it() {
    let now = Instant::now();
    let mut sender = Sender::new(now, 4 * 1024 * 1024);
    let mut o = observation(now + SAMPLE_INTERVAL, 64 * 1024, 1_000_000, false);
    o.rtt = SAMPLE_INTERVAL;
    assert_eq!(sender.target(o), 128 * 1024);
    sender.grew(now + SAMPLE_INTERVAL);
    assert_eq!(sender.target(observation(now + SAMPLE_INTERVAL * 2, 128 * 1024, 0, false)), 0);
}
#[test]
fn delivery_must_support_the_next_step_with_phase_headroom() {
    let now = Instant::now();
    for (bytes, expected) in [(100_000, 0), (143_360, 32 * 1024), (163_840, 32 * 1024), (1_000_000, 32 * 1024)] {
        let mut sender = Sender::new(now, 4 * 1024 * 1024);
        assert_eq!(sender.target(observation(now + SAMPLE_INTERVAL, INITIAL_CAPACITY, bytes, false)), expected);
    }
}
#[test]
fn sustained_large_unsent_backlog_blocks_growth_then_recovers() {
    let now = Instant::now();
    let capacity = 128 * 1024;
    let mut sender = Sender::new(now, 4 * 1024 * 1024);
    let mut first = observation(now, capacity, 0, false);
    first.unsent = capacity * 3 / 4;
    assert_eq!(sender.target(first), 0);
    let mut end = observation(now + SAMPLE_INTERVAL, capacity, 2_000_000, false);
    end.unsent = capacity * 3 / 4;
    assert_eq!(sender.target(end), 0);
    assert_eq!(sender.target(observation(now + SAMPLE_INTERVAL * 2, capacity, 2_000_000, false)), capacity * 2);
}
#[test]
fn a_fresh_fill_or_draining_backlog_does_not_block_growth() {
    let now = Instant::now();
    let capacity = 128 * 1024;
    for fresh in [true, false] {
        let mut sender = Sender::new(now, 4 * 1024 * 1024);
        let mut first = observation(now, capacity, 0, false);
        first.unsent = if fresh { 0 } else { capacity };
        assert_eq!(sender.target(first), 0);
        let mut end = observation(now + SAMPLE_INTERVAL, capacity, 2_000_000, true);
        end.unsent = capacity * 3 / 4;
        assert_eq!(sender.target(end), capacity * 2);
    }
}
#[test]
fn startup_probe_survives_unsent_backlog_and_growth_clears_evidence() {
    let now = Instant::now();
    let mut sender = Sender::new(now, 4 * 1024 * 1024);
    for ms in [0, 1] {
        let mut o = observation(now + Duration::from_millis(ms), INITIAL_CAPACITY, 0, true);
        o.unsent = INITIAL_CAPACITY;
        assert_eq!(sender.target(o), 0);
    }
    let mut end = observation(now + SAMPLE_INTERVAL, INITIAL_CAPACITY, 62_464, true);
    end.unsent = INITIAL_CAPACITY;
    assert_eq!(sender.target(end), INITIAL_CAPACITY * 2);
    sender.grew(now + SAMPLE_INTERVAL);
    assert_eq!(sender.target(observation(now + SAMPLE_INTERVAL * 2, INITIAL_CAPACITY * 2, 0, false)), 0);
}
#[test]
fn unknown_rtt_drops_credit_and_maximum_is_enforced() {
    let now = Instant::now();
    let mut sender = Sender::new(now, 32 * 1024);
    let mut o = observation(now, INITIAL_CAPACITY, 1_000_000, true);
    o.rtt = Duration::ZERO;
    assert_eq!(sender.target(o), 0);
    assert_eq!(sender.target(observation(now + SAMPLE_INTERVAL, INITIAL_CAPACITY, 0, false)), 0);
    assert_eq!(sender.target(observation(now + SAMPLE_INTERVAL * 2, INITIAL_CAPACITY, 1_000_000, false)), 32 * 1024);
}
#[test]
fn isolated_fills_or_delivery_cannot_trigger_a_startup_probe() {
    let now = Instant::now();
    for (pressure, bytes) in [(0, 62_464), (1, 62_464), (2, 0)] {
        let mut sender = Sender::new(now, 4 * 1024 * 1024);
        for _ in 0..pressure {
            assert_eq!(sender.target(observation(now, INITIAL_CAPACITY, 0, true)), 0);
        }
        assert_eq!(sender.target(observation(now + Duration::from_millis(20), INITIAL_CAPACITY, bytes, false)), 0);
    }
}
#[test]
fn idle_reclaims_to_initial_only_when_no_accepted_bytes_remain() {
    let now = Instant::now();
    let mut sender = Sender::new(now, 4 * 1024 * 1024);
    assert_eq!(sender.reclaim_target(now + IDLE, 128 * 1024, 1), None);
    assert_eq!(sender.reclaim_target(now + IDLE, 128 * 1024, 0), Some(INITIAL_CAPACITY));
    sender.reclaimed(now + IDLE);
    assert_eq!(sender.reclaim_target(now + IDLE, INITIAL_CAPACITY, 0), None);
}

#[test]
fn saturated_wan_delivery_grows_despite_sampling_lag() {
    let now = Instant::now();
    for rtt_ms in [50, 100] {
        let mut sender = Sender::new(now, 4 * 1024 * 1024);
        let mut capacity = 64 * 1024;
        for round in 1..=3 {
            let time = now + Duration::from_millis((rtt_ms + 5) * round);
            let mut o = observation(time, capacity, capacity as u64, true);
            o.rtt = Duration::from_millis(rtt_ms);
            assert_eq!(sender.target(o), capacity * 2);
            sender.grew(time);
            capacity *= 2;
        }
    }
}
