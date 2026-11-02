use super::*;
const CAPACITY: usize = 32 * 1024;
fn observation(now: Instant, progress: u64, pressure: bool) -> Observation {
    Observation { now, rtt: Duration::from_millis(1), capacity: CAPACITY,
        queued: 0, progress, pressure: Pressure::Receive { storage_limited: pressure,
            credit_limited: false, output_ready: true } }
}
#[test]
fn sustained_pressure_and_turnover_grow_once_then_need_new_evidence() {
    let now = Instant::now();
    let mut growth = Growth::new(now, CAPACITY * 8);
    assert_eq!(growth.target(observation(now, CAPACITY as u64, true)), 0);
    assert_eq!(growth.target(observation(now + INTERVAL / 2, CAPACITY as u64 / 2, true)), 0);
    assert_eq!(growth.target(observation(now + INTERVAL, 0, false)), CAPACITY * 2);
    growth.grew(now + INTERVAL);
    assert_eq!(growth.target(observation(now + INTERVAL * 2, 0, true)), 0);
}
#[test]
fn a_single_burst_or_pressure_without_delivery_never_grows() {
    let now = Instant::now();
    for mode in 0..3 {
        let mut growth = Growth::new(now, CAPACITY * 8);
        for step in 0..=20 {
            let bytes = if mode == 0 && step == 0 || mode == 2 { CAPACITY as u64 * 4 } else { 0 };
            let pressure = if mode == 0 { step == 0 } else { mode == 1 };
            assert_eq!(growth.target(observation(now + INTERVAL * step, bytes, pressure)), 0);
        }
    }
}
#[test]
fn blocked_output_and_expired_evidence_do_not_accumulate_credit() {
    let now = Instant::now();
    let mut growth = Growth::new(now, CAPACITY * 8);
    growth.target(observation(now, CAPACITY as u64, true));
    let mut blocked = observation(now + INTERVAL / 2, CAPACITY as u64, true);
    blocked.pressure = Pressure::Receive { storage_limited: true, credit_limited: false, output_ready: false };
    assert_eq!(growth.target(blocked), 0);
    assert_eq!(growth.target(observation(now + INTERVAL, 0, true)), 0);
    assert_eq!(growth.target(observation(now + INTERVAL * 10, CAPACITY as u64 * 2, false)), 0);
}
#[test]
fn boundary_pressure_without_ack_survives_for_the_next_epoch() {
    let now = Instant::now();
    let mut growth = Growth::new(now, CAPACITY * 8);
    assert_eq!(growth.target(observation(now + INTERVAL * 10, 0, true)), 0);
    assert_eq!(growth.target(observation(now + INTERVAL * 10 + INTERVAL / 2, 62_464, true)), 0);
    assert_eq!(growth.target(observation(now + INTERVAL * 11, 0, false)), CAPACITY * 2);
}
#[test]
fn rx_idle_reclaim_survives_delivery_until_advertised_credit_drains() {
    let now = Instant::now();
    let mut growth = Growth::new(now, CAPACITY * 8);
    assert_eq!(growth.reclaim_request(now + IDLE, CAPACITY, 0), Some(INITIAL_CAPACITY));
    assert_eq!(growth.reclaim, Some(INITIAL_CAPACITY));
    growth.target(observation(now + IDLE, 1, false));
    assert_eq!(growth.reclaim, Some(INITIAL_CAPACITY));
    assert_eq!(growth.reclaim_request(now + IDLE * 2, CAPACITY, 0), Some(INITIAL_CAPACITY));
    growth.reclaimed(now + IDLE * 2);
    assert_eq!(growth.reclaim_request(now + IDLE * 2, INITIAL_CAPACITY, 0), None);
}
#[test]
fn unknown_rtt_never_grows_and_limits_are_preserved() {
    let now = Instant::now();
    let mut growth = Growth::new(now, CAPACITY * 8);
    for step in 0..=20 {
        let mut o = observation(now + INTERVAL * step, CAPACITY as u64 * 4, true);
        o.rtt = Duration::ZERO;
        assert_eq!(growth.target(o), 0);
    }
    assert_eq!(growth.target(observation(now + INTERVAL * 21, 0, true)), 0);
    let mut at_limit = Growth::new(now, CAPACITY);
    for step in 0..=2 {
        assert_eq!(at_limit.target(observation(now + INTERVAL * step, CAPACITY as u64 * 4, true)), 0);
    }
}

#[test]
fn partial_wan_refills_keep_pressure_across_ack_sampling_phase() {
    let now = Instant::now();
    let mut growth = Growth::new(now, CAPACITY * 8);
    assert_eq!(growth.target(observation(now, 0, true)), 0);
    assert_eq!(growth.target(observation(now + Duration::from_micros(600), 62_464, false)), 0);
    assert_eq!(growth.target(observation(now + INTERVAL * 2, 0, true)), CAPACITY * 2);
}
#[test]
fn slow_turnover_cannot_accumulate_over_an_arbitrarily_long_window() {
    let now = Instant::now();
    let mut growth = Growth::new(now, CAPACITY * 8);
    for step in 0..100 {
        assert_eq!(growth.target(observation(now + INTERVAL * step, CAPACITY as u64 / 4, true)), 0);
    }
}
#[test]
fn long_rtt_requires_a_complete_pressure_interval() {
    let now = Instant::now();
    let mut growth = Growth::new(now, CAPACITY * 8);
    for (ms, expected) in [(0, 0), (50, 0), (100, CAPACITY * 2)] {
        let mut o = observation(now + Duration::from_millis(ms), CAPACITY as u64, true);
        o.rtt = Duration::from_millis(100);
        assert_eq!(growth.target(o), expected);
    }
}

#[test]
fn boundary_progress_is_not_counted_again_in_the_next_rx_epoch() {
    let now = Instant::now();
    let mut growth = Growth::new(now, CAPACITY * 8);
    assert_eq!(growth.target(observation(now, 0, true)), 0);
    assert_eq!(growth.target(observation(now + INTERVAL, CAPACITY as u64, true)), 0);
    assert_eq!(growth.target(observation(now + INTERVAL * 2, CAPACITY as u64 / 2, true)), 0);
}

#[test]
fn idle_deadline_is_cancelled_while_reclaim_waits_for_credit() {
    let now = Instant::now();
    let mut growth = Growth::new(now, CAPACITY * 8);
    assert_eq!(growth.idle_deadline(INITIAL_CAPACITY, 0), None);
    assert_eq!(growth.idle_deadline(CAPACITY, 1), None);
    assert_eq!(growth.idle_deadline(CAPACITY, 0), Some(now + IDLE));
    growth.reclaim_request(now + IDLE, CAPACITY, 0);
    assert_eq!(growth.idle_deadline(CAPACITY, 0), None);
}
