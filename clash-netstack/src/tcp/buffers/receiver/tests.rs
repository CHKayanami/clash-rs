use super::*;
const CAPACITY: usize = 32 * 1024;
const STEP: Duration = Duration::from_millis(5);
fn observation(now: Instant) -> Observation {
    Observation { now, rtt: Duration::from_millis(1), consumed: CAPACITY,
        output_ready: true, state: ReceiveState { capacity: CAPACITY, stored: 0,
            required: CAPACITY, storage_limited: true, credit_limited: false } }
}
#[test]
fn only_sustained_storage_pressure_with_consumption_grows_rx() {
    let now = Instant::now();
    for mode in 0..5 {
        let mut receiver = Receiver::new(now, CAPACITY * 8);
        for step in 0..=2 {
            let mut o = observation(now + STEP * step);
            match mode {
                1 => o.state.storage_limited = false, // Consumption alone is insufficient.
                2 => o.output_ready = false,
                3 => o.consumed = 0,
                4 => o.rtt = Duration::ZERO,
                _ => {},
            }
            assert_eq!(receiver.target(o), if mode == 0 && step == 2 { CAPACITY * 2 } else { 0 });
        }
    }
}
#[test]
fn idle_request_does_not_authorize_releasing_advertised_credit() {
    let now = Instant::now();
    let mut receiver = Receiver::new(now, CAPACITY * 8);
    let state = observation(now).state;
    assert_eq!(receiver.reclaim_request(now + Duration::from_secs(31), state),
        Some(super::super::INITIAL_CAPACITY));
    assert!(state.required > super::super::INITIAL_CAPACITY);
    receiver.target(observation(now + Duration::from_secs(31)));
    assert_eq!(receiver.reclaim_request(now + Duration::from_secs(31), state),
        Some(super::super::INITIAL_CAPACITY));
}

#[test]
fn advertised_credit_pressure_survives_a_reader_draining_each_batch() {
    let now = Instant::now();
    let mut receiver = Receiver::new(now, CAPACITY * 8);
    for step in 0..=2 {
        let mut o = observation(now + STEP * step);
        o.state.storage_limited = false;
        o.state.credit_limited = true;
        // A drained userspace queue does not mean the sender had ample credit.
        o.state.stored = 0;
        assert_eq!(receiver.target(o), if step == 2 { CAPACITY * 2 } else { 0 });
    }
}
