use super::*;

#[test]
fn ready_connections_rotate_and_are_deduplicated() {
    let mut schedule = Schedule::default();
    let (a, b) = (SocketHandle(1), SocketHandle(2));
    for _ in 0..1000 { schedule.update(a, PollAt::Now); }
    schedule.update(b, PollAt::Now);
    assert_eq!(schedule.pop_ready(), Some(a));
    schedule.update(a, PollAt::Now);
    assert_eq!(schedule.pop_ready(), Some(b));
    assert_eq!(schedule.pop_ready(), Some(a));
    assert_eq!(schedule.pop_ready(), None);
}

#[test]
fn repeated_deadline_updates_keep_one_record_per_connection() {
    let mut schedule = Schedule::default();
    let a = SocketHandle(1);
    for tick in 1..10000 {
        schedule.update(a, PollAt::Time(Instant::from_millis(tick)));
        assert_eq!(schedule.timers.len(), 1);
    }
    assert_eq!(schedule.delay(Instant::from_millis(9998)), Some(Duration::from_millis(1)));
    schedule.update(a, PollAt::Time(Instant::from_millis(2)));
    schedule.expire(Instant::from_millis(2), 1);
    assert_eq!(schedule.timers.len(), 0);
    assert_eq!(schedule.pop_ready(), Some(a));
    assert_eq!(schedule.pop_ready(), None);
}

#[test]
fn ready_timer_transitions_and_removal_leave_no_stale_work() {
    let mut schedule = Schedule::default();
    let a = SocketHandle(1);
    schedule.update(a, PollAt::Now);
    schedule.update(a, PollAt::Time(Instant::from_millis(10)));
    assert!(!schedule.has_ready());
    schedule.update(a, PollAt::Now);
    assert_eq!(schedule.timers.len(), 0);
    schedule.remove(a);
    schedule.expire(Instant::from_millis(100), 128);
    assert!(!schedule.has_ready());
    assert_eq!(schedule.delay(Instant::ZERO), None);
    schedule.update(a, PollAt::Now);
    schedule.update(a, PollAt::Ingress);
    assert!(!schedule.has_ready());
}

#[test]
fn bounded_timer_expiry_keeps_due_deadlines_visible_under_backpressure() {
    let mut schedule = Schedule::default();
    for id in 1..=5 {
        schedule.update(SocketHandle(id), PollAt::Time(Instant::from_millis(10)));
    }
    schedule.expire(Instant::from_millis(10), 2);
    assert_eq!(schedule.timers.len(), 3);
    assert_eq!(schedule.delay(Instant::from_millis(10)), Some(Duration::ZERO));
    schedule.expire(Instant::from_millis(10), 2);
    schedule.expire(Instant::from_millis(10), 2);
    assert_eq!(schedule.delay(Instant::from_millis(10)), None);
    for id in 1..=5 { assert_eq!(schedule.pop_ready(), Some(SocketHandle(id))); }
    assert_eq!(schedule.pop_ready(), None);
}

#[test]
fn failed_output_retries_before_later_connections() {
    let mut schedule = Schedule::default();
    let (a, b) = (SocketHandle(1), SocketHandle(2));
    schedule.update(a, PollAt::Now);
    schedule.update(b, PollAt::Now);
    assert_eq!(schedule.pop_ready(), Some(a));
    schedule.retry(a);
    assert_eq!(schedule.pop_ready(), Some(a));
    schedule.update(a, PollAt::Now);
    assert_eq!(schedule.pop_ready(), Some(b));
}

#[test]
fn completion_is_explicit_deduplicated_and_cancelled_on_reactivation() {
    let mut schedule = Schedule::default();
    let a = SocketHandle(1);
    schedule.update(a, PollAt::Time(Instant::from_millis(10)));
    for _ in 0..1000 { schedule.complete(a); }
    assert_eq!(schedule.timers.len(), 0);
    assert!(!schedule.has_ready());
    assert_eq!(schedule.pop_completed(), Some(a));
    assert_eq!(schedule.pop_completed(), None);
    schedule.complete(a);
    schedule.update(a, PollAt::Now);
    assert_eq!(schedule.pop_completed(), None);
    schedule.complete(a);
    schedule.remove(a);
    assert_eq!(schedule.pop_completed(), None);
    schedule.expire(Instant::from_millis(20), 128);
    assert!(!schedule.has_ready());
}
