//! Independent diagnostic and exceptional event budgets.
use std::time::{Duration, Instant};

const MAX_PER_SECOND: u32 = 32;

struct Window {
    start: Instant,
    emitted: u32,
    suppressed: u64,
}

pub(super) struct Decision {
    pub allowed: bool,
    pub suppressed: u64,
}

pub(super) struct EventLogLimits {
    normal: Window,
    exceptional: Window,
}

impl Window {
    fn new(start: Instant) -> Self { Self { start, emitted: 0, suppressed: 0 } }

    fn check(&mut self, now: Instant) -> Decision {
        let mut suppressed = 0;
        if now.duration_since(self.start) >= Duration::from_secs(1) {
            suppressed = self.suppressed;
            *self = Self::new(now);
        }
        let allowed = self.emitted < MAX_PER_SECOND;
        if allowed { self.emitted += 1; }
        else { self.suppressed += 1; }
        Decision { allowed, suppressed }
    }
}

impl EventLogLimits {
    pub(super) fn new(now: Instant) -> Self {
        Self { normal: Window::new(now), exceptional: Window::new(now) }
    }

    pub(super) fn check(&mut self, normal: bool, now: Instant) -> Decision {
        if normal { self.normal.check(now) } else { self.exceptional.check(now) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_flood_cannot_consume_exceptional_budget() {
        let now = Instant::now();
        let mut limits = EventLogLimits::new(now);
        for _ in 0..MAX_PER_SECOND { assert!(limits.check(true, now).allowed); }
        for _ in 0..39 { assert!(!limits.check(true, now).allowed); }
        for _ in 0..MAX_PER_SECOND { assert!(limits.check(false, now).allowed); }
        assert!(!limits.check(false, now).allowed);
        let next = now + Duration::from_secs(1);
        let normal = limits.check(true, next);
        assert!(normal.allowed);
        assert_eq!(normal.suppressed, 39);
        let exceptional = limits.check(false, next);
        assert!(exceptional.allowed);
        assert_eq!(exceptional.suppressed, 1);
        assert_eq!(limits.check(true, next).suppressed, 0);
    }
}
