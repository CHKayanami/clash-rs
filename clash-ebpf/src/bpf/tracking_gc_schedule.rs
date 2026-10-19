//! Sweep cadence; batch pacing is independent of table occupancy.
use std::time::Duration;

const NORMAL: Duration = Duration::from_secs(5);
const PRESSURE: Duration = Duration::from_secs(1);
const IDLE_MAX: Duration = Duration::from_secs(30);

pub(super) struct Schedule {
    pause: Duration,
    idle: Duration,
    pressure: bool,
    low_rounds: u8,
}

impl Schedule {
    pub(super) fn new() -> Self {
        Self { pause: NORMAL, idle: Duration::ZERO, pressure: false, low_rounds: 0 }
    }

    pub(super) fn pause(&self) -> Duration { self.pause }

    /// Called once after both complete sweeps, never with a partial batch.
    pub(super) fn update(&mut self, usage_percent: u64, empty: bool) {
        if usage_percent >= 70 {
            self.pressure = true;
            self.low_rounds = 0;
        } else if self.pressure {
            if usage_percent < 50 {
                self.low_rounds += 1;
                if self.low_rounds == 3 {
                    self.pressure = false;
                    self.low_rounds = 0;
                }
            } else { self.low_rounds = 0; }
        }
        self.pause = if self.pressure {
            self.idle = Duration::ZERO;
            PRESSURE
        } else if empty {
            self.idle = if self.idle.is_zero() { NORMAL }
                else { (self.idle * 2).min(IDLE_MAX) };
            self.idle
        } else {
            self.idle = Duration::ZERO;
            NORMAL
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_sweeps_back_off_and_live_entries_reset_the_delay() {
        let mut schedule = Schedule::new();
        for seconds in [5, 10, 20, 30, 30] {
            schedule.update(0, true);
            assert_eq!(schedule.pause(), Duration::from_secs(seconds));
        }
        schedule.update(1, false);
        assert_eq!(schedule.pause(), NORMAL);
        schedule.update(0, true);
        assert_eq!(schedule.pause(), NORMAL);
    }

    #[test]
    fn pressure_has_hysteresis_and_requires_three_low_sweeps() {
        let mut schedule = Schedule::new();
        schedule.update(69, false);
        assert_eq!(schedule.pause(), NORMAL);
        schedule.update(70, false);
        assert_eq!(schedule.pause(), PRESSURE);
        for _ in 0..2 { schedule.update(49, false); }
        assert_eq!(schedule.pause(), PRESSURE);
        schedule.update(50, false); // Interrupt the low-usage streak.
        for _ in 0..2 { schedule.update(49, false); }
        assert_eq!(schedule.pause(), PRESSURE);
        schedule.update(49, false);
        assert_eq!(schedule.pause(), NORMAL);
    }

    #[test]
    fn pressure_cancels_idle_backoff() {
        let mut schedule = Schedule::new();
        for _ in 0..4 { schedule.update(0, true); }
        schedule.update(90, false);
        assert_eq!(schedule.pause(), PRESSURE);
        for _ in 0..3 { schedule.update(0, true); }
        assert_eq!(schedule.pause(), NORMAL);
    }
}
