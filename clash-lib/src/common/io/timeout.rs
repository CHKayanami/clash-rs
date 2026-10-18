//! One registered timer covers idle and half-close deadlines.
use std::{future::Future, pin::Pin, task::Context, time::Duration};
use tokio::time::{Instant, Sleep, sleep_until};
use super::{COPY_IDLE_TIMEOUT, transfer::Direction};

pub(super) struct CopyTimeouts {
    timer: Pin<Box<Sleep>>,
    last_active: Instant,
    half_close: Option<Instant>,
    upload_timeout: Duration,
    download_timeout: Duration,
}

impl CopyTimeouts {
    pub(super) fn new(upload_timeout: Duration, download_timeout: Duration) -> Self {
        let last_active = Instant::now();
        Self {
            timer: Box::pin(sleep_until(last_active + COPY_IDLE_TIMEOUT)),
            last_active,
            half_close: None,
            upload_timeout,
            download_timeout,
        }
    }

    pub(super) fn record_activity(&mut self, active: bool) {
        if active {
            self.last_active = Instant::now();
        }
    }

    pub(super) fn idle_expired(&self) -> bool {
        Instant::now() >= self.last_active + COPY_IDLE_TIMEOUT
    }

    pub(super) fn half_close_expired(&self) -> bool {
        self.half_close.is_some_and(|deadline| Instant::now() >= deadline)
    }

    pub(super) fn start_half_close(&mut self, direction: Direction) {
        let timeout = match direction {
            Direction::Upload => self.upload_timeout,
            Direction::Download => self.download_timeout,
        };
        self.half_close = Some(Instant::now() + timeout);
    }

    pub(super) fn wrote(&mut self, direction: Direction) {
        if self.half_close.is_some() {
            let timeout = match direction {
                Direction::Upload => self.upload_timeout,
                Direction::Download => self.download_timeout,
            };
            self.half_close = Some(self.last_active + timeout);
        }
    }

    pub(super) fn stop_half_close(&mut self) {
        self.half_close = None;
    }

    pub(super) fn poll_wait(&mut self, cx: &mut Context<'_>) {
        let idle = self.last_active + COPY_IDLE_TIMEOUT;
        let deadline = self.half_close.map_or(idle, |half| idle.min(half));
        // Keep an earlier registration during activity. Only shorten it for
        // a new half-close deadline, or rearm once the old timer has fired.
        if deadline < self.timer.deadline() {
            self.timer.as_mut().reset(deadline);
        }
        if self.timer.as_mut().poll(cx).is_ready() {
            if Instant::now() >= deadline {
                cx.waker().wake_by_ref();
            } else {
                self.timer.as_mut().reset(deadline);
                if self.timer.as_mut().poll(cx).is_ready() {
                    cx.waker().wake_by_ref();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;
    use tokio::time::advance;

    #[tokio::test(start_paused = true)]
    async fn activity_defers_timer_reset_until_registered_deadline() {
        let mut timeouts = CopyTimeouts::new(Duration::from_secs(10), Duration::from_secs(10));
        let initial = timeouts.timer.deadline();
        let mut task = tokio_test::task::spawn(pending::<()>());
        task.enter(|cx, _| timeouts.poll_wait(cx));
        advance(Duration::from_secs(90)).await;
        timeouts.record_activity(true);
        task.enter(|cx, _| timeouts.poll_wait(cx));
        assert_eq!(timeouts.timer.deadline(), initial);
        advance(Duration::from_secs(90)).await;
        assert!(task.is_woken());
        assert!(!timeouts.idle_expired());
        task.enter(|cx, _| timeouts.poll_wait(cx));
        assert_eq!(timeouts.timer.deadline(), initial + Duration::from_secs(90));
        advance(Duration::from_secs(90)).await;
        assert!(timeouts.idle_expired());
    }
}
