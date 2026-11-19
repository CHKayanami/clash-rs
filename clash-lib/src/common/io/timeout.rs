//! The idle timer is rearmed only when its registered deadline is reached.
use std::{future::Future, pin::Pin, task::Context};
use tokio::time::{Instant, Sleep, sleep_until};
use super::COPY_IDLE_TIMEOUT;

pub(super) struct IdleTimeout {
    timer: Pin<Box<Sleep>>,
    last_active: Instant,
}

impl IdleTimeout {
    pub(super) fn new() -> Self {
        let last_active = Instant::now();
        Self {
            timer: Box::pin(sleep_until(last_active + COPY_IDLE_TIMEOUT)),
            last_active,
        }
    }

    pub(super) fn record_activity(&mut self, active: bool) {
        if active {
            self.last_active = Instant::now();
        }
    }

    pub(super) fn expired(&self) -> bool {
        Instant::now() >= self.last_active + COPY_IDLE_TIMEOUT
    }

    pub(super) fn poll_wait(&mut self, cx: &mut Context<'_>) {
        if self.timer.as_mut().poll(cx).is_ready() {
            let deadline = self.last_active + COPY_IDLE_TIMEOUT;
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
    use std::{future::pending, time::Duration};
    use tokio::time::advance;

    #[tokio::test(start_paused = true)]
    async fn activity_defers_timer_reset_until_registered_deadline() {
        let mut timeouts = IdleTimeout::new();
        let initial = timeouts.timer.deadline();
        let mut task = tokio_test::task::spawn(pending::<()>());
        task.enter(|cx, _| timeouts.poll_wait(cx));
        advance(Duration::from_secs(90)).await;
        timeouts.record_activity(true);
        task.enter(|cx, _| timeouts.poll_wait(cx));
        assert_eq!(timeouts.timer.deadline(), initial);
        advance(Duration::from_secs(90)).await;
        assert!(task.is_woken());
        assert!(!timeouts.expired());
        task.enter(|cx, _| timeouts.poll_wait(cx));
        assert_eq!(timeouts.timer.deadline(), initial + Duration::from_secs(90));
        advance(Duration::from_secs(90)).await;
        assert!(timeouts.expired());
    }
}
