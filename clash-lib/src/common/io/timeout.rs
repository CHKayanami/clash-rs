//! One registered timer covers idle and half-close deadlines.
use std::{future::Future, pin::Pin, task::Context, time::Duration};
use tokio::time::{Instant, Sleep, sleep_until};
use super::{COPY_IDLE_TIMEOUT, transfer::Direction};

pub(super) struct CopyTimeouts {
    timer: Pin<Box<Sleep>>,
    pub(super) last_active: Instant,
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
            self.start_half_close(direction);
        }
    }

    pub(super) fn stop_half_close(&mut self) {
        self.half_close = None;
    }

    pub(super) fn poll_wait(&mut self, cx: &mut Context<'_>) {
        let idle = self.last_active + COPY_IDLE_TIMEOUT;
        let deadline = self.half_close.map_or(idle, |half| idle.min(half));
        if self.timer.deadline() != deadline {
            self.timer.as_mut().reset(deadline);
        }
        // Register after I/O has updated both deadlines. If a deadline crossed
        // during this poll, schedule another poll to apply its timeout policy.
        if self.timer.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
    }
}
