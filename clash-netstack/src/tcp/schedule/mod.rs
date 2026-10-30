//! Protocol readiness is independent of application I/O readiness. Ingress,
//! application mutations and timer expiry all refresh this owner-only index.
mod ready;
mod timers;
use smoltcp::time::{Duration, Instant};
use super::{connections::SocketHandle, protocol::PollAt};
use ready::ReadyList;
use timers::Timers;

#[derive(Default)]
pub(crate) struct Schedule {
    ready: ReadyList,
    timers: Timers,
    completed: ReadyList,
}

impl Schedule {
    pub fn update(&mut self, handle: SocketHandle, poll: PollAt) {
        self.completed.remove(handle);
        match poll {
            PollAt::Now => { self.timers.remove(handle); self.ready.push_back(handle); }
            PollAt::Time(deadline) => { self.ready.remove(handle); self.timers.set(handle, deadline); }
            PollAt::Ingress => self.remove(handle),
        }
    }

    pub fn remove(&mut self, handle: SocketHandle) {
        self.ready.remove(handle);
        self.timers.remove(handle);
        self.completed.remove(handle);
    }

    pub fn complete(&mut self, handle: SocketHandle) {
        self.ready.remove(handle);
        self.timers.remove(handle);
        self.completed.push_back(handle);
    }

    pub fn pop_completed(&mut self) -> Option<SocketHandle> { self.completed.pop_front() }

    pub fn expire(&mut self, now: Instant, budget: usize) {
        for _ in 0..budget {
            let Some(handle) = self.timers.pop_due(now) else { break; };
            self.ready.push_back(handle);
        }
    }

    pub fn has_ready(&self) -> bool { !self.ready.is_empty() }
    pub fn pop_ready(&mut self) -> Option<SocketHandle> { self.ready.pop_front() }

    pub fn retry(&mut self, handle: SocketHandle) {
        self.timers.remove(handle);
        self.ready.push_front(handle);
    }

    pub fn delay(&self, now: Instant) -> Option<Duration> {
        self.timers.first().map(|deadline| if deadline > now { deadline - now } else { Duration::ZERO })
    }
}

#[cfg(test)]
mod tests;
