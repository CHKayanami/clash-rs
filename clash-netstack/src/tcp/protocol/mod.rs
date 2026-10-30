//! TCP protocol state, buffering and congestion control owned by ClashRS.
//! Derived from smoltcp; see LICENSE-0BSD.txt for upstream attribution.
#[cfg(test)]
macro_rules! net_trace {
    ($($arg:tt)*) => { log::trace!($($arg)*) };
}
macro_rules! net_debug {
    ($($arg:tt)*) => { log::debug!($($arg)*) };
}
macro_rules! net_log {
    (trace, $($arg:tt)*) => { log::trace!($($arg)*) };
    (debug, $($arg:tt)*) => { log::debug!($($arg)*) };
}
mod context;
mod socket;
pub mod storage;
mod waker;

pub use context::Context;
pub use socket::*;
use waker::WakerRegistration;
use smoltcp::time::Instant;

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
pub(crate) enum PollAt {
    Now,
    Time(Instant),
    Ingress,
}
