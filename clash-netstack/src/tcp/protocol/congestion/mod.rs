// Derived from smoltcp commit 6b126ba1e965add8d765dffee0338756ffdfb6da.
// Copyright (C) smoltcp contributors; licensed under 0BSD.
// See the protocol directory's LICENSE-0BSD.txt.

use smoltcp::time::Instant;

use super::RttEstimator;

pub(super) mod no_control;

pub(super) mod cubic;

pub(super) mod reno;

#[allow(unused_variables)]
pub(super) trait Controller {
    /// Returns the number of bytes that can be sent.
    fn window(&self) -> usize;

    /// Set the remote window size.
    fn set_remote_window(&mut self, remote_window: usize) {}

    fn on_ack(&mut self, now: Instant, len: usize, in_flight: usize, rtt: &RttEstimator) {}

    /// Fired on each duplicate ack received, after `on_loss` has been called.
    fn on_dup_ack(&mut self, now: Instant, len: usize, in_flight: usize) {}

    /// Fired on a retransmission timeout.
    fn on_rto(&mut self, now: Instant, in_flight: usize) {}

    /// Fired after an inferred loss via three duplicate acks.
    fn on_loss(&mut self, now: Instant, in_flight: usize) {}

    fn pre_transmit(&mut self, now: Instant) {}

    fn post_transmit(&mut self, now: Instant, len: usize) {}

    /// Set the maximum segment size.
    fn set_mss(&mut self, mss: usize) {}
}

#[derive(Debug)]

pub(super) enum AnyController {
    None(no_control::NoControl),

    Reno(reno::Reno),

    Cubic(cubic::Cubic),
}

impl AnyController {
    /// Use CUBIC by default; callers may select Reno or disable congestion control.
    #[inline]
    pub fn new() -> Self {
        AnyController::Cubic(cubic::Cubic::new())
    }

    #[inline]
    pub fn inner_mut(&mut self) -> &mut dyn Controller {
        match self {
            AnyController::None(n) => n,

            AnyController::Reno(r) => r,

            AnyController::Cubic(c) => c,
        }
    }

    #[inline]
    pub fn inner(&self) -> &dyn Controller {
        match self {
            AnyController::None(n) => n,

            AnyController::Reno(r) => r,

            AnyController::Cubic(c) => c,
        }
    }
}
