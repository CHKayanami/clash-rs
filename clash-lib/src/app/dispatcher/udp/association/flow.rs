use std::{net::SocketAddr, sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}}, time::Duration};
use tokio::{sync::mpsc, time::Instant};

use crate::{app::dispatcher::{TrackGuard, TrackerInfo}, proxy::datagram::UdpPacket, session::SocksAddr};
use super::{Association, Control, Outgoing};

pub(crate) struct ReplyActivity {
    epoch: Instant,
    last_reply: AtomicU64,
}

impl ReplyActivity {
    pub(crate) fn new() -> Self {
        Self { epoch: Instant::now(), last_reply: AtomicU64::new(0) }
    }
    #[cfg(test)]
    pub(crate) fn record(&self) {
        self.record_at(Instant::now());
    }
    pub(crate) fn record_at(&self, now: Instant) {
        self.last_reply.store(now.duration_since(self.epoch).as_nanos() as u64 + 1, Ordering::Relaxed);
    }
    pub(crate) fn latest(&self) -> Option<Instant> {
        let elapsed = self.last_reply.load(Ordering::Relaxed);
        (elapsed != 0).then(|| self.epoch + Duration::from_nanos(elapsed - 1))
    }
}

#[derive(Clone)]
pub(crate) struct FlowClosed {
    pub id: u64,
    pub source: SocketAddr,
    pub original: SocksAddr,
    pub user: Option<Arc<str>>,
}

pub(super) struct FlowState {
    pub id: u64,
    pub source: SocketAddr,
    pub target: SocksAddr,
    pub original: SocksAddr,
    pub aliases: Vec<SocksAddr>,
    pub tracker: Arc<TrackerInfo>,
    pub activity: Arc<ReplyActivity>,
    pub closed: AtomicBool,
    pub events: mpsc::UnboundedSender<FlowClosed>,
    pub _guard: TrackGuard,
}

impl FlowState {
    pub fn is_closed(&self) -> bool { self.closed.load(Ordering::Relaxed) }
    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::Relaxed) {
            let _ = self.events.send(FlowClosed {
                id: self.id, source: self.source, original: self.original.clone(), user: self.tracker.session_holder.inbound_user.clone(),
            });
        }
    }
}

/// A cached route and a lease. No per-flow task, packet queue or receive loop.
pub(crate) struct UdpFlow {
    pub(super) state: Arc<FlowState>,
    pub(super) association: Arc<Association>,
}

impl UdpFlow {
    pub(crate) fn is_closed(&self) -> bool {
        self.state.is_closed() || self.association.outgoing.is_closed()
    }
    pub(crate) fn reply_activity(&self) -> Arc<ReplyActivity> {
        self.state.activity.clone()
    }
    pub(crate) fn try_send(&self, mut packet: UdpPacket) -> Result<(), mpsc::error::TrySendError<UdpPacket>> {
        if self.is_closed() {
            return Err(mpsc::error::TrySendError::Closed(packet));
        }
        if packet.dst_addr != self.state.target { packet.dst_addr = self.state.target.clone(); }
        self.association.outgoing.try_send(Outgoing {
            id: self.state.id, packet,
        }).map_err(|err| match err {
            mpsc::error::TrySendError::Full(outgoing) => mpsc::error::TrySendError::Full(outgoing.packet),
            mpsc::error::TrySendError::Closed(outgoing) => mpsc::error::TrySendError::Closed(outgoing.packet),
        })
    }
}

impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.state.closed.store(true, Ordering::Relaxed);
        let _ = self.association.control.try_send(Control::Remove(self.state.id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn reply_activity_uses_the_receive_timestamp_without_resampling() {
        let activity = ReplyActivity::new();
        let received = Instant::now();
        tokio::time::advance(Duration::from_millis(5)).await;
        activity.record_at(received);
        assert_eq!(activity.latest(), Some(received));
    }
}
