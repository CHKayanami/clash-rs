//! Adapter for proxy relays. TUN DIRECT drives the same policy state itself.
use std::{io, mem, net::SocketAddr, sync::Arc, task::{Context, Poll}};
use tokio::{sync::mpsc, time::Instant};
use tracing::warn;
use crate::{common::io::datagram_relay::RelayContext,
    proxy::datagram::UdpPacket, session::SocksAddr};
use super::{AssociationConfig, Outgoing, Registration, state::AssociationState};
use super::super::replies::Sender as ReplySender;

pub(super) struct AssociationRelay {
    packets: mpsc::Receiver<Outgoing>,
    state: AssociationState,
    now: Instant,
    replies: ReplySender,
}
impl AssociationRelay {
    pub(super) fn new(packets: mpsc::Receiver<Outgoing>, commands: mpsc::Receiver<Registration>,
        config: &AssociationConfig, source: SocketAddr, user: Option<Arc<str>>,
        force_source: Option<SocksAddr>, replies: ReplySender, native: bool,
    ) -> Self {
        Self { packets, now: Instant::now(), state: AssociationState::new(commands, config, source, user, force_source, native), replies }
    }
}
impl RelayContext for AssociationRelay {
    fn poll_control(&mut self, cx: &mut Context<'_>) -> bool {
        self.now = Instant::now();
        !self.replies.is_closed() && self.state.poll_control(cx)
    }
    fn poll_outgoing(&mut self, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>> {
        for _ in 0..32 {
            match self.packets.poll_recv(cx) {
                Poll::Ready(Some(packet)) => if let Some(packet) = self.state.outgoing(packet, self.now) {
                    return Poll::Ready(Some(packet));
                },
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn sent(&mut self, result: io::Result<usize>) -> bool { self.state.sent(result, self.now) }
    fn received_batch(&mut self, packets: &mut Vec<UdpPacket>) -> bool {
        packets.retain_mut(|packet| self.state.map_received(packet, self.now));
        reply_result(self.replies.send_batch(mem::take(packets)))
    }

}

fn reply_result(result: io::Result<()>) -> bool {
    match result {
        Ok(()) => true,
        Err(error) => { warn!("UDP reply batch failed: {error}"); false },
    }
}
