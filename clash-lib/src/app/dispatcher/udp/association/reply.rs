//! One reply destination per physical association; mapping remains in worker.
use std::{io, mem, task::{Context, Poll}};
use crate::proxy::datagram::UdpPacket;
use super::super::replies::Sender;
#[cfg(feature = "tun")]
use super::direct::ReplyWriter;

pub(super) enum Destination {
    Queued(Sender),
    #[cfg(feature = "tun")]
    Direct(Box<dyn ReplyWriter>),
}
impl Destination {
    pub(super) fn queued(sender: &Sender) -> Self { Self::Queued(sender.clone()) }
    pub(super) fn is_closed(&self) -> bool {
        match self {
            Self::Queued(writer) => writer.is_closed(),
            #[cfg(feature = "tun")]
            Self::Direct(writer) => writer.is_closed(),
        }
    }
    pub(super) fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<bool> {
        match self {
            Self::Queued(_) => Poll::Ready(true),
            #[cfg(feature = "tun")]
            Self::Direct(writer) => writer.poll_ready(_cx),
        }
    }
    pub(super) fn send(&mut self, packets: &mut Vec<UdpPacket>) -> io::Result<()> {
        match self {
            Self::Queued(writer) => writer.send_batch(mem::take(packets)),
            #[cfg(feature = "tun")]
            Self::Direct(writer) => writer.send(packets),
        }
    }
}
