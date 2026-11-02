//! Final-device admission and batched replies for TUN DIRECT UDP associations.
use std::{io, task::{Context, Poll}};
use bytes::Bytes;
use tokio_util::sync::ReusableBoxFuture;
use tracing::warn;
use clash_netstack::UdpPacket as StackPacket;
use crate::{app::dispatcher::udp::association::direct::{ReplyTarget, ReplyWriter},
    proxy::datagram::{UdpPacket, batch::MAX_BATCH_PACKETS}, session::SocksAddr};
use super::super::packet_queue::Sender;

pub(super) struct Target(pub Sender);
struct Writer {
    sender: Sender,
    packets: Option<Vec<Bytes>>,
    pending: Option<ReusableBoxFuture<'static, io::Result<Vec<Bytes>>>>,
}
impl ReplyTarget for Target {
    fn writer(&self) -> Box<dyn ReplyWriter> {
        Box::new(Writer { sender: self.0.clone(),
            packets: Some(Vec::with_capacity(MAX_BATCH_PACKETS)), pending: None })
    }
}
impl ReplyWriter for Writer {
    fn is_closed(&self) -> bool { self.sender.is_closed() }
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        if self.is_closed() { return Poll::Ready(false); }
        if self.packets.is_some() { return Poll::Ready(true); }
        match self.pending.as_mut().expect("pending TUN reply").poll(cx) {
            Poll::Ready(Ok(packets)) => { self.packets = Some(packets); Poll::Ready(true) }
            Poll::Ready(Err(error)) => {
                warn!("TUN direct reply failed: {error}");
                Poll::Ready(false)
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn send(&mut self, packets: &mut Vec<UdpPacket>) -> io::Result<()> {
        let mut encoded_packets = self.packets.take().expect("previous TUN reply drained");
        for packet in packets.drain(..) {
            let encoded = match (&packet.src_addr, &packet.dst_addr) {
                (SocksAddr::Ip(source), SocksAddr::Ip(destination)) =>
                    StackPacket::from((packet.data, *source, *destination)).encode(),
                _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "TUN UDP reply requires IP addresses")),
            };
            match encoded {
                Ok(packet) => encoded_packets.push(packet.into_bytes()),
                // A malformed native datagram must not discard valid suffixes
                // or invalidate the association's endpoint-independent mapping.
                Err(error) => warn!("dropping invalid direct UDP reply: {error}"),
            }
        }
        let sender = self.sender.clone();
        // At most one native batch is retained per association. Charge actual
        // encoded lengths, and finish admission before reading another batch.
        let send = async move {
            sender.send_batch(&mut encoded_packets).await?;
            Ok(encoded_packets)
        };
        if let Some(pending) = &mut self.pending { pending.set(send); }
        else { self.pending = Some(ReusableBoxFuture::new(send)); }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
