//! Batch ownership crosses tasks once; credits include queued and pending writes.
use std::{collections::VecDeque, io, sync::Arc, task::{Context, Poll}};
#[cfg(test)]
use futures::future::poll_fn;
use tracing::debug;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use crate::proxy::datagram::{UdpPacket, batch::{PacketBatch, MAX_BATCH_PACKETS}};

const MAX_PACKET_BYTES: usize = 65535;

#[derive(Clone)]
pub(crate) struct Sender {
    channel: mpsc::Sender<Batch>,
    credits: Arc<Semaphore>,
}

pub(crate) struct Receiver {
    channel: mpsc::Receiver<Batch>,
    credits: Arc<Semaphore>,
    #[cfg(test)]
    pending: Option<Batch>,
}

pub(crate) struct Batch {
    packets: VecDeque<UdpPacket>,
    _credits: OwnedSemaphorePermit,
}

pub(crate) fn channel(capacity: usize) -> (Sender, Receiver) {
    assert!(capacity > 0);
    let credits = Arc::new(Semaphore::new(capacity));
    let (sender, receiver) = mpsc::channel(capacity);
    (Sender { channel: sender, credits: credits.clone() },
        Receiver { channel: receiver, credits, #[cfg(test)] pending: None })
}

impl Sender {
    pub fn is_closed(&self) -> bool { self.channel.is_closed() }
    pub async fn closed(&self) { self.channel.closed().await; }

    #[cfg(test)]
    pub async fn send(&self, packet: UdpPacket) -> io::Result<()> {
        let permit = self.credits.clone().acquire_owned().await.map_err(|_| io::ErrorKind::BrokenPipe)?;
        self.publish(vec![packet], permit)
    }

    pub fn send_batch(&self, mut packets: Vec<UdpPacket>) -> io::Result<()> {
        if packets.is_empty() { return Ok(()); }
        // Logical UDP payload lengths are bounded; Bytes may share storage.
        if packets.len() > MAX_BATCH_PACKETS || packets.iter().any(|p| p.data.len() > MAX_PACKET_BYTES) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "UDP receive batch exceeds bounds"));
        }
        let permit = (1..=packets.len()).rev().find_map(|count|
            self.credits.clone().try_acquire_many_owned(count as u32).ok());
        let Some(permit) = permit else {
            debug!(dropped = packets.len(), "UDP inbound reply queue full");
            return if self.is_closed() { Err(io::ErrorKind::BrokenPipe.into()) } else { Ok(()) };
        };
        let dropped = packets.len() - permit.num_permits();
        if dropped > 0 { debug!(dropped, "UDP inbound reply queue full"); }
        packets.truncate(permit.num_permits());
        self.publish(packets, permit)
    }

    fn publish(&self, packets: Vec<UdpPacket>, permit: OwnedSemaphorePermit) -> io::Result<()> {
        let batch = Batch { packets: packets.into(), _credits: permit };
        match self.channel.try_send(batch) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::ErrorKind::BrokenPipe.into()),
            // Each nonempty batch owns at least one credit, including ours.
            Err(mpsc::error::TrySendError::Full(_)) => unreachable!("reserved UDP reply slot"),
        }
    }
}

impl Batch {
    pub fn fill(&mut self, sending: &mut PacketBatch) {
        while !sending.is_full() {
            let Some(packet) = self.packets.pop_front() else { break; };
            if let Err(packet) = sending.push(packet) { self.packets.push_front(packet); break; }
        }
    }
    pub fn is_empty(&self) -> bool { self.packets.is_empty() }
}

impl Receiver {
    #[cfg(all(test, feature = "tun"))]
    pub fn available_credits(&self) -> usize { self.credits.available_permits() }
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Batch>> { self.channel.poll_recv(cx) }
    pub fn close(&mut self) { self.credits.close(); self.channel.close(); }

    #[cfg(test)]
    pub async fn recv(&mut self) -> Option<UdpPacket> {
        loop {
            if let Some(batch) = &mut self.pending && let Some(packet) = batch.packets.pop_front() {
                if batch.is_empty() { self.pending = None; }
                return Some(packet);
            }
            self.pending = Some(poll_fn(|cx| self.poll_recv(cx)).await?);
        }
    }
}
impl Drop for Receiver {
    fn drop(&mut self) { self.credits.close(); }
}

#[cfg(test)]
mod tests;
