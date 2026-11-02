//! Final device admission charges actual storage until device writes complete.
use std::{io, sync::Arc};
use bytes::{Bytes, BytesMut};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

const BYTE_BUDGET: usize = 4 * 1024 * 1024;
const PACKET_BUDGET: usize = 512;

pub(super) struct Packet {
    pub bytes: Bytes,
    pub budget: OwnedSemaphorePermit,
}

#[derive(Clone)]
pub(super) struct Sender {
    channel: mpsc::Sender<Packet>,
    budget: Arc<Semaphore>,
}

pub(super) struct Receiver {
    channel: mpsc::Receiver<Packet>,
    budget: Arc<Semaphore>,
}

pub(super) fn channel() -> (Sender, Receiver) {
    let (channel, receiver) = mpsc::channel(PACKET_BUDGET);
    let budget = Arc::new(Semaphore::new(BYTE_BUDGET));
    (Sender { channel, budget: budget.clone() }, Receiver { channel: receiver, budget })
}
impl Receiver {
    pub async fn recv_many(&mut self, packets: &mut Vec<Packet>, limit: usize) -> usize {
        self.channel.recv_many(packets, limit).await
    }
    #[cfg(test)]
    pub async fn recv(&mut self) -> Option<Packet> { self.channel.recv().await }
    #[cfg(test)]
    pub fn try_recv(&mut self) -> Result<Packet, mpsc::error::TryRecvError> { self.channel.try_recv() }
}
impl Drop for Receiver {
    fn drop(&mut self) { self.budget.close(); }
}

impl Sender {
    pub fn is_closed(&self) -> bool { self.channel.is_closed() }
    async fn acquire(&self, charge: usize) -> io::Result<OwnedSemaphorePermit> {
        if charge > BYTE_BUDGET {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "TUN batch exceeds byte budget"));
        }
        self.budget.clone().acquire_many_owned(charge as u32).await
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    pub async fn send(&self, packet: BytesMut) -> io::Result<()> {
        let budget = self.acquire(packet.capacity().max(1)).await?;
        self.channel.send(Packet { bytes: packet.freeze(), budget }).await
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    pub async fn send_batch(&self, packets: &mut Vec<Bytes>) -> io::Result<()> {
        if packets.is_empty() { return Ok(()); }
        let charge = packets.iter().map(|packet| packet.len().max(1)).sum();
        // Every producer acquires bytes before slots. Byte permits cover the
        // channel and device-write batch; packet slots cover the channel.
        let mut budget = self.acquire(charge).await?;
        let slots = self.channel.reserve_many(packets.len()).await
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        for (slot, bytes) in slots.zip(packets.drain(..)) {
            let permit = budget.split(bytes.len().max(1)).expect("reserved batch budget");
            slot.send(Packet { bytes, budget: permit });
        }
        Ok(())
    }

}

#[cfg(test)]
mod tests;
