use std::{io, sync::Arc};

use bytes::{Bytes, BytesMut};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

const BYTE_BUDGET: usize = 4 * 1024 * 1024;

pub(super) struct Packet {
    pub bytes: Bytes,
    pub budget: OwnedSemaphorePermit,
}

#[derive(Clone)]
pub(super) struct Sender {
    channel: mpsc::Sender<Packet>,
    budget: Arc<Semaphore>,
}

pub(super) fn channel() -> (Sender, mpsc::Receiver<Packet>) {
    let (channel, receiver) = mpsc::channel(512);
    (Sender { channel, budget: Arc::new(Semaphore::new(BYTE_BUDGET)) }, receiver)
}

impl Sender {
    async fn acquire(&self, charge: usize) -> io::Result<OwnedSemaphorePermit> {
        if charge > BYTE_BUDGET {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "TUN batch exceeds byte budget"));
        }
        self.budget.clone().acquire_many_owned(charge as u32).await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TUN byte budget closed"))
    }

    pub async fn send(&self, packet: BytesMut) -> io::Result<()> {
        // Device-reader packets own their allocation, so capacity accounts for
        // retained storage without a fixed MTU-dependent minimum charge.
        let charge = packet.capacity().max(1);
        let bytes = packet.freeze();
        let budget = self.acquire(charge).await?;
        self.channel.send(Packet { bytes, budget }).await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TUN packet queue closed"))
    }

    pub async fn send_batch(&self, packets: &mut Vec<Bytes>) -> io::Result<()> {
        if packets.is_empty() { return Ok(()); }
        let charge = packets.iter().map(|packet| packet.len().max(1)).sum();
        // All producers acquire bytes before channel slots, preventing a cycle
        // between slot reservations and the byte budget. Cancellation releases
        // both resources; writers retain byte permits until I/O completes.
        let mut budget = self.acquire(charge).await?;
        let slots = self.channel.reserve_many(packets.len()).await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TUN packet queue closed"))?;
        for (slot, bytes) in slots.zip(packets.drain(..)) {
            let permit = budget.split(bytes.len().max(1)).expect("reserved batch budget");
            slot.send(Packet { bytes, budget: permit });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocated(capacity: usize) -> BytesMut {
        let mut packet = BytesMut::with_capacity(capacity);
        packet.extend_from_slice(b"x");
        packet
    }

    #[tokio::test]
    async fn compact_replies_and_reader_allocations_share_the_same_budget() {
        let (compact, mut receiver) = channel();
        let mut replies = vec![Bytes::from(vec![0; 100]), Bytes::from(vec![0; 200])];
        compact.send_batch(&mut replies).await.unwrap();
        compact.send(allocated(4096)).await.unwrap();
        assert_eq!(compact.budget.available_permits(), BYTE_BUDGET - 4396);
        let first = receiver.recv().await.unwrap();
        let second = receiver.recv().await.unwrap();
        let third = receiver.recv().await.unwrap();
        assert_eq!(first.budget.num_permits(), 100);
        assert_eq!(second.budget.num_permits(), 200);
        assert_eq!(third.budget.num_permits(), 4096);
        drop((first, second, third));
        assert_eq!(compact.budget.available_permits(), BYTE_BUDGET);
    }

    #[tokio::test]
    async fn budget_is_held_until_writer_releases_packet_storage() {
        let (sender, mut receiver) = channel();
        sender.send(allocated(BYTE_BUDGET)).await.unwrap();
        let packet = receiver.recv().await.unwrap();
        assert_eq!(sender.budget.available_permits(), 0);
        assert!(sender.budget.clone().try_acquire_owned().is_err());
        drop(packet);
        assert_eq!(sender.budget.available_permits(), BYTE_BUDGET);
    }

    #[tokio::test]
    async fn closed_queue_and_cancelled_admission_return_budget() {
        let (sender, receiver) = channel();
        drop(receiver);
        let mut packets = vec![Bytes::from_static(b"one"), Bytes::from_static(b"two")];
        assert!(sender.send_batch(&mut packets).await.is_err());
        assert_eq!(sender.budget.available_permits(), BYTE_BUDGET);
        assert_eq!(packets.len(), 2);
        let (sender, mut receiver) = channel();
        sender.send(allocated(BYTE_BUDGET)).await.unwrap();
        let held = receiver.recv().await.unwrap();
        assert!(tokio::time::timeout(std::time::Duration::from_millis(10),
            sender.send(allocated(1))).await.is_err());
        drop(held);
        assert_eq!(sender.budget.available_permits(), BYTE_BUDGET);
        assert!(receiver.try_recv().is_err());
    }
}
