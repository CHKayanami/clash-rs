//! Final device admission charges actual storage until device writes complete.
use std::{sync::Arc, task::{Context, Poll}};
#[cfg(any(target_os = "linux", target_os = "android", test))]
use std::io;
use clash_netstack::Packet as IpPacket;
#[cfg(any(target_os = "linux", target_os = "android", test))]
use bytes::BytesMut;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

const BYTE_BUDGET: usize = 4 * 1024 * 1024;
const PACKET_BUDGET: usize = 512;

pub(super) struct Packet {
    pub bytes: IpPacket,
    pub budget: OwnedSemaphorePermit,
}

#[cfg(any(target_os = "linux", target_os = "android", test))]
#[derive(Clone)]
pub(super) struct Sender {
    channel: mpsc::Sender<Packet>,
    budget: Arc<Semaphore>,
}

pub(super) struct Receiver {
    channel: mpsc::Receiver<Packet>,
    budget: Arc<Semaphore>,
}

#[cfg(any(target_os = "linux", target_os = "android", test))]
pub(super) fn channel() -> (Sender, Receiver) {
    let (channel, receiver) = mpsc::channel(PACKET_BUDGET);
    let budget = Arc::new(Semaphore::new(BYTE_BUDGET));
    (Sender { channel, budget: budget.clone() }, Receiver { channel: receiver, budget })
}
#[cfg(not(any(target_os = "linux", target_os = "android", test)))]
pub(super) fn closed() -> Receiver {
    let (_, channel) = mpsc::channel(PACKET_BUDGET);
    Receiver { channel, budget: Arc::new(Semaphore::new(BYTE_BUDGET)) }
}
impl Receiver {
    pub fn poll_recv_many(&mut self, cx: &mut Context<'_>, packets: &mut Vec<Packet>,
        limit: usize) -> Poll<usize> {
        self.channel.poll_recv_many(cx, packets, limit)
    }

    #[cfg(test)]
    pub async fn recv(&mut self) -> Option<Packet> { self.channel.recv().await }
    #[cfg(test)]
    pub fn try_recv(&mut self) -> Result<Packet, mpsc::error::TryRecvError> { self.channel.try_recv() }
}
impl Drop for Receiver {
    fn drop(&mut self) { self.budget.close(); }
}

#[cfg(any(target_os = "linux", target_os = "android", test))]
impl Sender {
    async fn acquire(&self, charge: usize) -> io::Result<OwnedSemaphorePermit> {
        if charge > BYTE_BUDGET {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "TUN batch exceeds byte budget"));
        }
        self.budget.clone().acquire_many_owned(charge as u32).await
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    #[cfg(any(target_os = "linux", target_os = "android", test))]
    pub async fn send(&self, packet: BytesMut) -> io::Result<()> {
        let budget = self.acquire(packet.capacity().max(1)).await?;
        self.channel.send(Packet { bytes: IpPacket::from(packet), budget }).await
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }


}

#[cfg(test)]
mod tests;
