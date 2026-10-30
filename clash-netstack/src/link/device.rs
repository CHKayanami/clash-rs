use crate::Packet;
use clash_common::ring_buffer::acquire_vec;
use std::collections::VecDeque;
use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use tokio::sync::mpsc;

pub struct NetstackDevice {
    rx_queue: VecDeque<Packet>,

    tx_sender: mpsc::Sender<Packet>,

}

impl NetstackDevice {
    pub fn new(tx_sender: mpsc::Sender<Packet>) -> Self {
        Self { rx_queue: VecDeque::with_capacity(32), tx_sender }
    }

    /// Reserve reply capacity before consuming input, including pure ACKs.
    pub(crate) fn take_packet(&mut self) -> Option<(Packet, mpsc::Permit<'_, Packet>)> {
        let permit = self.tx_sender.try_reserve().ok()?;
        let packet = self.rx_queue.pop_front()?;
        Some((packet, permit))
    }

    pub fn inject(&mut self, packet: Packet) { self.rx_queue.push_back(packet); }

    pub fn is_empty(&self) -> bool { self.rx_queue.is_empty() }

    pub fn output_available(&self) -> bool { self.tx_sender.capacity() > 0 }

    pub fn output(&self) -> &mpsc::Sender<Packet> { &self.tx_sender }
}

/// One synchronous ICMP exchange. The packet never enters an unbounded queue;
/// reserving output capacity first keeps receive/transmit token ownership paired.
pub(crate) struct SinglePacketDevice<'a> {
    packet: Option<Packet>,
    outbound: &'a mpsc::Sender<Packet>,
    mtu: usize,
}

impl<'a> SinglePacketDevice<'a> {
    pub(crate) fn new(packet: Option<Packet>, outbound: &'a mpsc::Sender<Packet>, mtu: usize) -> Self {
        Self { packet, outbound, mtu }
    }
}

impl Device for SinglePacketDevice<'_> {
    type RxToken<'a> = RxTokenImpl where Self: 'a;
    type TxToken<'a> = TxTokenImpl<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let permit = self.outbound.try_reserve().ok()?;
        let packet = self.packet.take()?;
        Some((RxTokenImpl { packet }, TxTokenImpl { tx_sender: permit }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.outbound.try_reserve().ok().map(|permit| TxTokenImpl { tx_sender: permit })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = self.mtu;
        capabilities.medium = Medium::Ip;
        capabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full output queue must leave ingress untouched so TCP ACKs cannot
    /// disappear before the protocol has a chance to advance its send window.
    #[tokio::test]
    async fn input_waits_for_reply_capacity() {
        let (tx_sender, mut tx_receiver) = tokio::sync::mpsc::channel::<Packet>(1);
        let mut device = NetstackDevice::new(tx_sender);

        // Fill the tx channel to its capacity of 1
        device
            .tx_sender
            .try_send(Packet::new(vec![0u8; 60]))
            .expect("should fit in empty channel");
        // tx channel: FULL (capacity = 1)

        // Simulate an inbound ACK entering rx_queue
        device.inject(Packet::new(vec![0u8; 60]));
        // rx_queue: [ack_packet]

        // Full output must not consume the pending ACK.
        {
            let result = device.take_packet();
            assert!(
                result.is_none(),
                "receive() must return None when tx channel is full"
            );
        } // result dropped here — releasing the borrow on device

        // Drain the tx channel to make space
        tx_receiver.recv().await.expect("should have a packet");

        // Releasing output capacity makes the same ACK available again.
        let result2 = device.take_packet();
        assert!(
            result2.is_some(),
            "BUG: inbound ACK was silently dropped when tx channel was full; \
             TCP will never advance its send window → download stalls to 0"
        );
    }
}

pub struct RxTokenImpl {
    packet: Packet,
}

impl RxToken for RxTokenImpl {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.packet.data())
    }
}

pub struct TxTokenImpl<'a> {
    tx_sender: mpsc::Permit<'a, Packet>,
}

impl<'a> TxToken for TxTokenImpl<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = acquire_vec(len);
        let result = f(&mut buffer[..len]);

        let packet = Packet::new(buffer);
        self.tx_sender.send(packet);

        result
    }
}
