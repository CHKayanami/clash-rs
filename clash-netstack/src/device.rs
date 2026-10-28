use crate::Packet;
use std::collections::VecDeque;
use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use tokio::sync::mpsc;

pub struct NetstackDevice {
    rx_queue: VecDeque<Packet>,

    tx_sender: mpsc::Sender<Packet>,
    capabilities: DeviceCapabilities,

}

impl NetstackDevice {
    pub fn new(
        tx_sender: mpsc::Sender<Packet>, mtu: usize,
    ) -> Self {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = mtu;
        capabilities.medium = Medium::Ip;


        Self {
            rx_queue: VecDeque::with_capacity(32),
            tx_sender,
            capabilities,
        }
    }

    pub fn inject(&mut self, packet: Packet) { self.rx_queue.push_back(packet); }

    pub fn is_empty(&self) -> bool { self.rx_queue.is_empty() }

    pub fn output_available(&self) -> bool { self.tx_sender.capacity() > 0 }

    pub fn output(&self) -> &mpsc::Sender<Packet> { &self.tx_sender }
}

impl Device for NetstackDevice {
    type RxToken<'a> = RxTokenImpl;
    type TxToken<'a> = TxTokenImpl<'a>;

    fn receive(
        &mut self,
        _timestamp: Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Reserve a tx slot FIRST before touching rx_queue.
        // If we checked rx_queue first, a successful try_recv() would consume
        // the inbound packet even when try_reserve() subsequently fails, silently
        // dropping ACKs and preventing smoltcp from advancing its send window.
        let permit = self.tx_sender.try_reserve().ok()?;
        let packet = self.rx_queue.pop_front()?;

        let rx_token = RxTokenImpl { packet };
        let tx_token = TxTokenImpl { tx_sender: permit };
        Some((rx_token, tx_token))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.tx_sender
            .try_reserve()
            .map(|permit| TxTokenImpl { tx_sender: permit })
            .ok()
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
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
    use smoltcp::phy::Device;

    /// Reproduces the ACK-drop bug: when the outbound tx channel is full
    /// (simulating a slow consumer), `receive()` calls `try_recv()`
    /// unconditionally, consuming the inbound ACK from the queue, then
    /// `try_reserve()` fails because the tx channel is at capacity → the ACK
    /// is silently dropped.
    ///
    /// Without ACKs, smoltcp never advances its send window and the download
    /// stalls.
    #[tokio::test]
    async fn test_receive_drops_inbound_packet_when_tx_channel_full() {
        let (tx_sender, mut tx_receiver) = tokio::sync::mpsc::channel::<Packet>(1);
        let mut device = NetstackDevice::new(tx_sender, 1500);

        // Fill the tx channel to its capacity of 1
        device
            .tx_sender
            .try_send(Packet::new(vec![0u8; 60]))
            .expect("should fit in empty channel");
        // tx channel: FULL (capacity = 1)

        // Simulate an inbound ACK entering rx_queue
        device.inject(Packet::new(vec![0u8; 60]));
        // rx_queue: [ack_packet]

        // Call receive() while tx is full.
        // Due to the bug: try_recv() pops the ACK, then try_reserve() fails,
        // and the ACK is dropped (never returned, never processed by smoltcp).
        {
            let result = device.receive(smoltcp::time::Instant::now());
            assert!(
                result.is_none(),
                "receive() must return None when tx channel is full"
            );
        } // result dropped here — releasing the borrow on device

        // Drain the tx channel to make space
        tx_receiver.recv().await.expect("should have a packet");

        // Now try to receive again — with the bug the ACK is gone forever.
        // After the fix (check try_reserve first), the packet stays in rx_queue
        // and receive() can process it once tx space is available.
        let result2 = device.receive(smoltcp::time::Instant::now());
        assert!(
            result2.is_some(),
            "BUG: inbound ACK was silently dropped when tx channel was full; \
             smoltcp will never advance its send window → download stalls to 0"
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
        let mut buffer = crate::ring_buffer::acquire_vec(len);
        let result = f(&mut buffer[..len]);

        let packet = Packet::new(buffer);
        self.tx_sender.send(packet);

        result
    }
}
