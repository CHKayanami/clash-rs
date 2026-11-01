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

    /// Reply capacity is owned by Driver, not tied to the output channel.
    pub(crate) fn take_packet(&mut self) -> Option<Packet> { self.rx_queue.pop_front() }

    /// Restore an unprocessed packet when its protocol still needs output space.
    pub(crate) fn put_back(&mut self, packet: Packet) { self.rx_queue.push_front(packet); }

    pub fn inject(&mut self, packet: Packet) { self.rx_queue.push_back(packet); }

    pub fn is_empty(&self) -> bool { self.rx_queue.is_empty() }

    #[cfg(test)]
    pub(crate) fn queue_len(&self) -> usize { self.rx_queue.len() }

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

    #[test]
    fn full_output_does_not_block_input() {
        let (sender, _receiver) = mpsc::channel(1);
        sender.try_send(Packet::new(&b"busy"[..])).unwrap();
        let mut device = NetstackDevice::new(sender);
        device.inject(Packet::new(&b"input"[..]));
        let packet = device.take_packet().expect("ingress must not reserve an output slot");
        assert_eq!(packet.data(), b"input");
        assert!(device.is_empty());
        device.put_back(packet);
        assert_eq!(device.take_packet().unwrap().data(), b"input");
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
