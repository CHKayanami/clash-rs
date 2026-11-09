use crate::{Packet, link::output::{Output, Permit}};
use clash_common::ring_buffer::acquire_vec;
use std::collections::VecDeque;
use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use tokio::sync::mpsc;

pub struct NetstackDevice {
    rx_queue: VecDeque<Packet>,

    tx_sender: Output,

}

impl NetstackDevice {
    pub fn new(tx_sender: mpsc::Sender<Packet>) -> Self {
        Self { rx_queue: VecDeque::with_capacity(32), tx_sender: Output::Channel(tx_sender) }
    }

    pub fn inject(&mut self, packet: Packet) { self.rx_queue.push_back(packet); }

    pub fn is_empty(&self) -> bool { self.rx_queue.is_empty() }

    pub(crate) fn queue_len(&self) -> usize { self.rx_queue.len() }


    pub fn output_available(&self) -> bool { self.tx_sender.capacity() > 0 }

    pub fn output(&self) -> &mpsc::Sender<Packet> {
        match &self.tx_sender { Output::Channel(sender) => sender, _ => unreachable!("local output") }
    }

    pub(crate) fn local(limit: usize) -> Self {
        Self { rx_queue: VecDeque::with_capacity(32), tx_sender: Output::local(limit) }
    }

    pub(crate) fn split(&mut self) -> (&mut VecDeque<Packet>, &mut Output) {
        (&mut self.rx_queue, &mut self.tx_sender)
    }

    pub(crate) fn pop_output(&mut self) -> Option<Packet> { self.tx_sender.pop() }
}

/// One synchronous ICMP exchange. The packet never enters an unbounded queue;
/// reserving output capacity first keeps receive/transmit token ownership paired.
pub(crate) struct SinglePacketDevice<'a> {
    packet: Option<Packet>,
    outbound: &'a mut Output,
    mtu: usize,
}

impl<'a> SinglePacketDevice<'a> {
    pub(crate) fn new(packet: Option<Packet>, outbound: &'a mut Output, mtu: usize) -> Self {
        Self { packet, outbound, mtu }
    }
}

impl Device for SinglePacketDevice<'_> {
    type RxToken<'a> = RxTokenImpl where Self: 'a;
    type TxToken<'a> = TxTokenImpl<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let permit = self.outbound.reserve()?;
        let packet = self.packet.take()?;
        Some((RxTokenImpl { packet }, TxTokenImpl { tx_sender: permit }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.outbound.reserve().map(|permit| TxTokenImpl { tx_sender: permit })
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
        let packet = device.split().0.pop_front().expect("ingress must not reserve an output slot");
        assert_eq!(packet.data(), b"input");
        assert!(device.is_empty());
        device.split().0.push_front(packet);
        assert_eq!(device.split().0.pop_front().unwrap().data(), b"input");
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
    tx_sender: Permit<'a>,
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
