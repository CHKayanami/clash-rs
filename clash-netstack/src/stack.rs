use bytes::Bytes;
use futures::future::poll_fn;
use std::io;
use futures::Stream;
use log::debug;
use smoltcp::wire::IpProtocol;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::mpsc;

use crate::{
    UdpSocket,
    debug::trace_ip_packet,
    packet::IpPacket,
    interface::IcmpResponder,
    tcp_listener::TcpListener,
};

/// Thin `Stream` wrapper around a bounded `mpsc::Receiver`.
struct ReceiverStream(Option<mpsc::Receiver<Packet>>);

impl Stream for ReceiverStream {
    type Item = Packet;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.0.as_mut() {
            Some(receiver) => receiver.poll_recv(cx),
            None => Poll::Ready(None),
        }
    }
}

/// IO of the stack:
/// Sink to the stack with any IP packets
/// it will be demultiplexed to the correct protocol handler and each handler
/// will process the packets accordingly and write back to the stack Stream
/// Application can Stream the packets from the stack
pub struct NetStack {
    // where the packets get into UDP Stack
    udp_inbound: mpsc::Sender<crate::udp_socket::UdpPacket>,
    // inject TCP packets into the stack
    // where the packets get into TCP Stack
    tcp_inbound: Option<mpsc::Sender<Packet>>,

    // outside poll this to receive packets from the stack
    tcp_outbound: Option<mpsc::Receiver<Packet>>,
    udp_outbound: mpsc::Receiver<Packet>,
    icmp_outbound: Option<mpsc::Sender<Packet>>,
    enable_icmp: bool,
    mtu: usize,
}

#[derive(Debug, Clone)]
pub struct Packet {
    data: Bytes,
}

impl Packet {
    #[inline]
    pub fn new(data: impl Into<Bytes>) -> Self {
        Packet {
            data: data.into(),
        }
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }

    #[inline]
    pub fn into_bytes(self) -> Bytes {
        self.data
    }
}

impl From<Bytes> for Packet {
    fn from(data: Bytes) -> Self {
        Packet::new(data)
    }
}

impl From<Vec<u8>> for Packet {
    fn from(data: Vec<u8>) -> Self {
        Packet::new(Bytes::from(data))
    }
}

impl From<&'static [u8]> for Packet {
    fn from(data: &'static [u8]) -> Self {
        Packet::new(Bytes::from_static(data))
    }
}

impl From<bytes::BytesMut> for Packet {
    fn from(data: bytes::BytesMut) -> Self {
        Packet::new(data.freeze())
    }
}

impl NetStack {
    /// Returns the NetStack instance, a TcpListener and a UdpSocket
    pub fn new() -> (
        Self,
        crate::tcp_listener::TcpListener,
        crate::udp_socket::UdpSocket,
    ) {
        let (stack, listener, udp) = Self::new_with_protocols(true, true);
        (stack, listener.expect("TCP enabled"), udp)
    }

    /// Select TCP and local ICMP handling independently; UDP is always enabled.
    pub fn new_with_protocols(enable_tcp: bool, enable_icmp: bool) -> (Self, Option<TcpListener>, UdpSocket) {
        Self::new_with_mtu(enable_tcp, enable_icmp, 1500).expect("valid default MTU")
    }

    /// Configure the actual L3 link MTU, independently of read buffer capacity.
    pub fn new_with_mtu(enable_tcp: bool, enable_icmp: bool, mtu: usize)
        -> io::Result<(Self, Option<TcpListener>, UdpSocket)> {
        if !(1280..=65535).contains(&mtu) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid dual-stack MTU"));
        }
        // UDP uses a separate bounded channel. UDP is inherently lossy so
        // drop-on-full (via try_send) is correct; the bound prevents unbounded
        // memory growth if a remote floods responses faster than the consumer
        // can drain them.
        let (udp_packet_sender, udp_packet_receiver) = mpsc::channel::<Packet>(4096);

        let (udp_inbound_app, udp_outbound_stack) =
            mpsc::channel::<crate::udp_socket::UdpPacket>(4096);

        // this UdpSocket is essentially an Iface for UDP but much simpler as it only
        // does packets forwarding
        let udp_socket = UdpSocket::new(udp_outbound_stack, udp_packet_sender.clone());
        let (tcp_inbound_app, tcp_packet_receiver, tcp_listener) = if enable_tcp {
            let (sender, receiver) = mpsc::channel(4096);
            let (inbound, packets) = mpsc::channel(4096);
            (Some(inbound), Some(receiver), Some(TcpListener::new(packets, sender, mtu)))
        } else { (None, None, None) };

        let stack = NetStack {
            udp_inbound: udp_inbound_app,
            tcp_inbound: tcp_inbound_app,
            tcp_outbound: tcp_packet_receiver,
            udp_outbound: udp_packet_receiver,
            icmp_outbound: (!enable_tcp && enable_icmp).then_some(udp_packet_sender),
            enable_icmp, mtu,
        };

        Ok((stack, tcp_listener, udp_socket))
    }

    pub fn split(self) -> (StackSplitSink, StackSplitStream) {
        (
            StackSplitSink::new(self.udp_inbound, self.tcp_inbound, self.icmp_outbound, self.enable_icmp, self.mtu),
            StackSplitStream::new(self.tcp_outbound, self.udp_outbound),
        )
    }
}

enum PendingInbound {
    Udp(crate::udp_socket::UdpPacket),
    Tcp(Packet),
}

pub struct StackSplitSink {
    udp_inbound: mpsc::Sender<crate::udp_socket::UdpPacket>,
    tcp_inbound: Option<mpsc::Sender<Packet>>,

    packet_container: Option<PendingInbound>,
    icmp_outbound: Option<mpsc::Sender<Packet>>,
    enable_icmp: bool,
    mtu: usize,
    icmp: Option<Box<IcmpResponder>>,
}

impl StackSplitSink {
    pub fn new(
        udp_inbound: mpsc::Sender<crate::udp_socket::UdpPacket>,
        tcp_inbound: Option<mpsc::Sender<Packet>>,
        icmp_outbound: Option<mpsc::Sender<Packet>>,
        enable_icmp: bool,
        mtu: usize,
    ) -> Self {
        Self {
            udp_inbound,
            tcp_inbound,
            packet_container: None,
            icmp_outbound,
            enable_icmp, mtu,
            icmp: None,
        }
    }
}

impl StackSplitSink {
    /// Submit synchronously without creating a per-packet Sink future.
    /// Full queues retain the same drop policy as the Sink adapter.
    pub fn send_packet(&mut self, item: Packet) -> io::Result<()> {
        self.flush_pending()?;
        self.enqueue_packet(item)?;
        self.flush_pending()
    }

    fn enqueue_packet(&mut self, item: Packet) -> io::Result<()> {
        if item.data().is_empty() {
            return Ok(());
        }

        trace_ip_packet("tun inbound packet", item.data());

        // Fast-path: single-pass zero-copy parsing for UDP packets
        if let Some((src_addr, dst_addr, payload_range)) =
            crate::udp_socket::parse_udp_packet(item.data())
        {
            let payload = item.into_bytes().slice(payload_range);
            self.packet_container = Some(PendingInbound::Udp(
                crate::udp_socket::UdpPacket {
                    data: Packet::new(payload),
                    local_addr: src_addr,
                    remote_addr: dst_addr,
                },
            ));
            return Ok(());
        }

        // TCP / ICMP parsing
        let packet = match IpPacket::new_checked(item.data()) {
            Ok(packet) => packet,
            Err(error) => {
                log::trace!("dropping malformed TUN IP packet: {error}");
                return Ok(());
            }
        };

        let protocol = packet.protocol();
        if !self.enable_icmp && matches!(protocol, IpProtocol::Icmp | IpProtocol::Icmpv6) {
            return Ok(());
        }
        if self.tcp_inbound.is_some() && matches!(protocol,
            IpProtocol::Tcp | IpProtocol::Icmp | IpProtocol::Icmpv6) {
            self.packet_container = Some(PendingInbound::Tcp(item));
        } else if matches!(protocol, IpProtocol::Icmp | IpProtocol::Icmpv6) {
            let this = self;
            let outbound = this.icmp_outbound.as_ref().expect("ICMP output without TCP");
            this.icmp.get_or_insert_with(|| Box::new(IcmpResponder::new(outbound, this.mtu))).respond(item, outbound);
        } else {
            debug!("tun IP packet ignored (protocol: {protocol:?})");
        }

        Ok(())
    }

    fn flush_pending(&mut self) -> io::Result<()> {
        let pending = match self.packet_container.take() {
            Some(val) => val,
            None => return Ok(()),
        };

        match pending {
            PendingInbound::Udp(udp_pkt) => {
                match self.udp_inbound.try_send(udp_pkt) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        log::trace!("UDP inbound queue full, dropped packet");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        log::debug!("UDP inbound queue closed");
                    }
                }
            }
            PendingInbound::Tcp(tcp_pkt) => {
                match self.tcp_inbound.as_ref().expect("TCP enabled").try_send(tcp_pkt) {
                    Ok(()) => {}
                    // TCP retransmission recovers congestion loss. Never block
                    // the shared TUN reader (and UDP) on this queue.
                    Err(mpsc::error::TrySendError::Full(_)) => log::trace!("TCP input queue full"),
                    Err(mpsc::error::TrySendError::Closed(_)) => return Err(
                        io::Error::new(io::ErrorKind::BrokenPipe, "TCP stack stopped")),
                }
            }
        }
        Ok(())
    }
}

impl futures::Sink<Packet> for StackSplitSink {
    type Error = std::io::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if self.packet_container.is_none() {
            std::task::Poll::Ready(Ok(()))
        } else {
            std::task::Poll::Pending
        }
    }

    fn start_send(self: Pin<&mut Self>, item: Packet) -> Result<(), Self::Error> {
        self.get_mut().enqueue_packet(item)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(self.get_mut().flush_pending())
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

pub struct StackSplitStream {
    inner: futures::stream::Select<ReceiverStream, ReceiverStream>,
}
impl StackSplitStream {
    pub fn new(
        tcp_outbound: Option<mpsc::Receiver<Packet>>,
        udp_outbound: mpsc::Receiver<Packet>,
    ) -> Self {
        Self {
            inner: futures::stream::select(
                ReceiverStream(tcp_outbound),
                ReceiverStream(Some(udp_outbound)),
            ),
        }
    }

    /// Drain currently ready replies into reusable storage without waiting for
    /// a full batch. A partial batch is returned as soon as the stream parks.
    pub async fn recv_many(&mut self, packets: &mut Vec<Bytes>, limit: usize) -> io::Result<usize> {
        let initial = packets.len();
        poll_fn(|cx| {
            while packets.len() - initial < limit {
                match Pin::new(&mut *self).poll_next(cx) {
                    Poll::Ready(Some(Ok(packet))) => packets.push(packet.into_bytes()),
                    Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                    Poll::Ready(None) => break,
                    Poll::Pending if packets.len() == initial => return Poll::Pending,
                    Poll::Pending => break,
                }
            }
            Poll::Ready(Ok(packets.len() - initial))
        }).await
    }

}
impl futures::Stream for StackSplitStream {
    type Item = std::io::Result<Packet>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use futures::StreamExt;
        self.inner.poll_next_unpin(cx).map(|opt| {
            opt.map(|packet| {
                trace_ip_packet("tun reply packet", packet.data());
                Ok(packet)
            })
        })
    }
}

#[cfg(test)]
#[path = "stack_tests.rs"]
mod tests;
