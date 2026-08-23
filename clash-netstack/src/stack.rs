use std::sync::Arc;

use bytes::Bytes;
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
    tcp_listener::{TcpListener, TcpStreamHandle},
};

/// Thin `Stream` wrapper around a bounded `mpsc::Receiver`.
struct ReceiverStream(mpsc::Receiver<Packet>);

impl Stream for ReceiverStream {
    type Item = Packet;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

pub(crate) enum IfaceEvent<'a> {
    Icmp, // ICMP packet received
    TcpStream(Box<(smoltcp::socket::tcp::Socket<'a>, Arc<TcpStreamHandle>)>), /* new TCP stream created */
    TcpSocketReady, // at least one TCP socket is ready to read/write
    TcpSocketClosed, /* TCP socket closed by the application, e.g. the TcpStream
                     * is dropped */
    DeviceReady, // Device generated some packets
}
impl std::fmt::Debug for IfaceEvent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IfaceEvent::Icmp => write!(f, "IfaceEvent::Icmp"),
            IfaceEvent::TcpStream(_) => write!(f, "IfaceEvent::TcpStream"),
            IfaceEvent::TcpSocketReady => write!(f, "IfaceEvent::TcpSocketReady"),
            IfaceEvent::TcpSocketClosed => write!(f, "IfaceEvent::TcpSocketClosed"),
            IfaceEvent::DeviceReady => write!(f, "IfaceEvent::DeviceReady"),
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
    tcp_inbound: mpsc::UnboundedSender<Packet>,

    // outside poll this to receive packets from the stack
    tcp_outbound: mpsc::Receiver<Packet>,
    udp_outbound: mpsc::Receiver<Packet>,
}

use crate::ring_buffer::PooledBuffer;

#[derive(Debug)]
pub enum PacketData {
    Bytes(Bytes),
    Pooled(PooledBuffer),
}

pub struct Packet {
    data: PacketData,
}

impl Packet {
    pub fn new(data: impl Into<Bytes>) -> Self {
        Packet {
            data: PacketData::Bytes(data.into()),
        }
    }

    pub fn from_pooled(pooled: PooledBuffer) -> Self {
        Packet {
            data: PacketData::Pooled(pooled),
        }
    }

    pub fn data(&self) -> &[u8] {
        match &self.data {
            PacketData::Bytes(b) => b.as_ref(),
            PacketData::Pooled(p) => p.as_ref(),
        }
    }

    pub fn into_bytes(self) -> Bytes {
        match self.data {
            PacketData::Bytes(b) => b,
            PacketData::Pooled(p) => p.into_bytes(),
        }
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

impl From<PooledBuffer> for Packet {
    fn from(pooled: PooledBuffer) -> Self {
        Packet::from_pooled(pooled)
    }
}

impl NetStack {
    /// Returns the NetStack instance, a TcpListener and a UdpSocket
    pub fn new() -> (
        Self,
        crate::tcp_listener::TcpListener,
        crate::udp_socket::UdpSocket,
    ) {
        let (tcp_packet_sender, tcp_packet_receiver) = mpsc::channel::<Packet>(4096);
        // UDP uses a separate bounded channel. UDP is inherently lossy so
        // drop-on-full (via try_send) is correct; the bound prevents unbounded
        // memory growth if a remote floods responses faster than the consumer
        // can drain them.
        let (udp_packet_sender, udp_packet_receiver) = mpsc::channel::<Packet>(4096);

        let (udp_inbound_app, udp_outbound_stack) =
            mpsc::channel::<crate::udp_socket::UdpPacket>(4096);

        // this UdpSocket is essentially an Iface for UDP but much simpler as it only
        // does packets forwarding
        let udp_socket = UdpSocket::new(udp_outbound_stack, udp_packet_sender);
        let (tcp_inbound_app, tcp_outbound_stack) =
            mpsc::unbounded_channel::<Packet>();
        let tcp_listener = TcpListener::new(tcp_outbound_stack, tcp_packet_sender);

        let stack = NetStack {
            udp_inbound: udp_inbound_app,
            tcp_inbound: tcp_inbound_app,
            tcp_outbound: tcp_packet_receiver,
            udp_outbound: udp_packet_receiver,
        };

        (stack, tcp_listener, udp_socket)
    }

    pub fn split(self) -> (StackSplitSink, StackSplitStream) {
        (
            StackSplitSink::new(self.udp_inbound, self.tcp_inbound),
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
    tcp_inbound: mpsc::UnboundedSender<Packet>,

    packet_container: Option<PendingInbound>,
}

impl StackSplitSink {
    pub fn new(
        udp_inbound: mpsc::Sender<crate::udp_socket::UdpPacket>,
        tcp_inbound: mpsc::UnboundedSender<Packet>,
    ) -> Self {
        Self {
            udp_inbound,
            tcp_inbound,
            packet_container: None,
        }
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

    fn start_send(
        mut self: std::pin::Pin<&mut Self>,
        item: Packet,
    ) -> Result<(), Self::Error> {
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
        let packet = IpPacket::new_checked(item.data())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let protocol = packet.protocol();
        if matches!(
            protocol,
            IpProtocol::Tcp | IpProtocol::Icmp | IpProtocol::Icmpv6
        ) {
            self.packet_container = Some(PendingInbound::Tcp(item));
        } else {
            debug!("tun IP packet ignored (protocol: {protocol:?})");
        }

        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let pending = match self.packet_container.take() {
            Some(val) => val,
            None => return std::task::Poll::Ready(Ok(())),
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
                self.tcp_inbound.send(tcp_pkt).map_err(|e| {
                    debug!("Failed to send TCP packet: {e}");
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)
                })?;
            }
        }
        std::task::Poll::Ready(Ok(()))
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
        tcp_outbound: mpsc::Receiver<Packet>,
        udp_outbound: mpsc::Receiver<Packet>,
    ) -> Self {
        Self {
            inner: futures::stream::select(
                ReceiverStream(tcp_outbound),
                ReceiverStream(udp_outbound),
            ),
        }
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
