//! Direct netstack adapter: no TUN-to-dispatcher bridge tasks or packet queues.
use std::{fmt, io, mem, pin::Pin, sync::Arc,
    task::{Context, Poll}};
use futures::{Sink, Stream, ready};
use ipnet::IpNet;
use tokio::{sync::oneshot, task::JoinSet};
use tracing::{debug, trace, warn};
use watfaq_netstack::{SplitRead, SplitWrite, UdpPacket as StackUdpPacket,
    UdpSocket};
use crate::{
    app::dns::{ThreadSafeDNSResolver, exchange_with_resolver, query::IngressProfile},
    config::internal::config::DnsHijack,
    proxy::datagram::{UdpPacket, batch::{BatchResult, DatagramBatch, PacketBatch,
        MAX_BATCH_PACKETS}},
    session::{Network, SocksAddr},
};

const MAX_PENDING_DNS: usize = 256;

pub(super) struct TunDatagram {
    reader: SplitRead,
    writer: SplitWrite,
    resolver: ThreadSafeDNSResolver,
    dns_hijack: DnsHijack,
    strict_route: bool,
    exclude_routes: Arc<Vec<IpNet>>,
    dns: JoinSet<()>,
    incoming: Vec<StackUdpPacket>,
    outgoing: Vec<StackUdpPacket>,
    // Dropping the adapter wakes its owner, including on dispatcher failure.
    _completion: oneshot::Sender<()>,
}

impl fmt::Debug for TunDatagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunDatagram").field("pending_dns", &self.dns.len()).finish()
    }
}

impl TunDatagram {
    pub(super) fn new(socket: UdpSocket, resolver: ThreadSafeDNSResolver,
        dns_hijack: DnsHijack, strict_route: bool, exclude_routes: Arc<Vec<IpNet>>)
        -> (Self, oneshot::Receiver<()>) {
        let (reader, writer) = socket.split();
        let (completion, finished) = oneshot::channel();
        (Self {
            reader, writer, resolver, dns_hijack, strict_route, exclude_routes,
            dns: JoinSet::new(), incoming: Vec::with_capacity(MAX_BATCH_PACKETS),
            outgoing: Vec::with_capacity(MAX_BATCH_PACKETS),
            _completion: completion,
        }, finished)
    }

    fn accept(&mut self, packet: StackUdpPacket) -> Option<UdpPacket> {
        let StackUdpPacket { data, local_addr, remote_addr } = packet;
        if remote_addr.ip().is_multicast() || (self.strict_route
            && self.exclude_routes.iter().any(|net| net.contains(&remote_addr.ip()))) {
            return None;
        }
        if self.dns_hijack.is_hijacked(Network::Udp, &remote_addr) {
            if self.dns.len() >= MAX_PENDING_DNS {
                debug!("TUN DNS concurrency limit reached, dropping query");
                return None;
            }
            let resolver = self.resolver.clone();
            let mut writer = self.writer.clone();
            self.dns.spawn(async move {
                match exchange_with_resolver(&resolver, data.into_bytes(),
                    IngressProfile::Udp { advertised_size: 512 }, Some(local_addr.ip())).await {
                    Ok(response) => {
                        if let Err(error) = writer.send((response, remote_addr, local_addr).into()).await {
                            debug!("failed to return TUN DNS response: {error}");
                        }
                    }
                    Err(error) => warn!("failed to exchange TUN DNS packet: {error}"),
                }
            });
            return None;
        }
        Some(UdpPacket { data: data.into_bytes(), src_addr: local_addr.into(),
            dst_addr: remote_addr.into(), inbound_user: None })
    }

    fn poll_dns(&mut self, cx: &mut Context<'_>) {
        for _ in 0..MAX_BATCH_PACKETS {
            match self.dns.poll_join_next(cx) {
                Poll::Ready(Some(Err(error))) => warn!("TUN DNS task failed: {error}"),
                Poll::Ready(Some(Ok(()))) => {}
                _ => return,
            }
        }
        cx.waker().wake_by_ref();
    }

    fn receive(&mut self, cx: &mut Context<'_>, packets: &mut Vec<UdpPacket>) -> Poll<Option<()>> {
        self.poll_dns(cx);
        let count = ready!(self.reader.poll_recv_many(cx, &mut self.incoming, MAX_BATCH_PACKETS));
        if count == 0 { return Poll::Ready(None); }
        let initial = packets.len();
        let mut incoming = mem::take(&mut self.incoming);
        for packet in incoming.drain(..) {
            if let Some(packet) = self.accept(packet) { packets.push(packet); }
        }
        self.incoming = incoming;
        if packets.len() > initial { Poll::Ready(Some(())) }
        else {
            // A filtered/DNS-only batch still consumes an ingress budget. Give
            // replies and control events a turn before reading another batch.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    fn stack_packet(packet: &UdpPacket) -> io::Result<StackUdpPacket> {
        match (&packet.src_addr, &packet.dst_addr) {
            (SocksAddr::Ip(source), SocksAddr::Ip(destination)) =>
                Ok((packet.data.clone(), *source, *destination).into()),
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "TUN UDP reply requires IP addresses")),
        }
    }

    fn send_batch(&mut self, batch: &PacketBatch) -> BatchResult {
        let mut mapping_error = None;
        for packet in batch.packets() {
            match Self::stack_packet(packet) {
                Ok(packet) => self.outgoing.push(packet),
                Err(error) => { mapping_error = Some(error); break; }
            }
        }
        let result = self.writer.send_batch(&self.outgoing);
        self.outgoing.clear();
        if result.dropped > 0 { debug!(dropped = result.dropped, "TUN UDP output queue full"); }
        let error = result.error.or(mapping_error);
        let fatal = error.as_ref().is_some_and(|error| error.kind() == io::ErrorKind::BrokenPipe);
        // Congestion drops are consumed, not retried. An error belongs only to
        // the next packet; later valid packets remain in the caller's batch.
        BatchResult { sent: result.sent + result.dropped, error, fatal }
    }
}

impl Stream for TunDatagram {
    type Item = UdpPacket;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>> {
        let this = self.get_mut();
        this.poll_dns(cx);
        for _ in 0..MAX_BATCH_PACKETS {
            match ready!(this.reader.poll_recv(cx)) {
                Some(packet) => if let Some(packet) = this.accept(packet) {
                    return Poll::Ready(Some(packet));
                },
                None => return Poll::Ready(None),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl Sink<UdpPacket> for TunDatagram {
    type Error = io::Error;
    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn start_send(mut self: Pin<&mut Self>, packet: UdpPacket) -> io::Result<()> {
        // The netstack writer never waits: submit or deliberately drop here,
        // so a Sink error cannot be attributed to a later batch's first packet.
        let packet = Self::stack_packet(&packet)?;
        let result = self.writer.send_batch(&[packet]);
        if result.dropped > 0 { trace!("TUN UDP output queue full, dropped reply"); }
        match result.error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl DatagramBatch for TunDatagram {
    fn poll_send_batch(&mut self, _: &mut Context<'_>, batch: &mut PacketBatch) -> Poll<BatchResult> {
        Poll::Ready(self.send_batch(batch))
    }
    fn poll_recv_batch(&mut self, cx: &mut Context<'_>, packets: &mut Vec<UdpPacket>) -> Poll<Option<()>> {
        self.receive(cx, packets)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
