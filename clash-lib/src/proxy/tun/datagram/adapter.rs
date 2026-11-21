//! Read netstack UDP batches and submit proxy replies to the device output.
use std::{io, mem, sync::Arc,
    task::{Context, Poll}};
use futures::ready;
use ipnet::IpNet;
use tokio::task::JoinSet;
use tracing::{debug, warn};
use clash_netstack::{SplitRead, SplitWrite, UdpPacket as StackUdpPacket,
    UdpSocket};
use crate::{
    app::dns::{ThreadSafeDNSResolver, exchange_with_resolver, query::IngressProfile},
    config::internal::config::DnsHijack,
    proxy::datagram::{UdpPacket, batch::MAX_BATCH_PACKETS},
    session::{Network, SocksAddr},
};

const MAX_PENDING_DNS: usize = 256;

pub(crate) struct TunDatagram {
    reader: SplitRead,
    writer: SplitWrite,
    resolver: ThreadSafeDNSResolver,
    dns_hijack: DnsHijack,
    strict_route: bool,
    exclude_routes: Arc<Vec<IpNet>>,
    dns: JoinSet<()>,
    incoming: Vec<StackUdpPacket>,
}

impl TunDatagram {
    pub(crate) fn new(socket: UdpSocket, resolver: ThreadSafeDNSResolver,
        dns_hijack: DnsHijack, strict_route: bool, exclude_routes: Arc<Vec<IpNet>>) -> Self {
        let (reader, writer) = socket.split();
        Self {
            reader, writer, resolver, dns_hijack, strict_route, exclude_routes,
            dns: JoinSet::new(), incoming: Vec::with_capacity(MAX_BATCH_PACKETS),
        }
    }

    pub(crate) fn reply_writer(&self) -> SplitWrite {
        self.writer.clone()
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

    pub(crate) fn receive(&mut self, cx: &mut Context<'_>, packets: &mut Vec<UdpPacket>) -> Poll<Option<()>> {
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
            // Let DNS completions and close events run before reading again.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

pub(crate) fn submit_udp_replies(writer: &SplitWrite, mut packets: &mut [UdpPacket]) -> io::Result<()> {
    while !packets.is_empty() {
        let result = writer.send_batch_mapped(packets, |packet| {
            let (SocksAddr::Ip(source), SocksAddr::Ip(destination)) =
                (&packet.src_addr, &packet.dst_addr)
            else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput, "TUN UDP reply requires IP addresses",
                ));
            };
            Ok((mem::take(&mut packet.data), *source, *destination).into())
        });
        if result.dropped > 0 { debug!(dropped = result.dropped, "TUN UDP output queue full"); }
        match result.error {
            Some(error) if error.kind() == io::ErrorKind::BrokenPipe => return Err(error),
            Some(error) => {
                debug!("failed to send TUN UDP reply: {error}");
                packets = &mut packets[result.sent + 1..];
            }
            None => break,
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
