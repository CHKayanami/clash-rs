use std::{collections::VecDeque, io, net::{SocketAddr, SocketAddrV6}, pin::Pin,
    task::{Context, Poll}};
use futures::{Sink, Stream, ready};
use tokio::net::UdpSocket;
use tracing::{trace, warn};
use crate::{proxy::{datagram::{UdpPacket, segments::DatagramSegments, batch::{DatagramBatch, PacketBatch, BatchResult, MAX_BATCH_PACKETS, MAX_DIRECT_BATCH_PACKETS}},
    utils::{poll_send_to_vectored, udp_batch::{self, DatagramSlice}}}, session::SocksAddr};

#[cfg(feature = "tun")]
use crate::proxy::datagram::segments::SegmentSendResult;

#[derive(Default)]
pub(crate) struct SendWorkspace {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    descriptors: udp_batch::SendWorkspace,
}
impl SendWorkspace {
    fn poll_plain(&mut self, socket: &UdpSocket, ipv6: bool, cx: &mut Context<'_>, slices: &[DatagramSlice<'_>]) -> Poll<BatchResult> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        { udp_batch::poll_send_with(socket, ipv6, cx, slices, &mut self.descriptors) }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        { udp_batch::poll_send_batch(socket, ipv6, cx, slices) }
    }
}

const MAX_CONSECUTIVE_RECV_ERRORS: usize = 32;
const MAX_BATCH_RECV_PACKETS: usize = 16;

/// A callback may return either an IP or a domain. An explicit tag preserves
/// receive-time mapping even when callers mix batch, segment and Stream APIs.
struct Received {
    packet: UdpPacket,
    mapped: bool,
}
impl Received {
    #[cfg(any(target_os = "linux", test))]
    fn raw(packet: UdpPacket) -> Self { Self { packet, mapped: false } }
    fn mapped(packet: UdpPacket) -> Self { Self { packet, mapped: true } }
    fn project(mut self, source: &mut impl FnMut(SocketAddr) -> SocksAddr) -> UdpPacket {
        if !self.mapped && let SocksAddr::Ip(peer) = self.packet.src_addr {
            self.packet.src_addr = source(peer);
        }
        self.packet
    }
}

/// Physical UDP I/O. No resolver or logical-address state is retained here.
pub struct NativeDatagram {
    inner: UdpSocket,
    local_is_ipv6: bool,
    #[cfg(target_os = "linux")]
    gro: bool,
    #[cfg(target_os = "linux")]
    receive_budget: super::recv::ReceiveBudget,
    #[cfg(target_os = "linux")]
    gso: bool,
    packet: Option<UdpPacket>,
    consecutive_recv_errors: usize,
    recv_queue: VecDeque<Received>,
}

impl NativeDatagram {
    pub fn new(inner: UdpSocket) -> io::Result<Self> {
        let local_is_ipv6 = inner.local_addr()?.is_ipv6();
        Ok(Self { inner, local_is_ipv6,
            #[cfg(target_os = "linux")] gro: false,
            #[cfg(target_os = "linux")] receive_budget: Default::default(),
            #[cfg(target_os = "linux")] gso: false,
            packet: None, consecutive_recv_errors: 0,
            recv_queue: VecDeque::with_capacity(MAX_BATCH_RECV_PACKETS) })
    }

    pub(super) fn local_is_ipv6(&self) -> bool { self.local_is_ipv6 }

    #[cfg(test)]
    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> { self.inner.local_addr() }

    pub(crate) fn physical_socket(&self) -> (&UdpSocket, bool) { (&self.inner, self.local_is_ipv6) }

    #[cfg(feature = "tun")]
    pub(crate) fn poll_send_segments(&mut self, cx: &mut Context<'_>, group: &DatagramSegments,
        offset: usize) -> Poll<SegmentSendResult> {
        let SocksAddr::Ip(destination) = group.packet.dst_addr else {
            return Poll::Ready(SegmentSendResult { bytes: 0, failed: group.packet.data.len() - offset,
                error: Some(io::Error::new(io::ErrorKind::InvalidInput, "UDP segment target must be an IP address")), fatal: false });
        };
        self.poll_send_segments_slice(cx, &group.packet.data[offset..], destination,
            usize::from(group.size.expect("segmented send").get()))
    }

    #[cfg(feature = "tun")]
    pub(crate) fn poll_send_segments_slice(&mut self, cx: &mut Context<'_>, remaining: &[u8],
        destination: SocketAddr, size: usize) -> Poll<SegmentSendResult> {
        self.poll_send_segments_with(cx, remaining, destination, size, &mut SendWorkspace::default())
    }

    #[cfg(feature = "tun")]
    pub(crate) fn poll_send_segments_with(&mut self, cx: &mut Context<'_>, remaining: &[u8],
        destination: SocketAddr, size: usize, workspace: &mut SendWorkspace) -> Poll<SegmentSendResult> {
        #[cfg(target_os = "linux")]
        if let Some(result) = super::offload::poll_send_segments(&self.inner, self.local_is_ipv6, cx,
            DatagramSlice { header: &[], payload: remaining, destination }, size, &mut self.gso, &mut workspace.descriptors) {
            return result.map(|result| SegmentSendResult { bytes: if result.sent > 0 { remaining.len() } else { 0 },
                failed: size.min(remaining.len()), error: result.error, fatal: result.fatal });
        }
        // Unsupported offload falls back only at the socket boundary. Slices
        // borrow the original aggregate; no payload is split/copied/recombined.
        let mut slices = std::array::from_fn::<_, MAX_DIRECT_BATCH_PACKETS, _>(|_| DatagramSlice {
            header: &[], payload: &[], destination,
        });
        let mut count = 0;
        for chunk in remaining.chunks(size).take(MAX_DIRECT_BATCH_PACKETS) {
            slices[count].payload = chunk; count += 1;
        }
        workspace.poll_plain(&self.inner, self.local_is_ipv6, cx, &slices[..count]).map(|result| {
            SegmentSendResult { bytes: slices[..result.sent].iter().map(|packet| packet.payload.len()).sum(),
                failed: if result.error.is_some() { slices[result.sent].payload.len() } else { 0 },
                error: result.error, fatal: result.fatal }
        })
    }

    // A raw receive must not bypass packets cached by Stream::poll_next.
    #[cfg(feature = "shadowsocks")]
    pub(crate) fn physical_recv_socket(&self) -> Option<&UdpSocket> {
        #[cfg(target_os = "linux")]
        if self.gro { return None; }
        self.recv_queue.is_empty().then_some(&self.inner)
    }

    pub(crate) fn poll_send_to_vectored(
        &self, cx: &mut Context<'_>, header: &[u8], payload: &[u8],
        mut destination: SocketAddr,
    ) -> Poll<io::Result<()>> {
        if self.local_is_ipv6 && let SocketAddr::V4(address) = destination {
            destination = SocketAddr::V6(SocketAddrV6::new(address.ip().to_ipv6_mapped(), address.port(), 0, 0));
        }
        poll_send_to_vectored(&self.inner, cx, header, payload, destination)
    }

    pub(super) fn poll_recv_batch_with(&mut self, cx: &mut Context<'_>,
        mut source: impl FnMut(SocketAddr) -> SocksAddr, packets: &mut Vec<UdpPacket>) -> Poll<Option<()>> {
        let start = packets.len();
        for _ in 0..MAX_BATCH_PACKETS {
            match self.poll_recv_with(cx, &mut source) {
                Poll::Ready(Some(packet)) => packets.push(packet),
                Poll::Ready(None) if packets.len() == start => return Poll::Ready(None),
                _ => break,
            }
        }
        if packets.len() > start { Poll::Ready(Some(())) } else { Poll::Pending }
    }
    pub(super) fn poll_recv_segments_with(&mut self, cx: &mut Context<'_>,
        mut source: impl FnMut(SocketAddr) -> SocksAddr, packets: &mut Vec<DatagramSegments>) -> Poll<Option<()>> {
        if !self.recv_queue.is_empty() {
            let count = self.recv_queue.len().min(MAX_BATCH_PACKETS);
            packets.extend(self.recv_queue.drain(..count).map(|packet| DatagramSegments::from(packet.project(&mut source))));
            return Poll::Ready(Some(()));
        }
        let start = packets.len();
        let result = self.poll_recv_segments(cx, packets);
        if matches!(result, Poll::Ready(Some(()))) {
            for group in &mut packets[start..] {
                if let SocksAddr::Ip(peer) = group.packet.src_addr { group.packet.src_addr = source(peer); }
            }
        }
        result
    }
    #[cfg(any(target_os = "linux", test))]
    fn observe_receive(&mut self, usable: bool) -> bool {
        if usable { self.consecutive_recv_errors = 0; }
        else { self.consecutive_recv_errors = self.consecutive_recv_errors.saturating_add(1); }
        self.consecutive_recv_errors < MAX_CONSECUTIVE_RECV_ERRORS
    }
    // The domain wrapper applies its mapping when the batch is received,
    // preserving the source of already-buffered packets across later sends.
    pub(super) fn poll_recv_with(&mut self, cx: &mut Context<'_>,
        mut source: impl FnMut(SocketAddr) -> SocksAddr,
    ) -> Poll<Option<UdpPacket>> {
        if let Some(packet) = self.recv_queue.pop_front() { return Poll::Ready(Some(packet.project(&mut source))); }
        #[cfg(target_os = "linux")]
        if self.gro {
            let mut groups = Vec::new();
            if ready!(self.poll_recv_segments(cx, &mut groups)).is_none() { return Poll::Ready(None); }
            for group in groups {
                for mut packet in group.into_packets() {
                    if let SocksAddr::Ip(peer) = packet.src_addr { packet.src_addr = source(peer); }
                    self.recv_queue.push_back(Received::mapped(packet));
                }
            }
            return Poll::Ready(self.recv_queue.pop_front().map(|packet| packet.project(&mut source)));
        }
        loop {
            let result = ready!(self.inner.poll_recv_ready(cx)).and_then(|()| {
                super::recv::recv_batch(&self.inner, MAX_BATCH_RECV_PACKETS, |data, peer| {
                    let mut peer = peer;
                    peer.set_ip(peer.ip().to_canonical());
                    self.recv_queue.push_back(Received::mapped(UdpPacket { data, src_addr: source(peer),
                        dst_addr: SocksAddr::any_ipv4(), ..Default::default() }));
                })
            });
            match result {
                Ok(_) => {
                    self.consecutive_recv_errors = 0;
                    if let Some(packet) = self.recv_queue.pop_front() { return Poll::Ready(Some(packet.project(&mut source))); }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => {
                    self.consecutive_recv_errors += 1;
                    if self.consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                        warn!("Direct UDP socket reached receive error limit: {err}");
                        return Poll::Ready(None);
                    }
                    trace!("Direct UDP transient receive error: {err}");
                }
            }
        }
    }
}

impl Sink<UdpPacket> for NativeDatagram {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, packet: UdpPacket) -> io::Result<()> {
        if !matches!(packet.dst_addr, SocksAddr::Ip(_)) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "physical UDP target must be an IP address"));
        }
        self.packet = Some(packet);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(packet) = self.packet.as_ref() else { return Poll::Ready(Ok(())); };
        let SocksAddr::Ip(mut destination) = packet.dst_addr else { unreachable!("validated by start_send"); };
        if self.local_is_ipv6 && let SocketAddr::V4(address) = destination {
            destination = SocketAddr::V6(SocketAddrV6::new(address.ip().to_ipv6_mapped(), address.port(), 0, 0));
        }
        let length = packet.data.len();
        let result = ready!(self.inner.poll_send_to(cx, &packet.data, destination));
        self.packet = None;
        Poll::Ready(result.and_then(|sent| {
            if sent == length { Ok(()) }
            else { Err(io::Error::new(io::ErrorKind::WriteZero, "partial UDP datagram send")) }
        }))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl Stream for NativeDatagram {
    type Item = UdpPacket;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>> {
        self.poll_recv_with(cx, SocksAddr::Ip)
    }
}

#[cfg(test)]
mod tests;

impl DatagramBatch for NativeDatagram {
    fn enable_udp_offload(&mut self) {
        #[cfg(target_os = "linux")]
        { self.gro = super::offload::enable_receive(&self.inner); self.gso = true; }
    }
    fn poll_recv_segments(&mut self, cx: &mut Context<'_>, packets: &mut Vec<DatagramSegments>) -> Poll<Option<()>> {
        self.poll_segments(cx, packets, #[cfg(target_os = "linux")] None)
    }

    fn poll_send_batch(&mut self, cx: &mut Context<'_>, batch: &mut PacketBatch) -> Poll<BatchResult> {
        let mut slices = std::array::from_fn::<_, MAX_DIRECT_BATCH_PACKETS, _>(|_| DatagramSlice {
            header: &[], payload: &[], destination: SocketAddr::from(([0, 0, 0, 0], 0)),
        });
        let mut count = 0;
        for packet in batch.packets() {
            let SocksAddr::Ip(destination) = packet.dst_addr else {
                if count > 0 { break; }
                return Poll::Ready(BatchResult::failed(io::Error::new(
                    io::ErrorKind::InvalidInput, "physical UDP target must be an IP address",
                )));
            };
            slices[count] = DatagramSlice { header: &[], payload: &packet.data, destination };
            count += 1;
        }
        self.poll_send_slices(cx, &slices[..count])
    }

    fn poll_recv_batch(&mut self, cx: &mut Context<'_>, packets: &mut Vec<UdpPacket>) -> Poll<Option<()>> {
        if !self.recv_queue.is_empty() {
            let count = self.recv_queue.len().min(MAX_DIRECT_BATCH_PACKETS);
            packets.extend(self.recv_queue.drain(..count).map(|received| received.packet));
            return Poll::Ready(Some(()));
        }
        #[cfg(target_os = "linux")]
        if self.gro {
            let mut groups = Vec::new();
            if ready!(self.poll_recv_segments(cx, &mut groups)).is_none() { return Poll::Ready(None); }
            self.recv_queue.extend(groups.into_iter().flat_map(DatagramSegments::into_packets).map(Received::raw));
            let count = self.recv_queue.len().min(MAX_DIRECT_BATCH_PACKETS);
            packets.extend(self.recv_queue.drain(..count).map(|received| received.packet));
            return Poll::Ready(Some(()));
        }
        for _ in 0..MAX_CONSECUTIVE_RECV_ERRORS {
            let result = ready!(self.inner.poll_recv_ready(cx)).and_then(|()| {
                super::recv::recv_batch(&self.inner, MAX_BATCH_RECV_PACKETS, |data, mut peer| {
                    peer.set_ip(peer.ip().to_canonical());
                    packets.push(UdpPacket { data, src_addr: peer.into(), ..Default::default() });
                })
            });
            match result {
                Ok(_) => {
                    self.consecutive_recv_errors = 0;
                    if !packets.is_empty() { return Poll::Ready(Some(())); }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => {
                    self.consecutive_recv_errors += 1;
                    if self.consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                        warn!("Direct UDP socket reached receive error limit: {error}");
                        return Poll::Ready(None);
                    }
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(test)]
mod batch_tests;

impl NativeDatagram {
    pub(crate) fn poll_segments(&mut self, cx: &mut Context<'_>, packets: &mut Vec<DatagramSegments>,
        #[cfg(target_os = "linux")] mut slots: Option<&mut super::recv::ReceiveSlots>) -> Poll<Option<()>> {
        if !self.recv_queue.is_empty() {
            let count = self.recv_queue.len().min(MAX_BATCH_PACKETS);
            packets.extend(self.recv_queue.drain(..count).map(|received| DatagramSegments::from(received.packet)));
            return Poll::Ready(Some(()));
        }
        #[cfg(target_os = "linux")]
        if self.gro || slots.is_some() {
            if self.consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS { return Poll::Ready(None); }
            let start = packets.len();
            for _ in 0..MAX_CONSECUTIVE_RECV_ERRORS {
                // Bound work by the native message batch, regardless of
                // whether this socket returns small datagrams or GRO groups.
                let limit = self.receive_budget.limit();
                let result = ready!(self.inner.poll_recv_ready(cx)).and_then(|()| {
                    let mut received = |data: bytes::Bytes, mut peer: SocketAddr, size| {
                        peer.set_ip(peer.ip().to_canonical());
                        match DatagramSegments::new(UdpPacket { data, src_addr: peer.into(), ..Default::default() }, size) {
                            Ok(group) => packets.push(group),
                            Err(error) => trace!("dropping invalid UDP GRO message: {error}"),
                        }
                    };
                    match slots.as_deref_mut() {
                        Some(slots) => super::recv::recv_groups_in(&self.inner, limit, self.gro, slots, &mut received),
                        None => super::recv::recv_groups(&self.inner, limit, &mut received),
                    }
                });
                match result {
                    Ok(count) => {
                        self.receive_budget.observe(limit, count);
                        let usable = packets.len() > start;
                        if !self.observe_receive(usable) {
                            warn!(gro = self.gro, "Direct UDP socket reached unusable receive batch limit");
                            return Poll::Ready(None);
                        }
                        if usable { return Poll::Ready(Some(())); }
                    },
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {},
                    Err(error) => {
                        self.consecutive_recv_errors += 1;
                        if self.consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                            warn!("Direct UDP socket reached receive error limit: {error}");
                            return Poll::Ready(None);
                        }
                    }
                }
            }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        while packets.len() < MAX_BATCH_PACKETS {
            match self.poll_recv_with(cx, SocksAddr::Ip) {
                Poll::Ready(Some(packet)) => packets.push(packet.into()),
                Poll::Ready(None) if packets.is_empty() => return Poll::Ready(None),
                _ => break,
            }
        }
        if packets.is_empty() { Poll::Pending } else { Poll::Ready(Some(())) }
    }

}

impl NativeDatagram {
    pub(crate) fn poll_send_slices(&mut self, cx: &mut Context<'_>, slices: &[DatagramSlice<'_>]) -> Poll<BatchResult> {
        self.poll_send_slices_with(cx, slices, &mut SendWorkspace::default())
    }
    pub(crate) fn poll_send_slices_with(&mut self, cx: &mut Context<'_>, slices: &[DatagramSlice<'_>], workspace: &mut SendWorkspace) -> Poll<BatchResult> {
        #[cfg(target_os = "linux")]
        if let Some(result) = super::offload::poll_send(&self.inner, self.local_is_ipv6, cx, slices, &mut self.gso, &mut workspace.descriptors) {
            return result;
        }
        workspace.poll_plain(&self.inner, self.local_is_ipv6, cx, slices)
    }
}
