//! Bounded, opportunistic datagram batches. Queue capacity remains packet-based.
use std::{collections::VecDeque, io, pin::Pin, task::{Context, Poll}};
use futures::{Sink, Stream};
#[cfg(any(
    test,
    feature = "tun",
    feature = "shadowquic",
    all(target_os = "linux", any(feature = "tproxy", feature = "ebpf")),
))]
use tokio_util::sync::PollSender;
use super::UdpPacket;

pub const MAX_BATCH_PACKETS: usize = 16;
pub const MAX_BATCH_BYTES: usize = 64 * 1024;

struct Entry {
    packet: Option<UdpPacket>,
    len: usize,
}

/// Own payloads across Pending; a single-packet Sink may temporarily own the
/// first payload instead. Only completion removes its accounting entry.
pub struct PacketBatch {
    entries: VecDeque<Entry>,
    bytes: usize,
    flushing: bool,
}

impl Default for PacketBatch {
    fn default() -> Self {
        Self { entries: VecDeque::with_capacity(MAX_BATCH_PACKETS), bytes: 0, flushing: false }
    }
}

impl PacketBatch {
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_full(&self) -> bool {
        self.len() == MAX_BATCH_PACKETS || self.bytes >= MAX_BATCH_BYTES
    }
    // A lone oversize packet is admitted so its transport can report its error.
    pub fn push(&mut self, packet: UdpPacket) -> Result<(), UdpPacket> {
        let len = packet.data.len();
        if self.is_full() || (!self.is_empty() && self.bytes + len > MAX_BATCH_BYTES) {
            return Err(packet);
        }
        self.bytes += len;
        self.entries.push_back(Entry { packet: Some(packet), len });
        Ok(())
    }
    pub fn packets(&self) -> impl Iterator<Item = &UdpPacket> {
        self.entries.iter().map(|entry| entry.packet.as_ref().expect("batch payload owned by transport"))
    }
    /// Skip packets already owned by a pending single-packet Sink. Their
    /// addresses were mapped before submission and must not be mapped again.
    pub(crate) fn packets_mut(&mut self) -> impl Iterator<Item = &mut UdpPacket> {
        self.entries.iter_mut().filter_map(|entry| entry.packet.as_mut())
    }
    pub fn complete(&mut self) -> usize {
        let entry = self.entries.pop_front().expect("completed batch entry");
        self.bytes -= entry.len;
        self.flushing = false;
        entry.len
    }
}

/// `sent` is a successful prefix. An error belongs to the immediately following
/// packet; the caller completes it separately and retains the remaining suffix.
/// A terminal transport failure closes the relay instead of retrying that suffix.
pub struct BatchResult {
    pub sent: usize,
    pub error: Option<io::Error>,
    pub fatal: bool,
}

impl BatchResult {
    pub fn sent(sent: usize) -> Self { Self { sent, error: None, fatal: false } }
    pub fn failed(error: io::Error) -> Self { Self { sent: 0, error: Some(error), fatal: false } }
    pub fn terminated(error: io::Error) -> Self { Self { sent: 0, error: Some(error), fatal: true } }
}

/// Physical transports override these operations. Protocols without batch I/O
/// use the same relay and retain their existing Sink completion semantics.
pub trait DatagramBatch: Stream<Item = UdpPacket> + Sink<UdpPacket, Error = io::Error> + Unpin {
    fn poll_send_batch(&mut self, cx: &mut Context<'_>, batch: &mut PacketBatch)
        -> Poll<BatchResult>
    {
        poll_send_single(self, cx, batch)
    }

    fn poll_recv_batch(&mut self, cx: &mut Context<'_>, packets: &mut Vec<UdpPacket>)
        -> Poll<Option<()>>
    {
        poll_recv_packets(self, cx, packets)
    }
}

/// Submit independent datagrams synchronously without copying their payloads.
/// Errors are terminal: a protocol may already have submitted some fragments.
pub(crate) fn poll_send_ready(
    batch: &PacketBatch, mut send: impl FnMut(&UdpPacket) -> io::Result<()>,
) -> BatchResult {
    let mut sent = 0;
    for packet in batch.packets() {
        if let Err(error) = send(packet) {
            return BatchResult { sent, error: Some(error), fatal: true };
        }
        sent += 1;
    }
    BatchResult::sent(sent)
}

/// Move ready packets into a packet-capacity channel without cloning payloads.
/// The caller completes the returned prefix before polling the batch again.
#[cfg(any(
    test,
    feature = "tun",
    feature = "shadowquic",
    all(target_os = "linux", any(feature = "tproxy", feature = "ebpf")),
))]
pub(crate) fn poll_send_channel(
    sender: &mut PollSender<UdpPacket>, cx: &mut Context<'_>, batch: &mut PacketBatch,
) -> Poll<BatchResult> {
    let mut sent = 0;
    for entry in &mut batch.entries {
        match sender.poll_reserve(cx) {
            Poll::Pending => break,
            Poll::Ready(Err(_)) => return Poll::Ready(BatchResult { sent, fatal: true,
                error: Some(io::Error::new(io::ErrorKind::BrokenPipe, "datagram channel closed")) }),
            Poll::Ready(Ok(())) => {}
        }
        let packet = entry.packet.take().expect("unsubmitted channel batch packet");
        if sender.send_item(packet).is_err() {
            return Poll::Ready(BatchResult { sent, fatal: true,
                error: Some(io::Error::new(io::ErrorKind::BrokenPipe, "datagram channel closed")) });
        }
        sent += 1;
    }
    if sent == 0 { Poll::Pending } else { Poll::Ready(BatchResult::sent(sent)) }
}

pub fn poll_send_single<D: Sink<UdpPacket, Error = io::Error> + Unpin + ?Sized>(
    datagram: &mut D, cx: &mut Context<'_>, batch: &mut PacketBatch,
) -> Poll<BatchResult> {
    poll_single(datagram, cx, batch, false)
}

/// Framing validation can reject one packet, but a stream write/flush failure
/// may leave a partial frame and must terminate the transport.
pub(crate) fn poll_send_stream<D: Sink<UdpPacket, Error = io::Error> + Unpin + ?Sized>(
    datagram: &mut D, cx: &mut Context<'_>, batch: &mut PacketBatch,
) -> Poll<BatchResult> {
    poll_single(datagram, cx, batch, true)
}

fn poll_single<D: Sink<UdpPacket, Error = io::Error> + Unpin + ?Sized>(
    datagram: &mut D, cx: &mut Context<'_>, batch: &mut PacketBatch, stream: bool,
) -> Poll<BatchResult> {
    let failed = |error| if stream { BatchResult::terminated(error) } else { BatchResult::failed(error) };
    if !batch.flushing {
        match Pin::new(&mut *datagram).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(failed(error)),
            Poll::Ready(Ok(())) => {}
        }
        let packet = batch.entries.front_mut().expect("nonempty batch").packet.take().unwrap();
        if let Err(error) = Pin::new(&mut *datagram).start_send(packet) {
            return Poll::Ready(BatchResult::failed(error));
        }
        batch.flushing = true;
    }
    match Pin::new(datagram).poll_flush(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(())) => Poll::Ready(BatchResult::sent(1)),
        Poll::Ready(Err(error)) => Poll::Ready(failed(error)),
    }
}

pub fn poll_recv_packets<D: Stream<Item = UdpPacket> + Unpin + ?Sized>(
    datagram: &mut D, cx: &mut Context<'_>, packets: &mut Vec<UdpPacket>,
) -> Poll<Option<()>> {
    let mut bytes = 0;
    while packets.len() < MAX_BATCH_PACKETS && bytes < MAX_BATCH_BYTES {
        match Pin::new(&mut *datagram).poll_next(cx) {
            Poll::Ready(Some(packet)) => { bytes += packet.data.len(); packets.push(packet); }
            Poll::Ready(None) if packets.is_empty() => return Poll::Ready(None),
            _ => break,
        }
    }
    if packets.is_empty() { Poll::Pending } else { Poll::Ready(Some(())) }
}

impl<T: DatagramBatch + ?Sized> DatagramBatch for Box<T> {
    fn poll_send_batch(&mut self, cx: &mut Context<'_>, batch: &mut PacketBatch) -> Poll<BatchResult> {
        (**self).poll_send_batch(cx, batch)
    }
    fn poll_recv_batch(&mut self, cx: &mut Context<'_>, packets: &mut Vec<UdpPacket>) -> Poll<Option<()>> {
        (**self).poll_recv_batch(cx, packets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn synchronous_batch_failure_preserves_successful_prefix_and_suffix() {
        let mut batch = PacketBatch::default();
        for _ in 0..4 { batch.push(UdpPacket::default()).unwrap(); }
        let mut attempts = 0;
        let result = poll_send_ready(&batch, |_| {
            attempts += 1;
            if attempts == 3 { Err(io::Error::other("connection closed")) } else { Ok(()) }
        });
        assert_eq!(result.sent, 2);
        assert!(result.fatal && result.error.is_some());
        assert_eq!(attempts, 3);
        // Completion belongs to the relay; submission leaves packet ownership intact.
        assert_eq!(batch.len(), 4);
        assert_eq!(batch.packets().count(), 4);
    }

    #[test]
    fn outgoing_batches_bound_packet_count_and_payload_bytes() {
        let mut batch = PacketBatch::default();
        for _ in 0..MAX_BATCH_PACKETS { batch.push(UdpPacket::default()).unwrap(); }
        assert!(batch.push(UdpPacket::default()).is_err());
        for _ in 0..MAX_BATCH_PACKETS { batch.complete(); }
        let mut packet = UdpPacket::default();
        packet.data = Bytes::from(vec![0; MAX_BATCH_BYTES]);
        batch.push(packet).unwrap();
        assert!(batch.is_full());
        assert!(batch.push(UdpPacket::default()).is_err());
        assert_eq!(batch.complete(), MAX_BATCH_BYTES);
        assert!(batch.is_empty());
    }
}
