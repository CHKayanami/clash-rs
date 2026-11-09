//! Single-queue reader and TCP owner with bounded device output.
use std::{collections::VecDeque, future::Future, io, pin::pin, task::{Context, Poll}};
use bytes::Bytes;
#[cfg(test)]
use bytes::BytesMut;
use futures::{StreamExt, future::poll_fn};
use tokio::{sync::OwnedSemaphorePermit, task::consume_budget, time::Instant};
use tracing::{trace, warn};
use clash_netstack::{Packet, StackSplitSink, StackSplitStream, TcpDriver, udp_payload_segments, UdpPayloadSegments};
use crate::{Error, app::dispatcher::udp::association::direct::{engine::Engine as UdpEngine},
    proxy::datagram::batch::{MAX_BATCH_PACKETS, MAX_BATCH_BYTES}};
use super::{device_io::{DEVICE_BATCH, recoverable_write_error}, packet::{Dispatch, PacketDispatcher}, packet_queue};

pub(super) trait PacketIo {
    /// Synchronous only; false means no bytes were sent.
    fn try_send_tcp(&mut self, _header: &[u8], _payload: &[u8], _size: Option<u16>) -> io::Result<bool> { Ok(false) }
    fn poll_receive(&mut self, cx: &mut Context<'_>, packets: &mut Vec<Packet>) -> Poll<io::Result<usize>>;
    /// Pending retains ownership of the operation, including byte credits.
    /// Ready either completes the device write or transfers ownership to the
    /// independent writer; credits remain held through the actual write.
    fn poll_send(&mut self, cx: &mut Context<'_>, packets: &mut Vec<Packet>, credits: &mut Vec<OwnedSemaphorePermit>) -> Poll<io::Result<()>>;
}

pub(super) struct Protocols {
    pub tcp: Option<TcpDriver>,
    pub sink: StackSplitSink,
    pub stream: StackSplitStream,
}

pub(super) struct DeviceLoop<I, F> {
    io: I,
    udp: Option<UdpEngine>,
    protocols: Protocols,
    packets: PacketDispatcher,
    replies: packet_queue::Receiver,
    intercept: F,
    received: Vec<Packet>,
    input: VecDeque<Packet>,
    udp_input: Option<UdpPayloadSegments>,
    local: VecDeque<Bytes>,
    external: Vec<packet_queue::Packet>,
    output: Vec<Packet>,
    udp_output: VecDeque<Packet>,
    credits: Vec<OwnedSemaphorePermit>,
    writing: bool,
    source: usize,
    udp_burst: usize,
    udp_bytes: usize,
}

impl<I: PacketIo, F: Fn(&[u8]) -> bool> DeviceLoop<I, F> {
    pub fn new(io: I, protocols: Protocols, packets: PacketDispatcher,
        replies: packet_queue::Receiver, intercept: F) -> Self {
        let udp = packets.direct.take_engine();
        Self { io, udp, protocols, packets, replies, intercept,
            received: Vec::with_capacity(DEVICE_BATCH), input: VecDeque::new(), udp_input: None,
            local: VecDeque::with_capacity(DEVICE_BATCH), external: Vec::with_capacity(DEVICE_BATCH),
            output: Vec::with_capacity(DEVICE_BATCH), udp_output: VecDeque::new(),
            credits: Vec::with_capacity(DEVICE_BATCH), writing: false, source: 0, udp_burst: 0, udp_bytes: 0 }
    }

    pub async fn run(mut self) -> Result<(), Error> {
        loop {
            poll_fn(|cx| self.poll(cx)).await?;
            let mut budget = pin!(consume_budget());
            poll_fn(|cx| {
                let result = budget.as_mut().poll(cx);
                // Compact only when the budget future actually yields, including
                // yield paths other than an exhausted cooperative budget.
                if result.is_pending() { self.prepare_wait(); }
                result
            }).await;
        }
    }

    fn prepare_wait(&mut self) {
        if let Some(udp) = &mut self.udp { udp.compact_pending(); }
        for packet in &mut self.udp_output { packet.compact_payload(); }
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let now = Instant::now();
        let mut progress = false;
        if self.writing && self.finish_write(cx)? { progress = true; }
        if self.input.is_empty() && self.udp_input.is_none() {
            let receive = self.io.poll_receive(cx, &mut self.received);
            match receive {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof).into())),
                Poll::Ready(Ok(_)) => {
                    self.input.extend(self.received.drain(..)); progress = true;
                },
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Pending => {},
            }
        }
        for _ in 0..DEVICE_BATCH {
            if let Some(packet) = self.udp_input.as_mut().and_then(Iterator::next) {
                self.protocols.sink.send_udp_payload(packet)?; progress = true; continue;
            }
            self.udp_input = None;
            let Some(packet) = self.input.pop_front() else { break; };
            progress = true;
            if (self.intercept)(&packet) { continue; }
            match self.packets.prepare_frame(packet, now) {
                Dispatch::Drop => {},
                Dispatch::Split(packet) => {
                    let mut segments = udp_payload_segments(packet)?;
                    if let Some(packet) = segments.next() {
                        self.protocols.sink.send_udp_payload(packet)?;
                    }
                    self.udp_input = Some(segments);
                },
                Dispatch::Direct(upload) => {
                    if let Some(udp) = &mut self.udp { udp.queue_upload(upload); }
                },
                Dispatch::Reply(packet) => {
                    if self.local.len() < DEVICE_BATCH { self.local.push_back(packet.freeze()); }
                    else { trace!("system TCP reply queue full, dropping packet"); }
                }
                Dispatch::Udp(packet) => self.protocols.sink.send_udp_payload(packet)?,
                Dispatch::Stack(packet, protocol) => {
                    let packet = match &mut self.protocols.tcp {
                        Some(tcp) => tcp.receive(packet)?,
                        None => Some(packet),
                    };
                    if let Some(packet) = packet { self.protocols.sink.send_checked_packet(packet, protocol)?; }
                }
            }
        }
        if let Some(udp) = &mut self.udp {
            udp.flush_ingress(cx, now);
            udp.set_output_blocked(self.writing);
            progress |= udp.poll(cx, now);
        }
        if let Some(tcp) = &mut self.protocols.tcp {
            let inline = !self.writing && self.output.is_empty() && self.local.is_empty()
                && self.external.is_empty();
            let io = &mut self.io;
            let mut failure = None;
            let mut direct_packets = 0;
            let result = tcp.poll_with_output(cx, &mut |header, payload, size| {
                if !inline || failure.is_some() || direct_packets == DEVICE_BATCH { return false; }
                match io.try_send_tcp(header, payload, size) {
                    Ok(sent) => { direct_packets += usize::from(sent); sent },
                    Err(error) if recoverable_write_error(&error) => false,
                    Err(error) => { failure = Some(error); true },
                }
            });
            if let Some(error) = failure { return Poll::Ready(Err(error.into())); }
            match result {
                Poll::Ready(Ok(())) => progress = true,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Pending => {},
            }
        }
        if !self.writing {
            self.fill_output(cx)?;
            if !self.output.is_empty() {
                self.writing = true;
                if self.finish_write(cx)? { progress = true; }
            }
        }
        // Every pass visits input, timers and output even with a blocked writer.
        // Continue useful work within Tokio's budget rather than yielding once
        // per packet batch; park only after every event source has been armed.
        if let Some(udp) = &self.udp { progress |= udp.needs_poll(); }
        if progress { Poll::Ready(Ok(())) } else { self.prepare_wait(); Poll::Pending }
    }

    fn finish_write(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let result = self.io.poll_send(cx, &mut self.output, &mut self.credits);
        match result {
            Poll::Pending => Ok(false),
            Poll::Ready(result) => {
                self.output.clear();
                self.credits.clear();
                self.writing = false;
                if let Err(error) = result {
                    if !recoverable_write_error(&error) {
                        return Err(error.into());
                    }
                    warn!("failed to write TUN batch, dropping unsent packets: {error}");
                }
                Ok(true)
            }
        }
    }

    fn fill_output(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        if self.external.is_empty()
            && self.replies.poll_recv_many(cx, &mut self.external, DEVICE_BATCH).is_ready() {
            // Reverse metadata once so pop() preserves FIFO without shifting or
            // allocating. Unsent entries keep their original byte credits.
            self.external.reverse();
        }
        // Rotate system TCP, local TCP, external replies, DIRECT UDP and stack.
        // No producer can monopolize a perpetually writable device.
        let mut udp_groups = 0;
        for _ in 0..DEVICE_BATCH {
            let mut found = false;
            for offset in 0..5 {
                let source = (self.source + offset) % 5;
                let packet = match source {
                    0 => self.local.pop_front().map(Packet::new),
                    1 => self.protocols.tcp.as_mut().and_then(TcpDriver::take_output),
                    2 => self.external.pop().map(|packet| {
                        self.credits.push(packet.budget);
                        packet.bytes
                    }),
                    3 => {
                        while self.udp_output.is_empty() && udp_groups < DEVICE_BATCH {
                            let Some(udp) = &mut self.udp else { break; };
                            let Some(group) = udp.take_reply() else { break; };
                            udp_groups += 1;
                            super::datagram::encode_direct_reply(group, udp.mtu(), &mut self.udp_output);
                        }
                        self.udp_output.pop_front()
                    },
                    _ => match self.protocols.stream.poll_next_unpin(cx) {
                        Poll::Ready(Some(packet)) => Some(packet?),
                        _ => None,
                    },
                };
                if let Some(packet) = packet {
                    if source >= 3 {
                        if source != self.source { self.udp_burst = 0; self.udp_bytes = 0; }
                        self.udp_burst += 1; self.udp_bytes += packet.len();
                    } else { self.udp_burst = 0; self.udp_bytes = 0; }
                    self.output.push(packet);
                    if source >= 3 && self.udp_burst < MAX_BATCH_PACKETS && self.udp_bytes < MAX_BATCH_BYTES {
                        self.source = source;
                    } else {
                        self.source = (source + 1) % 5;
                        self.udp_burst = 0; self.udp_bytes = 0;
                    }
                    found = true;
                    break;
                }
            }
            if !found { break; }
        }
        // Invalid replies must not strand a valid suffix, but a malformed
        // flood must still return control after one bounded scan.
        if self.output.is_empty() && udp_groups == DEVICE_BATCH { cx.waker().wake_by_ref(); }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod forward_tests;
