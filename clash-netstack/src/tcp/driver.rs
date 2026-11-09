//! Indexed L3 delivery and bounded round-robin protocol output.
use smoltcp::{phy::{Checksum, ChecksumCapabilities}, time::{Duration, Instant}, wire::{
    IpProtocol, IpRepr, IpVersion, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
    TcpControl, TcpPacket, TcpRepr, checksum,
}};
use crate::link::{output::{Output, Permit}, packet::IpPacket};
use crate::{Packet, link::{device::NetstackDevice, icmp::IcmpResponder}};
use super::{buffers::Buffers, protocol::{Context, Socket, State}, connections::{SocketHandle, SocketTable},
    schedule::Schedule, replies::Replies};
use std::{convert::Infallible, net::SocketAddr};

pub(crate) const OUTPUT_PACKETS: usize = 128;
pub(crate) const OUTPUT_BYTES: usize = 256 * 1024;
pub(crate) const OUTPUT_BURST: usize = 2;
pub(crate) const SOLO_OUTPUT_BURST: usize = 8;

pub(crate) struct Egress {
    pub packets: usize,
    pub bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IngressStatus {
    Drained,
    RepliesFull,
    OutputFull,
}

pub(crate) struct Driver {
    context: Context,
    icmp: Option<IcmpResponder>,
    mtu: usize,
    schedule: Schedule,
    replies: Replies,
    ingress_dirty: Vec<SocketHandle>,
}

impl Driver {
    pub fn new(mtu: usize) -> Self {
        Self { context: Context::new(mtu), icmp: None, mtu, schedule: Schedule::default(), replies: Replies::default(),
            ingress_dirty: Vec::with_capacity(32) }
    }

    pub fn enable_tcp_gso(&mut self) { self.context.enable_tcp_gso(); }

    pub fn ingress(&mut self, now: Instant, device: &mut NetstackDevice,
        sockets: &mut SocketTable) -> IngressStatus {
        self.context.set_now(now);
        let (input, output) = device.split();
        self.replies.flush(output);
        let mut needs_output = false;
        // One processed TCP input produces at most one immediate reply. Local
        // reply capacity is guaranteed before process() commits socket state.
        while self.replies.has_capacity() {
            let Some(packet) = input.pop_front() else { break; };
            let data = packet.data();
            let parsed = parse_ip(data);
            let Some((ip, payload)) = parsed else { continue; };
            if matches!(ip.next_header(), IpProtocol::Icmp | IpProtocol::Icmpv6) {
                // Preserve ICMP's existing paired receive/transmit reservation.
                if output.capacity() == 0 {
                    input.push_front(packet);
                    needs_output = true;
                    break;
                }
                self.icmp.get_or_insert_with(|| IcmpResponder::new(output, self.mtu))
                    .respond(packet, output);
                continue;
            }
            if ip.next_header() != IpProtocol::Tcp
                || !ip.src_addr().is_unicast() || !ip.dst_addr().is_unicast() { continue; }
            let Ok(tcp) = TcpPacket::new_checked(payload) else { continue; };
            let Some(repr) = parse_tcp(&tcp, &ip, packet.rx_checksum_verified()) else { continue; };
            let flow = (SocketAddr::new(ip.src_addr().into(), repr.src_port),
                SocketAddr::new(ip.dst_addr().into(), repr.dst_port));
            let handle = sockets.find(&flow);
            let reply = match handle {
                Some(handle) if sockets.get_mut(handle).accepts(&mut self.context, &ip, &repr) =>
                    sockets.get_mut(handle).process(&mut self.context, &ip, &repr),
                _ if repr.control != TcpControl::Rst => Some(Socket::rst_reply(&ip, &repr)),
                _ => None,
            };
            if let Some(handle) = handle && sockets.get_mut(handle).state() == State::SynReceived {
                sockets.mark_started(handle);
            }
            if let Some((ip, tcp)) = reply {
                let packet = reply_packet(ip, tcp);
                self.replies.send(packet, output);
            } else if repr.control == TcpControl::Syn && let Some(handle) = handle
                && sockets.get_mut(handle).state() == State::SynReceived {
                // Commit SYN transmission into the reserved local reply space.
                // Deferred SYN|ACK must precede application close/data output.
                let result: Result<(), Infallible> = sockets.get_mut(handle)
                    .dispatch(&mut self.context, |_, _, (ip, tcp)| {
                        let packet = reply_packet(ip, tcp);
                        self.replies.send(packet, output);
                        Ok(())
                    });
                result.expect("reserved SYN response capacity");
            }
            if let Some(handle) = handle && !self.ingress_dirty.contains(&handle) {
                self.ingress_dirty.push(handle);
            }
        }
        // Preserve first-seen order, including when output backpressure stops
        // ingress early. Retain the scratch allocation for the next batch.
        for index in 0..self.ingress_dirty.len() {
            self.refresh(now, self.ingress_dirty[index], sockets);
        }
        self.ingress_dirty.clear();
        if input.is_empty() { IngressStatus::Drained }
        else if needs_output { IngressStatus::OutputFull }
        else {
            IngressStatus::RepliesFull
        }
    }

    pub fn reply_capacity_available(&self) -> bool { self.replies.has_capacity() }

    /// Admission reuses checked headers; only new SYNs need full validation.
    pub fn valid_syn_parsed(packet: &IpPacket<&[u8]>,
        tcp: &TcpPacket<&[u8]>, verified: bool) -> bool {
        let ip = match packet {
            IpPacket::Ipv4(packet) => {
                if packet.more_frags() || packet.frag_offset() != 0 { return false; }
                let Ok(repr) = Ipv4Repr::parse(packet, &ChecksumCapabilities::default()) else { return false; };
                IpRepr::Ipv4(repr)
            },
            IpPacket::Ipv6(packet) => {
                let Ok(repr) = Ipv6Repr::parse(packet) else { return false; };
                IpRepr::Ipv6(repr)
            },
        };
        if !ip.src_addr().is_unicast() || !ip.dst_addr().is_unicast() { return false; }
        parse_tcp(tcp, &ip, verified)
            .is_some_and(|repr| repr.control == TcpControl::Syn && repr.ack_number.is_none())
    }

    #[cfg(test)]
    fn valid_syn(packet: &Packet) -> bool {
        let Ok(ip) = IpPacket::new_checked(packet.data()) else { return false; };
        if ip.protocol() != IpProtocol::Tcp { return false; }
        let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else { return false; };
        Self::valid_syn_parsed(&ip, &tcp, packet.rx_checksum_verified())
    }

    pub fn refresh(&mut self, now: Instant, handle: SocketHandle, sockets: &mut SocketTable) {
        self.context.set_now(now);
        let started = sockets.started(handle);
        let socket = sockets.get_mut(handle);
        if !socket.is_active() && socket.remote_endpoint().is_none()
            && (started || socket.state() != State::Listen) {
            self.schedule.complete(handle);
        } else {
            self.schedule.update(handle, socket.poll_at(&mut self.context));
        }
    }

    pub fn remove(&mut self, handle: SocketHandle, sockets: &mut SocketTable) {
        self.schedule.remove(handle);
        sockets.remove(handle);
    }

    /// A small burst per ready connection, then rotate to the tail. Keep both
    /// packet and byte budgets independent of MTU and active connection count.
    #[cfg(test)]
    pub fn poll_egress(&mut self, now: Instant, device: &mut NetstackDevice, sockets: &mut SocketTable) {
        self.poll_egress_with(now, device, sockets, &mut |_, _, _| false);
    }

    #[cfg(test)]
    pub fn poll_egress_with(&mut self, now: Instant, device: &mut NetstackDevice, sockets: &mut SocketTable,
        transmit: &mut dyn FnMut(&[u8], &[u8], Option<u16>) -> bool) {
        let mut egress = self.begin_egress(now, device);
        self.poll_egress_from(now, device, sockets, &mut egress, transmit);
    }

    pub fn begin_egress(&mut self, now: Instant, device: &mut NetstackDevice) -> Egress {
        self.context.set_now(now);
        self.schedule.expire(now, OUTPUT_PACKETS);
        let (_, output) = device.split();
        // Previously committed immediate replies precede all protocol data,
        // FINs and RSTs. Timer expiry above still advances while output is full.
        let (packets, bytes) = self.replies.flush(output);
        Egress { packets, bytes }
    }

    pub fn flush_socket(&mut self, now: Instant, device: &mut NetstackDevice, handle: SocketHandle,
        socket: &mut Socket<'_>, max_packets: usize, egress: &mut Egress,
        transmit: &mut dyn FnMut(&[u8], &[u8], Option<u16>) -> bool) -> usize {
        // Inline application work shares the protocol FIFO: it must not spend
        // the round's output budget ahead of an older ready connection.
        if !self.replies.is_empty() || max_packets == 0 || !self.schedule.can_dispatch(handle)
            || egress.packets >= OUTPUT_PACKETS || egress.bytes >= OUTPUT_BYTES {
            return 0;
        }
        if !device.output_available() { return 0; }
        self.context.set_now(now);
        let (_, output) = device.split();
        let peer_mss = socket.peer_mss();
        let mut sent = 0;
        for _ in 0..max_packets {
            match Self::dispatch_one(&mut self.context, self.mtu, peer_mss, output, egress, socket, transmit) {
                Ok(true) => sent += 1,
                Ok(false) | Err(()) => break,
            }
        }
        // The caller refreshes protocol readiness after its local mutations.
        // Preserve timers and completion bookkeeping until that refresh.
        if sent > 0 { self.schedule.remove_ready(handle); }
        sent
    }

    pub fn poll_egress_from(&mut self, now: Instant, device: &mut NetstackDevice, sockets: &mut SocketTable,
        egress: &mut Egress, transmit: &mut dyn FnMut(&[u8], &[u8], Option<u16>) -> bool) {
        self.context.set_now(now);
        if !self.replies.is_empty() {
            return;
        }
        let (_, output) = device.split();
        // Also bound visits that produce no packets (for example a timer that
        // changes state), independently of the emitted-packet budget.
        for _ in 0..OUTPUT_PACKETS {
            if egress.packets >= OUTPUT_PACKETS || egress.bytes >= OUTPUT_BYTES
                || output.capacity() == 0 { break; }
            let Some(handle) = self.schedule.pop_ready() else { break; };
            let socket = sockets.get_mut(handle);
            let reader_blocked = Buffers::read_budget(socket) == 0;
            let peer_mss = socket.peer_mss();
            // Preserve the short round-robin quantum under contention. A lone
            // ready flow can amortize scheduling, still within byte/packet caps.
            let burst = if self.schedule.has_ready() { OUTPUT_BURST } else { SOLO_OUTPUT_BURST };
            let mut sent_in_burst = false;
            let mut blocked = false;
            for _ in 0..burst {
                if egress.packets >= OUTPUT_PACKETS || egress.bytes >= OUTPUT_BYTES
                    || output.capacity() == 0 { break; }
                match Self::dispatch_one(&mut self.context, self.mtu, peer_mss, output, egress, socket, transmit) {
                    Ok(true) => sent_in_burst = true,
                    Ok(false) => break,
                    Err(()) => {
                        blocked = true;
                        break;
                    }
                }
            }
            Self::wake_reader(socket, reader_blocked);
            if blocked && !sent_in_burst {
                self.schedule.retry(handle);
                return;
            }
            self.refresh(now, handle, sockets);
            if blocked { return; }
        }
    }

    fn dispatch_one(context: &mut Context, mtu: usize, peer_mss: usize,
        output: &mut Output, egress: &mut Egress, socket: &mut Socket<'_>,
        transmit: &mut dyn FnMut(&[u8], &[u8], Option<u16>) -> bool) -> Result<bool, ()> {
        let direct = output.len() == 0 && context.tcp_gso();
        if egress.packets >= OUTPUT_PACKETS || egress.bytes >= OUTPUT_BYTES
            || output.capacity() == 0 {
            return Err(());
        }
        let mut emitted = false;
        socket.dispatch(context, |cx, _, (ip, tcp)| {
            let length = ip.header_len() + tcp.buffer_len();
            if egress.bytes + length > OUTPUT_BYTES { return Err(()); }
            let mss = peer_mss.min(mtu - ip.header_len() - 20)
                .saturating_sub(tcp.header_len() - 20);
            let segmentation = (cx.tcp_gso() && mss > 0 && tcp.payload.len() > mss)
                .then_some(mss as u16);
            if direct {
                let mut header = [0u8; 100];
                let len = encode_header(&mut header, ip.clone(), tcp.clone());
                if transmit(&header[..len], tcp.payload, segmentation) {
                    egress.bytes += length;
                    egress.packets += 1;
                    emitted = true;
                    return Ok(());
                }
                let permit = output.reserve().ok_or(())?;
                egress.bytes += length;
                egress.packets += 1;
                emitted = true;
                if let Some(size) = segmentation {
                    permit.send(encoded_segment(&header[..len], tcp.payload, size));
                } else {
                    emit(permit, ip, tcp, None);
                }
                return Ok(());
            }
            let permit = output.reserve().ok_or(())?;
            egress.bytes += length;
            egress.packets += 1;
            emitted = true;
            emit(permit, ip, tcp, segmentation);
            Ok(())
        })?;
        Ok(emitted)
    }

    pub fn has_other_ready(&self, handle: SocketHandle) -> bool { self.schedule.has_other_ready(handle) }

    fn wake_reader(socket: &mut Socket<'_>, was_blocked: bool) {
        // Dispatch reduces unsent without freeing backing storage. Wake only
        // the zero-to-readable transition, not every packet or retransmission.
        if was_blocked && Buffers::read_budget(socket) > 0 { socket.wake_send(); }
    }

    #[cfg(test)]
    fn poll(&mut self, now: Instant, device: &mut NetstackDevice, sockets: &mut SocketTable) {
        self.ingress(now, device, sockets);
        self.poll_egress(now, device, sockets);
    }


    pub fn pop_completed(&mut self) -> Option<SocketHandle> { self.schedule.pop_completed() }

    // Deferred control replies remain work even without a live socket/timer.
    pub fn has_ready(&self) -> bool { !self.replies.is_empty() || self.schedule.has_ready() }

    pub fn poll_delay(&self, now: Instant) -> Option<Duration> { self.schedule.delay(now) }
}

fn parse_ip(data: &[u8]) -> Option<(IpRepr, &[u8])> {
    match IpVersion::of_packet(data).ok()? {
        IpVersion::Ipv4 => {
            let packet = Ipv4Packet::new_checked(data).ok()?;
            if packet.more_frags() || packet.frag_offset() != 0 { return None; }
            let repr = Ipv4Repr::parse(&packet, &ChecksumCapabilities::default()).ok()?;
            let start = usize::from(packet.header_len());
            let end = usize::from(packet.total_len());
            Some((IpRepr::Ipv4(repr), &data[start..end]))
        }
        IpVersion::Ipv6 => {
            let packet = Ipv6Packet::new_checked(data).ok()?;
            let repr = Ipv6Repr::parse(&packet).ok()?;
            Some((IpRepr::Ipv6(repr), &data[40..40 + usize::from(packet.payload_len())]))
        }
    }
}

fn parse_tcp<'a>(packet: &TcpPacket<&'a [u8]>, ip: &IpRepr, verified: bool) -> Option<TcpRepr<'a>> {
    let mut checksums = ChecksumCapabilities::default();
    if verified { checksums.tcp = Checksum::Tx; }
    TcpRepr::parse(packet, &ip.src_addr(), &ip.dst_addr(), &checksums).ok()
}

fn emit(permit: Permit<'_>, ip: IpRepr, tcp: TcpRepr<'_>, segmentation: Option<u16>) {
    permit.send(build_packet(ip, tcp, segmentation));
}

fn reply_packet(ip: IpRepr, tcp: TcpRepr<'_>) -> Packet {
    assert!(tcp.payload.is_empty(), "only immediate control replies may be deferred");
    build_packet(ip, tcp, None)
}

fn build_packet(mut ip: IpRepr, tcp: TcpRepr<'_>, segmentation: Option<u16>) -> Packet {
    if let Some(size) = segmentation {
        let mut header = [0u8; 100];
        let len = encode_header(&mut header, ip, tcp.clone());
        return encoded_segment(&header[..len], tcp.payload, size);
    }
    ip.set_payload_len(tcp.buffer_len());
    let header_len = ip.header_len();
    let mut bytes = vec![0; header_len + tcp.buffer_len()];
    let checksums = ChecksumCapabilities::default();
    match ip {
        IpRepr::Ipv4(repr) => repr.emit(&mut Ipv4Packet::new_unchecked(&mut bytes[..header_len]), &checksums),
        IpRepr::Ipv6(repr) => repr.emit(&mut Ipv6Packet::new_unchecked(&mut bytes[..header_len])),
    }
    tcp.emit(&mut TcpPacket::new_unchecked(&mut bytes[header_len..]),
        &ip.src_addr(), &ip.dst_addr(), &checksums);
    Packet::new(bytes)
}

fn encoded_segment(header: &[u8], payload: &[u8], size: u16) -> Packet {
    let mut bytes = Vec::with_capacity(header.len() + payload.len());
    bytes.extend_from_slice(header); bytes.extend_from_slice(payload);
    Packet::new(bytes).with_tcp_segmentation(size)
}

#[cfg(test)]
mod tests;

/// Header-only encoding for a borrowed TCP payload with checksum offload. The callback must finish
/// its syscall before returning; no reference into socket storage may escape.
fn encode_header(bytes: &mut [u8; 100], mut ip: IpRepr, tcp: TcpRepr<'_>) -> usize {
    ip.set_payload_len(tcp.buffer_len());
    let ip_len = ip.header_len();
    let tcp_len = tcp.header_len();
    let mut checksums = ChecksumCapabilities::default();
    checksums.tcp = Checksum::Rx;
    match ip {
        IpRepr::Ipv4(repr) => repr.emit(&mut Ipv4Packet::new_unchecked(&mut bytes[..ip_len]), &checksums),
        IpRepr::Ipv6(repr) => repr.emit(&mut Ipv6Packet::new_unchecked(&mut bytes[..ip_len])),
    }
    let seed = checksum::pseudo_header(&ip.src_addr(), &ip.dst_addr(), IpProtocol::Tcp, tcp.buffer_len() as u32);
    let header = TcpRepr { payload: &[], ..tcp };
    header.emit(&mut TcpPacket::new_unchecked(&mut bytes[ip_len..ip_len + tcp_len]),
        &ip.src_addr(), &ip.dst_addr(), &checksums);
    TcpPacket::new_unchecked(&mut bytes[ip_len..ip_len + tcp_len]).set_checksum(seed);
    ip_len + tcp_len
}
