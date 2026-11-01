//! Indexed L3 delivery and bounded round-robin protocol output.
use smoltcp::{phy::{ChecksumCapabilities}, time::{Duration, Instant}, wire::{
    IpProtocol, IpRepr, IpVersion, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
    TcpControl, TcpPacket, TcpRepr,
}};
use tokio::sync::mpsc;
use crate::{Packet, link::{device::NetstackDevice, icmp::IcmpResponder}};
use super::{protocol::{Context, Socket, State}, connections::{SocketHandle, SocketTable},
    schedule::Schedule, replies::Replies};
use std::{convert::Infallible, net::SocketAddr};

const OUTPUT_PACKETS: usize = 128;
const OUTPUT_BYTES: usize = 256 * 1024;
const OUTPUT_BURST: usize = 2;

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

    pub fn ingress(&mut self, now: Instant, device: &mut NetstackDevice,
        sockets: &mut SocketTable) -> IngressStatus {
        self.context.set_now(now);
        let output = device.output().clone();
        self.replies.flush(&output);
        let mut needs_output = false;
        // One processed TCP input produces at most one immediate reply. Local
        // reply capacity is guaranteed before process() commits socket state.
        while self.replies.has_capacity() {
            let Some(packet) = device.take_packet() else { break; };
            let data = packet.data();
            let parsed = parse_ip(data);
            let Some((ip, payload)) = parsed else { continue; };
            if matches!(ip.next_header(), IpProtocol::Icmp | IpProtocol::Icmpv6) {
                // Preserve ICMP's existing paired receive/transmit reservation.
                if output.capacity() == 0 {
                    device.put_back(packet);
                    needs_output = true;
                    break;
                }
                self.icmp.get_or_insert_with(|| IcmpResponder::new(&output, self.mtu))
                    .respond(packet, &output);
                continue;
            }
            if ip.next_header() != IpProtocol::Tcp
                || !ip.src_addr().is_unicast() || !ip.dst_addr().is_unicast() { continue; }
            let Ok(tcp) = TcpPacket::new_checked(payload) else { continue; };
            let Some(repr) = parse_tcp(&tcp, &ip) else { continue; };
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
                self.replies.send(packet, &output);
            } else if repr.control == TcpControl::Syn && let Some(handle) = handle
                && sockets.get_mut(handle).state() == State::SynReceived {
                // Commit SYN transmission into the reserved local reply space.
                // Deferred SYN|ACK must precede application close/data output.
                let result: Result<(), Infallible> = sockets.get_mut(handle)
                    .dispatch(&mut self.context, |_, _, (ip, tcp)| {
                        let packet = reply_packet(ip, tcp);
                        self.replies.send(packet, &output);
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
        if device.is_empty() { IngressStatus::Drained }
        else if needs_output { IngressStatus::OutputFull }
        else {
            IngressStatus::RepliesFull
        }
    }

    pub fn reply_capacity_available(&self) -> bool { self.replies.has_capacity() }

    /// Validate new-flow admission before publishing a stream. This extra
    /// validation is SYN-only; established traffic is decoded once in ingress.
    pub fn valid_syn(packet: &Packet) -> bool {
        let Some((ip, payload)) = parse_ip(packet.data()) else { return false; };
        if ip.next_header() != IpProtocol::Tcp
            || !ip.src_addr().is_unicast() || !ip.dst_addr().is_unicast() { return false; }
        let Ok(packet) = TcpPacket::new_checked(payload) else { return false; };
        TcpRepr::parse(&packet, &ip.src_addr(), &ip.dst_addr(), &ChecksumCapabilities::default())
            .is_ok_and(|repr| repr.control == TcpControl::Syn && repr.ack_number.is_none())
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
    pub fn poll_egress(&mut self, now: Instant, device: &mut NetstackDevice, sockets: &mut SocketTable) {
        self.context.set_now(now);
        self.schedule.expire(now, OUTPUT_PACKETS);
        let output = device.output().clone();
        // Previously committed immediate replies precede all protocol data,
        // FINs and RSTs. Timer expiry above still advances while output is full.
        let (mut packets, mut bytes) = self.replies.flush(&output);
        if !self.replies.is_empty() {
            return;
        }
        // Also bound visits that produce no packets (for example a timer that
        // changes state), independently of the emitted-packet budget.
        for _ in 0..OUTPUT_PACKETS {
            if packets >= OUTPUT_PACKETS || bytes >= OUTPUT_BYTES || output.capacity() == 0 { break; }
            let Some(handle) = self.schedule.pop_ready() else { break; };
            let socket = sockets.get_mut(handle);
            for _ in 0..OUTPUT_BURST {
                if packets >= OUTPUT_PACKETS || bytes >= OUTPUT_BYTES || output.capacity() == 0 { break; }
                let mut emitted = false;
                let result: Result<(), ()> = socket
                    .dispatch(&mut self.context, |_, _, (ip, tcp)| {
                        let length = ip.header_len() + tcp.buffer_len();
                        if bytes + length > OUTPUT_BYTES { return Err(()); }
                        let permit = output.try_reserve().map_err(|_| ())?;
                        bytes += length;
                        packets += 1;
                        emitted = true;
                        emit(permit, ip, tcp);
                        Ok(())
                    });
                if result.is_err() {
                    self.schedule.retry(handle);
                    return;
                }
                if !emitted { break; }
            }
            self.refresh(now, handle, sockets);
        }
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

fn parse_tcp<'a>(packet: &TcpPacket<&'a [u8]>, ip: &IpRepr) -> Option<TcpRepr<'a>> {
    TcpRepr::parse(packet, &ip.src_addr(), &ip.dst_addr(),
        &ChecksumCapabilities::default()).ok()
}

fn emit(permit: mpsc::Permit<'_, Packet>, ip: IpRepr, tcp: TcpRepr<'_>) {
    permit.send(build_packet(ip, tcp));
}

fn reply_packet(ip: IpRepr, tcp: TcpRepr<'_>) -> Packet {
    assert!(tcp.payload.is_empty(), "only immediate control replies may be deferred");
    build_packet(ip, tcp)
}

fn build_packet(mut ip: IpRepr, tcp: TcpRepr<'_>) -> Packet {
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

#[cfg(test)]
mod tests;
