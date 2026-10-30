//! Indexed L3 delivery and bounded round-robin protocol output.
use smoltcp::{phy::ChecksumCapabilities, time::{Duration, Instant}, wire::{
    IpProtocol, IpRepr, IpVersion, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
    TcpControl, TcpPacket, TcpRepr,
}};
use tokio::sync::mpsc;
use crate::{Packet, link::{device::NetstackDevice, icmp::IcmpResponder}};
use super::{protocol::{Context, Socket, State}, connections::{SocketHandle, SocketTable},
    schedule::Schedule};
use std::{convert::Infallible, net::SocketAddr};

const OUTPUT_PACKETS: usize = 128;
const OUTPUT_BYTES: usize = 256 * 1024;
const OUTPUT_BURST: usize = 2;

pub(crate) struct Driver {
    context: Context,
    icmp: Option<IcmpResponder>,
    mtu: usize,
    schedule: Schedule,
    ingress_dirty: Vec<SocketHandle>,
}

impl Driver {
    pub fn new(mtu: usize) -> Self {
        Self { context: Context::new(mtu), icmp: None, mtu, schedule: Schedule::default(),
            ingress_dirty: Vec::with_capacity(32) }
    }

    pub fn ingress(&mut self, now: Instant, device: &mut NetstackDevice, sockets: &mut SocketTable) {
        self.context.set_now(now);
        let output = device.output().clone();
        while let Some((packet, permit)) = device.take_packet() {
            let data = packet.data();
            let Some((ip, payload)) = parse_ip(data) else { continue; };
            if matches!(ip.next_header(), IpProtocol::Icmp | IpProtocol::Icmpv6) {
                drop(permit);
                self.icmp.get_or_insert_with(|| IcmpResponder::new(&output, self.mtu))
                    .respond(packet, &output);
                continue;
            }
            if ip.next_header() != IpProtocol::Tcp
                || !ip.src_addr().is_unicast() || !ip.dst_addr().is_unicast() { continue; }
            let Ok(tcp) = TcpPacket::new_checked(payload) else { continue; };
            let Ok(repr) = TcpRepr::parse(&tcp, &ip.src_addr(), &ip.dst_addr(),
                &ChecksumCapabilities::default()) else { continue; };
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
                emit(permit, ip, tcp);
            } else if repr.control == TcpControl::Syn && let Some(handle) = handle
                && sockets.get_mut(handle).state() == State::SynReceived {
                // Like immediate ACKs, the initial SYN response uses the ingress
                // reservation. Application close cannot overtake the SYN|ACK.
                let result: Result<(), Infallible> = sockets.get_mut(handle)
                    .dispatch(&mut self.context, |_, _, (ip, tcp)| {
                        emit(permit, ip, tcp);
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
    }

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
        let mut bytes = 0;
        let mut packets = 0;
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

    pub fn has_ready(&self) -> bool { self.schedule.has_ready() }

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

fn emit(permit: mpsc::Permit<'_, Packet>, mut ip: IpRepr, tcp: TcpRepr<'_>) {
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
    permit.send(Packet::new(bytes));
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::protocol::{CongestionControl, SocketBuffer, State};
    use smoltcp::wire::{Ipv6Address, TcpSeqNumber};

    fn syn(ipv6: bool) -> Packet {
        let ip = if ipv6 {
            IpRepr::Ipv6(Ipv6Repr {
                src_addr: Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3),
                next_header: IpProtocol::Tcp, payload_len: 0, hop_limit: 64,
            })
        } else {
            IpRepr::Ipv4(Ipv4Repr {
                src_addr: [192, 0, 2, 2].into(), dst_addr: [198, 51, 100, 2].into(),
                next_header: IpProtocol::Tcp, payload_len: 0, hop_limit: 64,
            })
        };
        let tcp = TcpRepr {
            src_port: 49152, dst_port: 80, control: TcpControl::Syn,
            seq_number: TcpSeqNumber(100), ack_number: None,
            window_len: 16384, window_scale: Some(0), max_seg_size: Some(1460),
            sack_permitted: true, sack_ranges: [None; 3], timestamp: None, payload: &[],
        };
        let (output, mut input) = mpsc::channel(1);
        emit(output.try_reserve().unwrap(), ip, tcp);
        input.try_recv().unwrap()
    }

    fn listener(ipv6: bool) -> (SocketTable, SocketHandle) {
        let mut sockets = SocketTable::new();
        let mut socket = Socket::new(SocketBuffer::new(vec![0; 16384]),
            SocketBuffer::new(vec![0; 16384]));
        socket.listen(80).unwrap();
        let packet = syn(ipv6);
        let (ip, _) = parse_ip(packet.data()).unwrap();
        let flow = (SocketAddr::new(ip.src_addr().into(), 49152),
            SocketAddr::new(ip.dst_addr().into(), 80));
        let handle = sockets.add(socket, flow);
        (sockets, handle)
    }

    #[test]
    fn both_ip_families_handshake_with_valid_reply_checksums() {
        for ipv6 in [false, true] {
            let (output, mut input) = mpsc::channel(8);
            let mut device = NetstackDevice::new(output);
            let mut driver = Driver::new(1400);
            let (mut sockets, handle) = listener(ipv6);
            device.inject(syn(ipv6));
            driver.poll(Instant::ZERO, &mut device, &mut sockets);
            assert_eq!(sockets.get_mut(handle).state(), State::SynReceived);
            let packet = input.try_recv().unwrap();
            let (ip, payload) = parse_ip(packet.data()).unwrap();
            let tcp = TcpPacket::new_checked(payload).unwrap();
            let repr = TcpRepr::parse(&tcp, &ip.src_addr(), &ip.dst_addr(),
                &ChecksumCapabilities::default()).unwrap();
            assert_eq!(repr.control, TcpControl::Syn);
            assert_eq!(repr.ack_number, Some(TcpSeqNumber(101)));
            assert_eq!(repr.max_seg_size, Some(if ipv6 { 1340 } else { 1360 }));
        }
    }

    #[test]
    fn invalid_tcp_checksum_does_not_change_socket_state() {
        for ipv6 in [false, true] {
            let (output, mut input) = mpsc::channel(8);
            let mut device = NetstackDevice::new(output);
            let mut driver = Driver::new(1500);
            let (mut sockets, handle) = listener(ipv6);
            let mut bytes = syn(ipv6).data().to_vec();
            bytes[if ipv6 { 56 } else { 36 }] ^= 1;
            device.inject(Packet::new(bytes));
            driver.poll(Instant::ZERO, &mut device, &mut sockets);
            assert_eq!(sockets.get_mut(handle).state(), State::Listen);
            assert!(input.try_recv().is_err());
        }
    }

    #[test]
    fn output_backpressure_preserves_inbound_handshake() {
        let (output, mut input) = mpsc::channel(1);
        output.try_send(Packet::new(&b"busy"[..])).unwrap();
        let mut device = NetstackDevice::new(output);
        let mut driver = Driver::new(1500);
        let (mut sockets, handle) = listener(false);
        device.inject(syn(false));
        driver.poll(Instant::ZERO, &mut device, &mut sockets);
        assert!(!device.is_empty());
        assert_eq!(sockets.get_mut(handle).state(), State::Listen);
        input.try_recv().unwrap();
        driver.poll(Instant::ZERO, &mut device, &mut sockets);
        assert!(device.is_empty());
        assert_eq!(sockets.get_mut(handle).state(), State::SynReceived);
        assert!(input.try_recv().is_ok());
    }
    fn client_packet(port: u16, ack: Option<TcpSeqNumber>) -> Packet {
        let packet = syn(false);
        let (ip, payload) = parse_ip(packet.data()).unwrap();
        let tcp = TcpPacket::new_checked(payload).unwrap();
        let mut repr = TcpRepr::parse(&tcp, &ip.src_addr(), &ip.dst_addr(),
            &ChecksumCapabilities::default()).unwrap();
        repr.src_port = port;
        if let Some(ack) = ack {
            repr.control = TcpControl::None;
            repr.seq_number = TcpSeqNumber(101);
            repr.ack_number = Some(ack);
            repr.max_seg_size = None;
            repr.window_scale = None;
            repr.sack_permitted = false;
        }
        let (output, mut input) = mpsc::channel(1);
        emit(output.try_reserve().unwrap(), ip, repr);
        input.try_recv().unwrap()
    }

    fn established(driver: &mut Driver, sockets: &mut SocketTable, port: u16)
        -> (SocketHandle, TcpSeqNumber) {
        let packet = client_packet(port, None);
        let (ip, payload) = parse_ip(packet.data()).unwrap();
        let tcp = TcpPacket::new_checked(payload).unwrap();
        let mut repr = TcpRepr::parse(&tcp, &ip.src_addr(), &ip.dst_addr(),
            &ChecksumCapabilities::default()).unwrap();
        repr.window_len = u16::MAX;
        repr.window_scale = Some(7);
        repr.max_seg_size = Some((driver.mtu - 40) as u16);
        let mut socket = Socket::new(SocketBuffer::new(vec![0; 16384]),
            SocketBuffer::new(vec![0; 512 * 1024]));
        socket.listen(80).unwrap();
        socket.process(&mut driver.context, &ip, &repr);
        let mut ack = TcpSeqNumber(0);
        socket.dispatch(&mut driver.context, |_, _, (_, tcp)| {
            ack = tcp.seq_number + 1;
            Ok::<_, Infallible>(())
        }).unwrap();
        repr.control = TcpControl::None;
        repr.seq_number += 1;
        repr.ack_number = Some(ack);
        repr.window_scale = None;
        repr.max_seg_size = None;
        socket.process(&mut driver.context, &ip, &repr);
        assert_eq!(socket.state(), State::Established);
        socket.set_congestion_control(CongestionControl::None);
        socket.set_nagle_enabled(false);
        socket.send_slice(&vec![b'x'; 400 * 1024]).unwrap();
        let flow = (SocketAddr::new(ip.src_addr().into(), port),
            SocketAddr::new(ip.dst_addr().into(), 80));
        let handle = sockets.add(socket, flow);
        driver.refresh(Instant::ZERO, handle, sockets);
        (handle, ack)
    }

    #[test]
    fn busy_flows_rotate_after_small_bursts_with_a_global_packet_budget() {
        let (output, mut input) = mpsc::channel(512);
        let mut device = NetstackDevice::new(output);
        let mut driver = Driver::new(1500);
        let mut sockets = SocketTable::new();
        established(&mut driver, &mut sockets, 49152);
        established(&mut driver, &mut sockets, 49153);
        driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
        let mut count = 0;
        while let Ok(packet) = input.try_recv() {
            let (_, payload) = parse_ip(packet.data()).unwrap();
            let tcp = TcpPacket::new_checked(payload).unwrap();
            assert_eq!(tcp.dst_port(), 49152 + ((count / OUTPUT_BURST) % 2) as u16);
            assert!(!tcp.payload().is_empty());
            count += 1;
        }
        assert_eq!(count, OUTPUT_PACKETS);
        assert!(driver.has_ready());
    }

    #[test]
    fn byte_budget_preserves_unsent_data_and_resumes_on_the_next_poll() {
        let (output, mut input) = mpsc::channel(512);
        let mut device = NetstackDevice::new(output);
        let mut driver = Driver::new(9000);
        let mut sockets = SocketTable::new();
        established(&mut driver, &mut sockets, 49152);
        let mut expected = None;
        for _ in 0..2 {
            driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
            let mut bytes = 0;
            while let Ok(packet) = input.try_recv() {
                bytes += packet.data().len();
                let (_, payload) = parse_ip(packet.data()).unwrap();
                let tcp = TcpPacket::new_checked(payload).unwrap();
                if let Some(sequence) = expected { assert_eq!(tcp.seq_number(), sequence); }
                expected = Some(tcp.seq_number() + tcp.payload().len());
            }
            assert!(bytes > 0 && bytes <= OUTPUT_BYTES);
        }
    }

    #[test]
    fn repeated_ingress_updates_keep_first_seen_order_and_final_deadlines() {
        let (output, mut input) = mpsc::channel(512);
        let mut device = NetstackDevice::new(output);
        let mut driver = Driver::new(1500);
        let mut sockets = SocketTable::new();
        let (first, first_ack) = established(&mut driver, &mut sockets, 49152);
        let (second, second_ack) = established(&mut driver, &mut sockets, 49153);
        driver.schedule.remove(first);
        driver.schedule.remove(second);
        for (port, ack) in [(49152, first_ack), (49153, second_ack), (49152, first_ack)] {
            device.inject(client_packet(port, Some(ack)));
        }
        driver.ingress(Instant::ZERO, &mut device, &mut sockets);
        assert!(driver.ingress_dirty.is_empty());
        assert_eq!(driver.schedule.pop_ready(), Some(first));
        assert_eq!(driver.schedule.pop_ready(), Some(second));
        assert_eq!(driver.schedule.pop_ready(), None);
        assert!(input.try_recv().is_err());
        driver.refresh(Instant::ZERO, first, &mut sockets);
        driver.refresh(Instant::ZERO, second, &mut sockets);
        driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
        assert!(input.try_recv().is_ok());
        for _ in 0..16 {
            if !driver.has_ready() { break; }
            while input.try_recv().is_ok() {}
            driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
        }
        assert!(!driver.has_ready());
        assert!(driver.poll_delay(Instant::ZERO).is_some());
    }

    #[test]
    fn one_packet_output_capacity_preserves_round_robin_across_busy_flows() {
        let (output, mut input) = mpsc::channel(1);
        let mut device = NetstackDevice::new(output);
        let mut driver = Driver::new(1500);
        let (mut sockets, first) = listener(false);
        let template = syn(false);
        let (ip, _) = parse_ip(template.data()).unwrap();
        let flow = (SocketAddr::new(ip.src_addr().into(), 49153),
            SocketAddr::new(ip.dst_addr().into(), 80));
        let mut second = Socket::new(SocketBuffer::new(vec![0; 16384]),
            SocketBuffer::new(vec![0; 16384]));
        second.listen(80).unwrap();
        let second = sockets.add(second, flow);
        device.inject(client_packet(49152, None));
        device.inject(client_packet(49153, None));
        for port in [49152, 49153] {
            driver.poll(Instant::ZERO, &mut device, &mut sockets);
            let packet = input.try_recv().unwrap();
            let (_, payload) = parse_ip(packet.data()).unwrap();
            let tcp = TcpPacket::new_checked(payload).unwrap();
            assert_eq!(tcp.dst_port(), port);
            device.inject(client_packet(port, Some(tcp.seq_number() + 1)));
        }
        driver.poll(Instant::ZERO, &mut device, &mut sockets);
        assert!(input.try_recv().is_err());
        for handle in [first, second] {
            let socket = sockets.get_mut(handle);
            assert_eq!(socket.state(), State::Established);
            socket.set_congestion_control(CongestionControl::None);
            socket.set_nagle_enabled(false);
            assert_eq!(socket.send_slice(&[b'x'; 8000]).unwrap(), 8000);
            driver.refresh(Instant::ZERO, handle, &mut sockets);
        }
        for port in [49152, 49153, 49152, 49153] {
            driver.poll(Instant::ZERO, &mut device, &mut sockets);
            let packet = input.try_recv().unwrap();
            let (_, payload) = parse_ip(packet.data()).unwrap();
            let tcp = TcpPacket::new_checked(payload).unwrap();
            assert_eq!(tcp.dst_port(), port);
            assert!(!tcp.payload().is_empty());
        }
    }

    #[test]
    fn retransmission_deadline_wakes_protocol_without_application_io() {
        let (output, mut input) = mpsc::channel(8);
        let mut device = NetstackDevice::new(output);
        let mut driver = Driver::new(1500);
        let (mut sockets, _) = listener(false);
        device.inject(syn(false));
        driver.poll(Instant::ZERO, &mut device, &mut sockets);
        let first = input.try_recv().unwrap();
        let delay = driver.poll_delay(Instant::ZERO).unwrap();
        assert!(delay > Duration::ZERO);
        driver.poll(Instant::ZERO + delay - Duration::from_millis(1), &mut device, &mut sockets);
        assert!(input.try_recv().is_err());
        driver.poll(Instant::ZERO + delay, &mut device, &mut sockets);
        let retransmission = input.try_recv().unwrap();
        assert_eq!(retransmission.data(), first.data());
        assert!(driver.poll_delay(Instant::ZERO + delay).unwrap() >= delay);
    }

    #[test]
    fn expired_timer_waits_for_output_capacity_without_zero_delay_spin() {
        let (output, mut input) = mpsc::channel(1);
        let mut device = NetstackDevice::new(output);
        let mut driver = Driver::new(1500);
        let (mut sockets, _) = listener(false);
        device.inject(syn(false));
        driver.poll(Instant::ZERO, &mut device, &mut sockets);
        let delay = driver.poll_delay(Instant::ZERO).unwrap();
        driver.poll(Instant::ZERO + delay, &mut device, &mut sockets);
        assert!(driver.has_ready());
        assert_eq!(driver.poll_delay(Instant::ZERO + delay), None);
        let first = input.try_recv().unwrap();
        driver.poll(Instant::ZERO + delay, &mut device, &mut sockets);
        assert_eq!(input.try_recv().unwrap().data(), first.data());
        assert!(!driver.has_ready());
        assert!(driver.poll_delay(Instant::ZERO + delay).unwrap() >= delay);
    }

    #[test]
    fn removal_cancels_deadline_before_reusing_the_flow() {
        let (output, mut input) = mpsc::channel(8);
        let mut device = NetstackDevice::new(output);
        let mut driver = Driver::new(1500);
        let (mut sockets, old) = listener(false);
        device.inject(syn(false));
        driver.poll(Instant::ZERO, &mut device, &mut sockets);
        input.try_recv().unwrap();
        assert!(driver.poll_delay(Instant::ZERO).is_some());
        driver.remove(old, &mut sockets);
        assert_eq!(driver.poll_delay(Instant::ZERO), None);
        let packet = syn(false);
        let (ip, _) = parse_ip(packet.data()).unwrap();
        let flow = (SocketAddr::new(ip.src_addr().into(), 49152),
            SocketAddr::new(ip.dst_addr().into(), 80));
        let mut replacement = Socket::new(SocketBuffer::new(vec![0; 16384]),
            SocketBuffer::new(vec![0; 16384]));
        replacement.listen(80).unwrap();
        let new = sockets.add(replacement, flow);
        assert_ne!(old, new);
        driver.poll(Instant::from_secs(60), &mut device, &mut sockets);
        assert_eq!(sockets.get_mut(new).state(), State::Listen);
        assert!(input.try_recv().is_err());
    }

}
