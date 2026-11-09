use super::*;
use tokio::sync::mpsc;
use crate::link::output::Output;
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
    emit(Output::Channel(output).reserve().unwrap(), ip, tcp, None);
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
    emit(Output::Channel(output).reserve().unwrap(), ip, repr, None);
    input.try_recv().unwrap()
}

fn established(driver: &mut Driver, sockets: &mut SocketTable, port: u16)
    -> (SocketHandle, TcpSeqNumber) {
    established_with_data(driver, sockets, port, 400 * 1024)
}

fn established_with_data(driver: &mut Driver, sockets: &mut SocketTable, port: u16, bytes: usize)
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
    socket.send_slice(&vec![b'x'; bytes]).unwrap();
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

mod ingress;

#[test]
fn native_gso_preserves_link_mss_and_emits_large_frames_with_checksum_seeds() {
    let mut device = NetstackDevice::local(8);
    let mut driver = Driver::new(1500);
    driver.enable_tcp_gso();
    let mut sockets = SocketTable::new();
    let (handle, _) = established(&mut driver, &mut sockets, 49152);
    driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    let mut end = None;
    let mut count = 0;
    while let Some(packet) = device.pop_output() {
        assert_eq!(packet.tcp_segmentation(), Some(1460));
        assert!(packet.len() <= 65535);
        let (ip, payload) = parse_ip(packet.data()).unwrap();
        let tcp = TcpPacket::new_checked(payload).unwrap();
        assert!(tcp.payload().len() > 1460);
        if let Some(end) = end { assert_eq!(tcp.seq_number(), end); }
        end = Some(tcp.seq_number() + tcp.payload().len());
        assert_eq!(tcp.checksum(), checksum::pseudo_header(&ip.src_addr(), &ip.dst_addr(),
            IpProtocol::Tcp, payload.len() as u32));
        assert_eq!(sockets.get_mut(handle).peer_mss(), 1460);
        count += 1;
    }
    assert!(count > 0);
}

#[test]
fn kernel_verified_checksum_is_explicit_and_does_not_disable_ip_validation() {
    let mut bytes = syn(false).data().to_vec();
    bytes[36] ^= 1;
    assert!(!Driver::valid_syn(&Packet::new(bytes.clone())));
    assert!(Driver::valid_syn(&Packet::new(bytes.clone()).with_verified_rx_checksum()));
    bytes[10] ^= 1;
    assert!(!Driver::valid_syn(&Packet::new(bytes).with_verified_rx_checksum()));
}

#[test]
fn borrowed_gso_output_preserves_headers_and_queues_only_after_backpressure() {
    let mut device = NetstackDevice::local(8);
    let mut driver = Driver::new(1500);
    driver.enable_tcp_gso();
    let mut sockets = SocketTable::new();
    let (handle, _) = established(&mut driver, &mut sockets, 49152);
    let mut sent = Vec::new();
    driver.poll_egress_with(Instant::ZERO, &mut device, &mut sockets, &mut |header, payload, size| {
        assert_eq!(size, Some(1460));
        let mut data = header.to_vec();
        data.extend_from_slice(payload);
        let (ip, tcp_bytes) = parse_ip(&data).unwrap();
        let tcp = TcpPacket::new_checked(tcp_bytes).unwrap();
        assert_eq!(tcp.checksum(), checksum::pseudo_header(&ip.src_addr(), &ip.dst_addr(),
            IpProtocol::Tcp, tcp_bytes.len() as u32));
        let queued = build_packet(ip.clone(), TcpRepr::parse(&tcp, &ip.src_addr(), &ip.dst_addr(), &{
                let mut caps = ChecksumCapabilities::default(); caps.tcp = Checksum::Tx; caps
            }).unwrap(), size);
        assert_eq!(queued.data(), data);
        sent.push(data);
        true
    });
    assert!(!sent.is_empty());
    assert!(device.pop_output().is_none());
    assert!(sockets.get_mut(handle).send_queue() > 0, "unacknowledged payload remains owned by TCP");

    let mut device = NetstackDevice::local(8);
    let mut driver = Driver::new(1500);
    driver.enable_tcp_gso();
    let mut sockets = SocketTable::new();
    established(&mut driver, &mut sockets, 49153);
    let mut calls = 0;
    let mut expected = Vec::new();
    driver.poll_egress_with(Instant::ZERO, &mut device, &mut sockets, &mut |header, payload, _| {
        calls += 1; expected.extend_from_slice(header); expected.extend_from_slice(payload);
        false
    });
    assert_eq!(calls, 1, "queued data must prevent later packets bypassing it");
    let fallback = device.pop_output().unwrap();
    assert_eq!(fallback.data(), expected);
    assert_eq!(fallback.tcp_segmentation(), Some(1460));
}

#[test]
fn full_output_preserves_fifo_and_direct_write_resumes_after_drain() {
    let mut device = NetstackDevice::local(1);
    let mut driver = Driver::new(1500);
    driver.enable_tcp_gso();
    let mut sockets = SocketTable::new();
    let (handle, initial_seq) = established_with_data(&mut driver, &mut sockets, 49152, 32 * 1024);
    let queued = syn(false);
    device.split().1.send(queued.clone()).unwrap();
    assert!(!device.output_available());

    let mut attempts = 0;
    driver.poll_egress_with(Instant::ZERO, &mut device, &mut sockets, &mut |_, _, _| {
        attempts += 1;
        false
    });
    assert_eq!(attempts, 0, "direct writes must not bypass queued output");
    let socket = sockets.get_mut(handle);
    assert_eq!(socket.transmit_state().unsent, 32 * 1024);
    assert_eq!(socket.transmit_allowance().1, 0, "failed direct write with full queue must not advance flight");
    assert!(driver.has_ready());
    assert_eq!(device.pop_output().unwrap().data(), queued.data());

    let mut direct_seq = None;
    let mut direct_len = 0;
    driver.poll_egress_with(Instant::ZERO, &mut device, &mut sockets, &mut |header, payload, size| {
        assert_eq!(size, Some(1460));
        let mut data = header.to_vec();
        data.extend_from_slice(payload);
        let (_, tcp_bytes) = parse_ip(&data).unwrap();
        let tcp = TcpPacket::new_checked(tcp_bytes).unwrap();
        direct_seq.get_or_insert(tcp.seq_number());
        direct_len += payload.len();
        true
    });
    assert_eq!(direct_seq, Some(initial_seq));
    assert_eq!(direct_len, 32 * 1024);
    assert!(device.pop_output().is_none());
    let socket = sockets.get_mut(handle);
    assert_eq!(socket.transmit_state().unsent, 0);
    assert_eq!(socket.transmit_allowance().1, 32 * 1024);
}

#[test]
fn inline_flush_cannot_bypass_an_older_protocol_ready_connection() {
    let mut device = NetstackDevice::local(8);
    let mut driver = Driver::new(1500);
    driver.enable_tcp_gso();
    let mut sockets = SocketTable::new();
    let (older, _) = established(&mut driver, &mut sockets, 49152);
    let (newer, _) = established(&mut driver, &mut sockets, 49153);
    let mut egress = driver.begin_egress(Instant::ZERO, &mut device);
    let mut calls = 0;
    let sent = driver.flush_socket(Instant::ZERO, &mut device, newer,
        sockets.get_mut(newer), OUTPUT_BURST, &mut egress, &mut |_, _, _| {
            calls += 1;
            true
        });
    assert_eq!(sent, 0);
    assert_eq!(calls, 0);
    assert_eq!(egress.bytes, 0);
    // Refreshing the application-ready connection must retain the older
    // protocol-only connection at the front, even with just one packet left.
    driver.refresh(Instant::ZERO, newer, &mut sockets);
    egress.packets = OUTPUT_PACKETS - 1;
    let mut ports = Vec::new();
    driver.poll_egress_from(Instant::ZERO, &mut device, &mut sockets, &mut egress,
        &mut |header, payload, _| {
            let mut packet = header.to_vec();
            packet.extend_from_slice(payload);
            let (_, tcp) = parse_ip(&packet).unwrap();
            ports.push(TcpPacket::new_unchecked(tcp).dst_port());
            true
        });
    assert_eq!(ports, vec![49152]);
    assert!(sockets.get_mut(older).transmit_allowance().1 > 0);
}

mod readiness;

#[test]
fn exhausted_inline_budget_does_not_change_protocol_time_or_readiness() {
    let mut device = NetstackDevice::local(1);
    let mut driver = Driver::new(1500);
    let mut sockets = SocketTable::new();
    let (handle, _) = established(&mut driver, &mut sockets, 49152);
    let now = Instant::from_millis(1000);
    driver.context.set_now(now);
    let mut egress = Egress { packets: OUTPUT_PACKETS, bytes: OUTPUT_BYTES };
    assert_eq!(driver.flush_socket(Instant::ZERO, &mut device, handle,
        sockets.get_mut(handle), SOLO_OUTPUT_BURST, &mut egress,
        &mut |_, _, _| panic!("exhausted budget must not transmit")), 0);
    assert_eq!(driver.context.now(), now);
    assert_eq!(driver.schedule.pop_ready(), Some(handle));
}
