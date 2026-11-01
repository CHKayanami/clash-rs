use super::*;
use crate::tcp::replies::MAX_PENDING_REPLIES;
use smoltcp::wire::{Icmpv4Message, Icmpv4Packet, Ipv4Address};

#[test]
fn blocked_output_defers_syn_ack_without_blocking_socket_state() {
    for ipv6 in [false, true] {
        let (output, mut input) = mpsc::channel(1);
        output.try_send(Packet::new(&b"busy"[..])).unwrap();
        let mut device = NetstackDevice::new(output);
        let mut driver = Driver::new(1500);
        let (mut sockets, handle) = listener(ipv6);
        device.inject(syn(ipv6));
        assert_eq!(driver.ingress(Instant::ZERO, &mut device, &mut sockets), IngressStatus::Drained);
        assert!(device.is_empty());
        assert_eq!(sockets.get_mut(handle).state(), State::SynReceived);
        assert_eq!(driver.replies.len(), 1);
        assert_eq!(input.try_recv().unwrap().data(), b"busy");
        driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
        let packet = input.try_recv().unwrap();
        let (ip, payload) = parse_ip(packet.data()).unwrap();
        let tcp = TcpPacket::new_checked(payload).unwrap();
        assert!(tcp.syn() && tcp.ack());
        assert!(TcpRepr::parse(&tcp, &ip.src_addr(), &ip.dst_addr(),
            &ChecksumCapabilities::default()).is_ok());
        assert!(driver.replies.is_empty());
        assert!(input.try_recv().is_err());
    }
}

#[test]
fn ack_frees_transmit_storage_while_output_is_full() {
    let (output, mut input) = mpsc::channel(1);
    let mut device = NetstackDevice::new(output.clone());
    let mut driver = Driver::new(1500);
    let mut sockets = SocketTable::new();
    let (handle, _) = established(&mut driver, &mut sockets, 49152);
    driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    let packet = input.try_recv().unwrap();
    let (_, payload) = parse_ip(packet.data()).unwrap();
    let tcp = TcpPacket::new_checked(payload).unwrap();
    let received = tcp.payload().len();
    assert!(received > 0);
    let acknowledged = tcp.seq_number() + received;
    let before = sockets.get_mut(handle).send_queue();
    output.try_send(Packet::new(&b"busy"[..])).unwrap();
    device.inject(client_packet(49152, Some(acknowledged)));
    assert_eq!(driver.ingress(Instant::ZERO, &mut device, &mut sockets), IngressStatus::Drained);
    assert_eq!(sockets.get_mut(handle).send_queue(), before - received);
    assert!(driver.replies.is_empty());
    assert_eq!(input.try_recv().unwrap().data(), b"busy");
    assert!(input.try_recv().is_err());
}

#[test]
fn immediate_reply_limit_preserves_remaining_input_and_fifo() {
    let (output, mut input) = mpsc::channel(1);
    output.try_send(Packet::new(&b"busy"[..])).unwrap();
    let mut device = NetstackDevice::new(output);
    let mut driver = Driver::new(1500);
    let mut sockets = SocketTable::new();
    for i in 0..=MAX_PENDING_REPLIES {
        device.inject(client_packet(49152 + i as u16, Some(TcpSeqNumber(10))));
    }
    assert_eq!(driver.ingress(Instant::ZERO, &mut device, &mut sockets), IngressStatus::RepliesFull);
    assert_eq!(driver.replies.len(), MAX_PENDING_REPLIES);
    assert_eq!(device.queue_len(), 1);
    assert!(!driver.reply_capacity_available());
    assert_eq!(input.try_recv().unwrap().data(), b"busy");
    driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    assert!(driver.reply_capacity_available());
    assert!(!device.output_available());
    // A flush freed local reply capacity but filled the single output slot.
    // The remaining input must still be processable, without losing its RST.
    assert_eq!(driver.ingress(Instant::ZERO, &mut device, &mut sockets), IngressStatus::Drained);
    assert!(device.is_empty());
    assert_eq!(driver.replies.len(), MAX_PENDING_REPLIES);
    for i in 0..=MAX_PENDING_REPLIES {
        let packet = input.try_recv().unwrap();
        let (_, payload) = parse_ip(packet.data()).unwrap();
        let tcp = TcpPacket::new_checked(payload).unwrap();
        assert!(tcp.rst());
        assert_eq!(tcp.dst_port(), 49152 + i as u16);
        driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    }
    assert!(driver.replies.is_empty());
    assert!(input.try_recv().is_err());
}

#[test]
fn deferred_syn_ack_precedes_abort_reset() {
    let (output, mut input) = mpsc::channel(1);
    output.try_send(Packet::new(&b"busy"[..])).unwrap();
    let mut device = NetstackDevice::new(output);
    let mut driver = Driver::new(1500);
    let (mut sockets, handle) = listener(false);
    device.inject(syn(false));
    driver.ingress(Instant::ZERO, &mut device, &mut sockets);
    sockets.get_mut(handle).abort();
    driver.refresh(Instant::ZERO, handle, &mut sockets);
    input.try_recv().unwrap();
    driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    let packet = input.try_recv().unwrap();
    let (_, payload) = parse_ip(packet.data()).unwrap();
    assert!(TcpPacket::new_checked(payload).unwrap().syn());
    driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    let packet = input.try_recv().unwrap();
    let (_, payload) = parse_ip(packet.data()).unwrap();
    assert!(TcpPacket::new_checked(payload).unwrap().rst());
    assert!(driver.replies.is_empty());
}

#[test]
fn deferred_reply_precedes_other_connections_data() {
    let (output, mut input) = mpsc::channel(1);
    let mut device = NetstackDevice::new(output.clone());
    let mut driver = Driver::new(1500);
    let (mut sockets, _) = listener(false);
    established(&mut driver, &mut sockets, 49153);
    output.try_send(Packet::new(&b"busy"[..])).unwrap();
    device.inject(syn(false));
    driver.ingress(Instant::ZERO, &mut device, &mut sockets);
    input.try_recv().unwrap();
    driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    let packet = input.try_recv().unwrap();
    let (_, payload) = parse_ip(packet.data()).unwrap();
    let tcp = TcpPacket::new_checked(payload).unwrap();
    assert_eq!(tcp.dst_port(), 49152);
    assert!(tcp.syn());
    driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    let packet = input.try_recv().unwrap();
    let (_, payload) = parse_ip(packet.data()).unwrap();
    let tcp = TcpPacket::new_checked(payload).unwrap();
    assert_eq!(tcp.dst_port(), 49153);
    assert!(!tcp.payload().is_empty());
}

#[test]
fn icmp_preserves_input_until_output_capacity_returns() {
    let mut bytes = vec![0; 28];
    let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
    ip.set_version(4);
    ip.set_header_len(20);
    ip.set_total_len(28);
    ip.set_next_header(IpProtocol::Icmp);
    ip.set_hop_limit(64);
    ip.set_src_addr(Ipv4Address::new(192, 0, 2, 2));
    ip.set_dst_addr(Ipv4Address::new(198, 51, 100, 2));
    ip.fill_checksum();
    let mut icmp = Icmpv4Packet::new_unchecked(ip.payload_mut());
    icmp.set_msg_type(Icmpv4Message::EchoRequest);
    icmp.set_msg_code(0);
    icmp.set_echo_ident(1);
    icmp.set_echo_seq_no(2);
    icmp.fill_checksum();
    let (output, mut input) = mpsc::channel(1);
    output.try_send(Packet::new(&b"busy"[..])).unwrap();
    let mut device = NetstackDevice::new(output);
    let mut driver = Driver::new(1500);
    let mut sockets = SocketTable::new();
    device.inject(Packet::new(bytes));
    assert_eq!(driver.ingress(Instant::ZERO, &mut device, &mut sockets), IngressStatus::OutputFull);
    assert_eq!(device.queue_len(), 1);
    input.try_recv().unwrap();
    assert_eq!(driver.ingress(Instant::ZERO, &mut device, &mut sockets), IngressStatus::Drained);
    let packet = input.try_recv().unwrap();
    let ip = Ipv4Packet::new_checked(packet.data()).unwrap();
    assert_eq!(Icmpv4Packet::new_checked(ip.payload()).unwrap().msg_type(), Icmpv4Message::EchoReply);
}

#[test]
fn deferred_reset_remains_ready_when_output_opens_after_egress() {
    let (output, mut input) = mpsc::channel(1);
    output.try_send(Packet::new(&b"busy"[..])).unwrap();
    let mut device = NetstackDevice::new(output);
    let mut driver = Driver::new(1500);
    let mut sockets = SocketTable::new();
    device.inject(client_packet(49152, Some(TcpSeqNumber(10))));
    assert_eq!(driver.ingress(Instant::ZERO, &mut device, &mut sockets), IngressStatus::Drained);
    driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(driver.replies.len(), 1);
    assert!(device.is_empty());
    assert!(!driver.schedule.has_ready());
    assert_eq!(driver.poll_delay(Instant::ZERO), None);

    // The writer frees output after the failed egress pass, before Engine's
    // capacity check. No socket timer or application wake can flush this RST.
    assert_eq!(input.try_recv().unwrap().data(), b"busy");
    assert!(device.output_available());
    assert!(driver.has_ready());
    driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    let packet = input.try_recv().unwrap();
    let (_, payload) = parse_ip(packet.data()).unwrap();
    let tcp = TcpPacket::new_checked(payload).unwrap();
    assert!(tcp.rst());
    assert_eq!(tcp.dst_port(), 49152);
    assert!(driver.replies.is_empty());
    assert!(!driver.has_ready());
}
