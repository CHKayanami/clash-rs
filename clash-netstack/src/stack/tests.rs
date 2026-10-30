use super::*;
use futures::{SinkExt, StreamExt};
use smoltcp::wire::{Icmpv4Message, Icmpv4Packet, Icmpv6Message, Icmpv6Packet,
    IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn recv_many_reuses_storage_and_returns_partial_ready_batches() {
    let (sender, receiver) = mpsc::channel(8);
    let mut stream = StackSplitStream::new(None, receiver);
    let mut packets = Vec::with_capacity(4);
    let storage = packets.as_ptr();
    for value in [b"one", b"two"] { sender.send(Packet::new(&value[..])).await.unwrap(); }
    assert_eq!(timeout(Duration::from_secs(1), stream.recv_many(&mut packets, 4)).await.unwrap().unwrap(), 2);
    assert_eq!(packets, [Bytes::from_static(b"one"), Bytes::from_static(b"two")]);
    assert_eq!(storage, packets.as_ptr());
    packets.clear();
    assert!(timeout(Duration::from_millis(10), stream.recv_many(&mut packets, 4)).await.is_err());
    sender.send(Packet::new(&b"last"[..])).await.unwrap();
    drop(sender);
    assert_eq!(stream.recv_many(&mut packets, 4).await.unwrap(), 1);
    packets.clear();
    assert_eq!(stream.recv_many(&mut packets, 4).await.unwrap(), 0);
}

#[tokio::test]
async fn protocol_switches_preserve_udp_and_control_local_icmp() {
    for (enable_tcp, enable_icmp) in [(false, false), (false, true), (true, true)] {
        let (stack, listener, udp) = NetStack::new_with_protocols(enable_tcp, enable_icmp);
        assert_eq!(listener.is_some(), enable_tcp);
        assert_eq!(stack.tcp_inbound.is_some(), enable_tcp);
        assert_eq!(stack.tcp_outbound.is_some(), enable_tcp);
        let (mut sink, mut replies) = stack.split();
        let (mut udp_in, mut udp_out) = udp.split();
        let source = "192.0.2.2:12345".parse().unwrap();
        let target = "198.51.100.2:53".parse().unwrap();
        udp_out.send((Bytes::from_static(b"udp"), source, target).into()).await.unwrap();
        let wire = timeout(Duration::from_secs(1), replies.next()).await.unwrap().unwrap().unwrap();
        sink.send(wire).await.unwrap();
        let received = timeout(Duration::from_secs(1), udp_in.recv()).await.unwrap().unwrap();
        assert_eq!(received.data.data(), b"udp");
        for ipv6 in [false, true] {
            let packet = echo_request(ipv6);
            sink.send(Packet::new(packet)).await.unwrap();
            if !enable_icmp {
                assert!(sink.icmp.is_none());
                assert!(timeout(Duration::from_millis(10), replies.next()).await.is_err());
                continue;
            }
            let reply = timeout(Duration::from_secs(1), replies.next()).await
                .unwrap_or_else(|_| panic!("ICMP timeout: enable_tcp={enable_tcp}, ipv6={ipv6}"))
                .unwrap().unwrap();
            if ipv6 {
                let ip = Ipv6Packet::new_checked(reply.data()).unwrap();
                assert_eq!(Icmpv6Packet::new_checked(ip.payload()).unwrap().msg_type(), Icmpv6Message::EchoReply);
            } else {
                let ip = Ipv4Packet::new_checked(reply.data()).unwrap();
                assert_eq!(Icmpv4Packet::new_checked(ip.payload()).unwrap().msg_type(), Icmpv4Message::EchoReply);
            }
        }
    }
}

fn echo_request(ipv6: bool) -> Vec<u8> {
    if ipv6 {
        let source = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let target = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3);
        let mut data = vec![0; 48];
        let mut ip = Ipv6Packet::new_unchecked(&mut data[..]);
        ip.set_version(6);
        ip.set_payload_len(8);
        ip.set_next_header(IpProtocol::Icmpv6);
        ip.set_hop_limit(64);
        ip.set_src_addr(source);
        ip.set_dst_addr(target);
        let mut icmp = Icmpv6Packet::new_unchecked(ip.payload_mut());
        icmp.set_msg_type(Icmpv6Message::EchoRequest);
        icmp.set_msg_code(0);
        icmp.set_echo_ident(1);
        icmp.set_echo_seq_no(2);
        icmp.fill_checksum(&source, &target);
        data
    } else {
        let mut data = vec![0; 28];
        let mut ip = Ipv4Packet::new_unchecked(&mut data[..]);
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
        data
    }
}
