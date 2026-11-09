//! Exercise the combined loop with actual native I/O and a simulated TCP peer.
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use futures::StreamExt;
use smoltcp::wire::{IpAddress, Ipv4Packet, TcpPacket, TcpSeqNumber};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::mpsc, time::{sleep, timeout}};
use tokio_util::task::AbortOnDropHandle;
use clash_netstack::NetStack;
use super::*;
use crate::proxy::tun::{datagram, packet::tests::tcp_syn, system_stack::SystemTcpNat};

struct ChannelIo {
    input: mpsc::Receiver<BytesMut>,
    output: mpsc::UnboundedSender<Bytes>,
}

impl PacketIo for ChannelIo {
    fn poll_receive(&mut self, cx: &mut Context<'_>, packets: &mut Vec<Packet>) -> Poll<io::Result<usize>> {
        self.input.poll_recv(cx).map(|packet| match packet {
            Some(packet) => { packets.push(Packet::from(packet)); Ok(1) },
            None => Ok(0),
        })
    }
    fn poll_send(&mut self, _: &mut Context<'_>, packets: &mut Vec<Packet>, _: &mut Vec<OwnedSemaphorePermit>) -> Poll<io::Result<()>> {
        for packet in packets.drain(..) {
            self.output.send(packet.into_bytes()).map_err(|_| io::ErrorKind::BrokenPipe)?;
        }
        Poll::Ready(Ok(()))
    }
}

fn ack(sequence: u32, acknowledgement: u32, fin: bool) -> BytesMut {
    let mut packet = tcp_syn(false);
    let mut tcp = TcpPacket::new_unchecked(&mut packet[20..]);
    tcp.set_seq_number(TcpSeqNumber(sequence as i32));
    tcp.set_ack_number(TcpSeqNumber(acknowledgement as i32));
    tcp.set_syn(false);
    tcp.set_ack(true);
    tcp.set_fin(fin);
    tcp.fill_checksum(&IpAddress::from(Ipv4Addr::new(192, 0, 2, 2)),
        &IpAddress::from(Ipv4Addr::new(198, 51, 100, 2)));
    packet
}

#[tokio::test(flavor = "current_thread")]
async fn direct_handoff_reads_native_socket_after_idle_and_drains_half_closes() {
    for gso in [false, true] {
    timeout(Duration::from_secs(10), async {
        let (mut tcp, mut listener) = TcpDriver::new(1500, 4).unwrap();
        if gso { tcp.enable_tcp_gso(); }
        let (stack, _, _udp) = NetStack::new_with_protocols(false, true);
        let (sink, stream) = stack.split();
        let (_replies, receive) = packet_queue::channel();
        let packets = PacketDispatcher { enable_tcp: true, system_tcp: false, ipv4: None, ipv6: None,
            nat: Arc::new(SystemTcpNat::new()), direct: datagram::direct_path(None), uploads: Default::default() };
        let (input, incoming) = mpsc::channel(32);
        let (outgoing, mut output) = mpsc::unbounded_channel();
        let owner = AbortOnDropHandle::new(tokio::spawn(DeviceLoop::new(
            ChannelIo { input: incoming, output: outgoing },
            Protocols { tcp: Some(tcp), sink, stream }, packets, receive, |_| false,
        ).run()));
        input.send(tcp_syn(false)).await.unwrap();
        let reply = output.recv().await.unwrap();
        let ip = Ipv4Packet::new_checked(&reply[..]).unwrap();
        let syn_ack = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(syn_ack.syn() && syn_ack.ack());
        let mut received_sequence = (syn_ack.seq_number().0 as u32).wrapping_add(1);
        input.send(ack(2, received_sequence, false)).await.unwrap();
        let stream = listener.next().await.unwrap();
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let native = TcpStream::connect(server.local_addr().unwrap()).await.unwrap();
        let (mut peer, _) = server.accept().await.unwrap();
        let relay = AbortOnDropHandle::new(tokio::spawn(stream.forward(native, b"prefix".to_vec(),
            Box::new(|_, _| {}), Duration::from_secs(2), Duration::from_secs(2))));
        input.send(ack(2, received_sequence, true)).await.unwrap();
        let peer = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut prefix = Vec::new();
            peer.read_to_end(&mut prefix).await.unwrap();
            assert_eq!(prefix, b"prefix");
            // Force the loop to park on native readiness before starting data.
            sleep(Duration::from_millis(20)).await;
            peer.write_all(&vec![0x7a; 1024 * 1024]).await.unwrap();
            peer.shutdown().await.unwrap();
        }));
        let mut received = 0;
        let mut saw_super_packet = false;
        loop {
            let packet = output.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            let length = tcp.payload().len();
            saw_super_packet |= length > 1460;
            if length == 0 && !tcp.fin() { continue; }
            assert_eq!(tcp.seq_number().0 as u32, received_sequence);
            assert!(tcp.payload().iter().all(|byte| *byte == 0x7a));
            received += length;
            received_sequence = received_sequence.wrapping_add(length as u32 + u32::from(tcp.fin()));
            input.send(ack(3, received_sequence, false)).await.unwrap();
            if tcp.fin() { break; }
        }
        assert_eq!(received, 1024 * 1024);
        assert_eq!(saw_super_packet, gso);
        assert_eq!(relay.await.unwrap().unwrap(), (6, received as u64));
        peer.await.unwrap();
        drop(owner);
    }).await.expect("combined DIRECT forwarding stalled");
    }
}
