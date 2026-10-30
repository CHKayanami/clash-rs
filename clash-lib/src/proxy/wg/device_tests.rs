use super::*;
use std::sync::Arc;

use crate::proxy::utils::test_utils::noop::NoopResolver;
use smoltcp::wire::{Ipv4Packet, UdpPacket as WireUdpPacket};
use tokio::sync::mpsc;

#[tokio::test]
async fn task_owned_socket_set_routes_udp_and_accepts_new_sockets() {
    let (notifier, notified) = mpsc::channel(4);
    let manager = Arc::new(DeviceManager::new(
        Ipv4Addr::new(10, 0, 0, 1), None, Arc::new(NoopResolver), Vec::new(), notified,
    ));
    let (outgoing, mut packets) = mpsc::channel(4);
    let (incoming, received) = mpsc::channel(4);
    let device = VirtualIpDevice::new(outgoing, received, notifier, 1500);
    let polling = tokio::spawn({
        let manager = manager.clone();
        async move { manager.poll_sockets(device).await }
    });

    for port in [5353, 5354] {
        let mut socket = manager.new_udp_socket().await;
        socket.send(UdpPacket {
            data: Bytes::from_static(b"hello"),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: SocketAddr::from(([10, 0, 0, 2], port)).into(),
            inbound_user: None,
        }).await.unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(1), packets.recv())
            .await.unwrap().unwrap();
        let ipv4 = Ipv4Packet::new_checked(packet.as_ref()).unwrap();
        assert_eq!(ipv4.src_addr(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ipv4.dst_addr(), Ipv4Addr::new(10, 0, 0, 2));
        let header_len = ipv4.header_len() as usize;
        let udp = WireUdpPacket::new_checked(ipv4.payload()).unwrap();
        let local_port = udp.src_port();
        assert_eq!(udp.dst_port(), port);
        assert_eq!(udp.payload(), b"hello");

        let mut reply = packet.to_vec();
        {
            let mut ipv4 = Ipv4Packet::new_unchecked(&mut reply[..]);
            ipv4.set_src_addr(Ipv4Addr::new(10, 0, 0, 2));
            ipv4.set_dst_addr(Ipv4Addr::new(10, 0, 0, 1));
            ipv4.fill_checksum();
        }
        {
            let mut udp = WireUdpPacket::new_unchecked(&mut reply[header_len..]);
            udp.set_src_port(port);
            udp.set_dst_port(local_port);
            udp.payload_mut().copy_from_slice(b"world");
        }
        incoming.send((PortProtocol::Udp, Bytes::from(reply))).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(1), socket.next())
            .await.unwrap().unwrap();
        assert_eq!(reply.data.as_ref(), b"world");
        assert_eq!(reply.src_addr, SocketAddr::from(([10, 0, 0, 2], port)).into());
    }
    assert!(manager.receivers.lock().is_none());
    polling.abort();
    let _ = polling.await;
    drop(incoming);
}

#[tokio::test]
async fn upstream_tcp_socket_completes_handshake_and_bidirectional_transfer() {
    use smoltcp::{phy::ChecksumCapabilities, wire::{IpAddress, IpProtocol, Ipv4Repr,
        TcpControl, TcpPacket, TcpRepr, TcpSeqNumber}};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (notifier, notified) = mpsc::channel(4);
    let manager = Arc::new(DeviceManager::new(
        Ipv4Addr::new(10, 0, 0, 1), None, Arc::new(NoopResolver), Vec::new(), notified,
    ));
    let (outgoing, mut packets) = mpsc::channel(8);
    let (incoming, received) = mpsc::channel(8);
    let device = VirtualIpDevice::new(outgoing, received, notifier, 1500);
    let polling = tokio::spawn({
        let manager = manager.clone();
        async move { manager.poll_sockets(device).await }
    });
    let mut stream = manager.new_tcp_socket(SocketAddr::from(([10, 0, 0, 2], 443))).await;
    let syn = tokio::time::timeout(Duration::from_secs(1), packets.recv()).await.unwrap().unwrap();
    let ip = Ipv4Packet::new_checked(&syn[..]).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.syn());
    let local_port = tcp.src_port();
    let client_sequence = tcp.seq_number() + 1;
    let reply = |control, sequence, ack, payload: &[u8]| {
        let tcp = TcpRepr {
            src_port: 443, dst_port: local_port, control, seq_number: sequence,
            ack_number: Some(ack), window_len: 65535, window_scale: None,
            max_seg_size: if control == TcpControl::Syn { Some(1460) } else { None },
            sack_permitted: false, sack_ranges: [None; 3], timestamp: None, payload,
        };
        let ip = Ipv4Repr {
            src_addr: Ipv4Addr::new(10, 0, 0, 2), dst_addr: Ipv4Addr::new(10, 0, 0, 1),
            next_header: IpProtocol::Tcp, payload_len: tcp.buffer_len(), hop_limit: 64,
        };
        let checksums = ChecksumCapabilities::default();
        let mut bytes = vec![0; 20 + tcp.buffer_len()];
        ip.emit(&mut Ipv4Packet::new_unchecked(&mut bytes[..20]), &checksums);
        tcp.emit(&mut TcpPacket::new_unchecked(&mut bytes[20..]),
            &IpAddress::from(ip.src_addr), &IpAddress::from(ip.dst_addr), &checksums);
        Bytes::from(bytes)
    };
    incoming.send((PortProtocol::Tcp,
        reply(TcpControl::Syn, TcpSeqNumber(900), client_sequence, &[]))).await.unwrap();
    stream.write_all(b"hello").await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let packet = packets.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            assert!(tcp.verify_checksum(&IpAddress::from(ip.src_addr()), &IpAddress::from(ip.dst_addr())));
            if !tcp.payload().is_empty() {
                assert_eq!(tcp.payload(), b"hello");
                assert_eq!(tcp.seq_number(), client_sequence);
                break;
            }
        }
    }).await.unwrap();
    incoming.send((PortProtocol::Tcp,
        reply(TcpControl::Psh, TcpSeqNumber(901), client_sequence + 5, b"world"))).await.unwrap();
    let mut bytes = [0; 5];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut bytes)).await.unwrap().unwrap();
    assert_eq!(&bytes, b"world");
    polling.abort();
    let _ = polling.await;
}
