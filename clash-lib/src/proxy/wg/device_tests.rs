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
