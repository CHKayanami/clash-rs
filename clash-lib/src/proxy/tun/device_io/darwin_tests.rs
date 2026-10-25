use std::{os::{fd::IntoRawFd, unix::net::UnixDatagram}, time::Duration};
use tokio::{net::UnixDatagram as AsyncDatagram, time::timeout};
use tokio::net::UdpSocket;
use tun_rs::DeviceBuilder;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv6Packet, UdpPacket as WireUdp};
use std::net::{Ipv6Addr, SocketAddr};
use uuid::Uuid;

use super::*;

fn device(socket: UnixDatagram) -> AsyncDevice {
    // SAFETY: one live FD transfers ownership exactly once. Tests exercise only
    // the socket's datagram I/O, never utun-specific control operations.
    unsafe { AsyncDevice::from_fd(socket.into_raw_fd()) }.unwrap()
}

#[tokio::test]
async fn tiny_packets_do_not_retain_large_receive_allocations() {
    let (peer, socket) = UnixDatagram::pair().unwrap();
    let device = device(socket);
    let mut reader = Reader::new(&device, 65535).unwrap();
    let scratch: Vec<_> = reader.buffers.iter().map(|buffer| buffer.as_ptr()).collect();
    let payload = [0x45; 40];
    let frame = [&(libc::AF_INET as u32).to_be_bytes()[..], &payload].concat();
    let mut retained = Vec::new();
    for _ in 0..8 {
        for _ in 0..4 { peer.send(&frame).unwrap(); }
        let mut batch = Vec::new();
        assert_eq!(timeout(Duration::from_secs(1), reader.recv(&mut batch)).await.unwrap().unwrap(), 4);
        retained.extend(batch);
    }
    assert_eq!(retained.len(), 32);
    assert!(retained.iter().all(|packet| packet.capacity() == payload.len()));
    for (buffer, pointer) in reader.buffers.iter().zip(scratch) {
        assert_eq!(buffer.as_ptr(), pointer, "small receives should reuse their scratch slot");
    }
    drop(reader);
    assert!(retained.iter().all(|packet| &packet[..] == &payload[..]));
}

#[tokio::test]
async fn large_packets_take_exclusive_ownership_without_a_payload_copy() {
    let (peer, socket) = UnixDatagram::pair().unwrap();
    let device = device(socket);
    let mut reader = Reader::new(&device, 1500).unwrap();
    let original = reader.buffers[0].as_ptr();
    let payload = [0x45; 1400];
    let frame = [&(libc::AF_INET as u32).to_be_bytes()[..], &payload].concat();
    peer.send(&frame).unwrap();
    let mut retained = Vec::new();
    assert_eq!(reader.recv(&mut retained).await.unwrap(), 1);
    assert_eq!(retained[0].as_ptr(), original);
    assert!(retained[0].capacity() <= 2 * retained[0].len());
    assert_eq!(reader.buffers[0].capacity(), 0);
    peer.send(&frame).unwrap();
    let mut next = Vec::new();
    assert_eq!(reader.recv(&mut next).await.unwrap(), 1);
    assert_ne!(next[0].as_ptr(), original);
    assert_eq!(&retained[0][..], &payload);
}

#[tokio::test]
async fn native_receive_preserves_ipv4_ipv6_boundaries_and_discards_truncation() {
    let (peer, socket) = UnixDatagram::pair().unwrap();
    let device = device(socket);
    let mut reader = Reader::new(&device, 1500).unwrap();
    for (family, payload) in [(libc::AF_INET, b"ipv4".as_slice()),
        (libc::AF_INET6, b"ipv6".as_slice())] {
        let mut frame = (family as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(payload);
        peer.send(&frame).unwrap();
    }
    let mut packets = Vec::new();
    assert_eq!(timeout(Duration::from_secs(1), reader.recv(&mut packets)).await.unwrap().unwrap(), 2);
    assert_eq!(&packets[0][..], b"ipv4");
    assert_eq!(&packets[1][..], b"ipv6");
    packets.clear();
    let mut oversized = (libc::AF_INET as u32).to_be_bytes().to_vec();
    oversized.resize(1600, 1);
    peer.send(&oversized).unwrap();
    let mut valid = (libc::AF_INET6 as u32).to_be_bytes().to_vec();
    valid.extend_from_slice(b"next");
    peer.send(&valid).unwrap();
    assert_eq!(timeout(Duration::from_secs(1), reader.recv(&mut packets)).await.unwrap().unwrap(), 1);
    assert_eq!(&packets[0][..], b"next");
}

#[tokio::test]
async fn native_send_delivers_each_datagram_once_under_backpressure() {
    let (socket, peer) = UnixDatagram::pair().unwrap();
    SockRef::from(&socket).set_send_buffer_size(4096).unwrap();
    peer.set_nonblocking(true).unwrap();
    let peer = AsyncDatagram::from_std(peer).unwrap();
    let device = device(socket);
    let mut writer = Reader::new(&device, 1500).unwrap().writer().unwrap();
    let packets: Vec<_> = (0..DEVICE_BATCH).map(|index| {
        let mut bytes = vec![index as u8; 1024];
        bytes[0] = if index % 2 == 0 { 0x45 } else { 0x60 };
        Bytes::from(bytes)
    }).collect();
    let receive = async {
        let mut buffer = vec![0; 2048];
        for packet in &packets {
            let size = peer.recv(&mut buffer).await.unwrap();
            assert_eq!(size, packet.len() + FAMILY_SIZE);
            let family = if packet[0] >> 4 == 4 { libc::AF_INET } else { libc::AF_INET6 };
            assert_eq!(&buffer[..FAMILY_SIZE], &(family as u32).to_be_bytes());
            assert_eq!(&buffer[FAMILY_SIZE..size], &packet[..]);
        }
    };
    timeout(Duration::from_secs(5), async {
        tokio::try_join!(writer.send(&packets), async {
            receive.await;
            Ok::<(), io::Error>(())
        }).unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn shared_registration_handles_simultaneous_read_and_write() {
    let (socket, peer) = UnixDatagram::pair().unwrap();
    peer.set_nonblocking(true).unwrap();
    let peer = AsyncDatagram::from_std(peer).unwrap();
    let device = device(socket);
    let mut reader = Reader::new(&device, 1500).unwrap();
    let mut writer = reader.writer().unwrap();
    let payload = Bytes::from_static(b"\x45duplex");
    let outgoing = [payload.clone()];
    let frame = [&(libc::AF_INET as u32).to_be_bytes()[..], &payload[..]].concat();
    let mut packets = Vec::new();
    timeout(Duration::from_secs(2), async {
        tokio::try_join!(
            reader.recv(&mut packets),
            writer.send(&outgoing),
            async {
                peer.send(&frame).await?;
                let mut buffer = [0; 64];
                let size = peer.recv(&mut buffer).await?;
                assert_eq!(&buffer[..size], &frame);
                Ok::<(), io::Error>(())
            },
        ).unwrap();
    }).await.unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(&packets[0][..], &payload[..]);
}

#[tokio::test]
#[ignore = "requires privileges; creates a temporary utun with a unique IPv6 /126 and no default routes"]
async fn native_utun_udp_roundtrip() {
    let mut address = *Uuid::new_v4().as_bytes();
    address[0] = 0xfd;
    address[12..].copy_from_slice(&[0, 0, 0, 1]);
    let local = Ipv6Addr::from(address);
    address[15] = 2;
    let peer = Ipv6Addr::from(address);
    let device = DeviceBuilder::new().ipv6(local, 126).mtu(1500).build_async().unwrap();
    let client = timeout(Duration::from_secs(3), async {
        loop {
            match UdpSocket::bind((local, 0)).await {
                Ok(socket) => break socket,
                Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("bind temporary utun client: {error}"),
            }
        }
    }).await.unwrap();
    let port = client.local_addr().unwrap().port();
    for index in 0..8u8 {
        client.send_to(&[index; 32], SocketAddr::from((peer, 5555))).await.unwrap();
    }
    let mut reader = Reader::new(&device, 1500).unwrap();
    let mut packets = Vec::new();
    let mut replies = Vec::new();
    timeout(Duration::from_secs(5), async {
        while replies.len() < 8 {
            reader.recv(&mut packets).await.unwrap();
            for packet in packets.drain(..) {
                let ip = Ipv6Packet::new_checked(&packet[..]).unwrap();
                if ip.next_header() != IpProtocol::Udp { continue; }
                let udp = WireUdp::new_checked(ip.payload()).unwrap();
                if udp.src_port() != port || udp.dst_port() != 5555 { continue; }
                assert!(udp.verify_checksum(&IpAddress::from(local), &IpAddress::from(peer)));
                let mut reply = vec![0; 40 + 8 + udp.payload().len()];
                reply[0] = 0x60;
                reply[4..6].copy_from_slice(&((8 + udp.payload().len()) as u16).to_be_bytes());
                reply[6] = 17;
                reply[7] = 64;
                reply[8..24].copy_from_slice(&peer.octets());
                reply[24..40].copy_from_slice(&local.octets());
                let mut outgoing = WireUdp::new_unchecked(&mut reply[40..]);
                outgoing.set_src_port(5555);
                outgoing.set_dst_port(port);
                outgoing.set_len((8 + udp.payload().len()) as u16);
                outgoing.payload_mut().copy_from_slice(udp.payload());
                outgoing.fill_checksum(&IpAddress::from(peer), &IpAddress::from(local));
                replies.push(Bytes::from(reply));
            }
        }
    }).await.unwrap();
    reader.writer().unwrap().send(&replies).await.unwrap();
    for index in 0..8u8 {
        let mut bytes = [0; 64];
        let (size, source) = timeout(Duration::from_secs(2), client.recv_from(&mut bytes))
            .await.unwrap().unwrap();
        assert_eq!(source, SocketAddr::from((peer, 5555)));
        assert_eq!(&bytes[..size], &[index; 32]);
    }
}
