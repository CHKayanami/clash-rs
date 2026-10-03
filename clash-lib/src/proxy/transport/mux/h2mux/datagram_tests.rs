use std::{io, sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};

use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt, future::poll_fn};
use h2::{SendStream, server::Builder};
use http::Response;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::Mutex, time::timeout};
use tokio_util::codec::{Decoder, Encoder};

use super::{H2MuxDatagram, PacketCodec};
use crate::{
    proxy::{AnyStream, datagram::UdpPacket, transport::mux::MuxOption},
    session::SocksAddr,
};
use super::super::{padding::PaddingStream, pool::H2MuxPool};

fn packet(addr: &str, data: &[u8]) -> UdpPacket {
    UdpPacket::new(Bytes::copy_from_slice(data), SocksAddr::any_ipv4(),
        SocksAddr::try_from((addr, 53)).unwrap())
}

#[test]
fn packet_wire_handles_fragmentation_and_multiple_addresses() {
    // Independently specified sing-mux packet-address frames.
    let wire = [
        1, 1, 2, 3, 4, 0, 53, 0, 2, b'a', b'b',
        3, 3, b'd', b'n', b's', 0, 53, 0, 0,
        4, 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 53, 0, 1, b'c',
    ];
    let expected = [packet("1.2.3.4", b"ab"), packet("dns", b""),
        packet("2001:db8::1", b"c")];
    let mut codec = PacketCodec;
    let mut encoded = BytesMut::new();
    for packet in &expected { codec.encode(packet.clone(), &mut encoded).unwrap(); }
    assert_eq!(&encoded[..], wire);
    let mut buf = BytesMut::new();
    let mut decoded = Vec::new();
    for byte in wire {
        buf.extend_from_slice(&[byte]);
        if let Some(packet) = codec.decode(&mut buf).unwrap() { decoded.push(packet); }
    }
    assert!(buf.is_empty());
    for (actual, expected) in decoded.iter().zip(&expected) {
        assert_eq!(actual.data, expected.data);
        assert_eq!(actual.src_addr, expected.dst_addr);
    }
    assert_eq!(decoded.len(), expected.len());
    let mut buf = BytesMut::from(&wire[..]);
    for _ in &expected { assert!(codec.decode(&mut buf).unwrap().is_some()); }
    assert!(codec.decode(&mut buf).unwrap().is_none());
}

#[test]
fn packet_limits_and_truncated_frames_are_checked() {
    let mut codec = PacketCodec;
    let mut buf = BytesMut::new();
    let mut max_packet = packet("1.2.3.4", b"");
    max_packet.data = Bytes::from(vec![42; u16::MAX as usize]);
    codec.encode(max_packet.clone(), &mut buf).unwrap();
    assert_eq!(codec.decode(&mut buf).unwrap().unwrap().data, max_packet.data);
    max_packet.data = Bytes::from(vec![42; u16::MAX as usize + 1]);
    assert_eq!(codec.encode(max_packet, &mut buf).unwrap_err().kind(),
        io::ErrorKind::InvalidInput);
    for domain in ["".to_owned(), "x".repeat(256)] {
        let bad = UdpPacket::new(Bytes::new(), SocksAddr::any_ipv4(),
            SocksAddr::Domain(domain.into(), 53));
        assert_eq!(codec.encode(bad, &mut buf).unwrap_err().kind(),
            io::ErrorKind::InvalidInput);
        assert!(buf.is_empty());
    }
    for wire in [&[2][..], &[3, 0, 0, 53, 0, 0], &[3, 1, 0xff, 0, 53, 0, 0]] {
        assert_eq!(codec.decode(&mut BytesMut::from(wire)).unwrap_err().kind(),
            io::ErrorKind::InvalidData);
    }
    let wire = [3, 3, b'd', b'n', b's', 0, 53, 0, 2, b'a', b'b'];
    for len in 1..wire.len() {
        assert_eq!(codec.decode_eof(&mut BytesMut::from(&wire[..len]))
            .unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }
}

#[tokio::test]
async fn packet_sink_preserves_partial_writes_and_close() {
    timeout(Duration::from_secs(5), async {
        let (client, mut peer) = tokio::io::duplex(1);
        let mut datagram = H2MuxDatagram::new(AnyStream::new(client));
        let reader = tokio::spawn(async move {
            let mut wire = Vec::new();
            peer.read_to_end(&mut wire).await.unwrap();
            wire
        });
        datagram.send(packet("1.2.3.4", b"ab")).await.unwrap();
        datagram.send(packet("dns", b"")).await.unwrap();
        datagram.close().await.unwrap();
        assert_eq!(reader.await.unwrap(), [1, 1, 2, 3, 4, 0, 53, 0, 2,
            b'a', b'b', 3, 3, b'd', b'n', b's', 0, 53, 0, 0]);
    }).await.unwrap();
}

#[tokio::test]
async fn packet_decode_error_terminates_read() {
    let (client, mut peer) = tokio::io::duplex(64);
    let mut datagram = H2MuxDatagram::new(AnyStream::new(client));
    peer.write_all(&[2]).await.unwrap();
    assert!(datagram.next().await.is_none());
    assert!(datagram.next().await.is_none());
}

#[tokio::test]
async fn large_packets_grow_buffers_without_losing_payload() {
    timeout(Duration::from_secs(5), async {
        let (client, mut peer) = tokio::io::duplex(512);
        let mut datagram = H2MuxDatagram::new(AnyStream::new(client));
        let payload = vec![42; u16::MAX as usize];
        let mut wire = vec![1, 1, 2, 3, 4, 0, 53, 0xff, 0xff];
        wire.extend_from_slice(&payload);
        let server = tokio::spawn(async move {
            let mut received = vec![0; wire.len()];
            peer.read_exact(&mut received).await.unwrap();
            assert_eq!(received, wire);
            peer.write_all(&wire).await.unwrap();
            peer.shutdown().await.unwrap();
        });
        datagram.send(packet("1.2.3.4", &payload)).await.unwrap();
        let response = datagram.next().await.unwrap();
        assert_eq!(&response.data[..], payload);
        assert_eq!(response.src_addr, SocksAddr::try_from(("1.2.3.4", 53)).unwrap());
        assert!(datagram.next().await.is_none());
        server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn tcp_and_udp_share_carrier_with_and_without_padding() {
    for padding in [false, true] {
        timeout(Duration::from_secs(5), check_carrier(padding)).await.unwrap();
    }
}

async fn send_bytes(send: &mut SendStream<Bytes>, mut bytes: Bytes) {
    while !bytes.is_empty() {
        send.reserve_capacity(bytes.len());
        let capacity = poll_fn(|cx| send.poll_capacity(cx)).await.unwrap().unwrap();
        let n = capacity.min(bytes.len());
        if n > 0 { send.send_data(bytes.split_to(n), false).unwrap(); }
    }
}

async fn check_carrier(padding: bool) {
    let (client, mut peer) = tokio::io::duplex(128);
    let server = tokio::spawn(async move {
        assert_eq!(peer.read_u8().await.unwrap(), u8::from(padding));
        assert_eq!(peer.read_u8().await.unwrap(), 2);
        if padding {
            assert_eq!(peer.read_u8().await.unwrap(), 1);
            let n = peer.read_u16().await.unwrap();
            peer.read_exact(&mut vec![0; usize::from(n)]).await.unwrap();
        }
        let mut peer = AnyStream::new(peer);
        if padding { peer = AnyStream::new(PaddingStream::new(peer)); }
        let mut builder = Builder::new();
        builder.initial_window_size(3);
        let mut conn = builder.handshake::<_, Bytes>(peer).await.unwrap();
        let mut tasks = Vec::new();
        let mut flags = Vec::new();
        while let Some(request) = conn.accept().await {
            let (req, mut respond) = request.unwrap();
            tasks.push(tokio::spawn(async move {
                let mut recv = req.into_body();
                let response = Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                send_bytes(&mut send, Bytes::from_static(&[0])).await;
                let mut prefix = BytesMut::new();
                let mut flag = None;
                while let Some(chunk) = recv.data().await {
                    let chunk = chunk.unwrap();
                    recv.flow_control().release_capacity(chunk.len()).unwrap();
                    if flag.is_none() {
                        prefix.extend_from_slice(&chunk);
                        if prefix.len() < 9 { continue; }
                        flag = Some(u16::from_be_bytes([prefix[0], prefix[1]]));
                        assert_eq!(&prefix[2..9], &[1, 127, 0, 0, 1, 0, 53]);
                        let payload = prefix.split_off(9).freeze();
                        send_bytes(&mut send, payload).await;
                    } else {
                        send_bytes(&mut send, chunk).await;
                    }
                }
                send.send_data(Bytes::new(), true).unwrap();
                flag.unwrap()
            }));
        }
        for task in tasks { flags.push(task.await.unwrap()); }
        flags.sort_unstable();
        assert_eq!(flags, [0, 3]);
    });
    let pool = H2MuxPool::new(MuxOption { enable: true, padding,
        max_connections: 1, ..Default::default() });
    let carrier = Arc::new(Mutex::new(Some(AnyStream::new(client))));
    let count = Arc::new(AtomicUsize::new(0));
    let dial = || async {
        count.fetch_add(1, Ordering::Relaxed);
        Ok(carrier.lock().await.take().expect("only one carrier"))
    };
    let target = SocksAddr::try_from(("127.0.0.1", 53)).unwrap();
    let mut tcp = pool.open_stream(&target, false, &dial).await.unwrap();
    let mut udp = pool.open_datagram(&target, &dial).await.unwrap();
    tcp.write_all(b"tcp").await.unwrap();
    let mut reply = [0; 3];
    tcp.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"tcp");
    for packet in [packet("1.2.3.4", b"udp"), packet("dns", b""),
        packet("2001:db8::1", b"ipv6")] {
        udp.send(packet.clone()).await.unwrap();
        let response = udp.next().await.unwrap();
        assert_eq!(response.data, packet.data);
        assert_eq!(response.src_addr, packet.dst_addr);
    }
    udp.close().await.unwrap();
    tcp.shutdown().await.unwrap();
    assert!(udp.next().await.is_none());
    assert_eq!(tcp.read(&mut reply).await.unwrap(), 0);
    assert_eq!(count.load(Ordering::Relaxed), 1);
    drop((tcp, udp, pool));
    server.await.unwrap();
}

#[tokio::test]
async fn only_tcp_rejects_udp_before_dial() {
    let pool = H2MuxPool::new(MuxOption { only_tcp: true, ..Default::default() });
    assert!(!pool.supports_udp());
    let err = pool.open_datagram(&SocksAddr::any_ipv4(), || async {
        panic!("UDP must not dial when only-tcp is enabled")
    }).await.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    let config: MuxOption = yaml_serde::from_str("enabled: true\nonly-tcp: true").unwrap();
    assert!(config.only_tcp);
    assert!(!MuxOption::default().only_tcp);
}
