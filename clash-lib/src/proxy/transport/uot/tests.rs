use super::*;
use super::super::codec::MAX_PACKET_LENGTH;
use bytes::BufMut;
use futures::{SinkExt, StreamExt};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

fn make_target_addr() -> SocksAddr {
    SocksAddr::try_from(("127.0.0.1".to_owned(), 9999u16)).unwrap()
}

fn make_packet(data: Vec<u8>) -> UdpPacket {
    let addr = make_target_addr();
    UdpPacket {
        data: Bytes::from(data),
        src_addr: addr.clone(),
        dst_addr: addr,
        inbound_user: None,
    }
}

fn encode_wire(payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + payload.len());
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

// ── Read path ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_read_normal_packet() {
    let (mut client_side, server_side) = duplex(4096);
    let target_addr = make_target_addr();
    let mut datagram = OutboundDatagramUotV2::new(
        AnyStream::new(server_side),
        target_addr.clone(),
    );

    client_side.write_all(&encode_wire(b"hello")).await.unwrap();
    drop(client_side);

    let pkt = datagram.next().await.expect("expected one packet");
    assert_eq!(pkt.data.as_ref(), b"hello");
    assert_eq!(pkt.src_addr, target_addr);
    assert_eq!(pkt.dst_addr, target_addr);
    assert!(pkt.inbound_user.is_none());

    assert!(datagram.next().await.is_none(), "expected EOF");
}

#[tokio::test]
async fn test_read_zero_length_packet() {
    let (mut client_side, server_side) = duplex(4096);
    let target_addr = make_target_addr();
    let mut datagram =
        OutboundDatagramUotV2::new(AnyStream::new(server_side), target_addr);

    client_side.write_all(&[0x00, 0x00]).await.unwrap();
    drop(client_side);

    let pkt = datagram
        .next()
        .await
        .expect("zero-length packet must not be None");
    assert!(pkt.data.is_empty());
}

#[tokio::test]
async fn test_read_multiple_consecutive_packets() {
    let (mut client_side, server_side) = duplex(4096);
    let target_addr = make_target_addr();
    let mut datagram =
        OutboundDatagramUotV2::new(AnyStream::new(server_side), target_addr);

    let mut wire = encode_wire(b"first");
    wire.extend(encode_wire(b"second"));
    wire.extend(encode_wire(b"third"));
    client_side.write_all(&wire).await.unwrap();
    drop(client_side);

    let pkt1 = datagram.next().await.expect("expected first packet");
    assert_eq!(pkt1.data.as_ref(), b"first");

    let pkt2 = datagram.next().await.expect("expected second packet");
    assert_eq!(pkt2.data.as_ref(), b"second");

    let pkt3 = datagram.next().await.expect("expected third packet");
    assert_eq!(pkt3.data.as_ref(), b"third");

    assert!(datagram.next().await.is_none());
}

#[tokio::test]
async fn test_read_eof_returns_none() {
    let (client_side, server_side) = duplex(4096);
    let mut datagram = OutboundDatagramUotV2::new(
        AnyStream::new(server_side),
        make_target_addr(),
    );

    drop(client_side);
    assert!(datagram.next().await.is_none());
}

// ── Write path (Sink) ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_write_normal_packet() {
    let (mut client_side, server_side) = duplex(4096);
    let target_addr = make_target_addr();
    let mut datagram = OutboundDatagramUotV2::new(
        AnyStream::new(server_side),
        target_addr.clone(),
    );

    datagram.send(make_packet(b"hello".to_vec())).await.unwrap();

    let mut buf = vec![0u8; 7];
    client_side.read_exact(&mut buf).await.unwrap();

    assert_eq!(&buf[..2], &[0x00, 0x05]);
    assert_eq!(&buf[2..], b"hello");
}

#[tokio::test]
async fn test_write_empty_packet() {
    let (mut client_side, server_side) = duplex(4096);
    let target_addr = make_target_addr();
    let mut datagram =
        OutboundDatagramUotV2::new(AnyStream::new(server_side), target_addr);

    datagram.send(make_packet(vec![])).await.unwrap();

    let mut buf = vec![0u8; 2];
    client_side.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, &[0x00, 0x00]);
}

#[tokio::test]
async fn test_write_oversized_packet_returns_error() {
    let (_client_side, server_side) = duplex(4096);
    let target_addr = make_target_addr();
    let mut datagram =
        OutboundDatagramUotV2::new(AnyStream::new(server_side), target_addr);

    let oversized = vec![0u8; MAX_PACKET_LENGTH + 1];
    let result = datagram.send(make_packet(oversized)).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn test_write_then_read_wire_bytes() {
    let (mut client_side, server_side) = duplex(4096);
    let target_addr = make_target_addr();
    let mut datagram =
        OutboundDatagramUotV2::new(AnyStream::new(server_side), target_addr);

    let payload = b"round-trip-uot";
    datagram.send(make_packet(payload.to_vec())).await.unwrap();

    let expected_len = payload.len();
    let mut buf = vec![0u8; 2 + expected_len];
    client_side.read_exact(&mut buf).await.unwrap();

    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    assert_eq!(len, expected_len);
    assert_eq!(&buf[2..], payload);
}
#[tokio::test]
async fn packet_mode_wire_addresses_and_fragmented_frames() {
    let addresses = [
        ("192.0.2.1", 7u16, 0u8),
        ("2001:db8::1", 53, 1),
        ("example.com", 443, 2),
    ];
    for (host, port, atyp) in addresses {
        let addr = SocksAddr::try_from((host.to_owned(), port)).unwrap();
        let (mut wire, stream) = duplex(512);
        let mut datagram = OutboundDatagramUotV2::packet_mode(AnyStream::new(stream));
        let mut packet = make_packet(b"hello".to_vec());
        packet.dst_addr = addr.clone();
        datagram.send(packet).await.unwrap();
        let mut expected = BytesMut::new();
        addr.write_buf(&mut expected);
        expected[0] = atyp;
        expected.put_u16(5);
        expected.extend_from_slice(b"hello");
        let mut actual = vec![0; expected.len()];
        wire.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
        let writer = tokio::spawn(async move {
            for byte in actual {
                wire.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let packet = datagram.next().await.unwrap();
        assert_eq!(packet.src_addr, addr);
        assert_eq!(&packet.data[..], b"hello");
        writer.await.unwrap();
        assert!(datagram.next().await.is_none());
    }
}

#[tokio::test]
async fn connect_rejects_changed_destination_without_writing() {
    let (wire, stream) = duplex(32);
    let mut datagram = OutboundDatagramUotV2::new(AnyStream::new(stream), make_target_addr());
    let mut packet = make_packet(vec![1]);
    packet.dst_addr = SocksAddr::any_ipv4();
    assert_eq!(datagram.send(packet).await.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    drop(wire);
}

#[tokio::test]
async fn packet_mode_max_payload_survives_backpressure() {
    let (mut wire, stream) = duplex(1);
    let mut datagram = OutboundDatagramUotV2::packet_mode(AnyStream::new(stream));
    let packet = make_packet(vec![42; MAX_PACKET_LENGTH]);
    let expected_addr = packet.dst_addr.clone();
    let reader = tokio::spawn(async move {
        let mut header = [0u8; 9];
        wire.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0);
        header[0] = 1;
        assert_eq!(SocksAddr::try_from(&header[..7]).unwrap(), expected_addr);
        assert_eq!(&header[7..], &[255, 255]);
        let mut data = vec![0; MAX_PACKET_LENGTH];
        wire.read_exact(&mut data).await.unwrap();
        assert!(data.iter().all(|byte| *byte == 42));
    });
    datagram.send(packet).await.unwrap();
    reader.await.unwrap();
}

#[tokio::test]
async fn malformed_packet_mode_frames_are_terminal() {
    for wire in [vec![3], vec![2, 0], vec![0, 127],
        vec![2, 1, 255, 0, 53, 0, 0], vec![0, 127, 0, 0, 1, 0, 53, 0, 2, 1]] {
        let (mut client, stream) = duplex(32);
        let mut datagram = OutboundDatagramUotV2::packet_mode(AnyStream::new(stream));
        client.write_all(&wire).await.unwrap();
        drop(client);
        assert!(datagram.next().await.is_none());
        assert!(datagram.next().await.is_none());
    }
}

#[tokio::test]
async fn maximum_frame_after_small_packet_preserves_retained_payloads() {
    let (mut wire, stream) = duplex(131072);
    let mut datagram = OutboundDatagramUotV2::packet_mode(AnyStream::new(stream));
    assert_eq!(datagram.read_buf.capacity(), 0);
    let address = make_target_addr();
    let mut encoded = BytesMut::new();
    for size in [300, MAX_PACKET_LENGTH, 20] {
        let mut header = BytesMut::new();
        encode_header(&mut header, &address, size, true).unwrap();
        encoded.extend_from_slice(&header);
        encoded.resize(encoded.len() + size, size as u8);
    }
    wire.write_all(&encoded).await.unwrap();
    drop(wire);
    let first = datagram.next().await.unwrap();
    assert!(datagram.read_buf.capacity() <= INITIAL_BUFFER_SIZE);
    let maximum = datagram.next().await.unwrap();
    let last = datagram.next().await.unwrap();
    // Returned storage must survive subsequent reads and buffer growth.
    assert_eq!(first.data, vec![300usize as u8; 300]);
    assert_eq!(maximum.data, vec![255; MAX_PACKET_LENGTH]);
    assert_eq!(last.data, vec![20; 20]);
    assert!(datagram.read_buf.capacity() <= INITIAL_BUFFER_SIZE);
    assert!(datagram.next().await.is_none());
    assert!(datagram.read_error.get().is_none());
}

#[tokio::test]
async fn malformed_address_is_rejected_before_its_payload_arrives() {
    let (mut wire, stream) = duplex(32);
    let mut datagram = OutboundDatagramUotV2::packet_mode(AnyStream::new(stream));
    // Invalid UTF-8 in the domain with a maximum payload advertised but unsent.
    wire.write_all(&[2, 1, 255, 0, 53, 255, 255]).await.unwrap();
    assert!(datagram.next().await.is_none());
    assert_eq!(datagram.read_error.get().unwrap().kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn truncated_payload_keeps_error_after_stream_is_dropped() {
    let (mut wire, stream) = duplex(32);
    let mut datagram = OutboundDatagramUotV2::new(AnyStream::new(stream), make_target_addr());
    let error = datagram.read_error_handle();
    wire.write_all(&[0, 2, 1]).await.unwrap();
    drop(wire);
    assert!(datagram.next().await.is_none());
    assert!(datagram.next().await.is_none());
    drop(datagram);
    assert_eq!(error.get().unwrap().kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn batch_packet_mode_preserves_boundaries_after_partial_writes() {
    use futures::future::poll_fn;
    let (writer, reader) = duplex(3);
    let mut sender = OutboundDatagramUotV2::packet_mode(AnyStream::new(writer));
    let mut receiver = OutboundDatagramUotV2::packet_mode(AnyStream::new(reader));
    let mut batch = PacketBatch::default();
    for payload in [b"one".as_slice(), b"", b"three"] {
        batch.push(make_packet(payload.to_vec())).unwrap();
    }
    let send = poll_fn(|cx| sender.poll_send_batch(cx, &mut batch));
    let receive = async {
        for payload in [b"one".as_slice(), b"", b"three"] {
            let packet = receiver.next().await.unwrap();
            assert_eq!(packet.data.as_ref(), payload);
            assert_eq!(packet.src_addr, make_target_addr());
        }
    };
    let (result, ()) = tokio::join!(send, receive);
    assert_eq!(result.sent, 3);
    assert!(result.error.is_none());
}

async fn tcp_packets_roundtrip(batched: bool) {
    use futures::future::poll_fn;
    use tokio::{net::{TcpListener, TcpStream}, time::{timeout, Duration}};
    timeout(Duration::from_secs(3), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        client.set_nodelay(true).unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut sender = OutboundDatagramUotV2::new(AnyStream::new(client), make_target_addr());
        let mut receiver = OutboundDatagramUotV2::new(AnyStream::new(server), make_target_addr());
        if batched {
            let mut batch = PacketBatch::default();
            for _ in 0..16 { batch.push(make_packet(b"query".to_vec())).unwrap(); }
            let result = poll_fn(|cx| sender.poll_send_batch(cx, &mut batch)).await;
            assert_eq!(result.sent, 16);
            assert!(result.error.is_none());
        } else {
            for _ in 0..16 { sender.send(make_packet(b"query".to_vec())).await.unwrap(); }
        }
        for _ in 0..16 { assert_eq!(receiver.next().await.unwrap().data, b"query"[..]); }
    }).await.unwrap();
}

#[tokio::test]
async fn tcp_batch_roundtrip() { tcp_packets_roundtrip(true).await; }

#[tokio::test]
async fn tcp_single_roundtrip() { tcp_packets_roundtrip(false).await; }
