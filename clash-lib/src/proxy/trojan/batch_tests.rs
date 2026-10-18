use super::*;
use bytes::Bytes;
use futures::{StreamExt, future::poll_fn, task::noop_waker_ref};
use tokio::{io::{AsyncReadExt, duplex}, time::{Duration, timeout}};

fn packet(host: &str, data: &'static [u8]) -> UdpPacket {
    UdpPacket::new(Bytes::from_static(data), SocksAddr::any_ipv4(),
        SocksAddr::try_from((host, 53)).unwrap())
}

#[tokio::test]
async fn batch_preserves_addresses_and_empty_packets_under_backpressure() {
    timeout(Duration::from_secs(3), async {
        let (writer, reader) = duplex(3);
        let mut sender = OutboundDatagramTrojan::new(AnyStream::new(writer));
        let mut receiver = OutboundDatagramTrojan::new(AnyStream::new(reader));
        let expected = [packet("1.1.1.1", b"one"), packet("example.org", b""),
            packet("::1", b"three")];
        let mut batch = PacketBatch::default();
        for packet in &expected { batch.push(packet.clone()).unwrap(); }
        let send = poll_fn(|cx| sender.poll_send_batch(cx, &mut batch));
        let receive = async {
            for expected in &expected {
                let received = receiver.next().await.unwrap();
                assert_eq!(received.data, expected.data);
                assert_eq!(received.src_addr, expected.dst_addr);
            }
        };
        let (result, ()) = tokio::join!(send, receive);
        assert_eq!(result.sent, 3);
        assert!(result.error.is_none());
    }).await.unwrap();
}

#[tokio::test]
async fn invalid_packet_commits_prefix_and_preserves_suffix() {
    for host in ["".to_owned(), "x".repeat(256)] {
        let (writer, mut reader) = duplex(128);
        let mut sender = OutboundDatagramTrojan::new(AnyStream::new(writer));
        let mut batch = PacketBatch::default();
        batch.push(packet("1.1.1.1", b"one")).unwrap();
        batch.push(UdpPacket { dst_addr: SocksAddr::Domain(host.into(), 53), ..Default::default() }).unwrap();
        batch.push(packet("1.1.1.1", b"end")).unwrap();
        let result = poll_fn(|cx| sender.poll_send_batch(cx, &mut batch)).await;
        assert_eq!(result.sent, 1);
        assert_eq!(result.error.unwrap().kind(), io::ErrorKind::InvalidInput);
        batch.complete();
        batch.complete();
        let result = poll_fn(|cx| sender.poll_send_batch(cx, &mut batch)).await;
        assert_eq!(result.sent, 1);
        assert!(result.error.is_none());
        let mut wire = [0; 28];
        reader.read_exact(&mut wire).await.unwrap();
        assert_eq!(&wire, b"\x01\x01\x01\x01\x01\x00\x35\x00\x03\r\none\x01\x01\x01\x01\x01\x00\x35\x00\x03\r\nend");
    }
}

#[tokio::test]
async fn single_batch_resumes_without_resubmitting_packet() {
    timeout(Duration::from_secs(3), async {
        let (writer, reader) = duplex(1);
        let mut sender = OutboundDatagramTrojan::new(AnyStream::new(writer));
        let mut receiver = OutboundDatagramTrojan::new(AnyStream::new(reader));
        let mut batch = PacketBatch::default();
        batch.push(packet("1.1.1.1", b"one")).unwrap();
        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(sender.poll_send_batch(&mut cx, &mut batch).is_pending());
        assert!(sender.poll_send_batch(&mut cx, &mut batch).is_pending());
        let send = poll_fn(|cx| sender.poll_send_batch(cx, &mut batch));
        let (result, received) = tokio::join!(send, receiver.next());
        assert_eq!(result.sent, 1);
        assert!(result.error.is_none());
        assert_eq!(received.unwrap().data, b"one"[..]);
    }).await.unwrap();
}

#[tokio::test]
async fn oversized_single_batch_is_rejected_before_writing() {
    let (writer, mut reader) = duplex(128);
    let mut sender = OutboundDatagramTrojan::new(AnyStream::new(writer));
    let mut batch = PacketBatch::default();
    let mut oversized = packet("1.1.1.1", b"");
    oversized.data = Bytes::from(vec![0; u16::MAX as usize + 1]);
    batch.push(oversized).unwrap();
    let result = poll_fn(|cx| sender.poll_send_batch(cx, &mut batch)).await;
    assert_eq!(result.sent, 0);
    assert_eq!(result.error.unwrap().kind(), io::ErrorKind::InvalidInput);
    drop(sender);
    let mut wire = Vec::new();
    reader.read_to_end(&mut wire).await.unwrap();
    assert!(wire.is_empty());
}

#[tokio::test]
async fn batch_receive_drains_complete_frames_with_independent_payloads() {
    let (writer, reader) = duplex(1024);
    let mut sender = OutboundDatagramTrojan::new(AnyStream::new(writer));
    let mut receiver = OutboundDatagramTrojan::new(AnyStream::new(reader));
    let expected = [packet("1.1.1.1", b"one"), packet("example.org", b""),
        packet("::1", b"three")];
    let mut batch = PacketBatch::default();
    for packet in &expected { batch.push(packet.clone()).unwrap(); }
    let result = poll_fn(|cx| sender.poll_send_batch(cx, &mut batch)).await;
    assert_eq!(result.sent, 3);
    assert!(result.error.is_none());
    let mut received = Vec::new();
    assert!(poll_fn(|cx| receiver.poll_recv_batch(cx, &mut received)).await.is_some());
    assert_eq!(received.len(), expected.len());
    for (received, expected) in received.iter().zip(&expected) {
        assert_eq!(received.data, expected.data);
        assert_eq!(received.src_addr, expected.dst_addr);
    }
}
