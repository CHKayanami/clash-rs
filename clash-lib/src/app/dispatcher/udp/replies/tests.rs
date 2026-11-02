use super::*;
use futures::task::noop_waker_ref;
use bytes::Bytes;

#[tokio::test]
async fn credits_include_batches_with_pending_inbound_writes() {
    let (sender, mut receiver) = channel(32);
    for _ in 0..2 {
        sender.send_batch((0..16).map(|_| UdpPacket::default()).collect()).unwrap();
    }
    assert_eq!(sender.credits.available_permits(), 0);
    let mut cx = Context::from_waker(noop_waker_ref());
    let Poll::Ready(Some(mut batch)) = receiver.poll_recv(&mut cx) else { panic!("queued batch"); };
    let mut sending = PacketBatch::default();
    batch.fill(&mut sending);
    assert!(batch.is_empty());
    assert_eq!(sending.len(), 16);
    assert_eq!(sender.credits.available_permits(), 0);
    while !sending.is_empty() { sending.complete(); }
    drop(batch);
    assert_eq!(sender.credits.available_permits(), 16);
}

#[tokio::test]
async fn batches_keep_prefix_admission_and_drop_on_full() {
    let (sender, mut receiver) = channel(16);
    for index in 0..3 {
        sender.send(UdpPacket { data: Bytes::from(vec![index]), ..Default::default() }).await.unwrap();
    }
    sender.send_batch((3..19).map(|index| UdpPacket {
        data: Bytes::from(vec![index]), ..Default::default()
    }).collect()).unwrap();
    assert_eq!(sender.credits.available_permits(), 0);
    sender.send_batch(vec![UdpPacket::default()]).unwrap();
    for index in 0..16 {
        assert_eq!(receiver.recv().await.unwrap().data.as_ref(), &[index]);
    }
    assert_eq!(sender.credits.available_permits(), 16);
}

#[tokio::test]
async fn closing_inbound_releases_credits_and_reports_closed() {
    let (sender, receiver) = channel(16);
    sender.send_batch((0..16).map(|_| UdpPacket::default()).collect()).unwrap();
    drop(receiver);
    assert!(sender.is_closed());
    assert_eq!(sender.credits.available_permits(), 16);
    assert_eq!(sender.send_batch(vec![UdpPacket::default()]).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn oversized_transport_payload_is_an_explicit_error() {
    let (sender, _receiver) = channel(16);
    let result = sender.send_batch(vec![UdpPacket {
        data: Bytes::from(vec![0; MAX_PACKET_BYTES + 1]), ..Default::default()
    }]);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(sender.credits.available_permits(), 16);
}
