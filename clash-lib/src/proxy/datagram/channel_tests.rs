use super::*;
use super::batch::{DatagramBatch, PacketBatch};
use bytes::Bytes;
use futures::task::noop_waker_ref;
use tokio::sync::mpsc;

#[tokio::test]
async fn batch_channel_moves_payloads_and_respects_packet_backpressure() {
    let (send, mut receive) = mpsc::channel(2);
    let (_, incoming) = mpsc::channel(1);
    let mut channel = ChannelDatagram::new(send, incoming);
    let mut batch = PacketBatch::default();
    let mut pointers = Vec::new();
    for value in 0..3 {
        let data = Bytes::from(vec![value; 128]);
        pointers.push(data.as_ptr());
        batch.push(UdpPacket { data, ..Default::default() }).unwrap();
    }
    let mut cx = Context::from_waker(noop_waker_ref());
    let Poll::Ready(result) = channel.poll_send_batch(&mut cx, &mut batch) else { panic!("expected ready batch"); };
    assert_eq!(result.sent, 2);
    assert!(result.error.is_none());
    for _ in 0..result.sent { batch.complete(); }
    assert!(channel.poll_send_batch(&mut cx, &mut batch).is_pending());
    for pointer in &pointers[..2] {
        assert_eq!(receive.recv().await.unwrap().data.as_ptr(), *pointer);
    }
    let Poll::Ready(result) = channel.poll_send_batch(&mut cx, &mut batch) else { panic!("expected ready batch"); };
    assert_eq!(result.sent, 1);
    batch.complete();
    assert_eq!(receive.recv().await.unwrap().data.as_ptr(), pointers[2]);
    assert!(batch.is_empty());
}

#[tokio::test]
async fn batch_channel_close_is_terminal() {
    let (send, receive) = mpsc::channel(1);
    let (_, incoming) = mpsc::channel(1);
    let mut channel = ChannelDatagram::new(send, incoming);
    drop(receive);
    let mut batch = PacketBatch::default();
    batch.push(UdpPacket::default()).unwrap();
    let mut cx = Context::from_waker(noop_waker_ref());
    let Poll::Ready(result) = channel.poll_send_batch(&mut cx, &mut batch) else { panic!("expected ready batch"); };
    assert!(result.fatal);
    assert!(result.error.is_some());
    assert_eq!(result.sent, 0);
}
