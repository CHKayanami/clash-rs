use super::*;
use super::batch::{DatagramBatch, MAX_BATCH_PACKETS, PacketBatch};
use bytes::Bytes;
use futures::task::noop_waker_ref;
use std::task::{Context, Poll};
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

#[tokio::test]
async fn batch_channel_poll_recv_batch_respects_limit_order_and_eof() {
    let (outgoing, _) = mpsc::channel(1);
    let (tx, incoming) = mpsc::channel(MAX_BATCH_PACKETS * 2);
    let mut channel = ChannelDatagram::new(outgoing, incoming);
    let mut cx = Context::from_waker(noop_waker_ref());
    let mut packets = Vec::new();

    assert!(channel.poll_recv_batch(&mut cx, &mut packets).is_pending());

    let mut pointers = Vec::new();
    for i in 0..(MAX_BATCH_PACKETS + 3) {
        let data = Bytes::from(vec![i as u8; 64]);
        pointers.push(data.as_ptr());
        tx.send(UdpPacket { data, ..Default::default() }).await.unwrap();
    }

    assert_eq!(channel.poll_recv_batch(&mut cx, &mut packets), Poll::Ready(Some(())));
    assert_eq!(packets.len(), MAX_BATCH_PACKETS);
    for (i, pkt) in packets.iter().enumerate() {
        assert_eq!(pkt.data.as_ptr(), pointers[i]);
    }

    // Calling again when already at MAX_BATCH_PACKETS keeps existing packets untouched.
    assert_eq!(channel.poll_recv_batch(&mut cx, &mut packets), Poll::Ready(Some(())));
    assert_eq!(packets.len(), MAX_BATCH_PACKETS);

    // Pre-populated buffer only receives up to MAX_BATCH_PACKETS total.
    packets.truncate(MAX_BATCH_PACKETS - 2);
    assert_eq!(channel.poll_recv_batch(&mut cx, &mut packets), Poll::Ready(Some(())));
    assert_eq!(packets.len(), MAX_BATCH_PACKETS);
    assert_eq!(packets[MAX_BATCH_PACKETS - 2].data.as_ptr(), pointers[MAX_BATCH_PACKETS]);
    assert_eq!(packets[MAX_BATCH_PACKETS - 1].data.as_ptr(), pointers[MAX_BATCH_PACKETS + 1]);

    packets.clear();
    drop(tx);
    assert_eq!(channel.poll_recv_batch(&mut cx, &mut packets), Poll::Ready(Some(())));
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].data.as_ptr(), pointers[MAX_BATCH_PACKETS + 2]);

    packets.clear();
    assert_eq!(channel.poll_recv_batch(&mut cx, &mut packets), Poll::Ready(None));
}
