use super::*;
use std::{net::SocketAddr, sync::Arc};
use futures::{future::poll_fn, task::noop_waker_ref};
use clash_netstack::parse_udp_packet;
use crate::proxy::tun::packet_queue;

#[tokio::test]
async fn direct_reply_encodes_both_families_and_keeps_valid_suffix_after_bad_packet() {
    let (sender, mut output) = packet_queue::channel();
    let target = Arc::new(Target(sender));
    let mut writer = target.writer();
    let mut cx = Context::from_waker(noop_waker_ref());
    assert_eq!(writer.poll_ready(&mut cx), Poll::Ready(true));
    let v4: SocketAddr = "192.0.2.1:1234".parse().unwrap();
    let v4_client: SocketAddr = "192.0.2.2:5000".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
    let v6_client: SocketAddr = "[2001:db8::2]:5000".parse().unwrap();
    let mut packets = vec![
        UdpPacket::new(Bytes::from_static(b"v4"), v4.into(), v4_client.into()),
        UdpPacket::new(Bytes::from_static(b"bad"), v4.into(), v6_client.into()),
        UdpPacket::new(Bytes::from(vec![0; 65527]), v6.into(), v6_client.into()),
        UdpPacket::new(Bytes::from_static(b"v6"), v6.into(), v6_client.into()),
    ];
    writer.send(&mut packets).unwrap();
    assert!(packets.is_empty());
    assert!(poll_fn(|cx| writer.poll_ready(cx)).await);
    for (source, destination, payload) in [(v4, v4_client, b"v4"), (v6, v6_client, b"v6")] {
        let packet = output.recv().await.unwrap();
        let (actual_source, actual_destination, range) = parse_udp_packet(&packet.bytes).unwrap();
        assert_eq!((actual_source, actual_destination), (source, destination));
        assert_eq!(&packet.bytes[range], payload);
    }
    assert!(output.try_recv().is_err());
}

#[tokio::test]
async fn idle_writers_do_not_reserve_capacity_and_small_replies_use_actual_lengths() {
    let (sender, mut output) = packet_queue::channel();
    let target = Target(sender.clone());
    let mut writers: Vec<_> = (0..16).map(|_| target.writer()).collect();
    let mut cx = Context::from_waker(noop_waker_ref());
    for writer in &mut writers { assert_eq!(writer.poll_ready(&mut cx), Poll::Ready(true)); }
    let mut occupied = vec![Bytes::from_static(b"occupied"); 512];
    sender.send_batch(&mut occupied).await.unwrap();
    let source: SocketAddr = "192.0.2.1:1234".parse().unwrap();
    let client: SocketAddr = "192.0.2.2:5000".parse().unwrap();
    for writer in &mut writers {
        writer.send(&mut vec![UdpPacket::new(Bytes::from_static(b"small"), source.into(), client.into())]).unwrap();
        assert!(writer.poll_ready(&mut cx).is_pending());
    }
    let mut held = Vec::new();
    assert_eq!(output.recv_many(&mut held, 512).await, 512);
    for writer in &mut writers { assert!(poll_fn(|cx| writer.poll_ready(cx)).await); }
    for _ in 0..writers.len() {
        let packet = output.recv().await.unwrap();
        assert_eq!(packet.budget.num_permits(), packet.bytes.len());
        assert_eq!(packet.bytes.len(), 28 + b"small".len());
    }
    assert!(output.try_recv().is_err());
}

#[tokio::test]
async fn dropping_pending_reply_returns_budget_and_device_close_stops_writer() {
    let (sender, mut output) = packet_queue::channel();
    let mut occupied = vec![Bytes::from_static(b"x"); 512];
    sender.send_batch(&mut occupied).await.unwrap();
    let mut writer = Target(sender.clone()).writer();
    let source: SocketAddr = "192.0.2.1:1234".parse().unwrap();
    let client: SocketAddr = "192.0.2.2:5000".parse().unwrap();
    writer.send(&mut vec![UdpPacket::new(Bytes::from_static(b"pending"), source.into(), client.into())]).unwrap();
    let mut cx = Context::from_waker(noop_waker_ref());
    assert!(writer.poll_ready(&mut cx).is_pending());
    drop(writer);
    let mut held = Vec::new();
    output.recv_many(&mut held, 512).await;
    assert!(output.try_recv().is_err());
    drop(held);
    let mut full_budget = vec![Bytes::from(vec![0; 4 * 1024 * 1024])];
    tokio::time::timeout(std::time::Duration::from_secs(1), sender.send_batch(&mut full_budget))
        .await.unwrap().unwrap();
    drop(output.recv().await.unwrap());
    let mut writer = Target(sender).writer();
    drop(output);
    assert_eq!(writer.poll_ready(&mut cx), Poll::Ready(false));
}
