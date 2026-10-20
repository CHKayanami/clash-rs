use super::*;
use futures::{SinkExt, future::poll_fn};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use crate::proxy::{
    AnyOutboundDatagram,
    datagram::batch::{DatagramBatch, PacketBatch},
    shadowquic::UdpSessionWrapper,
};

#[tokio::test]
async fn batch_submission_keeps_prefix_and_payload_ownership() {
    let (sender, mut outgoing) = mpsc::channel(2);
    let (_incoming, receiver) = mpsc::channel(2);
    let mut wrapper = UdpSessionWrapper {
        s: PollSender::new(sender), r: receiver,
        src_addr: "127.0.0.1:1000".parse().unwrap(),
    };
    let mut batch = PacketBatch::default();
    let data = Bytes::from_static(b"payload");
    let original = data.as_ptr();
    for port in 1..=3 {
        batch.push(UdpPacket {
            data: data.clone(),
            dst_addr: SocksAddr::from((Ipv4Addr::LOCALHOST, port)),
            ..Default::default()
        }).unwrap();
    }
    let result = poll_fn(|cx| wrapper.poll_send_batch(cx, &mut batch)).await;
    assert_eq!(result.sent, 2);
    assert!(result.error.is_none());
    for port in 1..=2 {
        batch.complete();
        let packet = outgoing.recv().await.unwrap();
        assert_eq!(packet.dst_addr.port(), port);
        assert_eq!(packet.data.as_ptr(), original);
    }
    let result = poll_fn(|cx| wrapper.poll_send_batch(cx, &mut batch)).await;
    assert_eq!(result.sent, 1);
    assert_eq!(outgoing.recv().await.unwrap().dst_addr.port(), 3);
    assert!(AnyOutboundDatagram::new(wrapper).supports_multi_target());
}

#[tokio::test]
async fn invalid_packet_fails_without_closing_a_valid_association() {
    let (sender, mut outgoing) = mpsc::channel(2);
    let (_incoming, receiver) = mpsc::channel(2);
    let mut wrapper = UdpSessionWrapper {
        s: PollSender::new(sender), r: receiver,
        src_addr: "127.0.0.1:1000".parse().unwrap(),
    };
    for packet in [
        UdpPacket { data: Bytes::from(vec![0; 65536]), ..Default::default() },
        UdpPacket { dst_addr: SocksAddr::Domain("a".repeat(256).into(), 53),
            ..Default::default() },
    ] {
        assert_eq!(wrapper.send(packet).await.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(outgoing.try_recv().is_err());
    }
    wrapper.send(UdpPacket::default()).await.unwrap();
    assert!(outgoing.recv().await.unwrap().data.is_empty());
}
