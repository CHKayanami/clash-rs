use super::*;
use crate::{
    proxy::{datagram::ChannelDatagram, direct::{datagram::OutboundDatagramImpl, native::NativeDatagram},
        utils::{new_dual_stack_udp_socket, test_utils::noop::NoopResolver}},
    session::SocksAddr,
};
use tokio::{net::UdpSocket, sync::mpsc, time::{Duration, timeout}};

fn datagram(remote: SocketAddr, inner: AnyOutboundDatagram) -> Socks5Datagram {
    let (control, _peer) = tokio::io::duplex(64);
    Socks5Datagram::new(control.into(), remote, inner)
}

fn wire(address: &SocksAddr, payload: Bytes) -> Bytes {
    let mut data = BytesMut::new();
    Socks5UDPCodec.encode((payload, address.clone()), &mut data).unwrap();
    data.freeze()
}

#[test]
fn headers_reject_every_truncated_address_and_fragment() {
    for address in ["127.0.0.1:53", "[::1]:443", "example.test:123"] {
        let address: SocksAddr = address.parse().unwrap();
        let data = wire(&address, Bytes::new());
        for len in 0..data.len() {
            assert!(Socks5UDPCodec::decode_header(&data[..len]).is_none());
        }
        assert_eq!(Socks5UDPCodec::decode_header(&data), Some((address, data.len())));
        let mut fragmented = data.to_vec();
        fragmented[2] = 1;
        assert!(Socks5UDPCodec::decode_header(&fragmented).is_none());
    }
}

#[tokio::test]
async fn native_sends_preserve_payload_storage_and_datagram_boundaries() {
    timeout(Duration::from_secs(5), async {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = relay.local_addr().unwrap();
        for wrapped in [false, true] {
            let socket = new_dual_stack_udp_socket(None,
                #[cfg(target_os = "linux")] None).unwrap();
            let inner = if wrapped {
                AnyOutboundDatagram::Udp(Box::new(OutboundDatagramImpl::new(socket, Arc::new(NoopResolver)).unwrap()))
            } else {
                AnyOutboundDatagram::NativeUdp(Box::new(NativeDatagram::new(socket).unwrap()))
            };
            let mut socks = datagram(remote, inner);
            for address in ["192.0.2.1:53", "[2001:db8::1]:443", "example.test:123"] {
                let address: SocksAddr = address.parse().unwrap();
                for len in [0, 1, 8000] {
                    let payload = Bytes::from(vec![0x5a; len]);
                    let expected = wire(&address, payload.clone());
                    Pin::new(&mut socks).start_send(UdpPacket::new(
                        payload.clone(), SocksAddr::any_ipv4(), address.clone(),
                    )).unwrap();
                    assert_eq!(socks.pending.as_ref().unwrap().as_ptr(), payload.as_ptr());
                    assert!(Pin::new(&mut socks).start_send(UdpPacket::default()).is_err());
                    socks.flush().await.unwrap();
                    let mut received = vec![0; 65535];
                    let (count, source) = relay.recv_from(&mut received).await.unwrap();
                    assert_eq!(&received[..count], expected.as_ref());
                    relay.send_to(&received[..count], source).await.unwrap();
                    let reply = socks.next().await.unwrap();
                    assert_eq!(reply.src_addr, address);
                    assert_eq!(reply.data, payload);
                }
            }
            assert!(socks.send(UdpPacket::new(
                Bytes::from(vec![0; 70000]), SocksAddr::any_ipv4(), remote.into(),
            )).await.is_err());
            assert!(socks.pending.is_none());
            Pin::new(&mut socks).start_send(UdpPacket::new(
                Bytes::from_static(b"after error"), SocksAddr::any_ipv4(), remote.into(),
            )).unwrap();
            socks.close().await.unwrap();
            let mut received = [0; 64];
            let count = relay.recv(&mut received).await.unwrap();
            let (_, header_len) = Socks5UDPCodec::decode_header(&received[..count]).unwrap();
            assert_eq!(&received[header_len..count], b"after error");
        }
    }).await.unwrap();
}

#[tokio::test]
async fn chained_transport_preserves_framing_and_slices_received_payload() {
    let (sent, mut outgoing) = mpsc::channel(8);
    let (incoming, received) = mpsc::channel(8);
    let remote: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    let mut socks = datagram(remote, AnyOutboundDatagram::dynamic(ChannelDatagram::new(sent, received)));
    let address: SocksAddr = "example.test:53".parse().unwrap();
    let payload = Bytes::from_static(b"payload");
    let expected = wire(&address, payload.clone());
    socks.send(UdpPacket::new(payload.clone(), SocksAddr::any_ipv4(), address.clone())).await.unwrap();
    let packet = outgoing.recv().await.unwrap();
    assert_eq!(packet.dst_addr, remote.into());
    assert_eq!(packet.data, expected);

    // Neither wrong peers nor truncated/fragmented frames stop the association.
    let response = Bytes::from(expected.to_vec());
    let source: SocksAddr = remote.into();
    incoming.send(UdpPacket::new(response.clone(), "127.0.0.1:1081".parse().unwrap(), SocksAddr::any_ipv4())).await.unwrap();
    incoming.send(UdpPacket::new(response.slice(..response.len() - payload.len() - 1), source.clone(), SocksAddr::any_ipv4())).await.unwrap();
    let mut fragmented = response.to_vec();
    fragmented[2] = 1;
    incoming.send(UdpPacket::new(fragmented.into(), source.clone(), SocksAddr::any_ipv4())).await.unwrap();
    incoming.send(UdpPacket::new(response.clone(), source, SocksAddr::any_ipv4())).await.unwrap();
    let reply = timeout(Duration::from_secs(2), socks.next()).await.unwrap().unwrap();
    assert_eq!(reply.src_addr, address);
    assert_eq!(reply.data, payload);
    assert_eq!(reply.data.as_ptr(), response[3 + address.size()..].as_ptr());
}

#[tokio::test]
async fn batch_send_preserves_socks_headers_and_payloads() {
    use crate::proxy::datagram::batch::{DatagramBatch, PacketBatch};
    use futures::future::poll_fn;
    timeout(Duration::from_secs(3), async {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = relay.local_addr().unwrap();
        let socket = new_dual_stack_udp_socket(None,
            #[cfg(target_os = "linux")] None).unwrap();
        let inner = AnyOutboundDatagram::Udp(Box::new(OutboundDatagramImpl::new(socket, Arc::new(NoopResolver)).unwrap()));
        let mut socks = datagram(remote, inner);
        let mut batch = PacketBatch::default();
        let mut expected = Vec::new();
        for (address, data) in [("192.0.2.1:53", Bytes::new()), ("[2001:db8::1]:443", Bytes::from_static(b"ipv6")), ("example.test:123", Bytes::from_static(b"domain"))] {
            let address: SocksAddr = address.parse().unwrap();
            expected.push(wire(&address, data.clone()));
            batch.push(UdpPacket::new(data, SocksAddr::any_ipv4(), address)).unwrap();
        }
        let result = poll_fn(|cx| socks.poll_send_batch(cx, &mut batch)).await;
        #[cfg(target_os = "linux")]
        assert_eq!(result.sent, 3);
        assert!(result.error.is_none());
        for _ in 0..result.sent { batch.complete(); }
        while !batch.is_empty() {
            let result = poll_fn(|cx| socks.poll_send_batch(cx, &mut batch)).await;
            assert!(result.error.is_none());
            for _ in 0..result.sent { batch.complete(); }
        }
        for packet in expected {
            let mut data = [0; 512];
            let (len, source) = relay.recv_from(&mut data).await.unwrap();
            assert_eq!(&data[..len], packet.as_ref());
            relay.send_to(&data[..len], source).await.unwrap();
        }
        let mut replies = Vec::new();
        let mut count = 0;
        while count < 3 {
            assert!(poll_fn(|cx| socks.poll_recv_batch(cx, &mut replies)).await.is_some());
            count += replies.len();
            replies.clear();
        }
    }).await.unwrap();
}
