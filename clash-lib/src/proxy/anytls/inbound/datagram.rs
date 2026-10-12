use std::{fmt, io, pin::Pin, task::{Context, Poll}};
use futures::{Sink, Stream};
use crate::{
    proxy::{AnyStream, datagram::UdpPacket, transport::uot::OutboundDatagramUotV2},
    session::SocksAddr,
};

#[cfg(test)]
const MAX_PACKET_LENGTH: usize = u16::MAX as usize;

/// Inbound direction of the common UoT v2 framing implementation.
pub struct InboundDatagramAnytls {
    inner: OutboundDatagramUotV2,
    source: Option<SocksAddr>,
}

impl fmt::Debug for InboundDatagramAnytls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboundDatagramAnytls").finish()
    }
}

impl InboundDatagramAnytls {
    #[cfg(test)]
    pub fn new(inner: AnyStream, target: SocksAddr) -> Self {
        Self { inner: OutboundDatagramUotV2::new(inner, target), source: None }
    }

    pub fn with_mode(inner: AnyStream, target: SocksAddr,
        source: SocksAddr, is_connect: bool) -> Self {
        let inner = if is_connect {
            OutboundDatagramUotV2::new(inner, target)
        } else { OutboundDatagramUotV2::packet_mode(inner) };
        Self { inner, source: Some(source) }
    }
}

impl Sink<UdpPacket> for InboundDatagramAnytls {
    type Error = io::Error;
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_ready(cx)
    }
    fn start_send(self: Pin<&mut Self>, mut packet: UdpPacket) -> io::Result<()> {
        packet.dst_addr = packet.src_addr.clone();
        Pin::new(&mut self.get_mut().inner).start_send(packet)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

impl Stream for InboundDatagramAnytls {
    type Item = UdpPacket;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_next(cx).map(|packet| packet.map(|mut packet| {
            if let Some(source) = &this.source { packet.src_addr = source.clone(); }
            packet
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn make_peer_addr() -> SocksAddr {
        SocksAddr::try_from(("127.0.0.1".to_owned(), 9999u16)).unwrap()
    }

    fn make_packet(data: Vec<u8>) -> UdpPacket {
        let addr = make_peer_addr();
        UdpPacket {
            data: bytes::Bytes::from(data),
            src_addr: addr.clone(),
            dst_addr: addr,
            inbound_user: None,
        }
    }

    /// Helper: encode a single packet in wire format `u16(len) | payload`.
    fn encode_wire(payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + payload.len());
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    // ── Read path ────────────────────────────────────────────────────────────

    /// `\x00\x05hello` → `UdpPacket { data: b"hello" }`.
    #[tokio::test]
    async fn test_read_normal_packet() {
        let (mut client_side, server_side) = duplex(4096);
        let peer_addr = make_peer_addr();
        let mut datagram = InboundDatagramAnytls::new(
            AnyStream::new(server_side),
            peer_addr.clone(),
        );

        client_side.write_all(&encode_wire(b"hello")).await.unwrap();
        // Close the client end so poll_next can return None after the packet.
        drop(client_side);

        let pkt = datagram.next().await.expect("expected one packet");
        assert_eq!(pkt.data.as_ref(), b"hello");
        assert_eq!(pkt.src_addr, peer_addr);
        assert_eq!(pkt.dst_addr, peer_addr);
        assert!(pkt.inbound_user.is_none());

        assert!(datagram.next().await.is_none(), "expected EOF");
    }

    /// `\x00\x00` (zero-length) → `UdpPacket { data: [] }` — must NOT be
    /// dropped. This was a bug-fix regression case.
    #[tokio::test]
    async fn test_read_zero_length_packet() {
        let (mut client_side, server_side) = duplex(4096);
        let peer_addr = make_peer_addr();
        let mut datagram =
            InboundDatagramAnytls::new(AnyStream::new(server_side), peer_addr);

        client_side.write_all(&[0x00, 0x00]).await.unwrap();
        drop(client_side);

        let pkt = datagram
            .next()
            .await
            .expect("zero-length packet must not be None");
        assert!(
            pkt.data.is_empty(),
            "zero-length packet must yield empty data, got {:?}",
            pkt.data
        );
    }

    /// Two packets concatenated in the stream → both returned in order.
    #[tokio::test]
    async fn test_read_two_consecutive_packets() {
        let (mut client_side, server_side) = duplex(4096);
        let peer_addr = make_peer_addr();
        let mut datagram =
            InboundDatagramAnytls::new(AnyStream::new(server_side), peer_addr);

        let mut wire = encode_wire(b"first");
        wire.extend(encode_wire(b"second"));
        client_side.write_all(&wire).await.unwrap();
        drop(client_side);

        let pkt1 = datagram.next().await.expect("expected first packet");
        assert_eq!(pkt1.data.as_ref(), b"first");

        let pkt2 = datagram.next().await.expect("expected second packet");
        assert_eq!(pkt2.data.as_ref(), b"second");

        assert!(
            datagram.next().await.is_none(),
            "expected EOF after two packets"
        );
    }

    /// EOF on inner stream → `poll_next` returns `None`.
    #[tokio::test]
    async fn test_read_eof_returns_none() {
        let (client_side, server_side) = duplex(4096);
        let mut datagram = InboundDatagramAnytls::new(
            AnyStream::new(server_side),
            make_peer_addr(),
        );

        drop(client_side); // immediate EOF

        assert!(
            datagram.next().await.is_none(),
            "EOF on inner stream must yield None"
        );
    }

    // ── Write path (Sink) ─────────────────────────────────────────────────────

    /// Sending `UdpPacket { data: b"hello" }` writes `\x00\x05hello` to the
    /// inner stream.
    #[tokio::test]
    async fn test_write_normal_packet() {
        let (mut client_side, server_side) = duplex(4096);
        let peer_addr = make_peer_addr();
        let mut datagram = InboundDatagramAnytls::new(
            AnyStream::new(server_side),
            peer_addr.clone(),
        );

        datagram.send(make_packet(b"hello".to_vec())).await.unwrap();

        let mut buf = vec![0u8; 7];
        client_side.read_exact(&mut buf).await.unwrap();

        assert_eq!(
            &buf[..2],
            &[0x00, 0x05],
            "length prefix should be 5 (big-endian)"
        );
        assert_eq!(&buf[2..], b"hello", "payload mismatch");
    }

    /// Sending an empty payload writes exactly `\x00\x00` to the inner stream.
    #[tokio::test]
    async fn test_write_empty_packet() {
        let (mut client_side, server_side) = duplex(4096);
        let peer_addr = make_peer_addr();
        let mut datagram = InboundDatagramAnytls::new(
            AnyStream::new(server_side),
            peer_addr.clone(),
        );

        datagram.send(make_packet(vec![])).await.unwrap();

        let mut buf = vec![0u8; 2];
        client_side.read_exact(&mut buf).await.unwrap();
        assert_eq!(
            &buf,
            &[0x00, 0x00],
            "empty packet must produce two zero bytes"
        );
    }

    /// A payload larger than `u16::MAX` bytes must produce an error — not a
    /// silent truncation or panic.
    #[tokio::test]
    async fn test_write_oversized_packet_returns_error() {
        let (_client_side, server_side) = duplex(4096);
        let peer_addr = make_peer_addr();
        let mut datagram = InboundDatagramAnytls::new(
            AnyStream::new(server_side),
            peer_addr.clone(),
        );

        let oversized = vec![0u8; MAX_PACKET_LENGTH + 1];
        let result = datagram.send(make_packet(oversized)).await;

        assert!(
            result.is_err(),
            "sending a payload > u16::MAX must return an error"
        );
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// Verify the round-trip: write a packet, read the wire bytes back, decode
    /// them manually.
    #[tokio::test]
    async fn test_write_then_read_wire_bytes() {
        let (mut client_side, server_side) = duplex(4096);
        let peer_addr = make_peer_addr();
        let mut datagram = InboundDatagramAnytls::new(
            AnyStream::new(server_side),
            peer_addr.clone(),
        );

        let payload = b"round-trip";
        datagram.send(make_packet(payload.to_vec())).await.unwrap();

        // Read the raw bytes from the other end and verify the framing.
        let expected_len = payload.len();
        let mut buf = vec![0u8; 2 + expected_len];
        client_side.read_exact(&mut buf).await.unwrap();

        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        assert_eq!(
            len, expected_len,
            "decoded length must match payload length"
        );
        assert_eq!(&buf[2..], payload, "decoded payload must match");
    }
    #[tokio::test]
    async fn packet_mode_preserves_client_target_and_unsolicited_reply() {
        let (client, server) = duplex(128);
        let source: SocksAddr = "127.0.0.1:12345".parse::<SocketAddr>().unwrap().into();
        let mut inbound = InboundDatagramAnytls::with_mode(
            AnyStream::new(server), SocksAddr::any_ipv4(), source.clone(), false,
        );
        let mut outbound = OutboundDatagramUotV2::packet_mode(AnyStream::new(client));
        for host in ["example.com", "192.0.2.1", "2001:db8::1"] {
            let target = SocksAddr::try_from((host.to_owned(), 53)).unwrap();
            let mut packet = make_packet(b"request".to_vec());
            packet.dst_addr = target.clone();
            outbound.send(packet).await.unwrap();
            let packet = inbound.next().await.unwrap();
            assert_eq!(packet.src_addr, source);
            assert_eq!(packet.dst_addr, target);
        }
        let peer = SocksAddr::try_from(("192.0.2.3".to_owned(), 9000)).unwrap();
        let mut reply = make_packet(b"unsolicited".to_vec());
        reply.src_addr = peer.clone();
        reply.dst_addr = source;
        inbound.send(reply).await.unwrap();
        let reply = outbound.next().await.unwrap();
        assert_eq!(reply.src_addr, peer);
        assert_eq!(&reply.data[..], b"unsolicited");
    }

}
