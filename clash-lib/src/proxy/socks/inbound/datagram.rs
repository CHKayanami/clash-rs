use crate::{proxy::datagram::UdpPacket, session::SocksAddr};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt, ready};
use std::{
    fmt::{self, Debug},
    io,
    mem::take,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::net::UdpSocket;
use crate::proxy::utils::poll_send_to_vectored;
use tokio_util::{
    codec::{Decoder, Encoder},
    udp::UdpFramed,
};
use tracing::debug;

// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+
//
// The fields in the UDP request header are:
//
// o  RSV  Reserved X'0000'
// o  FRAG    Current fragment number
// o  ATYP    address type of following addresses:
// o  IP V4 address: X'01'
// o  DOMAINNAME: X'03'
// o  IP V6 address: X'04'
// o  DST.ADDR       desired destination address
// o  DST.PORT       desired destination port
// o  DATA     user data
pub struct Socks5UDPCodec;

impl Socks5UDPCodec {
    pub(crate) fn encode_header(addr: &SocksAddr, dst: &mut BytesMut) {
        dst.reserve(3 + addr.size());
        dst.put_slice(&[0, 0, 0]);
        addr.write_buf(dst);
    }

    pub(crate) fn decode_header(src: &[u8]) -> Option<(SocksAddr, usize)> {
        if src.len() < 3 || src[2] != 0 { return None; }
        let addr = SocksAddr::peek_read(&src[3..]).ok()?;
        let header_len = 3 + addr.size();
        Some((addr, header_len))
    }
}

impl Encoder<(Bytes, SocksAddr)> for Socks5UDPCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        item: (Bytes, SocksAddr),
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.reserve(3 + item.1.size() + item.0.len());
        Self::encode_header(&item.1, dst);
        dst.put_slice(item.0.as_ref());

        Ok(())
    }
}

impl Decoder for Socks5UDPCodec {
    type Error = io::Error;
    type Item = (SocksAddr, BytesMut);

    /// A malformed datagram is dropped, never surfaced as an error.
    ///
    /// `UdpFramed` propagates a decoder error without clearing its read buffer,
    /// so returning `Err` here would either kill the association or, if the
    /// caller tried to recover, re-decode the same bad bytes forever. Returning
    /// `Ok(None)` makes `UdpFramed` discard the datagram and read the next one.
    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        let Some((addr, header_len)) = Self::decode_header(src) else {
            return Ok(None);
        };
        src.advance(header_len);
        let packet = take(src);
        Ok(Some((addr, packet)))
    }
}

/// Keep the decoder's receive buffering, but send header and payload separately.
/// The pending packet owns its payload across writable-readiness waits.
pub(crate) struct Socks5UdpFramed {
    inner: UdpFramed<Socks5UDPCodec>,
    header: BytesMut,
    pending: Option<(Bytes, SocketAddr)>,
}

impl Socks5UdpFramed {
    pub(crate) fn new(socket: UdpSocket) -> Self {
        Self {
            inner: UdpFramed::new(socket, Socks5UDPCodec),
            header: BytesMut::with_capacity(262),
            pending: None,
        }
    }
}

impl Stream for Socks5UdpFramed {
    type Item = Result<((SocksAddr, BytesMut), SocketAddr), io::Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.inner.poll_next_unpin(cx)
    }
}

impl Sink<((Bytes, SocksAddr), SocketAddr)> for Socks5UdpFramed {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        ((data, addr), peer): ((Bytes, SocksAddr), SocketAddr),
    ) -> Result<(), Self::Error> {
        if self.pending.is_some() {
            return Err(io::Error::other("previous SOCKS UDP packet is pending"));
        }
        self.header.clear();
        Socks5UDPCodec::encode_header(&addr, &mut self.header);
        self.pending = Some((data, peer));
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let Some((data, peer)) = self.pending.as_ref() else {
            return Poll::Ready(Ok(()));
        };
        let result = ready!(poll_send_to_vectored(
            self.inner.get_ref(), cx, &self.header, data, *peer,
        ));
        self.pending = None;
        Poll::Ready(result)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

pub struct InboundUdp<I> {
    inner: I,
    /// Only datagrams from this address are relayed. A UDP association belongs
    /// to the client that opened it; the relay socket is otherwise reachable by
    /// any host that can route to us.
    allowed_src: IpAddr,
}

impl<I> InboundUdp<I>
where
    I: Stream + Unpin,
    I: Sink<((Bytes, SocksAddr), SocketAddr)>,
{
    pub fn new(inner: I, allowed_src: IpAddr) -> Self {
        Self {
            inner,
            // compared against canonicalized peer addresses, so normalize the
            // v4-mapped-v6 form once here
            allowed_src: allowed_src.to_canonical(),
        }
    }
}

impl Debug for InboundUdp<Socks5UdpFramed> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboundUdp").finish()
    }
}

impl Stream for InboundUdp<Socks5UdpFramed> {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        // Datagrams from anyone other than the client that opened the
        // association are dropped, not fatal — skipping one always consumes it,
        // so the loop makes progress.
        loop {
            match ready!(pin.inner.poll_next_unpin(cx)) {
                None => return Poll::Ready(None),
                Some(Ok(((dst, pkt), src))) => {
                    if src.ip().to_canonical() != pin.allowed_src {
                        debug!(
                            "dropping socks5 udp packet from unexpected source \
                             {src}; association belongs to {}",
                            pin.allowed_src
                        );
                        continue;
                    }
                    return Poll::Ready(Some(UdpPacket {
                        data: pkt.freeze(),
                        src_addr: SocksAddr::Ip(src),
                        dst_addr: dst,
                        inbound_user: None,
                    }));
                }
                // decode never errors (see `Socks5UDPCodec::decode`), so this is
                // a socket-level failure — end the association
                Some(Err(e)) => {
                    debug!("socks5 udp association read error: {e}");
                    return Poll::Ready(None);
                }
            }
        }
    }
}

impl Sink<UdpPacket> for InboundUdp<Socks5UdpFramed> {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let pin = self.get_mut();
        pin.inner.poll_ready_unpin(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.inner.start_send_unpin((
            (item.data, item.src_addr),
            item.dst_addr.must_into_socket_addr(),
        ))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let pin = self.get_mut();
        pin.inner.poll_flush_unpin(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let pin = self.get_mut();
        pin.inner.poll_close_unpin(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn vectored_send_preserves_datagram_boundaries_and_addresses() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = receiver.local_addr().unwrap();
        let mut framed = Socks5UdpFramed::new(socket);
        let addresses = [
            SocksAddr::from((Ipv4Addr::LOCALHOST, 53)),
            SocksAddr::from((Ipv6Addr::LOCALHOST, 443)),
            SocksAddr::try_from(("example.org".to_owned(), 123)).unwrap(),
        ];
        for addr in addresses {
            for len in [0, 1, 8000] {
                let payload = Bytes::from(vec![0x5a; len]);
                framed
                    .send(((payload.clone(), addr.clone()), peer))
                    .await
                    .unwrap();
                let mut wire = vec![0; 65535];
                let n = receiver.recv(&mut wire).await.unwrap();
                let mut wire = BytesMut::from(&wire[..n]);
                let (decoded_addr, data) =
                    Socks5UDPCodec.decode(&mut wire).unwrap().unwrap();
                assert_eq!(decoded_addr, addr);
                assert_eq!(data.as_ref(), payload.as_ref());
            }
        }
        framed.close().await.unwrap();
    }

    #[tokio::test]
    async fn pending_payload_survives_readiness_wait_and_rejects_overwrite() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = receiver.local_addr().unwrap();
        let mut framed = Socks5UdpFramed::new(socket);
        let payload = Bytes::from(vec![0x42; 1000]);
        let ptr = payload.as_ptr();
        let addr = SocksAddr::from(peer);
        Pin::new(&mut framed)
            .start_send(((payload, addr.clone()), peer))
            .unwrap();
        assert_eq!(framed.pending.as_ref().unwrap().0.as_ptr(), ptr);
        assert!(
            Pin::new(&mut framed)
                .start_send(((Bytes::new(), addr), peer))
                .is_err()
        );
        framed.flush().await.unwrap();
        let mut wire = [0; 2048];
        let n = receiver.recv(&mut wire).await.unwrap();
        assert_eq!(&wire[n - 1000..n], &[0x42; 1000]);
        assert!(framed.pending.is_none());
    }
}
