use crate::{proxy::datagram::UdpPacket, session::SocksAddr};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt};
use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};
use tokio_util::{
    codec::{Decoder, Encoder},
    udp::UdpFramed,
};
use tracing::{debug, trace};

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

impl Encoder<(Bytes, SocksAddr)> for Socks5UDPCodec {
    type Error = std::io::Error;

    fn encode(
        &mut self,
        item: (Bytes, SocksAddr),
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.reserve(3 + item.1.size() + item.0.len());
        dst.put_slice(&[0x0, 0x0, 0x0]);
        item.1.write_buf(dst);
        dst.put_slice(item.0.as_ref());

        Ok(())
    }
}

impl Decoder for Socks5UDPCodec {
    type Error = std::io::Error;
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
        if src.len() < 3 {
            return Ok(None);
        }

        if src[2] != 0 {
            trace!(
                "dropping socks5 udp packet with unsupported FRAG {}",
                src[2]
            );
            return Ok(None);
        }

        src.advance(3);
        let addr = match SocksAddr::peek_read(src) {
            Ok(addr) => addr,
            Err(e) => {
                trace!("dropping socks5 udp packet with bad address: {e}");
                return Ok(None);
            }
        };
        src.advance(addr.size());
        let packet = std::mem::take(src);
        Ok(Some((addr, packet)))
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

impl std::fmt::Debug for InboundUdp<UdpFramed<Socks5UDPCodec>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundUdp").finish()
    }
}

impl Stream for InboundUdp<UdpFramed<Socks5UDPCodec>> {
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
            match std::task::ready!(pin.inner.poll_next_unpin(cx)) {
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

impl Sink<UdpPacket> for InboundUdp<UdpFramed<Socks5UDPCodec>> {
    type Error = std::io::Error;

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
