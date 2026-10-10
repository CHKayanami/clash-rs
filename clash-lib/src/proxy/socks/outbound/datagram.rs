use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use crate::proxy::utils::dialer_route::{self, Route};

use futures::{Sink, SinkExt, Stream, StreamExt, ready};
use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};
use tracing::trace;

use crate::{
    proxy::{AnyOutboundDatagram, AnyStream, datagram::UdpPacket, socks::inbound::Socks5UDPCodec},
};

pub struct Socks5Datagram {
    // hold the socket to keep it alive and drop it when this is dropped
    _socket: AnyStream,
    remote: SocketAddr,
    inner: AnyOutboundDatagram,
    // Keep pinned routes alive for transport workers until the association closes.
    _route: Option<Arc<Route>>,
}

impl Socks5Datagram {
    pub(crate) fn new(
        socket: AnyStream,
        remote: SocketAddr,
        datagram: AnyOutboundDatagram,
    ) -> Self {
        Self {
            _socket: socket,
            remote,
            inner: datagram,
            _route: dialer_route::retain(),
        }
    }
}

impl Drop for Socks5Datagram {
    fn drop(&mut self) {
        // this should drop the inner socket too.
        // https://datatracker.ietf.org/doc/html/rfc1928
        // A UDP association terminates when the TCP connection that the UDP
        // ASSOCIATE request arrived on terminates.
        // ideally we should be able to shutdown the UDP association
        // when the TCP connection is closed, but we don't have a way to do that
        // as there is no close() method on UdpSocket.
        trace!("UDP relay to {} closed, closing socket", self.remote);
    }
}

impl Sink<UdpPacket> for Socks5Datagram {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let pin = self.get_mut();
        pin.inner.poll_ready_unpin(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let remote = self.remote;
        trace!(
            "sending UDP packet to {}, item dst: {}",
            remote, item.dst_addr
        );
        let pin = self.get_mut();
        let mut data = BytesMut::new();
        Socks5UDPCodec.encode((item.data, item.dst_addr), &mut data)?;
        pin.inner.start_send_unpin(UdpPacket {
            data: data.freeze(), dst_addr: remote.into(), ..Default::default()
        })
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

impl Stream for Socks5Datagram {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();
        loop {
            let packet = match ready!(pin.inner.poll_next_unpin(cx)) {
                Some(packet) => packet,
                None => return Poll::Ready(None),
            };
            if packet.src_addr.ip().is_some_and(|ip| ip != pin.remote.ip())
                || packet.src_addr.port() != pin.remote.port()
            {
                trace!("dropping socks5 UDP packet from unexpected relay {}", packet.src_addr);
                continue;
            }
            let mut data = BytesMut::from(packet.data.as_ref());
            match Socks5UDPCodec.decode(&mut data) {
                Ok(Some((src_addr, data))) => return Poll::Ready(Some(UdpPacket {
                    src_addr, dst_addr: pin.remote.into(),
                    data: data.freeze(), inbound_user: None,
                })),
                _ => trace!("dropping malformed socks5 UDP packet"),
            }
        }
    }
}
