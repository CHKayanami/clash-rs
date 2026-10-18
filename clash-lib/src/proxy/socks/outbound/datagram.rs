use crate::proxy::{datagram::batch::{DatagramBatch, PacketBatch, BatchResult, poll_send_single},
    socks::batch::{BatchTarget, poll_send_socks_batch}};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use crate::proxy::utils::dialer_route::{self, Route};

use futures::{Sink, SinkExt, Stream, StreamExt, ready};
use bytes::{Bytes, BytesMut};
use tokio_util::codec::Encoder;
use tracing::trace;

use crate::{
    proxy::{AnyOutboundDatagram, AnyStream, datagram::UdpPacket, socks::inbound::Socks5UDPCodec},
};

pub struct Socks5Datagram {
    // hold the socket to keep it alive and drop it when this is dropped
    _socket: AnyStream,
    remote: SocketAddr,
    inner: AnyOutboundDatagram,
    header: BytesMut,
    pending: Option<Bytes>,
    // Keep pinned routes alive for transport workers until the association closes.
    _route: Option<Arc<Route>>,
}

impl Socks5Datagram {
    pub(crate) fn has_native_send(&self) -> bool { self.inner.physical_socket().is_some() }

    pub(crate) fn new(
        socket: AnyStream,
        remote: SocketAddr,
        datagram: AnyOutboundDatagram,
    ) -> Self {
        Self {
            _socket: socket,
            remote,
            inner: datagram,
            header: BytesMut::new(),
            pending: None,
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
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.pending.is_some() { ready!(self.as_mut().poll_flush(cx))?; }
        self.get_mut().inner.poll_ready_unpin(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let remote = self.remote;
        trace!(
            "sending UDP packet to {}, item dst: {}",
            remote, item.dst_addr
        );
        let pin = self.get_mut();
        if pin.pending.is_some() {
            return Err(io::Error::other("previous SOCKS UDP packet is pending"));
        }
        if matches!(pin.inner, AnyOutboundDatagram::Udp(_) | AnyOutboundDatagram::NativeUdp(_)) {
            pin.header.clear();
            Socks5UDPCodec::encode_header(&item.dst_addr, &mut pin.header);
            pin.pending = Some(item.data);
            return Ok(());
        }
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
        if let Some(data) = pin.pending.as_ref() {
            let result = ready!(match &pin.inner {
                AnyOutboundDatagram::Udp(inner) => inner.poll_send_to_vectored(cx, &pin.header, data, pin.remote),
                AnyOutboundDatagram::NativeUdp(inner) => inner.poll_send_to_vectored(cx, &pin.header, data, pin.remote),
                _ => unreachable!("vectored SOCKS send requires a native socket"),
            });
            pin.pending = None;
            return Poll::Ready(result);
        }
        pin.inner.poll_flush_unpin(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        self.get_mut().inner.poll_close_unpin(cx)
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
            match Socks5UDPCodec::decode_header(&packet.data) {
                Some((src_addr, header_len)) => return Poll::Ready(Some(UdpPacket {
                    src_addr, dst_addr: pin.remote.into(),
                    data: packet.data.slice(header_len..), inbound_user: None,
                })),
                _ => trace!("dropping malformed socks5 UDP packet"),
            }
        }
    }
}

#[cfg(test)]
#[path = "datagram_tests.rs"]
mod tests;

impl DatagramBatch for Socks5Datagram {
    fn poll_send_batch(&mut self, cx: &mut Context<'_>, batch: &mut PacketBatch) -> Poll<BatchResult> {
        if let Some((socket, ipv6)) = self.inner.physical_socket() {
            poll_send_socks_batch(socket, ipv6, cx, batch, BatchTarget::Relay(self.remote))
        } else { poll_send_single(self, cx, batch) }
    }
    fn poll_recv_batch(&mut self, cx: &mut Context<'_>, packets: &mut Vec<UdpPacket>) -> Poll<Option<()>> {
        if ready!(self.inner.poll_recv_batch(cx, packets)).is_none() { return Poll::Ready(None); }
        packets.retain_mut(|packet| {
            if packet.src_addr.ip().is_some_and(|ip| ip != self.remote.ip())
                || packet.src_addr.port() != self.remote.port() { return false; }
            let Some((source, len)) = Socks5UDPCodec::decode_header(&packet.data) else { return false; };
            packet.src_addr = source;
            packet.dst_addr = self.remote.into();
            packet.data = packet.data.slice(len..);
            packet.inbound_user = None;
            true
        });
        if packets.is_empty() { cx.waker().wake_by_ref(); Poll::Pending }
        else { Poll::Ready(Some(())) }
    }
}
