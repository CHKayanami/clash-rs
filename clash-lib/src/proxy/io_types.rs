//! Unified transports. Concrete common paths and dynamic protocol stacks share
//! one connection API; dispatch belongs here, not in every outbound handler.

use super::{
    OutboundDatagram, ProxyStream,
    anytls::stream::AnyTlsStream,
    datagram::UdpPacket,
    direct::{datagram::OutboundDatagramImpl, pool::PooledDirectDatagram},
    hysteria2::{HystStream, HysteriaDatagramOutbound},
    socks::outbound::Socks5Datagram,
    transport::{
        GrpcStream, Http2Stream, HttpStream, WebsocketConn, WebsocketEarlyDataConn,
        mux::h2mux::stream::H2MuxStream, reality::SplicableTlsStream,
        uot::OutboundDatagramUotV2,
    },
    trojan::OutboundDatagramTrojan,
    vless::{VisionStream, VlessStream, xudp::pool::XudpChildDatagram},
    vmess::{OutboundDatagramVmess, VmessStream},
};
#[cfg(all(target_os = "linux", feature = "zero_copy"))]
use crate::common::io::SlideBuffer;
use futures::{Sink, Stream};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    net::TcpStream,
};

use crate::app::sniffer::PrefixedStream;
use tokio_boring::SslStream;
use tokio_rustls::client::TlsStream;

#[cfg(feature = "shadowquic")]
use super::shadowquic::UdpSessionWrapper;
#[cfg(feature = "ssh")]
use super::ssh::ChannelStreamWrapper;
#[cfg(feature = "tailscale")]
use super::tailscale::TailscaleDatagramOutbound;
#[cfg(feature = "onion")]
use super::tor::StreamWrapper;
#[cfg(feature = "tuic")]
use super::tuic::{TuicDatagramOutbound, stream::TuicStream};
#[cfg(feature = "wireguard")]
use super::wg::{SocketPair, UdpPair};
#[cfg(feature = "shadowsocks")]
use super::{
    shadowsocks::outbound::{
        OutboundDatagramShadowsocks, ShadowSocksStream, ShadowsocksUdpIo,
    },
    transport::{HTTPObfs, TLSObfs, VerifiedStream},
};
#[cfg(feature = "shadowquic")]
use shadowquic::{
    quic::{QuicClient, QuicConnection},
    shadowquic::EndClient,
    squic::inbound::Unsplit,
};
#[cfg(feature = "shadowsocks")]
use shadowsocks::{
    net::UdpSocket as ShadowsocksUdpSocket,
    relay::tcprelay::proxy_stream::server::ProxyServerStream,
};
#[cfg(feature = "tailscale")]
use tailscale::netstack::TcpStream as TailscaleTcpStream;
use tokio_tfo::TfoStream;
#[cfg(feature = "tun")]
use watfaq_netstack::TcpStream as TunTcpStream;
#[cfg(feature = "shadowquic")]
type ShadowQuicStream = Unsplit<
    <<EndClient as QuicClient>::C as QuicConnection>::SendStream,
    <<EndClient as QuicClient>::C as QuicConnection>::RecvStream,
>;

// Keep the variant list, conversions and dispatch together. Registered types
// select their concrete variant at compile time through Into.
// Concrete wrappers remain boxed to bound enum size and allow recursive stacks.
macro_rules! define_transport {
    ($d:tt, $name:ident, $bound:ty, [$($constraints:tt)+], $dispatch:ident,
     [$($base:ident($base_ty:ty)),*],
     [$($(#[$attr:meta])* $variant:ident($ty:ty)),* $(,)?]) => {
        pub enum $name {
            $($base($base_ty),)*
            $($(#[$attr])* $variant(Box<$ty>),)*
            Dynamic(Box<$bound>),
        }
        $(
            impl From<$base_ty> for $name {
                fn from(value: $base_ty) -> Self { Self::$base(value) }
            }
        )*
        $(
            $(#[$attr])*
            impl From<$ty> for $name {
                fn from(value: $ty) -> Self { Self::$variant(Box::new(value)) }
            }
        )*
        impl $name {
            pub fn new<T: Into<Self>>(value: T) -> Self { value.into() }

            /// Explicit fallback for extensions and test transports.
            pub fn dynamic<T: $($constraints)+ + 'static>(value: T) -> Self {
                Self::Dynamic(Box::new(value))
            }
        }
        macro_rules! $dispatch {
            ($d value:expr, |$d inner:ident| $d body:expr) => {
                match $d value {
                    $($name::$base($d inner) => $d body,)*
                    $($(#[$attr])* $name::$variant($d inner) => $d body,)*
                    $name::Dynamic($d inner) => $d body,
                }
            };
        }
        pub(crate) use $dispatch;
    };
}

type DynamicStream = dyn ProxyStream + Sync;
type DynamicDatagram =
    dyn OutboundDatagram<UdpPacket, Item = UdpPacket, Error = io::Error>;

define_transport!($, AnyStream, DynamicStream, [ProxyStream + Sync], dispatch_stream, [Tcp(TcpStream)], [
    Duplex(DuplexStream),
    Tfo(TfoStream),
    Hysteria2(HystStream),
    #[cfg(feature = "tuic")]
    Tuic(TuicStream),
    #[cfg(feature = "wireguard")]
    Wireguard(SocketPair),
    #[cfg(feature = "ssh")]
    Ssh(ChannelStreamWrapper),
    #[cfg(feature = "onion")]
    Tor(StreamWrapper),
    #[cfg(feature = "tailscale")]
    Tailscale(TailscaleTcpStream),
    #[cfg(feature = "tun")]
    Tun(TunTcpStream),
    #[cfg(feature = "shadowquic")]
    ShadowQuic(ShadowQuicStream),
    Tls(TlsStream<AnyStream>),
    BoringTls(SslStream<AnyStream>),
    Reality(SplicableTlsStream),
    Websocket(WebsocketConn),
    WebsocketEarlyData(WebsocketEarlyDataConn),
    Http(HttpStream),
    H2(Http2Stream),
    Grpc(GrpcStream),
    H2Mux(H2MuxStream),
    Vmess(VmessStream<AnyStream>),
    Vless(VlessStream),
    Vision(VisionStream),
    AnyTls(AnyTlsStream),
    Prefixed(PrefixedStream<AnyStream>),
    #[cfg(feature = "shadowsocks")]
    Shadowsocks(ShadowSocksStream),
    #[cfg(feature = "shadowsocks")]
    ShadowsocksServer(ProxyServerStream<TcpStream>),
    #[cfg(feature = "shadowsocks")]
    HttpObfs(HTTPObfs),
    #[cfg(feature = "shadowsocks")]
    TlsObfs(TLSObfs),
    #[cfg(feature = "shadowsocks")]
    ShadowTls(VerifiedStream<AnyStream>),
]);

impl AnyStream {
    pub fn from_boxed(stream: Box<dyn ProxyStream + Sync>) -> Self {
        Self::Dynamic(stream)
    }
}

macro_rules! stream_io {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        dispatch_stream!($self, |inner| Pin::new(inner).$method($($arg),*))
    };
}

impl AsyncRead for AnyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        stream_io!(self.get_mut(), poll_read, cx, buf)
    }
}

impl AsyncWrite for AnyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        stream_io!(self.get_mut(), poll_write, cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        stream_io!(self.get_mut(), poll_write_vectored, cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        dispatch_stream!(self, |inner| inner.is_write_vectored())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        stream_io!(self.get_mut(), poll_flush, cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        stream_io!(self.get_mut(), poll_shutdown, cx)
    }
}

impl ProxyStream for AnyStream {
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn underlying_socket(&mut self) -> Option<&mut TcpStream> {
        dispatch_stream!(self, |inner| inner.underlying_socket())
    }

    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn zero_copy_socket(&mut self) -> Option<&mut TcpStream> {
        dispatch_stream!(self, |inner| inner.zero_copy_socket())
    }

    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn take_read_prefix(&mut self) -> Option<SlideBuffer> {
        dispatch_stream!(self, |inner| inner.take_read_prefix())
    }
}

define_transport!($, AnyOutboundDatagram, DynamicDatagram, [OutboundDatagram<UdpPacket>], dispatch_datagram,
    [Direct(Box<PooledDirectDatagram>), Udp(Box<OutboundDatagramImpl>)], [
    Socks5(Socks5Datagram),
    Hysteria2(HysteriaDatagramOutbound),
    #[cfg(feature = "tuic")]
    Tuic(TuicDatagramOutbound),
    #[cfg(feature = "wireguard")]
    Wireguard(UdpPair),
    #[cfg(feature = "tailscale")]
    Tailscale(TailscaleDatagramOutbound),
    #[cfg(feature = "shadowquic")]
    ShadowQuic(UdpSessionWrapper),
    #[cfg(feature = "shadowsocks")]
    Shadowsocks(OutboundDatagramShadowsocks<ShadowsocksUdpIo>),
    #[cfg(feature = "shadowsocks")]
    ShadowsocksUdp(OutboundDatagramShadowsocks<ShadowsocksUdpSocket>),
    Trojan(OutboundDatagramTrojan),
    Vmess(OutboundDatagramVmess),
    Uot(OutboundDatagramUotV2),
    Xudp(XudpChildDatagram),
]);

macro_rules! datagram_io {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        dispatch_datagram!($self, |inner| Pin::new(inner).$method($($arg),*))
    };
}

impl Stream for AnyOutboundDatagram {
    type Item = UdpPacket;
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<UdpPacket>> {
        datagram_io!(self.get_mut(), poll_next, cx)
    }
}

impl Sink<UdpPacket> for AnyOutboundDatagram {
    type Error = io::Error;
    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        datagram_io!(self.get_mut(), poll_ready, cx)
    }
    fn start_send(self: Pin<&mut Self>, packet: UdpPacket) -> io::Result<()> {
        datagram_io!(self.get_mut(), start_send, packet)
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        datagram_io!(self.get_mut(), poll_flush, cx)
    }
    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        datagram_io!(self.get_mut(), poll_close, cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::io::SlideBuffer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn nested_transport_preserves_prefix_and_half_close() {
        for dynamic in [false, true] {
            let (client, mut peer) = tokio::io::duplex(64);
            let inner = if dynamic {
                AnyStream::dynamic(client)
            } else {
                AnyStream::new(client)
            };
            let mut prefix = SlideBuffer::new(8);
            prefix.extend_from_slice(b"prefix:");
            let mut stream = AnyStream::new(PrefixedStream::new(prefix, inner));
            assert!(matches!(stream, AnyStream::Prefixed(_)));

            peer.write_all(b"body").await.unwrap();
            peer.shutdown().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"prefix:body");

            stream.write_all(b"reply").await.unwrap();
            stream.shutdown().await.unwrap();
            received.clear();
            peer.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"reply");

            let AnyStream::Prefixed(wrapper) = stream else {
                unreachable!()
            };
            assert_eq!(
                matches!(wrapper.into_inner(), AnyStream::Dynamic(_)),
                dynamic
            );
        }
    }
}
