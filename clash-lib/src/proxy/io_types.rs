//! Unified transports. Concrete common paths and dynamic protocol stacks share
//! one connection API; dispatch belongs here, not in every outbound handler.

use super::{
    OutboundDatagram, ProxyStream,
    datagram::UdpPacket,
    direct::{datagram::OutboundDatagramImpl, pool::PooledDirectDatagram},
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
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

pub enum AnyStream {
    Tcp(TcpStream),
    Dynamic(Box<dyn ProxyStream + Sync>),
}

impl AnyStream {
    pub fn new<S: ProxyStream + Sync + 'static>(stream: S) -> Self {
        Self::Dynamic(Box::new(stream))
    }

    pub fn from_boxed(stream: Box<dyn ProxyStream + Sync>) -> Self {
        Self::Dynamic(stream)
    }
}

macro_rules! stream_io {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        match $self {
            AnyStream::Tcp(inner) => Pin::new(inner).$method($($arg),*),
            AnyStream::Dynamic(inner) => Pin::new(inner).$method($($arg),*),
        }
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
        match self {
            Self::Tcp(inner) => inner.is_write_vectored(),
            Self::Dynamic(inner) => inner.is_write_vectored(),
        }
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
        match self {
            Self::Tcp(inner) => inner.underlying_socket(),
            Self::Dynamic(inner) => inner.underlying_socket(),
        }
    }

    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn zero_copy_socket(&mut self) -> Option<&mut TcpStream> {
        match self {
            Self::Tcp(inner) => inner.zero_copy_socket(),
            Self::Dynamic(inner) => inner.zero_copy_socket(),
        }
    }

    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn take_read_prefix(&mut self) -> Option<SlideBuffer> {
        match self {
            Self::Tcp(inner) => inner.take_read_prefix(),
            Self::Dynamic(inner) => inner.take_read_prefix(),
        }
    }
}

pub enum AnyOutboundDatagram {
    Direct(Box<PooledDirectDatagram>),
    Udp(Box<OutboundDatagramImpl>),
    Dynamic(
        Box<dyn OutboundDatagram<UdpPacket, Item = UdpPacket, Error = io::Error>>,
    ),
}

impl AnyOutboundDatagram {
    pub fn new<D: OutboundDatagram<UdpPacket>>(datagram: D) -> Self {
        Self::Dynamic(Box::new(datagram))
    }
}

macro_rules! datagram_io {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        match $self {
            AnyOutboundDatagram::Direct(inner) => Pin::new(inner).$method($($arg),*),
            AnyOutboundDatagram::Udp(inner) => Pin::new(inner).$method($($arg),*),
            AnyOutboundDatagram::Dynamic(inner) => Pin::new(inner).$method($($arg),*),
        }
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
