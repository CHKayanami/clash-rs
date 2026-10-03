use std::{io, pin::Pin, task::{Context, Poll}};

use futures::{Sink, Stream, ready};
use tokio_util::codec::Framed;
use tracing::warn;

use super::datagram_codec::PacketCodec;
use crate::proxy::{AnyStream, datagram::UdpPacket};

// Most UDP frames fit in 2 KiB; grow on demand for larger packets. Keep the
// original 8 KiB batching boundary independently of the initial allocation.
const INITIAL_BUFFER_CAPACITY: usize = 2048;
const WRITE_BACKPRESSURE_BOUNDARY: usize = 8192;

pub struct H2MuxDatagram {
    inner: Framed<AnyStream, PacketCodec>,
    read_closed: bool,
}

impl H2MuxDatagram {
    pub fn new(stream: AnyStream) -> Self {
        let mut inner = Framed::with_capacity(stream, PacketCodec, INITIAL_BUFFER_CAPACITY);
        inner.set_backpressure_boundary(WRITE_BACKPRESSURE_BOUNDARY);
        Self { inner, read_closed: false }
    }
}

impl Stream for H2MuxDatagram {
    type Item = UdpPacket;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>> {
        let this = self.get_mut();
        if this.read_closed { return Poll::Ready(None); }
        match ready!(Pin::new(&mut this.inner).poll_next(cx)) {
            Some(Ok(packet)) => Poll::Ready(Some(packet)),
            Some(Err(err)) => {
                // OutboundDatagram cannot return read errors; terminate and log
                // instead of skipping malformed frames and desynchronizing.
                warn!(error = ?err, "h2mux UDP receive failed");
                this.read_closed = true;
                Poll::Ready(None)
            }
            None => {
                this.read_closed = true;
                Poll::Ready(None)
            }
        }
    }
}

impl Sink<UdpPacket> for H2MuxDatagram {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, packet: UdpPacket) -> io::Result<()> {
        Pin::new(&mut self.get_mut().inner).start_send(packet)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

#[cfg(test)]
#[path = "datagram_tests.rs"]
mod tests;
