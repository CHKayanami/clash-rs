use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{ready, Sink, Stream};
use tokio::io::AsyncWrite;
use tokio_util::io::poll_read_buf;
use tracing::{trace, warn};

use crate::{
    proxy::{datagram::{DatagramReadError, UdpPacket}, AnyStream},
    session::SocksAddr,
};
use super::codec::{PacketHeader, decode_header, encode_header};

const INITIAL_BUFFER_SIZE: usize = 2048;
const COALESCE_PAYLOAD_LIMIT: usize = 2048;

pub struct OutboundDatagramUotV2 {
    inner: AnyStream,
    target_addr: SocksAddr,
    packet_mode: bool,

    header_buf: BytesMut,
    header_written: usize,
    payload_buf: Option<Bytes>,
    payload_written: usize,
    flushed: bool,

    read_buf: BytesMut,
    read_header: Option<PacketHeader>,
    read_error: DatagramReadError,
    is_eof: bool,
}

impl OutboundDatagramUotV2 {
    pub fn new(inner: AnyStream, target_addr: SocksAddr) -> Self {
        Self {
            inner, target_addr, packet_mode: false,
            header_buf: BytesMut::new(), header_written: 0,
            payload_buf: None, payload_written: 0, flushed: true,
            read_buf: BytesMut::new(), read_header: None,
            read_error: Arc::new(OnceLock::new()), is_eof: false,
        }
    }

    pub fn packet_mode(inner: AnyStream) -> Self {
        let mut datagram = Self::new(inner, SocksAddr::any_ipv4());
        datagram.packet_mode = true;
        datagram
    }

    pub(crate) fn supports_multi_target(&self) -> bool { self.packet_mode }

    pub(crate) fn read_error_handle(&self) -> DatagramReadError {
        Arc::clone(&self.read_error)
    }

    fn fail_read(&mut self, error: io::Error) -> Poll<Option<UdpPacket>> {
        warn!(%error, "UoT receive failed");
        let _ = self.read_error.set(error);
        self.is_eof = true;
        self.read_buf = BytesMut::new();
        self.read_header = None;
        Poll::Ready(None)
    }
}

impl Sink<UdpPacket> for OutboundDatagramUotV2 {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.read_error.get() {
            return Poll::Ready(Err(io::Error::new(error.kind(), error.to_string())));
        }
        Pin::new(this).poll_flush(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> io::Result<()> {
        let this = self.get_mut();
        if !this.flushed {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock, "previous UoT packet not yet sent",
            ));
        }
        if !this.packet_mode && item.dst_addr != this.target_addr {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput, "UoT connect destination mismatch",
            ));
        }
        encode_header(
            &mut this.header_buf, &item.dst_addr, item.data.len(), this.packet_mode,
        )?;
        // Non-vectored transports can send small packets in one encrypted record.
        if !this.inner.is_write_vectored() && item.data.len() <= COALESCE_PAYLOAD_LIMIT {
            this.header_buf.extend_from_slice(&item.data);
            this.payload_buf = None;
        } else {
            this.payload_buf = Some(item.data);
        }
        this.header_written = 0;
        this.payload_written = 0;
        this.flushed = false;
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.flushed { return Poll::Ready(Ok(())); }
        let mut inner = Pin::new(&mut this.inner);
        loop {
            let header = &this.header_buf[this.header_written..];
            let payload = this.payload_buf.as_ref()
                .map_or(&[][..], |data| &data[this.payload_written..]);
            if header.is_empty() && payload.is_empty() { break; }
            let n = if inner.is_write_vectored() && !header.is_empty() && !payload.is_empty() {
                ready!(inner.as_mut().poll_write_vectored(cx, &[
                    IoSlice::new(header), IoSlice::new(payload),
                ]))?
            } else {
                let data = if header.is_empty() { payload } else { header };
                ready!(inner.as_mut().poll_write(cx, data))?
            };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero, "failed to write UoT packet",
                )));
            }
            let header_bytes = n.min(header.len());
            this.header_written += header_bytes;
            this.payload_written += n - header_bytes;
        }
        ready!(inner.poll_flush(cx))?;
        trace!("sent UoT packet");
        this.payload_buf = None;
        this.flushed = true;
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for OutboundDatagramUotV2 {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Option<UdpPacket>> {
        let this = self.get_mut();
        if this.is_eof { return Poll::Ready(None); }
        loop {
            if this.read_header.is_none() {
                match decode_header(&this.read_buf, &this.target_addr, this.packet_mode) {
                    Ok(Some(header)) => {
                        this.read_buf.advance(header.header_len);
                        // Grow once to the validated payload length, never to an
                        // unbounded stream length. Small retained packets only
                        // share the initial slab, rather than a large receive slab.
                        if this.read_buf.capacity() < header.payload_len {
                            let mut buffer = BytesMut::with_capacity(header.payload_len);
                            buffer.extend_from_slice(&this.read_buf);
                            this.read_buf = buffer;
                        }
                        this.read_header = Some(header);
                    }
                    Ok(None) => {}
                    Err(error) => return this.fail_read(error),
                }
            }
            if let Some(header) = &this.read_header
                && this.read_buf.len() >= header.payload_len
            {
                let header = this.read_header.take().unwrap();
                // Bytes owns the storage independently of this stream. Subsequent
                // reads cannot overwrite a returned or queued packet.
                let data = this.read_buf.split_to(header.payload_len).freeze();
                if this.read_buf.is_empty() { this.read_buf = BytesMut::new(); }
                return Poll::Ready(Some(UdpPacket {
                    data, src_addr: header.address.clone(), dst_addr: header.address,
                    inbound_user: None,
                }));
            }
            let read_limit = this.read_header.as_ref().map_or(
                INITIAL_BUFFER_SIZE, |header| header.payload_len - this.read_buf.len(),
            );
            this.read_buf.reserve(read_limit);
            let mut buffer = (&mut this.read_buf).limit(read_limit);
            match poll_read_buf(Pin::new(&mut this.inner), cx, &mut buffer) {
                Poll::Ready(Ok(0)) => {
                    if this.read_header.is_some() || !this.read_buf.is_empty() {
                        return this.fail_read(io::Error::new(
                            io::ErrorKind::UnexpectedEof, "UoT stream ended mid-packet",
                        ));
                    }
                    this.is_eof = true;
                    return Poll::Ready(None);
                }
                Poll::Ready(Ok(_)) => {}
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return this.fail_read(error),
            }
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
