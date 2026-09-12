use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{ready, Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, trace};

use crate::{
    common::io::SlideBuffer,
    proxy::{datagram::UdpPacket, AnyStream},
    session::SocksAddr,
};

const MAX_PACKET_LENGTH: usize = u16::MAX as usize;
const BUFFER_SIZE: usize = MAX_PACKET_LENGTH + 2;

pub struct OutboundDatagramUotV2 {
    inner: AnyStream,
    target_addr: SocksAddr,

    // Write state
    header_buf: [u8; 2],
    header_written: usize,
    payload_buf: Option<Bytes>,
    payload_written: usize,
    flushed: bool,

    // Read state
    read_buf: SlideBuffer,
    is_eof: bool,
}

impl OutboundDatagramUotV2 {
    pub fn new(inner: AnyStream, target_addr: SocksAddr) -> Self {
        Self {
            inner,
            target_addr,
            header_buf: [0; 2],
            header_written: 0,
            payload_buf: None,
            payload_written: 0,
            flushed: true,
            read_buf: SlideBuffer::new(BUFFER_SIZE),
            is_eof: false,
        }
    }
}

impl Sink<UdpPacket> for OutboundDatagramUotV2 {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let this = self.get_mut();
        if !this.flushed || this.payload_buf.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "previous packet not yet sent",
            ));
        }

        let payload_len = item.data.len();
        if payload_len > MAX_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "udp payload too large for uot v2: {} > {}",
                    payload_len, MAX_PACKET_LENGTH
                ),
            ));
        }

        this.header_buf = (payload_len as u16).to_be_bytes();
        this.header_written = 0;
        this.payload_buf = Some(item.data);
        this.payload_written = 0;
        this.flushed = false;
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();
        let mut inner = Pin::new(&mut this.inner);

        while this.header_written < this.header_buf.len() {
            let n = ready!(
                inner.as_mut().poll_write(cx, &this.header_buf[this.header_written..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write udp packet header",
                )));
            }
            this.header_written += n;
        }

        if let Some(payload) = &this.payload_buf {
            while this.payload_written < payload.len() {
                let n = ready!(
                    inner.as_mut().poll_write(cx, &payload[this.payload_written..])
                )?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write udp packet payload",
                    )));
                }
                this.payload_written += n;
            }
        }

        ready!(inner.poll_flush(cx))?;

        if let Some(payload) = this.payload_buf.take() {
            trace!("sent uot v2 udp packet, len={}", payload.len());
        }

        this.header_written = 0;
        this.payload_written = 0;
        this.flushed = true;
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for OutboundDatagramUotV2 {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if this.is_eof {
            return Poll::Ready(None);
        }

        let mut inner = Pin::new(&mut this.inner);

        loop {
            // Try to parse a full packet from buffered data
            let slice = this.read_buf.as_slice();
            if slice.len() >= 2 {
                let packet_len = u16::from_be_bytes([slice[0], slice[1]]) as usize;
                let total_len = 2 + packet_len;

                if slice.len() >= total_len {
                    let data = Bytes::copy_from_slice(&slice[2..total_len]);
                    this.read_buf.consume(total_len);

                    return Poll::Ready(Some(UdpPacket {
                        data,
                        src_addr: this.target_addr.clone(),
                        dst_addr: this.target_addr.clone(),
                        inbound_user: None,
                    }));
                }
            }

            // Incomplete packet in buffer, compact if necessary before reading more
            this.read_buf.maybe_compact(4096);

            let write_slice = this.read_buf.write_slice();
            if write_slice.is_empty() {
                debug!("uot v2 read buffer full but no complete packet");
                return Poll::Ready(None);
            }

            let mut read_buf = ReadBuf::new(write_slice);
            match inner.as_mut().poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        this.is_eof = true;
                        if this.read_buf.is_empty() {
                            return Poll::Ready(None);
                        } else {
                            debug!("uot v2 EOF reached in the middle of a packet");
                            return Poll::Ready(None);
                        }
                    }
                    this.read_buf.advance_write(n);
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => {
                    debug!("failed to read uot v2 udp stream: {}", err);
                    return Poll::Ready(None);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    fn make_target_addr() -> SocksAddr {
        SocksAddr::try_from(("127.0.0.1".to_owned(), 9999u16)).unwrap()
    }

    fn make_packet(data: Vec<u8>) -> UdpPacket {
        let addr = make_target_addr();
        UdpPacket {
            data: Bytes::from(data),
            src_addr: addr.clone(),
            dst_addr: addr,
            inbound_user: None,
        }
    }

    fn encode_wire(payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + payload.len());
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    // ── Read path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_read_normal_packet() {
        let (mut client_side, server_side) = duplex(4096);
        let target_addr = make_target_addr();
        let mut datagram =
            OutboundDatagramUotV2::new(Box::new(server_side), target_addr.clone());

        client_side.write_all(&encode_wire(b"hello")).await.unwrap();
        drop(client_side);

        let pkt = datagram.next().await.expect("expected one packet");
        assert_eq!(pkt.data.as_ref(), b"hello");
        assert_eq!(pkt.src_addr, target_addr);
        assert_eq!(pkt.dst_addr, target_addr);
        assert!(pkt.inbound_user.is_none());

        assert!(datagram.next().await.is_none(), "expected EOF");
    }

    #[tokio::test]
    async fn test_read_zero_length_packet() {
        let (mut client_side, server_side) = duplex(4096);
        let target_addr = make_target_addr();
        let mut datagram =
            OutboundDatagramUotV2::new(Box::new(server_side), target_addr);

        client_side.write_all(&[0x00, 0x00]).await.unwrap();
        drop(client_side);

        let pkt = datagram
            .next()
            .await
            .expect("zero-length packet must not be None");
        assert!(pkt.data.is_empty());
    }

    #[tokio::test]
    async fn test_read_multiple_consecutive_packets() {
        let (mut client_side, server_side) = duplex(4096);
        let target_addr = make_target_addr();
        let mut datagram =
            OutboundDatagramUotV2::new(Box::new(server_side), target_addr);

        let mut wire = encode_wire(b"first");
        wire.extend(encode_wire(b"second"));
        wire.extend(encode_wire(b"third"));
        client_side.write_all(&wire).await.unwrap();
        drop(client_side);

        let pkt1 = datagram.next().await.expect("expected first packet");
        assert_eq!(pkt1.data.as_ref(), b"first");

        let pkt2 = datagram.next().await.expect("expected second packet");
        assert_eq!(pkt2.data.as_ref(), b"second");

        let pkt3 = datagram.next().await.expect("expected third packet");
        assert_eq!(pkt3.data.as_ref(), b"third");

        assert!(datagram.next().await.is_none());
    }

    #[tokio::test]
    async fn test_read_eof_returns_none() {
        let (client_side, server_side) = duplex(4096);
        let mut datagram =
            OutboundDatagramUotV2::new(Box::new(server_side), make_target_addr());

        drop(client_side);
        assert!(datagram.next().await.is_none());
    }

    // ── Write path (Sink) ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_write_normal_packet() {
        let (mut client_side, server_side) = duplex(4096);
        let target_addr = make_target_addr();
        let mut datagram =
            OutboundDatagramUotV2::new(Box::new(server_side), target_addr.clone());

        datagram.send(make_packet(b"hello".to_vec())).await.unwrap();

        let mut buf = vec![0u8; 7];
        client_side.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf[..2], &[0x00, 0x05]);
        assert_eq!(&buf[2..], b"hello");
    }

    #[tokio::test]
    async fn test_write_empty_packet() {
        let (mut client_side, server_side) = duplex(4096);
        let target_addr = make_target_addr();
        let mut datagram =
            OutboundDatagramUotV2::new(Box::new(server_side), target_addr);

        datagram.send(make_packet(vec![])).await.unwrap();

        let mut buf = vec![0u8; 2];
        client_side.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, &[0x00, 0x00]);
    }

    #[tokio::test]
    async fn test_write_oversized_packet_returns_error() {
        let (_client_side, server_side) = duplex(4096);
        let target_addr = make_target_addr();
        let mut datagram =
            OutboundDatagramUotV2::new(Box::new(server_side), target_addr);

        let oversized = vec![0u8; MAX_PACKET_LENGTH + 1];
        let result = datagram.send(make_packet(oversized)).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn test_write_then_read_wire_bytes() {
        let (mut client_side, server_side) = duplex(4096);
        let target_addr = make_target_addr();
        let mut datagram =
            OutboundDatagramUotV2::new(Box::new(server_side), target_addr);

        let payload = b"round-trip-uot";
        datagram.send(make_packet(payload.to_vec())).await.unwrap();

        let expected_len = payload.len();
        let mut buf = vec![0u8; 2 + expected_len];
        client_side.read_exact(&mut buf).await.unwrap();

        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        assert_eq!(len, expected_len);
        assert_eq!(&buf[2..], payload);
    }
}

