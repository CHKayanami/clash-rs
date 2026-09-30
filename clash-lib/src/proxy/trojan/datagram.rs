use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    pin::Pin,
    str::from_utf8,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{Sink, Stream, ready};
use tokio::io::AsyncWrite;
use tokio_util::io::poll_read_buf;
use tracing::debug;

use crate::{
    proxy::{AnyStream, datagram::UdpPacket},
    session::{SocksAddr, SocksAddrType},
};

pub struct OutboundDatagramTrojan {
    inner: AnyStream,
    remote_addr: SocksAddr,
    read_buf: BytesMut,
    read_done: bool,
    write_buf: BytesMut,
    written: usize,
    flushed: bool,
}

impl OutboundDatagramTrojan {
    pub fn new(inner: AnyStream, remote_addr: SocksAddr) -> Self {
        Self {
            inner,
            remote_addr,
            read_buf: BytesMut::new(),
            read_done: false,
            write_buf: BytesMut::new(),
            written: 0,
            flushed: true,
        }
    }
}

impl Sink<UdpPacket> for OutboundDatagramTrojan {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.as_mut().poll_flush(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: UdpPacket) -> io::Result<()> {
        if !self.flushed {
            return Err(io::Error::other("previous Trojan UDP packet is pending"));
        }
        if item.data.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Trojan UDP packet exceeds u16 length",
            ));
        }

        self.write_buf.clear();
        item.dst_addr.write_buf(&mut self.write_buf);
        self.write_buf.put_u16(item.data.len() as u16);
        self.write_buf.put_slice(b"\r\n");
        self.write_buf.put_slice(&item.data);
        self.written = 0;
        self.flushed = false;
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        while self.written < self.write_buf.len() {
            let n = {
                let this = &mut *self;
                ready!(
                    Pin::new(&mut this.inner)
                        .poll_write(cx, &this.write_buf[this.written..])
                )?
            };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write Trojan UDP packet",
                )));
            }
            self.written += n;
        }

        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        self.write_buf.clear();
        self.written = 0;
        self.flushed = true;
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn parse_packet(buf: &[u8]) -> io::Result<Option<(SocksAddr, usize, usize)>> {
    if buf.is_empty() {
        return Ok(None);
    }

    let addr_len = match buf[0] {
        SocksAddrType::V4 => 1 + 4,
        SocksAddrType::V6 => 1 + 16,
        SocksAddrType::DOMAIN => {
            if buf.len() < 2 {
                return Ok(None);
            }
            2 + buf[1] as usize
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Trojan UDP address type",
            ));
        }
    };
    let header_len = addr_len + 2 + 2 + 2; // port, payload length, CRLF
    if buf.len() < header_len {
        return Ok(None);
    }

    let port = u16::from_be_bytes([buf[addr_len], buf[addr_len + 1]]);
    let addr = match buf[0] {
        SocksAddrType::V4 => {
            SocksAddr::from((Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]), port))
        }
        SocksAddrType::V6 => {
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[1..17]).unwrap());
            SocksAddr::from((ip, port))
        }
        SocksAddrType::DOMAIN => {
            let domain = from_utf8(&buf[2..addr_len]).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Trojan UDP domain",
                )
            })?;
            SocksAddr::try_from((domain.to_owned(), port))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        }
        _ => unreachable!(),
    };

    let data_len =
        u16::from_be_bytes([buf[addr_len + 2], buf[addr_len + 3]]) as usize;
    if &buf[addr_len + 4..header_len] != b"\r\n" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Trojan UDP separator",
        ));
    }
    let frame_len = header_len + data_len;
    if buf.len() < frame_len {
        return Ok(None);
    }

    Ok(Some((addr, header_len, frame_len)))
}

impl Stream for OutboundDatagramTrojan {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if self.read_done {
            return Poll::Ready(None);
        }

        loop {
            match parse_packet(&self.read_buf) {
                Ok(Some((addr, header_len, frame_len))) => {
                    let mut frame = self.read_buf.split_to(frame_len);
                    frame.advance(header_len);
                    return Poll::Ready(Some(UdpPacket {
                        data: frame.freeze(),
                        src_addr: self.remote_addr.clone(),
                        dst_addr: addr,
                        inbound_user: None,
                    }));
                }
                Ok(None) => {}
                Err(err) => {
                    debug!("invalid Trojan UDP frame: {err}");
                    self.read_done = true;
                    return Poll::Ready(None);
                }
            }

            let this = &mut *self;
            this.read_buf.reserve(4096);
            match ready!(poll_read_buf(
                Pin::new(&mut this.inner),
                cx,
                &mut this.read_buf,
            )) {
                Ok(0) => {
                    if !self.read_buf.is_empty() {
                        debug!("Trojan UDP stream ended mid-frame");
                    }
                    self.read_done = true;
                    return Poll::Ready(None);
                }
                Ok(_) => {}
                Err(err) => {
                    debug!("failed to read Trojan UDP stream: {err}");
                    self.read_done = true;
                    return Poll::Ready(None);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures::{SinkExt, StreamExt, poll};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, duplex},
        spawn,
    };

    fn packet(addr: SocksAddr, data: &'static [u8]) -> UdpPacket {
        UdpPacket::new(Bytes::from_static(data), SocksAddr::any_ipv4(), addr)
    }

    fn frame(addr: &SocksAddr, data: &[u8]) -> Vec<u8> {
        let mut buf = BytesMut::new();
        addr.write_buf(&mut buf);
        buf.put_u16(data.len() as u16);
        buf.put_slice(b"\r\n");
        buf.put_slice(data);
        buf.to_vec()
    }

    #[tokio::test]
    async fn flush_resumes_after_partial_write() {
        let addr = SocksAddr::try_from(("example.org".to_owned(), 53)).unwrap();
        let expected = frame(&addr, b"hello world");
        let (client, mut server) = duplex(3);
        let mut datagram =
            OutboundDatagramTrojan::new(AnyStream::new(client), addr.clone());
        Pin::new(&mut datagram)
            .start_send(packet(addr, b"hello world"))
            .unwrap();

        assert!(matches!(poll!(datagram.flush()), Poll::Pending));

        let reader = spawn(async move {
            let mut received = Vec::new();
            server.read_to_end(&mut received).await.unwrap();
            received
        });
        datagram.close().await.unwrap();
        assert_eq!(reader.await.unwrap(), expected);
    }

    #[tokio::test]
    async fn fragmented_frames_preserve_read_progress() {
        let addr = SocksAddr::try_from(("example.org".to_owned(), 53)).unwrap();
        let remote = SocksAddr::any_ipv4();
        let first = frame(&addr, b"hello");
        let second = frame(&addr, b"next");
        let (mut server, client) = duplex(128);
        let mut datagram =
            OutboundDatagramTrojan::new(AnyStream::new(client), remote);

        server.write_all(&first[..3]).await.unwrap();
        assert!(matches!(poll!(datagram.next()), Poll::Pending));
        server.write_all(&first[3..first.len() - 2]).await.unwrap();
        assert!(matches!(poll!(datagram.next()), Poll::Pending));
        server.write_all(&first[first.len() - 2..]).await.unwrap();
        server.write_all(&second).await.unwrap();

        let received = datagram.next().await.unwrap();
        assert_eq!(received.dst_addr, addr);
        assert_eq!(received.data.as_ref(), b"hello");
        assert_eq!(datagram.next().await.unwrap().data.as_ref(), b"next");
        drop(server);
        assert!(datagram.next().await.is_none());
    }
}
