use bytes::{BufMut, BytesMut};
use http::{Method, Request, Uri};
use rand::RngExt;
use std::io;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::session::{Session, SocksAddr};

pub const MUX_DESTINATION_HOST: &str = "sp.mux.sing-box.arpa";
pub const MUX_DESTINATION_PORT: u16 = 444;

pub const VERSION_0: u8 = 0; // No padding
pub const VERSION_1: u8 = 1; // With padding support

#[allow(dead_code)]
pub const PROTOCOL_SMUX: u8 = 0;
#[allow(dead_code)]
pub const PROTOCOL_YAMUX: u8 = 1;
pub const PROTOCOL_H2MUX: u8 = 2;

pub const FLAG_UDP: u16 = 0x0001;
pub const FLAG_ADDR: u16 = 0x0002;

pub const STATUS_SUCCESS: u8 = 0;
#[allow(dead_code)]
pub const STATUS_ERROR: u8 = 1;

pub const MIN_PADDING: u16 = 256;
pub const MAX_PADDING: u16 = 767;

pub fn carrier_session(sess: &Session) -> Session {
    Session {
        destination: SocksAddr::Domain(MUX_DESTINATION_HOST.into(), MUX_DESTINATION_PORT),
        ..sess.clone()
    }
}

/// Session request sent over the raw carrier before HTTP/2 handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRequest {
    pub version: u8,
    pub protocol: u8,
    pub padding: bool,
}

impl SessionRequest {
    pub fn new_h2mux(padding: bool) -> Self {
        Self {
            version: if padding { VERSION_1 } else { VERSION_0 },
            protocol: PROTOCOL_H2MUX,
            padding,
        }
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(256);
        buf.put_u8(self.version);
        buf.put_u8(self.protocol);

        if self.version >= VERSION_1 {
            buf.put_u8(self.padding as u8);
            if self.padding {
                let padding_len = rand::rng().random_range(MIN_PADDING..=MAX_PADDING);
                buf.put_u16(padding_len);
                buf.put_bytes(0, padding_len as usize);
            }
        }
        buf
    }

    pub async fn write<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        let encoded = self.encode();
        writer.write_all(&encoded).await?;
        writer.flush().await
    }
}

/// Stream-level request header carrying the real destination address.
#[derive(Debug, Clone)]
pub struct StreamRequest {
    pub destination: SocksAddr,
    pub is_udp: bool,
}

impl StreamRequest {
    pub fn new(destination: SocksAddr, is_udp: bool) -> Self {
        Self {
            destination,
            is_udp,
        }
    }

    pub fn encode(&self) -> io::Result<BytesMut> {
        if let SocksAddr::Domain(host, _) = &self.destination {
            if host.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("hostname too long: {} bytes", host.len()),
                ));
            }
        }
        let mut buf = BytesMut::with_capacity(2 + self.destination.size());
        let mut flags: u16 = 0;
        if self.is_udp {
            // UDP uses packet-address mode, allowing a destination per packet.
            flags |= FLAG_UDP | FLAG_ADDR;
        }
        buf.put_u16(flags);

        self.destination.write_buf(&mut buf);

        Ok(buf)
    }
}

const MAX_ERROR_MESSAGE: u64 = 64 * 1024;

/// Decode the sing-mux status and unsigned-varint message length incrementally.
/// The returned size excludes any application payload following the response.
pub(super) fn parse_stream_response(buf: &[u8]) -> io::Result<Option<(usize, Option<String>)>> {
    let Some(&status) = buf.first() else { return Ok(None); };
    if status == STATUS_SUCCESS {
        return Ok(Some((1, None)));
    }
    if status != STATUS_ERROR {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid h2mux response status"));
    }
    let mut len = 0u64;
    for index in 0..10 {
        let Some(&byte) = buf.get(index + 1) else { return Ok(None); };
        if index == 9 && byte > 1 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "h2mux response varint overflow"));
        }
        len |= u64::from(byte & 0x7f) << (index * 7);
        if len > MAX_ERROR_MESSAGE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "h2mux error message too large"));
        }
        if byte & 0x80 == 0 {
            let start = index + 2;
            let end = start + len as usize;
            if buf.len() < end { return Ok(None); }
            return Ok(Some((end, Some(String::from_utf8_lossy(&buf[start..end]).into_owned()))));
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "h2mux response varint overflow"))
}

pub fn build_h2_connect_request() -> io::Result<Request<()>> {
    let authority = format!("{MUX_DESTINATION_HOST}:{MUX_DESTINATION_PORT}");
    let uri: Uri = authority
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .version(http::Version::HTTP_2)
        .body(())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

#[cfg(test)]
mod response_tests {
    use super::*;

    #[test]
    fn response_varint_is_incremental_and_bounded() {
        assert!(parse_stream_response(&[1, 0xac]).unwrap().is_none());
        let mut response = vec![1, 0xac, 2]; // message length 300
        response.extend_from_slice(&[b'x'; 300]);
        let (size, message) = parse_stream_response(&response).unwrap().unwrap();
        assert_eq!(size, 303);
        assert_eq!(message.unwrap(), "x".repeat(300));
        assert_eq!(parse_stream_response(&[0, 42]).unwrap(), Some((1, None)));
        for wire in [&[2][..], &[1, 0xff, 0xff, 0x7f], &[1, 0x80, 0x80, 0x80, 0x80,
            0x80, 0x80, 0x80, 0x80, 0x80, 2]] {
            assert_eq!(parse_stream_response(wire).unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
    }
}
