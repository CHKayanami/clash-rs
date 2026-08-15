use bytes::{BufMut, BytesMut};
use http::{Method, Request, Uri};
use rand::RngExt;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::session::SocksAddr;

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
#[allow(dead_code)]
pub const FLAG_ADDR: u16 = 0x0002;

pub const STATUS_SUCCESS: u8 = 0;
#[allow(dead_code)]
pub const STATUS_ERROR: u8 = 1;

pub const MIN_PADDING: u16 = 256;
pub const MAX_PADDING: u16 = 767;

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
        let mut buf = BytesMut::with_capacity(64);
        let mut flags: u16 = 0;
        if self.is_udp {
            flags |= FLAG_UDP;
        }
        buf.put_u16(flags);

        match &self.destination {
            SocksAddr::Ip(addr) => match addr.ip() {
                std::net::IpAddr::V4(ip) => {
                    buf.put_u8(0x01);
                    buf.put_slice(&ip.octets());
                    buf.put_u16(addr.port());
                }
                std::net::IpAddr::V6(ip) => {
                    buf.put_u8(0x04);
                    buf.put_slice(&ip.octets());
                    buf.put_u16(addr.port());
                }
            },
            SocksAddr::Domain(host, port) => {
                let host_bytes = host.as_bytes();
                if host_bytes.len() > 255 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("hostname too long: {} bytes", host_bytes.len()),
                    ));
                }
                buf.put_u8(0x03);
                buf.put_u8(host_bytes.len() as u8);
                buf.put_slice(host_bytes);
                buf.put_u16(*port);
            }
        }

        Ok(buf)
    }
}

/// Response returned on the stream by the sing-box server.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct StreamResponse {
    pub status: u8,
    pub message: Option<String>,
}

#[allow(dead_code)]
impl StreamResponse {
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let status = reader.read_u8().await?;
        let message = if status != STATUS_SUCCESS {
            let len = reader.read_u8().await? as usize;
            if len > 0 {
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf).await?;
                Some(String::from_utf8_lossy(&buf).to_string())
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self { status, message })
    }
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
