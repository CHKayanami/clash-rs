use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::{self, Error, ErrorKind};

use crate::session::SocksAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionStatus {
    New = 0x01,
    Keep = 0x02,
    End = 0x03,
    KeepAlive = 0x04,
}

impl TryFrom<u8> for SessionStatus {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(SessionStatus::New),
            0x02 => Ok(SessionStatus::Keep),
            0x03 => Ok(SessionStatus::End),
            0x04 => Ok(SessionStatus::KeepAlive),
            other => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid XUDP session status: {}", other),
            )),
        }
    }
}

pub struct FrameOption;

impl FrameOption {
    pub const DATA: u8 = 0x01;
}

pub const MAX_XUDP_METADATA_LEN: usize = 512;
pub const MAX_XUDP_PAYLOAD_LEN: usize = 65535;

#[derive(Debug)]
pub struct IncomingFrame {
    pub session_id: u16,
    pub status: SessionStatus,
    pub peer_addr: Option<SocksAddr>,
    pub payload: Option<Bytes>,
}

pub struct XudpFrame;

impl XudpFrame {
    pub fn encode_data_frame(
        session_id: u16,
        is_first: bool,
        dst_addr: Option<&SocksAddr>,
        payload: &[u8],
    ) -> io::Result<Bytes> {
        let mut buf = BytesMut::with_capacity(128 + payload.len());
        let frame_len_pos = buf.len();
        buf.put_u16(0); // placeholder for metadata length

        let header_start = buf.len();
        buf.put_u16(session_id);
        buf.put_u8(if is_first {
            SessionStatus::New as u8
        } else {
            SessionStatus::Keep as u8
        });
        buf.put_u8(FrameOption::DATA);

        if is_first || dst_addr.is_some() {
            buf.put_u8(2); // NetworkUDP = 2
            if let Some(addr) = dst_addr {
                addr.write_to_buf_vmess(&mut buf);
            }
        }

        let metadata_len = buf.len() - header_start;
        buf[frame_len_pos..frame_len_pos + 2]
            .copy_from_slice(&(metadata_len as u16).to_be_bytes());

        buf.put_u16(payload.len() as u16);
        buf.put_slice(payload);

        Ok(buf.freeze())
    }

    pub fn encode_end_frame(session_id: u16) -> Bytes {
        let mut buf = BytesMut::with_capacity(8);
        buf.put_u16(4); // metadata length = 4
        buf.put_u16(session_id);
        buf.put_u8(SessionStatus::End as u8);
        buf.put_u8(0); // option = 0 (no data)
        buf.freeze()
    }
}

pub fn read_addr_port_vmess_sync(
    buf: &mut std::io::Cursor<&[u8]>,
) -> io::Result<SocksAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    if buf.remaining() < 3 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "too short"));
    }
    let port = buf.get_u16();
    let atyp = buf.get_u8();
    match atyp {
        0x01 => {
            if buf.remaining() < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "too short for ipv4",
                ));
            }
            let mut ip = [0u8; 4];
            buf.copy_to_slice(&mut ip);
            Ok(SocksAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(ip)),
                port,
            )))
        }
        0x03 => {
            if buf.remaining() < 16 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "too short for ipv6",
                ));
            }
            let mut ip = [0u8; 16];
            buf.copy_to_slice(&mut ip);
            Ok(SocksAddr::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(ip)),
                port,
            )))
        }
        0x02 => {
            if buf.remaining() < 1 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "too short for domain len",
                ));
            }
            let len = buf.get_u8() as usize;
            if buf.remaining() < len {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "too short for domain name",
                ));
            }
            let mut name_buf = [0u8; 255];
            buf.copy_to_slice(&mut name_buf[..len]);
            let domain = std::str::from_utf8(&name_buf[..len])
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid domain")
                })?
                .to_string();
            Ok(SocksAddr::Domain(domain, port))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid address type",
        )),
    }
}

pub fn parse_peer_addr_vmess(metadata: &[u8]) -> io::Result<SocksAddr> {
    if metadata.len() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XUDP metadata too short for address",
        ));
    }
    // metadata[0..2] is session_id, [2] is status, [3] is option, [4] is network (2 for UDP)
    let mut cursor = std::io::Cursor::new(&metadata[5..]);
    read_addr_port_vmess_sync(&mut cursor)
}

/// Zero-copy incremental frame decoder from `BytesMut` buffer.
/// Returns:
/// - `Ok(Some(frame))` when a complete frame is decoded (consumed from `buf`)
/// - `Ok(None)` when more data is needed
/// - `Err(e)` on protocol error
pub fn decode_xudp_frame_from_buf(
    buf: &mut BytesMut,
) -> io::Result<Option<IncomingFrame>> {
    if buf.len() < 2 {
        return Ok(None);
    }

    let metadata_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if !(4..=MAX_XUDP_METADATA_LEN).contains(&metadata_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid XUDP metadata length: {}", metadata_len),
        ));
    }

    let header_total = 2 + metadata_len;
    if buf.len() < header_total {
        return Ok(None);
    }

    let option = buf[5];
    let has_data = (option & FrameOption::DATA) != 0;

    let payload_len = if has_data {
        if buf.len() < header_total + 2 {
            return Ok(None);
        }
        let plen = u16::from_be_bytes([buf[header_total], buf[header_total + 1]]) as usize;
        if plen > MAX_XUDP_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("XUDP payload length exceeds maximum: {}", plen),
            ));
        }
        plen
    } else {
        0
    };

    let frame_total = header_total + if has_data { 2 + payload_len } else { 0 };
    if buf.len() < frame_total {
        return Ok(None);
    }

    // Parse metadata
    let session_id = u16::from_be_bytes([buf[2], buf[3]]);
    let status = SessionStatus::try_from(buf[4])?;
    let peer_addr = if metadata_len > 4 {
        parse_peer_addr_vmess(&buf[2..2 + metadata_len]).ok()
    } else {
        None
    };

    // Advance past metadata length (2) + metadata body (metadata_len) + payload length field (2 if has_data)
    buf.advance(header_total + if has_data { 2 } else { 0 });

    let payload = if has_data {
        Some(buf.split_to(payload_len).freeze())
    } else {
        None
    };

    Ok(Some(IncomingFrame {
        session_id,
        status,
        peer_addr,
        payload,
    }))
}
