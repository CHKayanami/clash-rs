#![allow(dead_code, unused_imports)]

use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
};

use bytes::{Buf, BytesMut};

use super::frame::SessionStatus;
use crate::proxy::datagram::UdpPacket;
use crate::session::SocksAddr;

pub struct XudpCodec {
    read_state: XudpCodecReadState,
    session_to_destination: HashMap<u16, SocksAddr>,
}

enum XudpCodecReadState {
    WaitingHeader,
    WaitingFrameAndPayloadLen {
        option: u8,
        status: SessionStatus,
        session_id: u16,
    },
    WaitingPayloadLen {
        option: u8,
        status: SessionStatus,
        session_id: u16,
    },
    WaitingPayload {
        payload_len: usize,
        src_addr: SocksAddr,
        session_id: u16,
        status: SessionStatus,
    },
}

impl XudpCodec {
    pub fn new() -> Self {
        Self {
            read_state: XudpCodecReadState::WaitingHeader,
            session_to_destination: HashMap::new(),
        }
    }

    pub fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<UdpPacket>> {
        loop {
            match &self.read_state {
                XudpCodecReadState::WaitingHeader => {
                    if buf.len() < 2 {
                        return Ok(None);
                    }
                    let header_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;

                    if header_len == 0 {
                        buf.advance(2);
                        continue;
                    }

                    if buf.len() < 2 + header_len {
                        return Ok(None);
                    }

                    buf.advance(2); // Consume header length u16
                    let header_data = buf.split_to(header_len);

                    if header_len < 4 {
                        return Err(Error::new(ErrorKind::InvalidData, "XUDP header too short"));
                    }

                    let session_id = u16::from_be_bytes([header_data[0], header_data[1]]);
                    let status = SessionStatus::try_from(header_data[2])?;
                    let option = header_data[3];

                    if status == SessionStatus::New {
                        let mut cursor = std::io::Cursor::new(&header_data[4..]);
                        let network = if cursor.remaining() > 0 {
                            cursor.get_u8()
                        } else {
                            0
                        };
                        let _ = network;
                        let addr = read_addr_port_vmess_sync(&mut cursor)?;
                        self.session_to_destination.insert(session_id, addr.clone());
                        self.read_state = XudpCodecReadState::WaitingPayloadLen {
                            option,
                            status,
                            session_id,
                        };
                    } else if status == SessionStatus::Keep {
                        self.read_state = XudpCodecReadState::WaitingPayloadLen {
                            option,
                            status,
                            session_id,
                        };
                    } else if status == SessionStatus::End || status == SessionStatus::KeepAlive {
                        self.read_state = XudpCodecReadState::WaitingPayloadLen {
                            option,
                            status,
                            session_id,
                        };
                    }
                }
                XudpCodecReadState::WaitingPayloadLen { option, status, session_id } => {
                    let opt = *option;
                    let stat = *status;
                    let sid = *session_id;

                    if buf.len() < 2 {
                        return Ok(None);
                    }
                    let payload_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    buf.advance(2);

                    let src_addr = self
                        .session_to_destination
                        .get(&sid)
                        .cloned()
                        .unwrap_or_else(SocksAddr::any_ipv4);

                    if (opt & 1) == 1 {
                        self.read_state = XudpCodecReadState::WaitingPayload {
                            payload_len,
                            src_addr,
                            session_id: sid,
                            status: stat,
                        };
                    } else {
                        if stat == SessionStatus::End {
                            self.session_to_destination.remove(&sid);
                        }
                        self.read_state = XudpCodecReadState::WaitingHeader;
                    }
                }
                XudpCodecReadState::WaitingPayload {
                    payload_len,
                    src_addr,
                    session_id,
                    status,
                } => {
                    let p_len = *payload_len;
                    let sid = *session_id;
                    let stat = *status;
                    if buf.len() < p_len {
                        return Ok(None);
                    }

                    let payload = buf.split_to(p_len).freeze();
                    let packet = UdpPacket::new(payload, src_addr.clone(), SocksAddr::any_ipv4());

                    if stat == SessionStatus::End {
                        self.session_to_destination.remove(&sid);
                    }

                    self.read_state = XudpCodecReadState::WaitingHeader;
                    return Ok(Some(packet));
                }
                XudpCodecReadState::WaitingFrameAndPayloadLen { .. } => {
                    self.read_state = XudpCodecReadState::WaitingHeader;
                }
            }
        }
    }
}

fn read_addr_port_vmess_sync(buf: &mut std::io::Cursor<&[u8]>) -> io::Result<SocksAddr> {
    if buf.remaining() < 3 {
        return Err(Error::new(ErrorKind::UnexpectedEof, "too short"));
    }
    let port = buf.get_u16();
    let atyp = buf.get_u8();
    match atyp {
        0x01 => {
            if buf.remaining() < 4 {
                return Err(Error::new(ErrorKind::UnexpectedEof, "too short for ipv4"));
            }
            let mut ip = [0u8; 4];
            buf.copy_to_slice(&mut ip);
            Ok(SocksAddr::Ip(std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)),
                port,
            )))
        }
        0x03 => {
            if buf.remaining() < 16 {
                return Err(Error::new(ErrorKind::UnexpectedEof, "too short for ipv6"));
            }
            let mut ip = [0u8; 16];
            buf.copy_to_slice(&mut ip);
            Ok(SocksAddr::Ip(std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                port,
            )))
        }
        0x02 => {
            if buf.remaining() < 1 {
                return Err(Error::new(ErrorKind::UnexpectedEof, "too short for domain len"));
            }
            let len = buf.get_u8() as usize;
            if buf.remaining() < len {
                return Err(Error::new(ErrorKind::UnexpectedEof, "too short for domain name"));
            }
            let mut domain = vec![0u8; len];
            buf.copy_to_slice(&mut domain);
            let domain_str = String::from_utf8(domain)
                .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
            Ok(SocksAddr::Domain(domain_str, port))
        }
        _ => Err(Error::new(ErrorKind::InvalidData, format!("unknown atyp 0x{:02x}", atyp))),
    }
}
