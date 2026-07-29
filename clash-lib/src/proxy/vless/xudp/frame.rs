#![allow(dead_code, unused_imports)]

use bytes::{BufMut, BytesMut};
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

#[derive(Debug, Clone, Copy)]
pub struct FrameOption(pub u8);

impl FrameOption {
    pub const DATA: u8 = 0x01;
    pub const ERROR: u8 = 0x02;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn with_data(mut self) -> Self {
        self.0 |= Self::DATA;
        self
    }

    pub fn has_data(&self) -> bool {
        (self.0 & Self::DATA) != 0
    }
}

#[derive(Debug, Clone)]
pub struct XudpFrame {
    pub session_id: u16,
    pub status: SessionStatus,
    pub option: FrameOption,
    pub dst_addr: Option<SocksAddr>,
    pub payload: Vec<u8>,
}

impl XudpFrame {
    pub fn encode_payload(&self, payload: &[u8], buf: &mut BytesMut) -> io::Result<()> {
        let frame_len_pos = buf.len();
        buf.put_u16(0); // placeholder for frame length

        let header_start = buf.len();
        buf.put_u16(self.session_id);
        buf.put_u8(self.status as u8);
        buf.put_u8(self.option.0);
        if self.status == SessionStatus::New || self.dst_addr.is_some() {
            buf.put_u8(2); // NetworkUDP = 2
            if let Some(ref addr) = self.dst_addr {
                addr.write_to_buf_vmess(buf);
            }
        }

        let frame_len = buf.len() - header_start;
        buf[frame_len_pos..frame_len_pos + 2].copy_from_slice(&(frame_len as u16).to_be_bytes());

        buf.put_u16(payload.len() as u16);
        buf.put_slice(payload);
        Ok(())
    }

    pub fn encode(&self, buf: &mut BytesMut) -> io::Result<()> {
        self.encode_payload(&self.payload, buf)
    }
}
