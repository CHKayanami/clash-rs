use bytes::{Buf, BufMut, BytesMut};
use std::fmt;

pub const VER: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CmdType {
    Auth = 0,
    Connect = 1,
    Packet = 2,
    Dissociate = 3,
    Heartbeat = 4,
    Other(u8),
}

impl From<u8> for CmdType {
    fn from(val: u8) -> Self {
        match val {
            0 => CmdType::Auth,
            1 => CmdType::Connect,
            2 => CmdType::Packet,
            3 => CmdType::Dissociate,
            4 => CmdType::Heartbeat,
            other => CmdType::Other(other),
        }
    }
}

impl From<CmdType> for u8 {
    fn from(cmd: CmdType) -> Self {
        match cmd {
            CmdType::Auth => 0,
            CmdType::Connect => 1,
            CmdType::Packet => 2,
            CmdType::Dissociate => 3,
            CmdType::Heartbeat => 4,
            CmdType::Other(other) => other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub command: CmdType,
}

impl Header {
    pub fn new(command: CmdType) -> Self {
        Self {
            version: VER,
            command,
        }
    }

    pub fn encode(&self, dst: &mut BytesMut) {
        dst.reserve(2);
        dst.put_u8(self.version);
        dst.put_u8(u8::from(self.command));
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, super::ProtoError> {
        if buf.remaining() < 2 {
            return Err(super::ProtoError::Incomplete("header"));
        }
        let version = buf.get_u8();
        if version != VER {
            return Err(super::ProtoError::InvalidVersion(version));
        }
        let command = CmdType::from(buf.get_u8());
        if matches!(command, CmdType::Other(_)) {
            return Err(super::ProtoError::InvalidCommand);
        }
        Ok(Self { version, command })
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TUIC Header(v{}, cmd={:?})", self.version, self.command)
    }
}
