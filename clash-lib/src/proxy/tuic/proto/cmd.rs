use bytes::{Buf, BufMut, BytesMut};
use uuid::Uuid;

use super::header::CmdType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Auth {
        uuid: Uuid,
        token: [u8; 32],
    },
    Connect,
    Packet {
        assoc_id: u16,
        pkt_id: u16,
        frag_total: u8,
        frag_id: u8,
        size: u16,
    },
    Dissociate {
        assoc_id: u16,
    },
    Heartbeat,
}

impl Command {
    #[allow(dead_code)]
    pub fn cmd_type(&self) -> CmdType {
        match self {
            Command::Auth { .. } => CmdType::Auth,
            Command::Connect => CmdType::Connect,
            Command::Packet { .. } => CmdType::Packet,
            Command::Dissociate { .. } => CmdType::Dissociate,
            Command::Heartbeat => CmdType::Heartbeat,
        }
    }

    pub fn encode(&self, dst: &mut BytesMut) {
        match self {
            Command::Auth { uuid, token } => {
                dst.reserve(16 + 32);
                dst.put_slice(uuid.as_bytes());
                dst.put_slice(token);
            }
            Command::Connect => {}
            Command::Packet {
                assoc_id,
                pkt_id,
                frag_total,
                frag_id,
                size,
            } => {
                dst.reserve(2 + 2 + 1 + 1 + 2);
                dst.put_u16(*assoc_id);
                dst.put_u16(*pkt_id);
                dst.put_u8(*frag_total);
                dst.put_u8(*frag_id);
                dst.put_u16(*size);
            }
            Command::Dissociate { assoc_id } => {
                dst.reserve(2);
                dst.put_u16(*assoc_id);
            }
            Command::Heartbeat => {}
        }
    }

    pub fn decode(cmd_type: CmdType, buf: &mut impl Buf) -> Result<Self, super::ProtoError> {
        match cmd_type {
            CmdType::Auth => {
                if buf.remaining() < 16 + 32 {
                    return Err(super::ProtoError::Incomplete("auth payload"));
                }
                let mut uuid_bytes = [0u8; 16];
                buf.copy_to_slice(&mut uuid_bytes);
                let mut token = [0u8; 32];
                buf.copy_to_slice(&mut token);
                Ok(Command::Auth {
                    uuid: Uuid::from_bytes(uuid_bytes),
                    token,
                })
            }
            CmdType::Connect => Ok(Command::Connect),
            CmdType::Packet => {
                if buf.remaining() < 2 + 2 + 1 + 1 + 2 {
                    return Err(super::ProtoError::Incomplete("packet payload"));
                }
                let assoc_id = buf.get_u16();
                let pkt_id = buf.get_u16();
                let frag_total = buf.get_u8();
                let frag_id = buf.get_u8();
                let size = buf.get_u16();
                Ok(Command::Packet {
                    assoc_id,
                    pkt_id,
                    frag_total,
                    frag_id,
                    size,
                })
            }
            CmdType::Dissociate => {
                if buf.remaining() < 2 {
                    return Err(super::ProtoError::Incomplete("dissociate payload"));
                }
                let assoc_id = buf.get_u16();
                Ok(Command::Dissociate { assoc_id })
            }
            CmdType::Heartbeat => Ok(Command::Heartbeat),
            CmdType::Other(_) => Err(super::ProtoError::InvalidCommand),
        }
    }
}
