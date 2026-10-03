pub mod addr;
pub mod cmd;
pub mod fragment;
pub mod header;

pub use addr::Address;
pub use cmd::Command;
pub use header::{CmdType, Header};
use thiserror::Error;

use bytes::{BufMut, Bytes, BytesMut};
use uuid::Uuid;

pub const MAX_PACKET_FRAME_SIZE: usize = u16::MAX as usize + 10 + 259;

#[derive(Error, Debug)]
pub enum ProtoError {
    #[error("incomplete TUIC frame data: {0}")]
    Incomplete(&'static str),
    #[error("invalid TUIC protocol version: {0}, expected 5")]
    InvalidVersion(u8),
    #[error("invalid TUIC command")]
    InvalidCommand,
    #[error("invalid TUIC address type")]
    InvalidAddressType,
    #[error("invalid domain in TUIC address")]
    InvalidDomain,
    #[error("empty TUIC address")]
    EmptyAddress,
    #[error("packet payload exceeds maximum size")]
    PayloadTooLarge,
    #[error("TUIC frame exceeds available datagram size")]
    DatagramTooSmall,
    #[error("TUIC packet requires more than 255 fragments")]
    TooManyFragments,
    #[error("TUIC packet payload size does not match frame")]
    InvalidPayloadSize,
}

/// Encode authentication frame: Header(Auth) + Command::Auth
pub fn encode_auth(uuid: Uuid, token: [u8; 32]) -> Bytes {
    let mut buf = BytesMut::with_capacity(2 + 16 + 32);
    Header::new(CmdType::Auth).encode(&mut buf);
    Command::Auth { uuid, token }.encode(&mut buf);
    buf.freeze()
}

/// Encode heartbeat frame: Header(Heartbeat) + Command::Heartbeat
pub fn encode_heartbeat() -> Bytes {
    let mut buf = BytesMut::with_capacity(2);
    Header::new(CmdType::Heartbeat).encode(&mut buf);
    Command::Heartbeat.encode(&mut buf);
    buf.freeze()
}

/// Encode dissociate frame: Header(Dissociate) + Command::Dissociate
pub fn encode_dissociate(assoc_id: u16) -> Bytes {
    let mut buf = BytesMut::with_capacity(2 + 2);
    Header::new(CmdType::Dissociate).encode(&mut buf);
    Command::Dissociate { assoc_id }.encode(&mut buf);
    buf.freeze()
}

/// Encode connect frame prefix for bidirectional stream: Header(Connect) + Command::Connect + Address
pub fn encode_connect_prefix(addr: &Address) -> Bytes {
    let mut buf = BytesMut::with_capacity(64);
    Header::new(CmdType::Connect).encode(&mut buf);
    Command::Connect.encode(&mut buf);
    addr.encode(&mut buf);
    buf.freeze()
}

/// Encode a single UDP packet: Header(Packet) + Command::Packet + Address + Payload
pub fn encode_single_packet(
    assoc_id: u16,
    pkt_id: u16,
    addr: &Address,
    payload: &[u8],
) -> Result<Bytes, ProtoError> {
    encode_packet_fragment(assoc_id, pkt_id, 1, 0, addr, payload)
}

fn encode_packet_fragment(
    assoc_id: u16,
    pkt_id: u16,
    frag_total: u8,
    frag_id: u8,
    addr: &Address,
    payload: &[u8],
) -> Result<Bytes, ProtoError> {
    if payload.len() > u16::MAX as usize {
        return Err(ProtoError::PayloadTooLarge);
    }
    let mut buf =
        BytesMut::with_capacity(10 + encoded_address_len(addr) + payload.len());
    Header::new(CmdType::Packet).encode(&mut buf);
    Command::Packet {
        assoc_id,
        pkt_id,
        frag_total,
        frag_id,
        size: payload.len() as u16,
    }
    .encode(&mut buf);
    addr.encode(&mut buf);
    buf.put_slice(payload);
    Ok(buf.freeze())
}

fn encoded_address_len(addr: &Address) -> usize {
    match addr {
        Address::None => 1,
        Address::IPv4(..) => 7,
        Address::IPv6(..) => 19,
        Address::Domain(domain, _) => 4 + domain.len().min(u8::MAX as usize),
    }
}

/// Encode UDP fragments lazily so the sender holds only one frame at a time.
pub fn packet_fragments<'a>(
    assoc_id: u16,
    pkt_id: u16,
    addr: &'a Address,
    payload: &'a [u8],
    max_datagram_size: usize,
) -> Result<impl Iterator<Item = Result<Bytes, ProtoError>> + 'a, ProtoError> {
    if payload.len() > u16::MAX as usize {
        return Err(ProtoError::PayloadTooLarge);
    }
    let first_capacity = max_datagram_size
        .checked_sub(10 + encoded_address_len(addr))
        .filter(|size| *size > 0)
        .ok_or(ProtoError::DatagramTooSmall)?;
    let later_capacity = max_datagram_size
        .checked_sub(11)
        .filter(|size| *size > 0)
        .ok_or(ProtoError::DatagramTooSmall)?;
    let remaining = payload.len().saturating_sub(first_capacity);
    let count = 1 + remaining.div_ceil(later_capacity);
    let total = u8::try_from(count).map_err(|_| ProtoError::TooManyFragments)?;
    let mut offset = 0;
    let mut frag_id = 0usize;
    Ok(std::iter::from_fn(move || {
        if frag_id == count {
            return None;
        }
        let capacity = if frag_id == 0 {
            first_capacity
        } else {
            later_capacity
        };
        let end = (offset + capacity).min(payload.len());
        let fragment_addr = if frag_id == 0 { addr } else { &Address::None };
        let frame = encode_packet_fragment(
            assoc_id,
            pkt_id,
            total,
            frag_id as u8,
            fragment_addr,
            &payload[offset..end],
        );
        offset = end;
        frag_id += 1;
        Some(frame)
    }))
}

/// Parse incoming packet frame: Header + Command::Packet + Address + Payload
#[allow(dead_code)]
pub struct ParsedPacket {
    pub assoc_id: u16,
    pub pkt_id: u16,
    pub frag_total: u8,
    pub frag_id: u8,
    pub size: u16,
    pub addr: Address,
    pub payload: Bytes,
}

/// Heartbeats use QUIC datagrams regardless of the UDP relay mode.
/// `None` means a valid heartbeat; packet frames retain their full validation.
pub fn decode_relay_datagram(buf: Bytes) -> Result<Option<ParsedPacket>, ProtoError> {
    let mut prefix = buf.as_ref();
    let header = Header::decode(&mut prefix)?;
    if header.command == CmdType::Heartbeat {
        if !prefix.is_empty() {
            return Err(ProtoError::InvalidPayloadSize);
        }
        return Ok(None);
    }
    decode_packet_frame(buf).map(Some)
}

pub fn decode_packet_frame(mut buf: Bytes) -> Result<ParsedPacket, ProtoError> {
    let header = Header::decode(&mut buf)?;
    if header.command != CmdType::Packet {
        return Err(ProtoError::InvalidCommand);
    }
    let cmd = Command::decode(CmdType::Packet, &mut buf)?;
    let Command::Packet {
        assoc_id,
        pkt_id,
        frag_total,
        frag_id,
        size,
    } = cmd
    else {
        return Err(ProtoError::InvalidCommand);
    };

    let addr = Address::decode(&mut buf)?;
    if buf.len() != size as usize {
        return Err(ProtoError::InvalidPayloadSize);
    }
    let payload = buf;
    Ok(ParsedPacket {
        assoc_id,
        pkt_id,
        frag_total,
        frag_id,
        size,
        addr,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SocksAddr;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn test_relay_datagram_accepts_heartbeat_and_packet() {
        // Independent TUIC v5 heartbeat wire fixture.
        assert!(decode_relay_datagram(Bytes::from_static(&[5, 4])).unwrap().is_none());
        let addr = Address::IPv4(Ipv4Addr::LOCALHOST, 53);
        let packet = encode_single_packet(1, 2, &addr, b"reply").unwrap();
        let parsed = decode_relay_datagram(packet).unwrap().unwrap();
        assert_eq!(parsed.assoc_id, 1);
        assert_eq!(parsed.addr, addr);
        assert_eq!(parsed.payload.as_ref(), b"reply");
    }

    #[test]
    fn test_relay_datagram_rejects_invalid_control_frames() {
        for wire in [&[5][..], &[4, 4], &[5, 255], &[5, 1], &[5, 4, 0]] {
            assert!(decode_relay_datagram(Bytes::copy_from_slice(wire)).is_err());
        }
        let addr = Address::IPv4(Ipv4Addr::LOCALHOST, 53);
        let mut packet = encode_single_packet(1, 2, &addr, b"reply").unwrap().to_vec();
        packet.pop();
        assert!(matches!(decode_relay_datagram(Bytes::from(packet)),
            Err(ProtoError::InvalidPayloadSize)));
    }

    #[test]
    fn test_header_codec() {
        let h = Header::new(CmdType::Connect);
        let mut buf = BytesMut::new();
        h.encode(&mut buf);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf[0], 5);
        assert_eq!(buf[1], 1);

        let decoded = Header::decode(&mut buf).unwrap();
        assert_eq!(decoded.version, 5);
        assert_eq!(decoded.command, CmdType::Connect);
    }

    #[test]
    fn test_address_codec_ipv4() {
        let addr = Address::IPv4(Ipv4Addr::new(192, 168, 1, 1), 8080);
        let mut buf = BytesMut::new();
        addr.encode(&mut buf);
        assert_eq!(buf.len(), 1 + 4 + 2);

        let decoded = Address::decode(&mut buf).unwrap();
        assert_eq!(decoded, addr);

        let socks: SocksAddr = decoded.try_into().unwrap();
        assert_eq!(
            socks,
            SocksAddr::Ip(SocketAddr::new(
                Ipv4Addr::new(192, 168, 1, 1).into(),
                8080
            ))
        );
    }

    #[test]
    fn test_address_codec_ipv6() {
        let addr = Address::IPv6(Ipv6Addr::LOCALHOST, 9000);
        let mut buf = BytesMut::new();
        addr.encode(&mut buf);
        assert_eq!(buf.len(), 1 + 16 + 2);

        let decoded = Address::decode(&mut buf).unwrap();
        assert_eq!(decoded, addr);

        let socks: SocksAddr = decoded.try_into().unwrap();
        assert_eq!(
            socks,
            SocksAddr::Ip(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 9000))
        );
    }

    #[test]
    fn test_address_codec_domain() {
        let addr = Address::Domain("example.com".to_string(), 443);
        let mut buf = BytesMut::new();
        addr.encode(&mut buf);

        let decoded = Address::decode(&mut buf).unwrap();
        assert_eq!(decoded, addr);

        let socks: SocksAddr = decoded.try_into().unwrap();
        assert_eq!(socks, SocksAddr::Domain("example.com".into(), 443));
    }

    #[test]
    fn test_auth_frame() {
        let uuid = Uuid::new_v4();
        let token = [0x42u8; 32];
        let bytes = encode_auth(uuid, token);
        assert_eq!(bytes.len(), 2 + 16 + 32);

        let mut slice = bytes;
        let header = Header::decode(&mut slice).unwrap();
        assert_eq!(header.version, 5);
        assert_eq!(header.command, CmdType::Auth);

        let cmd = Command::decode(header.command, &mut slice).unwrap();
        match cmd {
            Command::Auth { uuid: u, token: t } => {
                assert_eq!(u, uuid);
                assert_eq!(t, token);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn test_packet_frame() {
        let payload = b"hello tuic v5";
        let addr = Address::Domain("target.internal".to_string(), 53);
        let wire = encode_single_packet(0x1234, 1, &addr, payload).unwrap();

        let parsed = decode_packet_frame(wire).unwrap();
        assert_eq!(parsed.assoc_id, 0x1234);
        assert_eq!(parsed.pkt_id, 1);
        assert_eq!(parsed.frag_total, 1);
        assert_eq!(parsed.frag_id, 0);
        assert_eq!(parsed.size, payload.len() as u16);
        assert_eq!(parsed.addr, addr);
        assert_eq!(&parsed.payload[..], payload);
    }

    #[test]
    fn test_packet_payload_size_is_checked() {
        let addr = Address::IPv4(Ipv4Addr::LOCALHOST, 53);
        let mut wire = encode_single_packet(1, 2, &addr, b"abc").unwrap().to_vec();
        wire.pop();
        assert!(matches!(
            decode_packet_frame(Bytes::from(wire)),
            Err(ProtoError::InvalidPayloadSize)
        ));
    }

    #[test]
    fn test_largest_stream_packet_fits_read_limit() {
        let addr = Address::Domain("a".repeat(255), 53);
        let payload = vec![0u8; u16::MAX as usize];
        let wire = encode_single_packet(1, 2, &addr, &payload).unwrap();
        assert_eq!(wire.len(), MAX_PACKET_FRAME_SIZE);
        assert_eq!(
            decode_packet_frame(wire).unwrap().payload.len(),
            payload.len()
        );
    }
}
