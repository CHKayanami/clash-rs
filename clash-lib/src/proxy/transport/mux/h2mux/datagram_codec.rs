use std::io;

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::{proxy::datagram::UdpPacket, session::{SocksAddr, SocksAddrType}};

/// sing-mux packet-address mode: SOCKS address, big-endian u16 length, payload.
pub(super) struct PacketCodec;

impl Decoder for PacketCodec {
    type Item = UdpPacket;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<UdpPacket>> {
        let Some(&atyp) = src.first() else { return Ok(None); };
        let addr_len = match atyp {
            SocksAddrType::V4 => 7,
            SocksAddrType::V6 => 19,
            SocksAddrType::DOMAIN => {
                let Some(&len) = src.get(1) else { return Ok(None); };
                if len == 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                        "empty h2mux UDP domain"));
                }
                usize::from(len) + 4
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData,
                "invalid h2mux UDP address type")),
        };
        let header_len = addr_len + 2;
        if src.len() < header_len { return Ok(None); }
        let payload_len = usize::from(u16::from_be_bytes([
            src[addr_len], src[addr_len + 1],
        ]));
        let frame_len = header_len + payload_len;
        if src.len() < frame_len {
            src.reserve(frame_len - src.len());
            return Ok(None);
        }
        // Validate the complete address before consuming any part of the frame.
        let addr = SocksAddr::try_from(&src[..addr_len])
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        src.advance(header_len);
        let data = src.split_to(payload_len).freeze();
        // The dispatcher fills in the local destination for outbound replies.
        Ok(Some(UdpPacket::new(data, addr, SocksAddr::any_ipv4())))
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> io::Result<Option<UdpPacket>> {
        match self.decode(src)? {
            Some(packet) => Ok(Some(packet)),
            None if src.is_empty() => Ok(None),
            None => Err(io::Error::new(io::ErrorKind::UnexpectedEof,
                "truncated h2mux UDP packet")),
        }
    }
}

impl Encoder<UdpPacket> for PacketCodec {
    type Error = io::Error;

    fn encode(&mut self, packet: UdpPacket, dst: &mut BytesMut) -> io::Result<()> {
        let len = u16::try_from(packet.data.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "h2mux UDP payload too large")
        })?;
        if let SocksAddr::Domain(host, _) = &packet.dst_addr {
            if host.is_empty() || host.len() > 255 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput,
                    "invalid h2mux UDP domain length"));
            }
        }
        dst.reserve(packet.dst_addr.size() + 2 + packet.data.len());
        packet.dst_addr.write_buf(dst);
        dst.put_u16(len);
        dst.extend_from_slice(&packet.data);
        Ok(())
    }
}
