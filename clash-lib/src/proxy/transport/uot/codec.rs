use std::io;

use bytes::{BufMut, BytesMut};

use crate::session::{SocksAddr, SocksAddrType};

pub(super) const MAX_PACKET_LENGTH: usize = u16::MAX as usize;
const IPV4: u8 = 0;
const IPV6: u8 = 1;
const DOMAIN: u8 = 2;

pub(super) struct PacketHeader {
    pub address: SocksAddr,
    pub header_len: usize,
    pub payload_len: usize,
}

pub(super) fn validate_address(address: &SocksAddr) -> io::Result<()> {
    if let SocksAddr::Domain(host, _) = address
        && (host.is_empty() || host.len() > 255)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput, "invalid UoT domain length",
        ));
    }
    Ok(())
}

pub(super) fn encode_header(
    buffer: &mut BytesMut, address: &SocksAddr, payload_len: usize,
    packet_mode: bool,
) -> io::Result<()> {
    buffer.clear();
    append_header(buffer, address, payload_len, packet_mode)
}

pub(super) fn append_header(
    buffer: &mut BytesMut, address: &SocksAddr, payload_len: usize,
    packet_mode: bool,
) -> io::Result<()> {
    validate_address(address)?;
    if payload_len > MAX_PACKET_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput, "UDP payload exceeds UoT frame capacity",
        ));
    }
    let start = buffer.len();
    if packet_mode {
        address.write_buf(buffer);
        buffer[start] = match buffer[start] {
            SocksAddrType::V4 => IPV4,
            SocksAddrType::V6 => IPV6,
            SocksAddrType::DOMAIN => DOMAIN,
            _ => unreachable!(),
        };
    }
    buffer.put_u16(payload_len as u16);
    Ok(())
}

pub(super) fn decode_header(
    data: &[u8], target: &SocksAddr, packet_mode: bool,
) -> io::Result<Option<PacketHeader>> {
    let (address_len, atyp) = if packet_mode {
        match data.first().copied() {
            Some(IPV4) => (7, SocksAddrType::V4),
            Some(IPV6) => (19, SocksAddrType::V6),
            Some(DOMAIN) => match data.get(1).copied() {
                Some(0) => return Err(io::Error::new(
                    io::ErrorKind::InvalidData, "empty UoT domain",
                )),
                Some(len) => (usize::from(len) + 4, SocksAddrType::DOMAIN),
                None => return Ok(None),
            },
            Some(_) => return Err(io::Error::new(
                io::ErrorKind::InvalidData, "invalid UoT address type",
            )),
            None => return Ok(None),
        }
    } else { (0, 0) };
    let header_len = address_len + 2;
    if data.len() < header_len { return Ok(None); }
    let address = if packet_mode {
        SocksAddr::parse_wire_address(&data[..address_len], atyp)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
    } else { target.clone() };
    let payload_len = usize::from(u16::from_be_bytes([
        data[address_len], data[address_len + 1],
    ]));
    Ok(Some(PacketHeader { address, header_len, payload_len }))
}
