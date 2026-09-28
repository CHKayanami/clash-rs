use bytes::{Buf, BufMut, BytesMut};
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::session::SocksAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    Domain,
    IPv4,
    IPv6,
    None,
    Other(u8),
}

impl From<u8> for AddressType {
    fn from(val: u8) -> Self {
        match val {
            0 => AddressType::Domain,
            1 => AddressType::IPv4,
            2 => AddressType::IPv6,
            0xFF => AddressType::None,
            other => AddressType::Other(other),
        }
    }
}

impl From<AddressType> for u8 {
    fn from(t: AddressType) -> Self {
        match t {
            AddressType::Domain => 0,
            AddressType::IPv4 => 1,
            AddressType::IPv6 => 2,
            AddressType::None => 0xFF,
            AddressType::Other(o) => o,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    None,
    Domain(String, u16),
    IPv4(Ipv4Addr, u16),
    IPv6(Ipv6Addr, u16),
}

impl Address {
    pub fn encode(&self, dst: &mut BytesMut) {
        match self {
            Address::None => {
                dst.reserve(1);
                dst.put_u8(u8::from(AddressType::None));
            }
            Address::IPv4(ip, port) => {
                dst.reserve(1 + 4 + 2);
                dst.put_u8(u8::from(AddressType::IPv4));
                dst.put_slice(&ip.octets());
                dst.put_u16(*port);
            }
            Address::IPv6(ip, port) => {
                dst.reserve(1 + 16 + 2);
                dst.put_u8(u8::from(AddressType::IPv6));
                dst.put_slice(&ip.octets());
                dst.put_u16(*port);
            }
            Address::Domain(domain, port) => {
                let bytes = domain.as_bytes();
                let len = bytes.len().min(u8::MAX as usize) as u8;
                dst.reserve(1 + 1 + len as usize + 2);
                dst.put_u8(u8::from(AddressType::Domain));
                dst.put_u8(len);
                dst.put_slice(&bytes[..len as usize]);
                dst.put_u16(*port);
            }
        }
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, super::ProtoError> {
        if buf.remaining() < 1 {
            return Err(super::ProtoError::Incomplete("address type"));
        }
        let addr_type = AddressType::from(buf.get_u8());
        match addr_type {
            AddressType::None => Ok(Address::None),
            AddressType::IPv4 => {
                if buf.remaining() < 4 + 2 {
                    return Err(super::ProtoError::Incomplete("IPv4 address"));
                }
                let mut octets = [0u8; 4];
                buf.copy_to_slice(&mut octets);
                let port = buf.get_u16();
                Ok(Address::IPv4(Ipv4Addr::from(octets), port))
            }
            AddressType::IPv6 => {
                if buf.remaining() < 16 + 2 {
                    return Err(super::ProtoError::Incomplete("IPv6 address"));
                }
                let mut octets = [0u8; 16];
                buf.copy_to_slice(&mut octets);
                let port = buf.get_u16();
                Ok(Address::IPv6(Ipv6Addr::from(octets), port))
            }
            AddressType::Domain => {
                if buf.remaining() < 1 {
                    return Err(super::ProtoError::Incomplete("domain length"));
                }
                let len = buf.get_u8() as usize;
                if buf.remaining() < len + 2 {
                    return Err(super::ProtoError::Incomplete("domain and port"));
                }
                let mut domain_bytes = vec![0u8; len];
                buf.copy_to_slice(&mut domain_bytes);
                let port = buf.get_u16();
                let domain = String::from_utf8(domain_bytes)
                    .map_err(|_| super::ProtoError::InvalidDomain)?;
                Ok(Address::Domain(domain, port))
            }
            AddressType::Other(_) => Err(super::ProtoError::InvalidAddressType),
        }
    }
}

impl From<SocksAddr> for Address {
    fn from(val: SocksAddr) -> Self {
        match val {
            SocksAddr::Ip(SocketAddr::V4(addr)) => {
                Address::IPv4(*addr.ip(), addr.port())
            }
            SocksAddr::Ip(SocketAddr::V6(addr)) => {
                Address::IPv6(*addr.ip(), addr.port())
            }
            SocksAddr::Domain(domain, port) => Address::Domain(domain.to_string(), port),
        }
    }
}

impl TryFrom<Address> for SocksAddr {
    type Error = super::ProtoError;

    fn try_from(addr: Address) -> Result<Self, Self::Error> {
        match addr {
            Address::None => Err(super::ProtoError::EmptyAddress),
            Address::IPv4(ip, port) => Ok(SocksAddr::Ip(SocketAddr::new(ip.into(), port))),
            Address::IPv6(ip, port) => Ok(SocksAddr::Ip(SocketAddr::new(ip.into(), port))),
            Address::Domain(domain, port) => Ok(SocksAddr::Domain(domain.into(), port)),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::None => write!(f, "none"),
            Address::IPv4(ip, port) => write!(f, "{ip}:{port}"),
            Address::IPv6(ip, port) => write!(f, "[{ip}]:{port}"),
            Address::Domain(domain, port) => write!(f, "{domain}:{port}"),
        }
    }
}
