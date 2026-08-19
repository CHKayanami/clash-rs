//! Socks5 address format definition (RFC1928)

use std::{
    convert::From,
    fmt::{self, Debug, Formatter},
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    slice,
};

use bytes::{Buf, BufMut};
use tokio::io::{AsyncRead, AsyncReadExt};

#[rustfmt::skip]
pub mod consts {
    pub const SOCKS5_ADDR_TYPE_IPV4:        u8 = 0x01;
    pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
    pub const SOCKS5_ADDR_TYPE_IPV6:        u8 = 0x04;
}

/// SOCKS5 protocol error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    IoError(#[from] io::Error),
    #[error("address type {0:#x} not supported")]
    AddressTypeNotSupported(u8),
    #[error("address domain name must be UTF-8 encoding")]
    AddressDomainInvalidEncoding,
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::IoError(err) => err,
            e => Self::other(e),
        }
    }
}

/// SOCKS5 address type
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Address {
    /// Socket address (IP Address)
    SocketAddress(SocketAddr),
    /// Domain name address
    DomainNameAddress(String, u16),
}

impl Address {
    /// read from a cursor
    pub fn read_cursor<T: AsRef<[u8]>>(cur: &mut io::Cursor<T>) -> Result<Self, Error> {
        if cur.remaining() < 2 {
            return Err(io::Error::other("invalid buf").into());
        }

        let atyp = cur.get_u8();
        match atyp {
            consts::SOCKS5_ADDR_TYPE_IPV4 => {
                if cur.remaining() < 4 + 2 {
                    return Err(io::Error::other("invalid buf").into());
                }
                let addr = Ipv4Addr::from(cur.get_u32());
                let port = cur.get_u16();
                Ok(Self::SocketAddress(SocketAddr::V4(SocketAddrV4::new(addr, port))))
            }
            consts::SOCKS5_ADDR_TYPE_IPV6 => {
                if cur.remaining() < 16 + 2 {
                    return Err(io::Error::other("invalid buf").into());
                }
                let addr = Ipv6Addr::from(cur.get_u128());
                let port = cur.get_u16();
                Ok(Self::SocketAddress(SocketAddr::V6(SocketAddrV6::new(addr, port, 0, 0))))
            }
            consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
                let domain_len = cur.get_u8() as usize;
                if cur.remaining() < domain_len {
                    return Err(Error::AddressDomainInvalidEncoding);
                }
                let mut buf = vec![0u8; domain_len];
                cur.copy_to_slice(&mut buf);
                let port = cur.get_u16();
                let addr = String::from_utf8(buf).map_err(|_| Error::AddressDomainInvalidEncoding)?;
                Ok(Self::DomainNameAddress(addr, port))
            }
            _ => Err(Error::AddressTypeNotSupported(atyp)),
        }
    }

    /// Parse from a `AsyncRead`
    pub async fn read_from<R>(stream: &mut R) -> Result<Self, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut addr_type_buf = [0u8; 1];
        let _ = stream.read_exact(&mut addr_type_buf).await?;

        let addr_type = addr_type_buf[0];
        match addr_type {
            consts::SOCKS5_ADDR_TYPE_IPV4 => {
                let mut buf = [0u8; 6];
                let _ = stream.read_exact(&mut buf).await?;

                let v4addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                Ok(Self::SocketAddress(SocketAddr::V4(SocketAddrV4::new(v4addr, port))))
            }
            consts::SOCKS5_ADDR_TYPE_IPV6 => {
                let mut buf = [0u16; 9];

                let bytes_buf = unsafe { slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut _, 18) };
                let _ = stream.read_exact(bytes_buf).await?;

                let v6addr = Ipv6Addr::new(
                    u16::from_be(buf[0]),
                    u16::from_be(buf[1]),
                    u16::from_be(buf[2]),
                    u16::from_be(buf[3]),
                    u16::from_be(buf[4]),
                    u16::from_be(buf[5]),
                    u16::from_be(buf[6]),
                    u16::from_be(buf[7]),
                );
                let port = u16::from_be(buf[8]);

                Ok(Self::SocketAddress(SocketAddr::V6(SocketAddrV6::new(
                    v6addr, port, 0, 0,
                ))))
            }
            consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
                let mut length_buf = [0u8; 1];
                let _ = stream.read_exact(&mut length_buf).await?;
                let length = length_buf[0] as usize;

                // Len(Domain) + Len(Port)
                let buf_length = length + 2;

                let mut raw_addr = vec![0u8; buf_length];
                let _ = stream.read_exact(&mut raw_addr).await?;

                let raw_port = &raw_addr[length..];
                let port = u16::from_be_bytes([raw_port[0], raw_port[1]]);

                raw_addr.truncate(length);

                let addr = match String::from_utf8(raw_addr) {
                    Ok(addr) => addr,
                    Err(..) => return Err(Error::AddressDomainInvalidEncoding),
                };

                Ok(Self::DomainNameAddress(addr, port))
            }
            _ => {
                // Wrong Address Type . Socks5 only supports ipv4, ipv6 and domain name
                Err(Error::AddressTypeNotSupported(addr_type))
            }
        }
    }

    /// Writes to buffer
    #[inline]
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        write_address(self, buf)
    }

    /// Get required buffer size for serializing
    #[inline]
    pub fn serialized_len(&self) -> usize {
        get_addr_len(self)
    }

    /// Get associated port number
    pub fn port(&self) -> u16 {
        match *self {
            Self::SocketAddress(addr) => addr.port(),
            Self::DomainNameAddress(.., port) => port,
        }
    }

    /// Get host address string
    pub fn host(&self) -> String {
        match *self {
            Self::SocketAddress(ref addr) => addr.ip().to_string(),
            Self::DomainNameAddress(ref domain, ..) => domain.to_owned(),
        }
    }
}

impl Debug for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SocketAddress(ref addr) => write!(f, "{addr}"),
            Self::DomainNameAddress(ref addr, ref port) => write!(f, "{addr}:{port}"),
        }
    }
}

impl fmt::Display for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SocketAddress(ref addr) => write!(f, "{addr}"),
            Self::DomainNameAddress(ref addr, ref port) => write!(f, "{addr}:{port}"),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(s: SocketAddr) -> Self {
        Self::SocketAddress(s)
    }
}

impl From<(String, u16)> for Address {
    fn from((dn, port): (String, u16)) -> Self {
        Self::DomainNameAddress(dn, port)
    }
}

impl From<&Self> for Address {
    fn from(addr: &Self) -> Self {
        addr.clone()
    }
}

fn write_ipv4_address<B: BufMut>(addr: &SocketAddrV4, buf: &mut B) {
    buf.put_u8(consts::SOCKS5_ADDR_TYPE_IPV4); // Address type
    buf.put_slice(&addr.ip().octets()); // Ipv4 bytes
    buf.put_u16(addr.port()); // Port
}

fn write_ipv6_address<B: BufMut>(addr: &SocketAddrV6, buf: &mut B) {
    buf.put_u8(consts::SOCKS5_ADDR_TYPE_IPV6); // Address type
    for seg in &addr.ip().segments() {
        buf.put_u16(*seg); // Ipv6 bytes
    }
    buf.put_u16(addr.port()); // Port
}

fn write_domain_name_address<B: BufMut>(dnaddr: &str, port: u16, buf: &mut B) {
    assert!(dnaddr.len() <= u8::MAX as usize);

    buf.put_u8(consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME);
    buf.put_u8(dnaddr.len() as u8);
    buf.put_slice(dnaddr.as_bytes());
    buf.put_u16(port);
}

fn write_socket_address<B: BufMut>(addr: &SocketAddr, buf: &mut B) {
    match *addr {
        SocketAddr::V4(ref addr) => write_ipv4_address(addr, buf),
        SocketAddr::V6(ref addr) => write_ipv6_address(addr, buf),
    }
}

fn write_address<B: BufMut>(addr: &Address, buf: &mut B) {
    match *addr {
        Address::SocketAddress(ref addr) => write_socket_address(addr, buf),
        Address::DomainNameAddress(ref dnaddr, ref port) => write_domain_name_address(dnaddr, *port, buf),
    }
}

#[inline]
fn get_addr_len(atyp: &Address) -> usize {
    match *atyp {
        Address::SocketAddress(SocketAddr::V4(..)) => 1 + 4 + 2,
        Address::SocketAddress(SocketAddr::V6(..)) => 1 + 8 * 2 + 2,
        Address::DomainNameAddress(ref dmname, _) => 1 + 1 + dmname.len() + 2,
    }
}
