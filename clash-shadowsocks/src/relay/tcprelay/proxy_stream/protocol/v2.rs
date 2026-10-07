//! Shadowsocks AEAD 2022 header protocol

use std::io;

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::relay::{Address, write_aead_2022_padding};

/// Maximum padding length
pub const MAX_PADDING_SIZE: usize = 900;

/// Stream (Client & Server) timestamp max differences (ABS)
pub const SERVER_STREAM_TIMESTAMP_MAX_DIFF: u64 = 30;

/// TCP Request Header
///
/// +-------+-------+-------+-------+-------+-------+-------+-------+-------+
/// | ADDR (Variable ...)
/// +-------+-------+-------+-------+-------+-------+-------+-------+-------+
/// | PADDING SIZE  | PADDING (Variable ...)
/// +-------+-------+-------+-------+-------+-------+-------+-------+-------+
#[derive(Debug, Clone)]
pub struct Aead2022TcpRequestHeader {
    pub addr: Address,
    pub padding_size: u16,
}

impl Aead2022TcpRequestHeader {
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let addr = Address::read_from(reader).await?;

        let mut padding_size_buffer = [0u8; 2];
        reader.read_exact(&mut padding_size_buffer).await?;

        let padding_size = u16::from_be_bytes(padding_size_buffer);
        if padding_size > 0 {
            let mut take_reader = reader.take(padding_size as u64);
            let mut buffer = [0u8; 64];
            loop {
                match take_reader.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(..) => continue,
                    Err(err) => return Err(err),
                }
            }
        }

        Ok(Self { addr, padding_size })
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        Aead2022TcpRequestHeaderRef {
            addr: &self.addr,
            padding_size: self.padding_size,
        }
        .write_to_buf(buf)
    }

    pub fn serialized_len(&self) -> usize {
        Aead2022TcpRequestHeaderRef {
            addr: &self.addr,
            padding_size: self.padding_size,
        }
        .serialized_len()
    }
}

#[derive(Debug)]
pub struct Aead2022TcpRequestHeaderRef<'a> {
    pub addr: &'a Address,
    pub padding_size: u16,
}

impl Aead2022TcpRequestHeaderRef<'_> {
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        assert!(
            self.padding_size as usize <= MAX_PADDING_SIZE,
            "padding length must be in [0, {MAX_PADDING_SIZE}]"
        );

        self.addr.write_to_buf(buf);
        buf.put_u16(self.padding_size);
        write_aead_2022_padding(buf, self.padding_size as usize);
    }

    pub fn serialized_len(&self) -> usize {
        self.addr.serialized_len() + 2 + self.padding_size as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_header_roundtrip_initializes_padding() {
        let addr: Address = ("example.test".to_owned(), 443).into();
        for padding_size in [0, 1, MAX_PADDING_SIZE as u16] {
            let header = Aead2022TcpRequestHeader { addr: addr.clone(), padding_size };
            let mut storage = [0xff_u8; 1024];
            let mut output = &mut storage[..];
            header.write_to_buf(&mut output);
            let len = 1024 - output.len();
            assert_eq!(len, header.serialized_len());
            if padding_size as usize == MAX_PADDING_SIZE {
                assert!(storage[addr.serialized_len() + 2..len].iter().any(|&b| b != 0xff));
            }
            let mut input = &storage[..len];
            let decoded = Aead2022TcpRequestHeader::read_from(&mut input).await.unwrap();
            assert_eq!(decoded.addr, addr);
            assert_eq!(decoded.padding_size, padding_size);
            assert!(input.is_empty());
        }
    }
}
