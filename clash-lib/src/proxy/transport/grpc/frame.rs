use bytes::{Buf, BufMut, Bytes, BytesMut};
use prost::encoding::{decode_varint, encode_varint, encoded_len_varint};
use std::io::{self, Error, ErrorKind};
use tokio::io::ReadBuf;

pub(super) fn encode_frame(data: &[u8]) -> Bytes {
    let protobuf_len = 1 + encoded_len_varint(data.len() as u64) + data.len();
    let mut frame = BytesMut::with_capacity(5 + protobuf_len);
    frame.put_u8(0);
    // The caller bounds data to MAX_WRITE_SIZE, well below the u32 wire limit.
    frame.put_u32(protobuf_len as u32);
    frame.put_u8(0x0a);
    encode_varint(data.len() as u64, &mut frame);
    frame.put_slice(data);
    frame.freeze()
}

#[derive(Default)]
pub(super) struct Decoder {
    // Five gRPC bytes, one protobuf tag, and at most ten varint bytes.
    header: [u8; 16],
    header_len: usize,
    payload_len: usize,
}

impl Decoder {
    pub(super) fn is_complete(&self) -> bool {
        self.header_len == 0 && self.payload_len == 0
    }

    fn read_header(&mut self, data: &mut Bytes) -> io::Result<bool> {
        while self.header_len < 5 && !data.is_empty() {
            self.header[self.header_len] = data.get_u8();
            self.header_len += 1;
        }
        if self.header_len < 5 {
            return Ok(false);
        }
        if self.header[0] != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData, "unsupported gRPC compression",
            ));
        }
        let frame_len =
            u32::from_be_bytes(self.header[1..5].try_into().unwrap()) as usize;
        if frame_len == 0 {
            self.header_len = 0;
            return Ok(true);
        }
        if frame_len < 2 {
            return Err(Error::new(
                ErrorKind::InvalidData, "invalid protobuf message length",
            ));
        }
        while !data.is_empty() {
            let byte = data.get_u8();
            self.header[self.header_len] = byte;
            self.header_len += 1;
            if self.header_len == 6 {
                if byte != 0x0a {
                    return Err(Error::new(
                        ErrorKind::InvalidData, "invalid protobuf data field",
                    ));
                }
                continue;
            }
            if byte & 0x80 == 0 {
                let mut length_bytes = &self.header[6..self.header_len];
                let payload_len = decode_varint(&mut length_bytes)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
                let payload_len = usize::try_from(payload_len)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
                if frame_len.checked_sub(self.header_len - 5) != Some(payload_len) {
                    return Err(Error::new(
                        ErrorKind::InvalidData, "invalid gRPC payload length",
                    ));
                }
                self.payload_len = payload_len;
                self.header_len = 0;
                return Ok(true);
            }
            if self.header_len == self.header.len()
                || self.header_len - 5 >= frame_len
            {
                return Err(Error::new(
                    ErrorKind::InvalidData, "invalid protobuf length",
                ));
            }
        }
        Ok(false)
    }

    pub(super) fn read(
        &mut self,
        data: &mut Bytes,
        buf: &mut ReadBuf<'_>,
    ) -> io::Result<()> {
        while !data.is_empty() {
            if self.payload_len == 0 && !self.read_header(data)? {
                return Ok(());
            }
            if self.payload_len > 0 && !data.is_empty() {
                let len = buf.remaining().min(self.payload_len).min(data.len());
                buf.put_slice(&data[..len]);
                data.advance(len);
                self.payload_len -= len;
                return Ok(());
            }
        }
        Ok(())
    }
}
