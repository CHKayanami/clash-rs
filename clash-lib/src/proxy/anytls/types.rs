//! AnyTLS protocol types - Frame, Command, and StringMap definitions
//!
//! Based on the AnyTLS protocol specification v2.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;

/// Frame header size: 1 (cmd) + 4 (stream_id) + 2 (data_len) = 7 bytes
pub const FRAME_HEADER_SIZE: usize = 7;

/// Largest payload a single frame can carry: the header's length field is 16
/// bits, so anything longer has to be split across frames.
pub const MAX_FRAME_DATA_SIZE: usize = u16::MAX as usize;

/// Command types for AnyTLS protocol frames
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Padding data (waste bytes for traffic obfuscation)
    Waste = 0,
    /// Open a new stream (client -> server)
    Syn = 1,
    /// Push data through the stream
    Psh = 2,
    /// Close the stream (EOF mark)
    Fin = 3,
    /// Client settings sent to server
    Settings = 4,
    /// Alert message (server -> client, fatal)
    Alert = 5,
    /// Update padding scheme (server -> client)
    UpdatePaddingScheme = 6,
    /// Server acknowledges stream open (protocol v2)
    SynAck = 7,
    /// Keep-alive request
    HeartRequest = 8,
    /// Keep-alive response
    HeartResponse = 9,
    /// Server settings sent to client (protocol v2)
    ServerSettings = 10,
}

impl TryFrom<u8> for Command {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Command::Waste),
            1 => Ok(Command::Syn),
            2 => Ok(Command::Psh),
            3 => Ok(Command::Fin),
            4 => Ok(Command::Settings),
            5 => Ok(Command::Alert),
            6 => Ok(Command::UpdatePaddingScheme),
            7 => Ok(Command::SynAck),
            8 => Ok(Command::HeartRequest),
            9 => Ok(Command::HeartResponse),
            10 => Ok(Command::ServerSettings),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown anytls command: {}", value),
            )),
        }
    }
}

/// Frame defines a packet for multiplexing over a single connection
#[derive(Debug, Clone)]
pub struct Frame {
    pub cmd: Command,
    pub stream_id: u32,
    pub data: Bytes,
}

impl Frame {
    /// Create a new control frame (no data)
    pub fn control(cmd: Command, stream_id: u32) -> Self {
        Self {
            cmd,
            stream_id,
            data: Bytes::new(),
        }
    }

    /// Create a new frame with data
    pub fn with_data(cmd: Command, stream_id: u32, data: Bytes) -> Self {
        Self {
            cmd,
            stream_id,
            data,
        }
    }

    /// Create a data (PSH) frame
    pub fn data(stream_id: u32, data: Bytes) -> Self {
        Self::with_data(Command::Psh, stream_id, data)
    }

    /// Encode frame parts into an existing buffer (zero allocation)
    #[inline]
    pub fn encode_parts(cmd: Command, stream_id: u32, data: &[u8], buf: &mut BytesMut) {
        buf.reserve(FRAME_HEADER_SIZE + data.len());
        buf.put_u8(cmd as u8);
        buf.put_u32(stream_id);
        buf.put_u16(data.len() as u16);
        if !data.is_empty() {
            buf.extend_from_slice(data);
        }
    }

    /// Encode frame into an existing buffer (zero allocation)
    #[inline]
    pub fn encode_into(&self, buf: &mut BytesMut) {
        Self::encode_parts(self.cmd, self.stream_id, &self.data, buf);
    }

    /// Decode frame header
    pub fn decode_header(
        header: &[u8; FRAME_HEADER_SIZE],
    ) -> io::Result<(Command, u32, u16)> {
        let cmd = Command::try_from(header[0])?;
        let stream_id =
            u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let length = u16::from_be_bytes([header[5], header[6]]);
        Ok((cmd, stream_id, length))
    }
}

/// StringMap - simple key=value format used for settings
/// Format: "key1=value1\nkey2=value2\n..."
#[derive(Debug, Clone, Default)]
pub struct StringMap(std::collections::HashMap<String, String>);

impl StringMap {
    pub fn new() -> Self {
        Self(std::collections::HashMap::new())
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.0.get(key)
    }

    /// Parse from bytes (newline-separated key=value pairs)
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut map = Self::new();
        let text = String::from_utf8_lossy(data);
        for line in text.lines() {
            if let Some((key, value)) = line.split_once('=') {
                map.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        map
    }

    /// Serialize to bytes.
    ///
    /// Sorted by key: iterating the map directly made the settings frame's byte
    /// order differ run to run, which is both unreproducible and a needless
    /// source of variation in a protocol whose point is looking uniform.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut lines: Vec<String> =
            self.0.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
        lines.sort();
        lines.join("\n").into_bytes()
    }
}

/// Frame codec for reading/writing frames from a buffer
pub struct FrameCodec;

impl FrameCodec {
    /// Try to decode a frame from the buffer
    /// Returns None if not enough data available
    pub fn decode(buf: &mut BytesMut) -> io::Result<Option<Frame>> {
        if buf.len() < FRAME_HEADER_SIZE {
            return Ok(None);
        }

        let header: [u8; FRAME_HEADER_SIZE] =
            buf[..FRAME_HEADER_SIZE].try_into().unwrap();
        let (cmd, stream_id, data_len) = Frame::decode_header(&header)?;
        let total_len = FRAME_HEADER_SIZE + data_len as usize;

        if buf.len() < total_len {
            return Ok(None);
        }

        buf.advance(FRAME_HEADER_SIZE);

        let data = if data_len > 0 {
            buf.split_to(data_len as usize).freeze()
        } else {
            Bytes::new()
        };

        Ok(Some(Frame {
            cmd,
            stream_id,
            data,
        }))
    }
}
