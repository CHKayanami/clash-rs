use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proxy::{AnyStream, transport::VisionOptions};
use rand::RngExt;

/// Vision command bytes (first byte of each frame header).
///
/// Source: Xray-core `proxy/proxy.go` (`CommandPadding*` constants).
const CMD_PADDING_CONTINUE: u8 = 0x00; // more Vision frames coming
const CMD_PADDING_END: u8 = 0x01; // last Vision frame, do not splice yet
const CMD_PADDING_DIRECT: u8 = 0x02; // last Vision frame, enter splice mode

/// TLS ApplicationData record type; triggers the direct-mode transition when inner TLS is verified.
const TLS_APPLICATION_DATA: u8 = 0x17;

/// TLS Handshake record type
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// TLS Handshake Types
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

/// TLS 1.3 Cipher Suites not supported for XTLS direct mode (Xray-core / sing-box rule)
const TLS13_CIPHER_AES_128_CCM_8_SHA256: u16 = 0x1305;

/// Maximum content bytes in a single Vision frame. `content_len` is a 16-bit
/// field, so a longer write has to be split across frames — casting it to `u16`
/// silently wrapped, and the default 64 KiB relay buffer is one byte past the
/// limit, so a full-size write declared a length of 0 and desynchronized the
/// peer permanently.
const MAX_VISION_CONTENT: usize = u16::MAX as usize;

/// Parsed ServerHello information for Vision filtering
#[derive(Debug)]
pub struct ParsedServerHello {
    pub cipher_suite: u16,
    pub is_tls13: bool,
}

/// Parses a ServerHello record to extract cipher suite and TLS 1.3 supported_versions extension.
pub fn parse_server_hello(record: &[u8]) -> Result<ParsedServerHello, io::Error> {
    if record.len() < 47 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello record too short",
        ));
    }
    if record[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected Handshake content type",
        ));
    }

    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record.len() < 5 + record_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello record payload truncated",
        ));
    }

    let msg = &record[5..5 + record_len];
    if msg.len() < 38 || msg[0] != TLS_HANDSHAKE_TYPE_SERVER_HELLO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ServerHello handshake type",
        ));
    }

    let mut offset = 4; // Skip type (1b) + length (3b)
    if msg.len() < offset + 34 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated ServerHello body",
        ));
    }

    // HelloRetryRequest random constant
    const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02,
        0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ];
    let random = &msg[offset + 2..offset + 34];
    if random == HELLO_RETRY_REQUEST_RANDOM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HelloRetryRequest received",
        ));
    }

    offset += 2 + 32; // Skip legacy version and random
    let session_id_len = msg[offset] as usize;
    offset += 1 + session_id_len;

    if msg.len() < offset + 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated cipher suite",
        ));
    }

    let cipher_suite = u16::from_be_bytes([msg[offset], msg[offset + 1]]);
    offset += 2 + 1; // Skip cipher suite and compression method

    let mut is_tls13 = false;
    if msg.len() >= offset + 2 {
        let ext_len = u16::from_be_bytes([msg[offset], msg[offset + 1]]) as usize;
        offset += 2;
        let ext_end = offset + ext_len;
        if msg.len() >= ext_end {
            let mut ext_offset = offset;
            while ext_offset + 4 <= ext_end {
                let ext_type =
                    u16::from_be_bytes([msg[ext_offset], msg[ext_offset + 1]]);
                let ext_data_len =
                    u16::from_be_bytes([msg[ext_offset + 2], msg[ext_offset + 3]])
                        as usize;
                ext_offset += 4;
                if ext_offset + ext_data_len > ext_end {
                    break;
                }
                if ext_type == 0x002b {
                    // supported_versions extension
                    let ext_bytes = &msg[ext_offset..ext_offset + ext_data_len];
                    if ext_bytes.len() >= 2
                        && ext_bytes[0] == 0x03
                        && ext_bytes[1] == 0x04
                    {
                        is_tls13 = true;
                    }
                }
                ext_offset += ext_data_len;
            }
        }
    }

    Ok(ParsedServerHello {
        cipher_suite,
        is_tls13,
    })
}

/// Filter state for inner TLS handshake detection
#[derive(Debug)]
pub struct VisionFilter {
    record_filter_count: usize,
    is_tls: bool,
    is_tls12_or_above: bool,
    supports_xtls: bool,
}

impl VisionFilter {
    pub fn new() -> Self {
        Self {
            record_filter_count: 8,
            is_tls: false,
            is_tls12_or_above: false,
            supports_xtls: false,
        }
    }

    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    pub fn supports_xtls(&self) -> bool {
        self.supports_xtls
    }

    pub fn filter_client_data(&mut self, data: &[u8]) {
        if self.is_tls {
            return;
        }
        let mut offset = 0;
        while offset + 5 <= data.len() {
            let record_type = data[offset];
            let version_major = data[offset + 1];
            let record_len =
                u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;

            if record_type == TLS_CONTENT_TYPE_HANDSHAKE && version_major == 3 {
                if offset + 5 + record_len <= data.len() {
                    let record_slice = &data[offset..offset + 5 + record_len];
                    if record_slice.len() >= 6
                        && record_slice[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
                    {
                        self.is_tls = true;
                        break;
                    }
                } else if data.len() >= offset + 6
                    && data[offset + 5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
                {
                    self.is_tls = true;
                    break;
                }
            }

            if record_len == 0 || offset + 5 + record_len > data.len() {
                break;
            }
            offset += 5 + record_len;
        }
    }

    pub fn filter_server_record(&mut self, data: &[u8]) {
        if self.record_filter_count == 0 {
            return;
        }
        self.record_filter_count = self.record_filter_count.saturating_sub(1);

        let mut offset = 0;
        while offset + 5 <= data.len() {
            let record_type = data[offset];
            let version_major = data[offset + 1];
            let record_len =
                u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;

            if record_type == TLS_CONTENT_TYPE_HANDSHAKE && version_major == 3 {
                self.is_tls = true;
                if offset + 5 + record_len <= data.len() {
                    let record_slice = &data[offset..offset + 5 + record_len];
                    if record_slice.len() >= 6
                        && record_slice[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO
                    {
                        self.is_tls12_or_above = true;
                        if let Ok(parsed) = parse_server_hello(record_slice) {
                            if parsed.is_tls13 {
                                if parsed.cipher_suite
                                    != TLS13_CIPHER_AES_128_CCM_8_SHA256
                                {
                                    self.supports_xtls = true;
                                }
                                self.record_filter_count = 0;
                                break;
                            }
                        }
                    }
                } else if data.len() >= offset + 6
                    && data[offset + 5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO
                {
                    self.is_tls12_or_above = true;
                    // must start at this record, not at the start of the buffer
                    if let Ok(parsed) = parse_server_hello(&data[offset..]) {
                        if parsed.is_tls13 {
                            if parsed.cipher_suite
                                != TLS13_CIPHER_AES_128_CCM_8_SHA256
                            {
                                self.supports_xtls = true;
                            }
                            self.record_filter_count = 0;
                            break;
                        }
                    }
                }
            }

            if record_len == 0 || offset + 5 + record_len > data.len() {
                break;
            }
            offset += 5 + record_len;
        }
    }
}

/// State machine for the server-side Vision read path.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadState {
    /// Still receiving Vision-framed data.
    Framed,
    /// Server sent `CMD_PADDING_END` (0x01): Vision framing done, stay in TLS.
    End,
    /// Server sent `CMD_PADDING_DIRECT` (0x02): Vision framing done, bypass
    /// Reality TLS (XTLS-splice).
    Direct,
}

impl ReadState {
    fn is_done(self) -> bool {
        matches!(self, ReadState::End | ReadState::Direct)
    }
}

/// Wraps a VLESS stream with Vision framing (xtls-rprx-vision flow).
///
/// ## Wire format (Xray-core `XtlsPadding`)
///
/// ```text
/// First frame only:   [UUID: 16 bytes]
/// Every frame:        [command: u8]
///                     [content_len: u16 big-endian]
///                     [padding_len: u16 big-endian]
///                     [content: content_len bytes]   ← actual TLS record
///                     [padding: padding_len bytes]   ← random, discarded by receiver
/// ```
///
/// ## Commands
/// - `0x00` `PaddingContinue`: more Vision frames follow.
/// - `0x01` `PaddingEnd`:      last Vision frame; stay in framed mode.
/// - `0x02` `PaddingDirect`:   last Vision frame; enter XTLS-splice (raw) mode.
///
/// ## XTLS-splice mode
/// When CMD_PADDING_DIRECT (0x02) is sent or received, both peers must bypass
/// the outer Reality TLS layer and communicate over raw TCP.  VisionStream
/// signals this via optional `Arc<AtomicBool>` flags shared with the
/// `SplicableTlsStream` that sits below VlessStream in the stack.
pub struct VisionStream {
    inner: AnyStream,

    // --- write state ---
    /// User UUID to prepend to the very first Vision frame, then `None`.
    user_uuid: Option<[u8; 16]>,
    /// True once we have sent the first TLS ApplicationData record as a
    /// Vision `0x02` frame; subsequent writes are raw.
    write_direct: bool,
    /// Buffered Vision-framed bytes for the in-progress write.
    write_buf: BytesMut,
    /// How many bytes of the caller's buffer `write_buf` was built from, so a
    /// re-poll reports what was actually consumed rather than the length of
    /// whatever buffer it happens to be handed.
    write_buf_consumed: usize,
    /// True when the pending `write_buf` was built from an ApplicationData
    /// payload, so we flip `write_direct` once the buffer is drained.
    write_buf_app_data: bool,

    // --- read state ---
    /// Whether the server's 16-byte UUID prefix has been consumed.
    server_uuid_consumed: bool,
    /// Fully decoded payload bytes ready to be returned to the caller.
    decoded: BytesMut,
    /// Raw bytes from `inner` that have not yet been Vision-decoded.
    raw: BytesMut,
    /// Current Vision read state (framed / end / direct-splice).
    read_state: ReadState,

    /// Filter tracking inner TLS handshake records
    filter: VisionFilter,

    // --- XTLS-splice signals (optional, only used with Reality transport) ---
    /// Set when CMD_DIRECT received from server → underlying TLS must switch
    /// to raw reads.
    read_splice_flag: Option<Arc<AtomicBool>>,
    /// Set when CMD_DIRECT sent to server → underlying TLS must switch to raw
    /// writes.
    write_splice_flag: Option<Arc<AtomicBool>>,
}

impl crate::proxy::ProxyStream for VisionStream {}

impl VisionStream {
    /// Create a `VisionStream`.
    ///
    /// Pass `Some(VisionOptions)` when the underlying transport is Reality, to
    /// enable XTLS-splice: once `CMD_PADDING_DIRECT` is exchanged, the flags
    /// inside `opts` signal `SplicableTlsStream` to bypass Reality TLS and
    /// communicate over raw TCP.  Pass `None` for plain TLS (no splice).
    pub fn new(
        inner: AnyStream,
        uuid: &str,
        opts: Option<VisionOptions>,
    ) -> io::Result<Self> {
        let uuid_bytes = uuid::Uuid::parse_str(uuid)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid UUID")
            })?
            .into_bytes();
        let (read_splice_flag, write_splice_flag) = opts
            .map(|o| (Some(o.read_flag), Some(o.write_flag)))
            .unwrap_or((None, None));
        Ok(Self {
            inner,
            user_uuid: Some(uuid_bytes),
            write_direct: false,
            write_buf: BytesMut::new(),
            write_buf_consumed: 0,
            write_buf_app_data: false,
            server_uuid_consumed: false,
            decoded: BytesMut::new(),
            raw: BytesMut::new(),
            read_state: ReadState::Framed,
            filter: VisionFilter::new(),
            read_splice_flag,
            write_splice_flag,
        })
    }

    /// Build a Vision frame for `data` into `self.write_buf`.
    fn build_vision_frame(&mut self, data: &[u8]) {
        let is_first_frame = self.user_uuid.is_some();

        // Prepend UUID on the first frame (cleared immediately after).
        if let Some(uuid) = self.user_uuid.take() {
            self.write_buf.put_slice(&uuid);
        }

        self.filter.filter_client_data(data);

        // Check if data is TLS ApplicationData: [0x17, 0x03] and len >= 3
        let is_app_data =
            data.len() >= 3 && data[0] == TLS_APPLICATION_DATA && data[1] == 0x03;

        let command = if is_app_data {
            if self.filter.is_tls() && self.filter.supports_xtls() {
                CMD_PADDING_DIRECT
            } else {
                CMD_PADDING_END
            }
        } else {
            CMD_PADDING_CONTINUE
        };

        let content_len = data.len() as u16;
        // Add random padding only on the first frame for traffic-analysis
        // resistance; subsequent frames use no padding.
        // Always at least 1 byte of padding on the first frame so receivers
        // can rely on non-zero padding_len (and to avoid a flaky test where
        // rand::random::<u8>() == 0 with probability 1/256).
        let padding_len: u16 = if is_first_frame {
            (rand::random::<u8>() as u16) + 1
        } else {
            0
        };
        let frame_len = 5 + data.len() + padding_len as usize;
        self.write_buf.reserve(frame_len);

        self.write_buf.put_u8(command);
        self.write_buf.put_u16(content_len);
        self.write_buf.put_u16(padding_len);
        self.write_buf.put_slice(data);
        if padding_len > 0 {
            let padding_start = self.write_buf.len();
            self.write_buf
                .resize(padding_start + padding_len as usize, 0);
            rand::rng().fill(&mut self.write_buf[padding_start..]);
        }

        if command == CMD_PADDING_DIRECT || command == CMD_PADDING_END {
            self.write_buf_app_data = true;
        }
    }
}

// ---------------------------------------------------------------------------
// AsyncRead
// ---------------------------------------------------------------------------

impl AsyncRead for VisionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut(); // safe: VisionStream is Unpin

        loop {
            // 1. Return already-decoded data.
            if !this.decoded.is_empty() {
                let amt = this.decoded.len().min(buf.remaining());
                buf.put_slice(&this.decoded[..amt]);
                this.decoded.advance(amt);
                return Poll::Ready(Ok(()));
            }

            // 2. Direct/splice mode: raw passthrough to inner stream.
            if this.read_state.is_done() {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            // 3. Decode Vision frames from the raw buffer.
            let changed = decode_vision_frames(
                &mut this.raw,
                &mut this.decoded,
                &mut this.read_state,
                &mut this.server_uuid_consumed,
                &mut this.filter,
            );

            // Signal the underlying SplicableTlsStream to bypass TLS.
            if this.read_state == ReadState::Direct
                && let Some(flag) = &this.read_splice_flag
            {
                flag.store(true, Ordering::Release);
            }

            if changed {
                continue;
            }

            // 4. Need more raw bytes from inner stream.
            let mut tmp = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut tmp);

            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let read_bytes = read_buf.filled();
                    if read_bytes.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    this.raw.extend_from_slice(read_bytes);
                }
            }
        }
    }
}

/// Drain Vision frames from `raw` into `decoded`.
///
/// Returns `true` if any content bytes were produced or `read_state` changed.
fn decode_vision_frames(
    raw: &mut BytesMut,
    decoded: &mut BytesMut,
    read_state: &mut ReadState,
    server_uuid_consumed: &mut bool,
    filter: &mut VisionFilter,
) -> bool {
    let before = decoded.len();

    loop {
        // First server frame is preceded by the 16-byte server UUID.
        if !*server_uuid_consumed {
            if raw.len() < 16 + 5 {
                break; // need UUID (16) + frame header (5)
            }
            raw.advance(16);
            *server_uuid_consumed = true;
        }

        // Frame header: [command:1][content_len:2 BE][padding_len:2 BE]
        if raw.len() < 5 {
            break;
        }
        let command = raw[0];
        let content_len = u16::from_be_bytes([raw[1], raw[2]]) as usize;
        let padding_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;

        if raw.len() < 5 + content_len + padding_len {
            break; // incomplete frame — wait for more data
        }

        raw.advance(5);
        let frame_content = &raw[..content_len];
        if *read_state == ReadState::Framed {
            filter.filter_server_record(frame_content);
        }
        decoded.extend_from_slice(frame_content);
        raw.advance(content_len);
        raw.advance(padding_len);

        // CMD_PADDING_END (0x01): Vision framing done, stay in TLS.
        // CMD_PADDING_DIRECT (0x02): Vision framing done, enter XTLS-splice.
        if command == CMD_PADDING_END {
            *read_state = ReadState::End;
            decoded.extend_from_slice(raw);
            raw.clear();
            break;
        } else if command == CMD_PADDING_DIRECT {
            *read_state = ReadState::Direct;
            decoded.extend_from_slice(raw);
            raw.clear();
            break;
        }
    }

    read_state.is_done() || decoded.len() > before
}

// ---------------------------------------------------------------------------
// AsyncWrite
// ---------------------------------------------------------------------------

impl AsyncWrite for VisionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut(); // safe: VisionStream is Unpin

        // After the splice transition, send raw bytes.
        if this.write_direct {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        // Build the Vision frame for `buf` if we don't already have one
        // pending from a previous Pending-returning call. A pending frame keeps
        // its own consumed count: `AsyncWrite` requires a `Pending` write to be
        // retried with the same buffer, and reporting `buf.len()` regardless
        // would claim bytes we never framed if that were ever violated.
        if this.write_buf.is_empty() {
            let consumed = buf.len().min(MAX_VISION_CONTENT);
            this.build_vision_frame(&buf[..consumed]);
            this.write_buf_consumed = consumed;
        }
        let consumed = this.write_buf_consumed;

        // Write all pending framed bytes to the inner stream.
        loop {
            if this.write_buf.is_empty() {
                break;
            }
            let n = {
                let pending: &[u8] = &this.write_buf;
                // `pending` borrows `this.write_buf` (field A)
                // `&mut this.inner` borrows `this.inner` (field B) — disjoint
                match Pin::new(&mut this.inner).poll_write(cx, pending) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "broken pipe",
                        )));
                    }
                    Poll::Ready(Ok(n)) => n,
                }
            }; // `pending` borrow ends here
            this.write_buf.advance(n);
        }

        // All framed bytes written.
        this.write_buf_consumed = 0;
        if this.write_buf_app_data {
            this.write_direct = true;
            this.write_buf_app_data = false;
            if this.filter.supports_xtls() {
                if let Some(flag) = &this.write_splice_flag {
                    flag.store(true, Ordering::Release);
                }
            }
        }
        Poll::Ready(Ok(consumed))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Drain any frame left over from a `Pending` write before flushing the
        // inner stream, otherwise those bytes never reach the wire if the
        // caller flushes instead of retrying the write.
        while !this.write_buf.is_empty() {
            let n = {
                let pending: &[u8] = &this.write_buf;
                match Pin::new(&mut this.inner).poll_write(cx, pending) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "broken pipe",
                        )));
                    }
                    Poll::Ready(Ok(n)) => n,
                }
            };
            this.write_buf.advance(n);
        }
        if this.write_buf_app_data {
            this.write_direct = true;
            this.write_buf_app_data = false;
            if this.filter.supports_xtls() {
                if let Some(flag) = &this.write_splice_flag {
                    flag.store(true, Ordering::Release);
                }
                if let Some(flag) = &this.read_splice_flag {
                    flag.store(true, Ordering::Release);
                }
            }
        }
        this.write_buf_consumed = 0;

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_UUID_STR: &str = "5415d8e0-df92-3655-afa4-b79de66413f5";
    const TEST_UUID: [u8; 16] = [
        0x54, 0x15, 0xd8, 0xe0, 0xdf, 0x92, 0x36, 0x55, 0xaf, 0xa4, 0xb7, 0x9d,
        0xe6, 0x64, 0x13, 0xf5,
    ];

    fn make_vision_pair() -> (VisionStream, tokio::io::DuplexStream) {
        let (client, server) = tokio::io::duplex(65536);
        (
            VisionStream::new(Box::new(client), TEST_UUID_STR, None).unwrap(),
            server,
        )
    }

    fn make_vision_pair_with_splice_flags()
    -> (VisionStream, tokio::io::DuplexStream, Arc<AtomicBool>) {
        let (client, server) = tokio::io::duplex(65536);
        let read_flag = Arc::new(AtomicBool::new(false));
        let write_flag = Arc::new(AtomicBool::new(false));
        let opts = VisionOptions {
            read_flag: Arc::clone(&read_flag),
            write_flag,
        };
        (
            VisionStream::new(Box::new(client), TEST_UUID_STR, Some(opts)).unwrap(),
            server,
            read_flag,
        )
    }

    // -----------------------------------------------------------------------
    // Write-side tests
    // -----------------------------------------------------------------------

    /// Parse a Vision frame starting at `buf[offset]`.
    /// Returns `(command, content, padding_len, next_offset)`.
    fn parse_frame(buf: &[u8], offset: usize) -> (u8, Vec<u8>, u16, usize) {
        let cmd = buf[offset];
        let clan = u16::from_be_bytes([buf[offset + 1], buf[offset + 2]]) as usize;
        let plen = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]);
        let content = buf[offset + 5..offset + 5 + clan].to_vec();
        let next = offset + 5 + clan + plen as usize;
        (cmd, content, plen, next)
    }

    #[tokio::test]
    async fn test_write_first_frame_has_uuid_and_padding() {
        let (mut vs, mut server) = make_vision_pair();

        let payload = b"hello";
        vs.write_all(payload).await.unwrap();
        vs.flush().await.unwrap();

        let mut received = vec![0u8; 65536];
        let n = server.read(&mut received).await.unwrap();
        let received = &received[..n];

        // First 16 bytes: UUID
        assert_eq!(&received[..16], &TEST_UUID);

        // Frame header at offset 16
        let (cmd, content, plen, _) = parse_frame(received, 16);
        assert_eq!(cmd, CMD_PADDING_CONTINUE);
        assert_eq!(content, payload);
        assert!(plen > 0, "first frame should carry padding");
    }

    #[tokio::test]
    async fn test_write_second_frame_no_uuid_no_padding() {
        let (mut vs, mut server) = make_vision_pair();

        vs.write_all(b"first").await.unwrap();
        vs.flush().await.unwrap();

        let mut buf = vec![0u8; 65536];
        let _ = server.read(&mut buf).await.unwrap(); // drain first frame

        let payload = b"second";
        vs.write_all(payload).await.unwrap();
        vs.flush().await.unwrap();

        let n = server.read(&mut buf).await.unwrap();
        let received = &buf[..n];

        // No UUID prefix on second frame.
        let (cmd, content, plen, _) = parse_frame(received, 0);
        assert_eq!(cmd, CMD_PADDING_CONTINUE);
        assert_eq!(content, payload);
        assert_eq!(plen, 0);
    }

    fn make_tls13_server_hello_record() -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(0x02); // ServerHello handshake type
        msg.extend_from_slice(&[0x00, 0x00, 0x2A]); // Handshake length = 42
        msg.extend_from_slice(&[0x03, 0x03]); // Legacy version = 3.3
        msg.extend_from_slice(&[0x01; 32]); // Server Random
        msg.push(0x00); // Session ID len = 0
        msg.extend_from_slice(&[0x13, 0x01]); // CipherSuite: TLS_AES_128_GCM_SHA256 (0x1301)
        msg.push(0x00); // Compression method = 0
        // Extensions
        msg.extend_from_slice(&[0x00, 0x06]); // Extensions length = 6
        msg.extend_from_slice(&[0x00, 0x2B]); // Ext Type: supported_versions (0x002B)
        msg.extend_from_slice(&[0x00, 0x02]); // Ext Length = 2
        msg.extend_from_slice(&[0x03, 0x04]); // Version: TLS 1.3 (0x0304)

        let mut record = Vec::new();
        record.push(0x16); // Record Type: Handshake
        record.extend_from_slice(&[0x03, 0x03]); // Version 3.3
        record
            .extend_from_slice(&[(msg.len() >> 8) as u8, (msg.len() & 0xFF) as u8]);
        record.extend_from_slice(&msg);
        record
    }

    fn make_client_hello_record() -> Vec<u8> {
        vec![
            0x16, 0x03, 0x01, 0x00, 0x06, 0x01, 0x00, 0x00, 0x02, 0x03, 0x03,
        ]
    }

    #[tokio::test]
    async fn test_write_app_data_uses_direct_command_and_switches_to_raw() {
        let (mut vs, mut server) = make_vision_pair();

        // 1. Send ClientHello from client
        let client_hello = make_client_hello_record();
        vs.write_all(&client_hello).await.unwrap();
        vs.flush().await.unwrap();

        let mut buf = vec![0u8; 65536];
        let _ = server.read(&mut buf).await.unwrap();

        // 2. Receive TLS 1.3 ServerHello from server
        let server_hello = make_tls13_server_hello_record();
        server
            .write_all(&server_first_frame(
                &TEST_UUID,
                CMD_PADDING_CONTINUE,
                &server_hello,
                0,
            ))
            .await
            .unwrap();

        let mut read_buf = vec![0u8; 64];
        let _ = vs.read(&mut read_buf).await.unwrap();

        // 3. Send TLS ApplicationData record
        let app_data = [TLS_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4];
        vs.write_all(&app_data).await.unwrap();
        vs.flush().await.unwrap();

        let n = server.read(&mut buf).await.unwrap();
        let received = &buf[..n];

        let (cmd, content, ..) = parse_frame(received, 0);
        assert_eq!(cmd, CMD_PADDING_DIRECT);
        assert_eq!(content, app_data);

        // Next write must be raw (no Vision framing).
        let raw_payload = b"raw bytes after splice";
        vs.write_all(raw_payload).await.unwrap();
        vs.flush().await.unwrap();

        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], raw_payload.as_slice());
    }

    #[tokio::test]
    async fn test_write_app_data_without_verified_tls_uses_end_command() {
        let (mut vs, mut server) = make_vision_pair();

        // Send a byte sequence starting with 0x17 0x03 0x03, BUT without prior ClientHello/ServerHello TLS 1.3 handshake.
        let non_tls_app_data =
            [TLS_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4];
        vs.write_all(&non_tls_app_data).await.unwrap();
        vs.flush().await.unwrap();

        let mut buf = vec![0u8; 65536];
        let n = server.read(&mut buf).await.unwrap();
        let received = &buf[..n];

        // Should receive CMD_PADDING_END (0x01) instead of CMD_PADDING_DIRECT (0x02)
        assert_eq!(&received[..16], &TEST_UUID);
        let (cmd, content, ..) = parse_frame(received, 16);
        assert_eq!(cmd, CMD_PADDING_END);
        assert_eq!(content, non_tls_app_data);
    }

    // -----------------------------------------------------------------------
    // Read-side tests
    // -----------------------------------------------------------------------

    /// Build a server-side first Vision frame (with UUID prefix).
    fn server_first_frame(
        uuid: &[u8; 16],
        command: u8,
        content: &[u8],
        padding_len: u16,
    ) -> Vec<u8> {
        let mut v = uuid.to_vec();
        v.push(command);
        v.push((content.len() >> 8) as u8);
        v.push(content.len() as u8);
        v.push((padding_len >> 8) as u8);
        v.push(padding_len as u8);
        v.extend_from_slice(content);
        v.resize(v.len() + padding_len as usize, 0x00); // zero padding
        v
    }

    /// Build a subsequent Vision frame (no UUID prefix).
    fn server_frame(command: u8, content: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(5 + content.len());
        v.push(command);
        v.push((content.len() >> 8) as u8);
        v.push(content.len() as u8);
        v.push(0); // padding_len hi
        v.push(0); // padding_len lo
        v.extend_from_slice(content);
        v
    }

    #[tokio::test]
    async fn test_read_decodes_first_server_frame() {
        let (mut vs, mut server) = make_vision_pair();

        let tls_hello = b"server hello";
        server
            .write_all(&server_first_frame(
                &TEST_UUID,
                CMD_PADDING_CONTINUE,
                tls_hello,
                10,
            ))
            .await
            .unwrap();

        let mut out = vec![0u8; 64];
        let n = vs.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], tls_hello);
    }

    #[tokio::test]
    async fn test_read_skips_padding_in_frames() {
        let (mut vs, mut server) = make_vision_pair();

        let payload = b"cert data";
        server
            .write_all(&server_first_frame(
                &TEST_UUID,
                CMD_PADDING_CONTINUE,
                payload,
                32,
            ))
            .await
            .unwrap();

        let mut out = vec![0u8; 64];
        let n = vs.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], payload);
    }

    #[tokio::test]
    async fn test_read_switches_to_direct_on_cmd_direct() {
        let (mut vs, mut server) = make_vision_pair();

        let tls_finished = b"finished";
        let raw_after = b"\x17\x03\x03\x00\x05hello";

        // First frame: continue; second frame: direct (triggers splice).
        let mut msg =
            server_first_frame(&TEST_UUID, CMD_PADDING_CONTINUE, tls_finished, 0);
        msg.extend(server_frame(CMD_PADDING_DIRECT, b"last-vision"));
        msg.extend_from_slice(raw_after);
        server.write_all(&msg).await.unwrap();
        drop(server);

        let mut out = Vec::new();
        vs.read_to_end(&mut out).await.unwrap();

        // Content from both Vision frames, then raw splice bytes.
        let mut expected = tls_finished.to_vec();
        expected.extend_from_slice(b"last-vision");
        expected.extend_from_slice(raw_after);
        assert_eq!(out, expected);
    }

    #[tokio::test]
    async fn test_read_switches_to_direct_on_cmd_end() {
        let (mut vs, mut server) = make_vision_pair();

        let content = b"end-frame-content";
        let raw_after = b"direct-data";

        let mut msg = server_first_frame(&TEST_UUID, CMD_PADDING_END, content, 0);
        msg.extend_from_slice(raw_after);
        server.write_all(&msg).await.unwrap();
        drop(server);

        let mut out = Vec::new();
        vs.read_to_end(&mut out).await.unwrap();

        let mut expected = content.to_vec();
        expected.extend_from_slice(raw_after);
        assert_eq!(out, expected);
    }

    #[tokio::test]
    async fn test_read_cmd_end_does_not_trigger_splice_flag() {
        let (mut vs, mut server, read_flag) = make_vision_pair_with_splice_flags();

        let content = b"end-frame-content";
        server
            .write_all(&server_first_frame(&TEST_UUID, CMD_PADDING_END, content, 0))
            .await
            .unwrap();

        let mut out = vec![0u8; 64];
        let n = vs.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], content);
        assert!(
            !read_flag.load(Ordering::Acquire),
            "CMD_PADDING_END must not enable XTLS splice"
        );
    }

    #[tokio::test]
    async fn test_read_cmd_direct_triggers_splice_flag() {
        let (mut vs, mut server, read_flag) = make_vision_pair_with_splice_flags();

        let content = b"direct-frame-content";
        server
            .write_all(&server_first_frame(
                &TEST_UUID,
                CMD_PADDING_DIRECT,
                content,
                0,
            ))
            .await
            .unwrap();

        let mut out = vec![0u8; 64];
        let n = vs.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], content);
        assert!(
            read_flag.load(Ordering::Acquire),
            "CMD_PADDING_DIRECT must enable XTLS splice"
        );
    }

    #[tokio::test]
    async fn test_read_multiple_continue_frames() {
        let (mut vs, mut server) = make_vision_pair();

        let part1 = b"chunk1";
        let part2 = b"chunk2";

        let mut msg = server_first_frame(&TEST_UUID, CMD_PADDING_CONTINUE, part1, 0);
        msg.extend(server_frame(CMD_PADDING_DIRECT, part2));
        server.write_all(&msg).await.unwrap();
        drop(server);

        let mut out = Vec::new();
        vs.read_to_end(&mut out).await.unwrap();

        let mut expected = part1.to_vec();
        expected.extend_from_slice(part2);
        assert_eq!(out, expected);
    }
}
