use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, error};

use crate::{
    common::io::{ReadExactSlideBase, ReadExactSlideExt, SlideBuffer},
    proxy::AnyStream,
    session::SocksAddr,
};

const VLESS_VERSION: u8 = 0;

/// Largest partial ClientHello we will hold before sending the handshake
/// anyway: a maximum-size TLS record (16384) plus its 5-byte header.
const MAX_BUFFERED_CLIENT_HELLO: usize = 5 + 16384;
pub(crate) const VLESS_COMMAND_TCP: u8 = 1;
pub(crate) const VLESS_COMMAND_UDP: u8 = 2;
pub(crate) const VLESS_COMMAND_MUX: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseState {
    WaitingHeader,
    WaitingPayload(usize),
    Done,
}

pub struct VlessStream {
    inner: AnyStream,
    handshake_done: bool,
    handshake_sent: bool,
    response_received: bool,
    uuid: uuid::Uuid,
    destination: SocksAddr,
    command: u8,
    addon_bytes: Option<Vec<u8>>,
    response_buf: SlideBuffer,
    response_state: ResponseState,
    write_buf: BytesMut,
    first_write_len: usize,
    pending_first_payload: BytesMut,
}

impl crate::proxy::ProxyStream for VlessStream {}

impl VlessStream {
    pub fn new(
        stream: AnyStream,
        uuid: &str,
        destination: &SocksAddr,
        command: u8,
        flow: Option<&str>,
    ) -> io::Result<Self> {
        let uuid = uuid::Uuid::parse_str(uuid).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid UUID format")
        })?;

        debug!("VLESS stream created for destination: {}", destination);

        Ok(Self {
            inner: stream,
            handshake_done: false,
            handshake_sent: false,
            response_received: false,
            uuid,
            destination: destination.clone(),
            command,
            addon_bytes: flow.map(build_addon_bytes),
            response_buf: SlideBuffer::new(64),
            response_state: ResponseState::WaitingHeader,
            write_buf: BytesMut::new(),
            first_write_len: 0,
            pending_first_payload: BytesMut::new(),
        })
    }

    fn build_handshake_header(&self, payload_len: usize) -> BytesMut {
        let estimated_len = 1
            + 16
            + 1
            + self.addon_bytes.as_ref().map_or(0, |a| a.len())
            + 1
            + 64
            + payload_len;
        let mut buf = BytesMut::with_capacity(estimated_len);

        // VLESS request header:
        // Version (1 byte) + UUID (16 bytes) + Addon length (1 byte)
        // + Addon bytes (variable) + Command (1 byte) + Port (2 bytes)
        // + Address type + Address
        buf.put_u8(VLESS_VERSION);
        buf.put_slice(self.uuid.as_bytes());

        if let Some(ref addon) = self.addon_bytes {
            buf.put_u8(addon.len() as u8);
            buf.extend_from_slice(addon);
        } else {
            buf.put_u8(0); // No addon
        }

        buf.put_u8(self.command);

        if self.command != VLESS_COMMAND_MUX {
            self.destination.write_to_buf_vmess(&mut buf);
        }
        buf
    }

    fn poll_send_pending_handshake(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.handshake_sent {
            return Poll::Ready(Ok(()));
        }

        if self.write_buf.is_empty() {
            if self.pending_first_payload.is_empty() {
                // Nothing buffered yet — the handshake goes out with the first
                // write.
                return Poll::Ready(Ok(()));
            }
            let payload = std::mem::take(&mut self.pending_first_payload);
            let mut header = self.build_handshake_header(payload.len());
            header.put_slice(&payload);
            self.write_buf = header;
        }

        let Self {
            inner, write_buf, ..
        } = self;
        while !write_buf.is_empty() {
            let n =
                futures::ready!(Pin::new(&mut *inner).poll_write(cx, write_buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write VLESS handshake",
                )));
            }
            write_buf.advance(n);
        }

        self.handshake_sent = true;
        debug!("VLESS handshake sent");
        Poll::Ready(Ok(()))
    }
}

impl ReadExactSlideBase for VlessStream {
    type I = AnyStream;

    fn decompose(&mut self) -> (&mut Self::I, &mut SlideBuffer) {
        (&mut self.inner, &mut self.response_buf)
    }
}

impl AsyncRead for VlessStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // A payload buffered while waiting for the rest of a TLS ClientHello
        // must not sit here forever: a client that writes a partial record and
        // then waits for a reply would otherwise deadlock, since nothing has
        // been sent to the server yet.
        futures::ready!(this.poll_send_pending_handshake(cx))?;

        // Must receive response before reading
        if this.handshake_sent && !this.response_received {
            loop {
                match this.response_state {
                    ResponseState::WaitingHeader => {
                        futures::ready!(this.poll_read_exact(cx, 2))?;
                        let version = this.response_buf[0];
                        if version != VLESS_VERSION {
                            error!("Invalid VLESS response version: {}", version);
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "invalid VLESS response version: {}",
                                    version
                                ),
                            )));
                        }
                        let additional_info_len = this.response_buf[1] as usize;
                        this.response_buf.consume(2);
                        if additional_info_len > 0 {
                            this.response_state =
                                ResponseState::WaitingPayload(additional_info_len);
                        } else {
                            this.response_state = ResponseState::Done;
                            this.response_received = true;
                            this.handshake_done = true;
                            debug!("VLESS handshake completed successfully");
                            break;
                        }
                    }
                    ResponseState::WaitingPayload(len) => {
                        futures::ready!(this.poll_read_exact(cx, len))?;
                        debug!(
                            "VLESS additional info received: {} bytes: {:02x?}",
                            len,
                            &this.response_buf[..len.min(32)],
                        );
                        this.response_buf.consume(len);
                        this.response_state = ResponseState::Done;
                        this.response_received = true;
                        this.handshake_done = true;
                        debug!("VLESS handshake completed successfully");
                        break;
                    }
                    ResponseState::Done => {
                        break;
                    }
                }
            }
        }

        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();

        // Send handshake with first write
        if !this.handshake_sent {
            if this.write_buf.is_empty() {
                this.pending_first_payload.extend_from_slice(buf);

                // Check if this payload starts with TLS ClientHello record header (0x16, 0x03)
                let is_tls = this.pending_first_payload.len() >= 5
                    && this.pending_first_payload[0] == 0x16
                    && this.pending_first_payload[1] == 0x03;

                let expected_tls_len = if is_tls {
                    5 + u16::from_be_bytes([
                        this.pending_first_payload[3],
                        this.pending_first_payload[4],
                    ]) as usize
                } else {
                    0
                };

                // If it's a TLS ClientHello and we haven't received the full
                // record yet, buffer the chunk and return Ok(buf.len()) to
                // consume it from inbound. The ceiling is a whole maximum-size
                // TLS record including its 5-byte header — using 16384 alone
                // excluded the largest legal ClientHellos.
                if is_tls
                    && this.pending_first_payload.len() < expected_tls_len
                    && expected_tls_len <= MAX_BUFFERED_CLIENT_HELLO
                {
                    debug!(
                        "VLESS buffering partial TLS ClientHello ({}/{} bytes) for destination: {}",
                        this.pending_first_payload.len(),
                        expected_tls_len,
                        this.destination
                    );
                    return Poll::Ready(Ok(buf.len()));
                }

                debug!(
                    "VLESS handshake starting for destination: {}",
                    this.destination
                );
                let payload = std::mem::take(&mut this.pending_first_payload);
                let mut header = this.build_handshake_header(payload.len());
                header.put_slice(&payload);
                this.write_buf = header;
                this.first_write_len = buf.len();
            }

            while !this.write_buf.is_empty() {
                let n = futures::ready!(
                    Pin::new(&mut this.inner).poll_write(cx, &this.write_buf)
                )?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write VLESS handshake",
                    )));
                }
                this.write_buf.advance(n);
            }

            this.handshake_sent = true;
            debug!(
                "VLESS handshake sent with {} bytes of data",
                this.first_write_len
            );
            return Poll::Ready(Ok(this.first_write_len));
        }

        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        futures::ready!(this.poll_send_pending_handshake(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Encode the flow field as a Protobuf field-1 length-delimited value.
/// Format: [0x0A][varint len][bytes]
pub(crate) fn build_addon_bytes(flow: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + flow.len());
    buf.push(0x0A); // field 1, wire type 2 (length-delimited)
    buf.push(flow.len() as u8); // single-byte varint (flow strings are short)
    buf.extend_from_slice(flow.as_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SocksAddr;

    fn dummy_stream() -> AnyStream {
        let (client, _server) = tokio::io::duplex(1024);
        Box::new(client)
    }

    fn tcp_dest() -> SocksAddr {
        "1.2.3.4:80".parse().unwrap()
    }

    // --- build_addon_bytes ---

    #[test]
    fn test_build_addon_bytes_empty_flow() {
        let addon = build_addon_bytes("");
        // tag(1) + len(0) = 2 bytes, no payload
        assert_eq!(addon, vec![0x0A, 0x00]);
    }

    #[test]
    fn test_build_addon_bytes_vision_flow() {
        let flow = "xtls-rprx-vision";
        let addon = build_addon_bytes(flow);
        assert_eq!(addon.len(), 2 + flow.len()); // 18 bytes
        assert_eq!(addon[0], 0x0A); // field-1, wire-type-2 tag
        assert_eq!(addon[1], flow.len() as u8); // 0x10 = 16
        assert_eq!(&addon[2..], flow.as_bytes());
    }

    // --- build_handshake_header ---

    #[test]
    fn test_handshake_header_no_flow() {
        let s = VlessStream::new(
            dummy_stream(),
            "5415d8e0-df92-3655-afa4-b79de66413f5",
            &tcp_dest(),
            VLESS_COMMAND_TCP,
            None,
        )
        .unwrap();
        let hdr = s.build_handshake_header(0);
        // byte 17 (0-indexed) is the addon-length byte
        assert_eq!(hdr[17], 0); // no addon
    }

    #[test]
    fn test_handshake_header_with_flow() {
        let flow = "xtls-rprx-vision";
        let s = VlessStream::new(
            dummy_stream(),
            "5415d8e0-df92-3655-afa4-b79de66413f5",
            &tcp_dest(),
            VLESS_COMMAND_TCP,
            Some(flow),
        )
        .unwrap();
        let hdr = s.build_handshake_header(0);
        let addon_len = hdr[17] as usize;
        assert_eq!(addon_len, 2 + flow.len()); // 18
        let addon = &hdr[18..18 + addon_len];
        assert_eq!(addon[0], 0x0A);
        assert_eq!(addon[1], flow.len() as u8);
        assert_eq!(&addon[2..], flow.as_bytes());
    }

    // --- new() ---

    #[test]
    fn test_new_invalid_uuid() {
        let result = VlessStream::new(
            dummy_stream(),
            "not-a-uuid",
            &tcp_dest(),
            VLESS_COMMAND_TCP,
            None,
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handshake_flow_success() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client_raw, mut server_raw) = tokio::io::duplex(1024);
        let mut client = VlessStream::new(
            Box::new(client_raw),
            "5415d8e0-df92-3655-afa4-b79de66413f5",
            &tcp_dest(),
            VLESS_COMMAND_TCP,
            None,
        )
        .unwrap();

        // 1. Client writes first data
        let test_data = b"hello world";
        let handle = tokio::spawn(async move {
            client.write_all(test_data).await.unwrap();
            client.flush().await.unwrap();

            // Try reading after writing
            let mut read_buf = vec![0u8; 10];
            let n = client.read(&mut read_buf).await.unwrap();
            assert_eq!(&read_buf[..n], b"response12");
        });

        // 2. Server reads handshake request
        let mut req_buf = vec![0u8; 1024];
        let n = server_raw.read(&mut req_buf).await.unwrap();
        // VLESS header is at least 1 + 16 + 1 + 1 + 2 + 1 + 4 = 26 bytes. Plus "hello world" (11 bytes) = 37 bytes.
        assert!(n >= 37);
        assert_eq!(&req_buf[n - 11..n], b"hello world");

        // 3. Server writes response in chunks
        // Response version (0x00), additional info len (0x04)
        server_raw.write_all(&[0x00]).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        server_raw.write_all(&[0x04]).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        // additional info (4 bytes)
        server_raw
            .write_all(&[0x01, 0x02, 0x03, 0x04])
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        // actual response data
        server_raw.write_all(b"response12").await.unwrap();

        handle.await.unwrap();
    }
}
