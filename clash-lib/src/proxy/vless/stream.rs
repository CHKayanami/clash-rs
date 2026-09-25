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
    first_write_len: Option<usize>,
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
            first_write_len: None,
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

        // If a first write was previously buffered into write_buf (which returned Pending),
        // we must finish flushing the handshake (whether here or completed concurrently by poll_read)
        // and return the length of that first write, rather than writing buf again to inner!
        if let Some(first_len) = this.first_write_len {
            futures::ready!(this.poll_send_pending_handshake(cx))?;
            this.first_write_len = None;
            return Poll::Ready(Ok(first_len));
        }

        // Send handshake with first write
        if !this.handshake_sent {
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
            // consume it from inbound.
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
            this.first_write_len = Some(buf.len());

            futures::ready!(this.poll_send_pending_handshake(cx))?;
            let len = this.first_write_len.take().unwrap_or(0);
            debug!(
                "VLESS handshake sent with {} bytes of data",
                len
            );
            return Poll::Ready(Ok(len));
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
        futures::ready!(this.poll_send_pending_handshake(cx))?;
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
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    fn dummy_stream() -> AnyStream {
        let (client, _server) = tokio::io::duplex(1024);
        Box::new(client)
    }

    fn tcp_dest() -> SocksAddr {
        "1.2.3.4:80".parse().unwrap()
    }

    // A mock stream that limits the first write to 10 bytes and then returns Pending,
    // allowing later writes to succeed normally.
    struct ChunkedStream {
        written: Arc<std::sync::Mutex<Vec<u8>>>,
        write_count: Arc<AtomicUsize>,
        response: Vec<u8>,
        resp_offset: usize,
    }

    impl crate::proxy::ProxyStream for ChunkedStream {}

    impl AsyncRead for ChunkedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.resp_offset < self.response.len() {
                let to_read = (self.response.len() - self.resp_offset).min(buf.remaining());
                buf.put_slice(&self.response[self.resp_offset..self.resp_offset + to_read]);
                self.resp_offset += to_read;
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ChunkedStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            let cnt = self.write_count.fetch_add(1, Ordering::SeqCst);
            if cnt == 0 {
                // First write writes partial (10 bytes) and returns Ready(Ok(10))
                let n = 10.min(buf.len());
                self.written.lock().unwrap().extend_from_slice(&buf[..n]);
                Poll::Ready(Ok(n))
            } else if cnt == 1 {
                // Next poll returns Pending to simulate backpressure
                Poll::Pending
            } else {
                self.written.lock().unwrap().extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
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

    #[tokio::test]
    async fn test_handshake_flow_server_speaks_first() {
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

        let banner = b"SSH-2.0-OpenSSH_9";

        let client_fut = async {
            let mut read_buf = vec![0u8; banner.len()];
            client.read_exact(&mut read_buf).await.unwrap();
            read_buf
        };

        let server_fut = async {
            let mut req_buf = vec![0u8; 1024];
            let n = server_raw.read(&mut req_buf).await.unwrap();
            assert_eq!(n, 26);
            assert_eq!(req_buf[0], VLESS_VERSION);

            server_raw.write_all(&[0x00, 0x00]).await.unwrap();
            server_raw.write_all(banner).await.unwrap();
        };

        let (read_buf, ()) = tokio::join!(client_fut, server_fut);
        assert_eq!(&read_buf, banner);
    }

    #[tokio::test]
    async fn test_no_duplicate_first_write_on_concurrent_read() {

        let written_bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let write_count = Arc::new(AtomicUsize::new(0));

        let mock = ChunkedStream {
            written: written_bytes.clone(),
            write_count,
            response: vec![0x00, 0x00], // Valid VLESS response
            resp_offset: 0,
        };

        let mut client = VlessStream::new(
            Box::new(mock),
            "5415d8e0-df92-3655-afa4-b79de66413f5",
            &tcp_dest(),
            VLESS_COMMAND_TCP,
            None,
        )
        .unwrap();

        let first_payload = b"FIRST_PAYLOAD_TEST_DATA";

        // 1. Initial write: only 10 bytes written, returns Pending
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let res1 = Pin::new(&mut client).poll_write(&mut cx, first_payload);
        assert!(res1.is_pending());

        // 2. Concurrent read runs (e.g. from copy_bidirectional), flushing the rest of the handshake+payload
        let mut dummy_read_buf = [0u8; 16];
        let mut read_buf = ReadBuf::new(&mut dummy_read_buf);
        let _ = Pin::new(&mut client).poll_read(&mut cx, &mut read_buf);

        // 3. Write task wakes up and polls write again with same buffer
        let res2 = Pin::new(&mut client).poll_write(&mut cx, first_payload);
        assert!(res2.is_ready());
        let written_len = res2.map(|r| r.unwrap());
        assert_eq!(written_len, Poll::Ready(first_payload.len()));

        // Verify: first_payload must appear EXACTLY ONCE in written_bytes!
        let total_written = written_bytes.lock().unwrap().clone();
        let payload_occurrences = total_written
            .windows(first_payload.len())
            .filter(|w| *w == first_payload)
            .count();

        assert_eq!(
            payload_occurrences, 1,
            "first_payload must be sent exactly once, but appeared {} times",
            payload_occurrences
        );
    }

    #[tokio::test]
    async fn test_shutdown_flushes_pending_first_payload() {
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

        // Partial TLS record: indicates 32 bytes of record data (total 37 bytes), but we only write 10 bytes
        let mut partial_tls = vec![0x16, 0x03, 0x01, 0x00, 0x20];
        partial_tls.extend_from_slice(b"12345"); // total 10 bytes

        // 1. poll_write buffers the partial TLS ClientHello
        let n = client.write(&partial_tls).await.unwrap();
        assert_eq!(n, 10);

        // 2. Client shuts down
        client.shutdown().await.unwrap();

        // 3. Server should receive handshake header followed by the 10-byte buffered payload
        let mut server_buf = vec![0u8; 1024];
        let n = server_raw.read(&mut server_buf).await.unwrap();
        // VLESS request header is 26 bytes + 10 bytes payload = 36 bytes
        assert_eq!(n, 36);
        assert_eq!(server_buf[0], VLESS_VERSION);
        assert_eq!(&server_buf[26..36], &partial_tls);
    }

    #[tokio::test]
    async fn test_empty_write_backpressure_does_not_corrupt_handshake() {
        let written_bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let write_count = Arc::new(AtomicUsize::new(0));

        let mock = ChunkedStream {
            written: written_bytes.clone(),
            write_count,
            response: vec![0x00, 0x00],
            resp_offset: 0,
        };

        let mut client = VlessStream::new(
            Box::new(mock),
            "5415d8e0-df92-3655-afa4-b79de66413f5",
            &tcp_dest(),
            VLESS_COMMAND_TCP,
            None,
        )
        .unwrap();

        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 1. Initial write with empty buffer: generates handshake header, writes partial (10 bytes), returns Pending
        let res1 = Pin::new(&mut client).poll_write(&mut cx, &[]);
        assert!(res1.is_pending());

        // 2. Second poll_write with &[]: must NOT regenerate header or overwrite write_buf!
        let res2 = Pin::new(&mut client).poll_write(&mut cx, &[]);
        assert!(matches!(res2, Poll::Ready(Ok(0))));

        // Verify total written bytes is exactly 1 handshake header (26 bytes), without duplication or truncation
        let total = written_bytes.lock().unwrap().clone();
        assert_eq!(total.len(), 26);
        assert_eq!(total[0], VLESS_VERSION);
    }
}
