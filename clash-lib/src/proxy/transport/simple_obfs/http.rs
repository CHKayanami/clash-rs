use base64::Engine;
use bytes::{BufMut, BytesMut};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proxy::{AnyStream, transport::Transport};

pub(super) const MAX_RESPONSE_HEADER_SIZE: usize = 64 * 1024;

pub struct Client {
    host: String,
    port: u16,
}

impl Client {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }
}

impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        Ok(HTTPObfs::new(stream, self.host.clone(), self.port).into())
    }
}

pub struct HTTPObfs {
    inner: AnyStream,
    host: String,
    port: u16,

    first_request: bool,
    first_response: bool,
    // First-request buffer and the source byte count still owed to poll_write.
    write_buf: Vec<u8>,
    write_pos: usize,
    write_committed: usize,
    // read-side: accumulates response bytes until \r\n\r\n is located
    read_buf: BytesMut,
}

impl crate::proxy::ProxyStream for HTTPObfs {}

/// Drain `this.write_buf[this.write_pos..]` into the inner stream, advancing
/// `this.write_pos` with each partial write.  Returns `Poll::Ready(Ok(()))`
/// once all bytes have been sent.
fn drain_write_buf(
    this: &mut HTTPObfs,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while this.write_pos < this.write_buf.len() {
        let n = ready!(
            Pin::new(&mut this.inner)
                .poll_write(cx, &this.write_buf[this.write_pos..])
        )?;
        if n == 0 {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
        }
        this.write_pos += n;
    }
    Poll::Ready(Ok(()))
}

impl AsyncWrite for HTTPObfs {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // If a previous first-request chunk is still being drained, finish it
        // before accepting new data.  The caller will supply the same `buf`
        // again (AsyncWrite contract), so returning `Ok(write_committed)` is
        // correct: it tells the caller those source bytes were consumed.
        if this.write_committed > 0 {
            ready!(drain_write_buf(this, cx))?;
            let committed = this.write_committed;
            this.write_committed = 0;
            return Poll::Ready(Ok(committed));
        }

        if this.first_request {
            // Build the HTTP upgrade request: headers + payload in one buffer.
            let rand_bytes = rand::random::<[u8; 16]>();
            let mut buffer = Vec::new();
            buffer.put_slice(b"GET / HTTP/1.1\r\n");
            buffer.put_slice(
                format!(
                    "Host: {}\r\n",
                    if this.port != 80 {
                        format!("{}:{}", this.host, this.port)
                    } else {
                        this.host.clone()
                    }
                )
                .as_bytes(),
            );
            buffer.put_slice(
                format!(
                    "User-Agent: curl/7.{}.{}\r\n",
                    rand::random_range(0..54),
                    rand::random_range(0..2),
                )
                .as_bytes(),
            );
            buffer.put_slice(b"Upgrade: websocket\r\n");
            buffer.put_slice(b"Connection: Upgrade\r\n");
            buffer.put_slice(
                format!(
                    "Sec-WebSocket-Key: {}\r\n",
                    base64::engine::general_purpose::STANDARD.encode(rand_bytes)
                )
                .as_bytes(),
            );
            buffer
                .put_slice(format!("Content-Length: {}\r\n", buf.len()).as_bytes());
            buffer.put_slice(b"\r\n");
            buffer.put_slice(buf);

            let n = buf.len(); // source bytes consumed (payload only)
            this.first_request = false;
            this.write_buf = buffer;
            this.write_pos = 0;
            this.write_committed = n;

            // Attempt to drain synchronously; if Pending, write_buf/write_pos
            // and write_committed survive in the struct for the next poll.
            ready!(drain_write_buf(this, cx))?;
            this.write_committed = 0;
            Poll::Ready(Ok(n))
        } else {
            // Subsequent writes: forward directly, no buffering needed.
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        // Drain any in-flight first-request write before flushing.
        ready!(drain_write_buf(this, cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        // Drain any in-flight first-request write before shutting down.
        ready!(drain_write_buf(this, cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for HTTPObfs {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        if this.first_response {
            let delimiter = b"\r\n\r\n";
            loop {
                // Only newly appended bytes can complete the header delimiter.
                let start = this.read_buf.len().saturating_sub(delimiter.len() - 1);
                let mut tmp = [0u8; 4096];
                let limit = (MAX_RESPONSE_HEADER_SIZE - this.read_buf.len()).min(tmp.len());
                if limit == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "simple-obfs HTTP response header exceeds 64 KiB",
                    )));
                }
                let mut tmp_buf = ReadBuf::new(&mut tmp[..limit]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf))?;
                if tmp_buf.filled().is_empty() {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.read_buf.put_slice(tmp_buf.filled());
                if let Some(pos) = this.read_buf[start..]
                    .windows(delimiter.len())
                    .position(|window| window == delimiter)
                {
                    this.first_response = false;
                    let _ = this.read_buf.split_to(start + pos + delimiter.len());
                    break;
                }
            }
        }

        if this.read_buf.is_empty() {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        let to_read = this.read_buf.len().min(buf.remaining());
        buf.put_slice(&this.read_buf.split_to(to_read));
        Poll::Ready(Ok(()))
    }
}

impl HTTPObfs {
    pub fn new(inner: AnyStream, host: String, port: u16) -> Self {
        Self {
            inner,
            host,
            port,

            first_request: true,
            first_response: true,
            write_buf: Vec::new(),
            write_pos: 0,
            write_committed: 0,
            read_buf: BytesMut::new(),
        }
    }
}
