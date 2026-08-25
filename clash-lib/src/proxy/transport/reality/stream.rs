use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::client_connection::RealityClientConnection;
use crate::{common::io::SlideBuffer, proxy::AnyStream};

pub struct RealityTlsStream {
    io: AnyStream,
    conn: RealityClientConnection,
    pending_write: SlideBuffer,
}

impl crate::proxy::ProxyStream for RealityTlsStream {}

impl RealityTlsStream {
    pub fn new(io: AnyStream, conn: RealityClientConnection) -> Self {
        Self {
            io,
            conn,
            pending_write: SlideBuffer::new(16384),
        }
    }

    pub fn get_mut(&mut self) -> (&mut AnyStream, &mut RealityClientConnection) {
        (&mut self.io, &mut self.conn)
    }

    fn flush_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending_write.is_empty() {
            let n = ready!(Pin::new(&mut self.io).poll_write(
                cx,
                self.pending_write.as_slice()
            ))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write TLS bytes",
                )));
            }
            self.pending_write.consume(n);
        }
        Poll::Ready(Ok(()))
    }

    fn drive_writes(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            ready!(self.flush_pending_write(cx))?;

            if !self.conn.wants_write() {
                break;
            }

            self.pending_write.maybe_compact(4096);
            let _ = self.conn.write_tls(&mut self.pending_write);
            if self.pending_write.is_empty() {
                break;
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for RealityTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // 1. Try to read decrypted plaintext
            let dst = buf.initialize_unfilled();
            let n = self.conn.read_plaintext(dst)?;
            if n > 0 {
                buf.advance(n);
                return Poll::Ready(Ok(()));
            }

            // 2. Drive write buffer if connection wants write
            ready!(self.drive_writes(cx))?;

            // 3. Read encrypted TLS records from raw I/O
            let mut raw_buf = [0u8; 16384];
            let mut read_buf_obj = ReadBuf::new(&mut raw_buf);
            match Pin::new(&mut self.io).poll_read(cx, &mut read_buf_obj) {
                Poll::Ready(Ok(())) => {
                    let filled = read_buf_obj.filled();
                    if filled.is_empty() {
                        // EOF
                        return Poll::Ready(Ok(()));
                    }
                    let mut cursor = std::io::Cursor::new(filled);
                    let _ = self.conn.read_tls(&mut cursor);
                    self.conn.process_new_packets()?;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl AsyncWrite for RealityTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.drive_writes(cx))?;
        let written = self.conn.write_plaintext(buf)?;
        ready!(self.drive_writes(cx))?;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.drive_writes(cx))?;
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.drive_writes(cx))?;
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
