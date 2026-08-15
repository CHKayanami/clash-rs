use bytes::{BufMut, Bytes, BytesMut};
use futures::ready;
use h2::{RecvStream, SendStream, client::ResponseFuture};
use std::{
    fmt::Debug,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::oneshot,
};

use super::protocol::{STATUS_ERROR, STATUS_SUCCESS, StreamRequest};
use crate::proxy::ProxyStream;

pub trait StreamCloser: Send + Sync {
    fn on_close(&self);
}

pub struct H2MuxStream {
    recv: Option<RecvStream>,
    recv_pending: Option<oneshot::Receiver<io::Result<RecvStream>>>,
    send: SendStream<Bytes>,
    recv_buf: Bytes,
    closer: Option<Arc<dyn StreamCloser>>,
    /// Pending initial request bytes to prepend on first write
    request_bytes: Option<Bytes>,
    /// Pending write data from partial send (combined_buffer, user_data_len, bytes_sent)
    pending_write: Option<(Bytes, usize, usize)>,
    /// Whether we have verified the initial status response
    response_read: bool,
}

impl ProxyStream for H2MuxStream {}

impl Debug for H2MuxStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2MuxStream")
            .field("recv_buf_len", &self.recv_buf.len())
            .field("response_read", &self.response_read)
            .finish()
    }
}

impl H2MuxStream {
    pub fn new(
        response_future: ResponseFuture,
        send: SendStream<Bytes>,
        request: StreamRequest,
        closer: Option<Arc<dyn StreamCloser>>,
    ) -> io::Result<Self> {
        let request_bytes = Bytes::from(request.encode()?);
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            match response_future.await {
                Ok(response) => {
                    if response.status().is_success() {
                        let _ = tx.send(Ok(response.into_body()));
                    } else {
                        let _ = tx.send(Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("h2mux server returned status: {}", response.status()),
                        )));
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("h2mux response error: {e}"),
                    )));
                }
            }
        });

        Ok(Self {
            recv: None,
            recv_pending: Some(rx),
            send,
            recv_buf: Bytes::new(),
            closer,
            request_bytes: Some(request_bytes),
            pending_write: None,
            response_read: false,
        })
    }

    fn poll_resolve_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.recv.is_some() {
            return Poll::Ready(Ok(()));
        }

        if let Some(rx) = self.recv_pending.as_mut() {
            match Pin::new(rx).poll(cx) {
                Poll::Ready(Ok(Ok(recv))) => {
                    self.recv = Some(recv);
                    self.recv_pending = None;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Ok(Err(e))) => {
                    self.recv_pending = None;
                    Poll::Ready(Err(e))
                }
                Poll::Ready(Err(_)) => {
                    self.recv_pending = None;
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "h2mux response channel closed",
                    )))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "no receiver available",
            )))
        }
    }

    fn read_status_response(&mut self) -> io::Result<()> {
        if self.recv_buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "need more data for status",
            ));
        }

        let status = self.recv_buf[0];
        match status {
            STATUS_SUCCESS => {
                self.recv_buf = self.recv_buf.slice(1..);
                self.response_read = true;
                Ok(())
            }
            STATUS_ERROR => {
                let msg = self.read_error_message()?;
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("h2mux stream rejected: {msg}"),
                ))
            }
            _ => {
                self.recv_buf = self.recv_buf.slice(1..);
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid status byte: {status}"),
                ))
            }
        }
    }

    fn read_error_message(&mut self) -> io::Result<String> {
        if self.recv_buf.len() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "need more data for error message",
            ));
        }

        let mut pos = 1;
        let mut len: usize = 0;
        let mut shift = 0;

        loop {
            if pos >= self.recv_buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "need more data for varint",
                ));
            }
            let byte = self.recv_buf[pos];
            pos += 1;
            len |= ((byte & 0x7F) as usize) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "varint too large",
                ));
            }
        }

        let total_len = pos + len;
        if self.recv_buf.len() < total_len {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "need more data for error message body",
            ));
        }

        let msg_bytes = &self.recv_buf[pos..total_len];
        let msg = String::from_utf8_lossy(msg_bytes).to_string();
        self.recv_buf = self.recv_buf.slice(total_len..);
        self.response_read = true;
        Ok(msg)
    }

    fn poll_h2_stream(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        let recv = self.recv.as_mut().expect("recv should be resolved");
        match Pin::new(recv).poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let len = data.len();
                let _ = self
                    .recv
                    .as_mut()
                    .unwrap()
                    .flow_control()
                    .release_capacity(len);
                Poll::Ready(Ok(Some(data)))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e)))
            }
            Poll::Ready(None) => Poll::Ready(Ok(None)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for H2MuxStream {
    fn drop(&mut self) {
        if let Some(closer) = self.closer.take() {
            closer.on_close();
        }
    }
}

impl AsyncRead for H2MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.recv.is_none() {
            ready!(self.poll_resolve_recv(cx))?;
        }

        if !self.response_read {
            if !self.recv_buf.is_empty() {
                match self.read_status_response() {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }

            while !self.response_read {
                match self.poll_h2_stream(cx) {
                    Poll::Ready(Ok(Some(data))) => {
                        if data.is_empty() {
                            continue;
                        }
                        let mut new_buf = BytesMut::with_capacity(self.recv_buf.len() + data.len());
                        new_buf.put_slice(&self.recv_buf);
                        new_buf.put_slice(&data);
                        self.recv_buf = new_buf.freeze();

                        match self.read_status_response() {
                            Ok(()) => break,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                            Err(e) => return Poll::Ready(Err(e)),
                        }
                    }
                    Poll::Ready(Ok(None)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF while reading stream response",
                        )));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        if !self.recv_buf.is_empty() {
            let to_copy = self.recv_buf.len().min(buf.remaining());
            buf.put_slice(&self.recv_buf[..to_copy]);
            self.recv_buf = self.recv_buf.slice(to_copy..);
            return Poll::Ready(Ok(()));
        }

        match self.poll_h2_stream(cx) {
            Poll::Ready(Ok(Some(data))) => {
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.recv_buf = data.slice(to_copy..);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(())), // EOF
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for H2MuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some((pending_data, user_len, sent)) = self.pending_write.take() {
            let remaining = &pending_data[sent..];
            let current_capacity = self.send.capacity();
            if current_capacity < remaining.len() {
                self.send.reserve_capacity(remaining.len());
            }

            match self.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(capacity))) => {
                    let to_send = remaining.len().min(capacity);
                    self.send
                        .send_data(pending_data.slice(sent..sent + to_send), false)
                        .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;

                    let new_sent = sent + to_send;
                    if new_sent < pending_data.len() {
                        self.pending_write = Some((pending_data, user_len, new_sent));
                        return Poll::Pending;
                    }
                    return Poll::Ready(Ok(user_len));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "H2 stream closed",
                    )));
                }
                Poll::Pending => {
                    self.pending_write = Some((pending_data, user_len, sent));
                    return Poll::Pending;
                }
            }
        }

        if let Some(request_bytes) = self.request_bytes.take() {
            let request_len = request_bytes.len();
            let mut combined = BytesMut::with_capacity(request_len + buf.len());
            combined.put_slice(&request_bytes);
            combined.put_slice(buf);
            let combined = combined.freeze();

            let current_capacity = self.send.capacity();
            if current_capacity < combined.len() {
                self.send.reserve_capacity(combined.len());
            }

            return match self.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(capacity))) => {
                    let to_send = combined.len().min(capacity);
                    self.send
                        .send_data(combined.slice(..to_send), false)
                        .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;

                    if to_send < combined.len() {
                        let user_written = to_send.saturating_sub(request_len).min(buf.len());
                        self.pending_write = Some((combined, user_written, to_send));
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(buf.len()))
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)))
                }
                Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "H2 stream closed",
                ))),
                Poll::Pending => {
                    self.request_bytes = Some(request_bytes);
                    Poll::Pending
                }
            };
        }

        let current_capacity = self.send.capacity();
        if current_capacity < buf.len() {
            self.send.reserve_capacity(buf.len());
        }

        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                let to_send = buf.len().min(capacity);
                self.send
                    .send_data(Bytes::copy_from_slice(&buf[..to_send]), false)
                    .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
                Poll::Ready(Ok(to_send))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "H2 stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.send.reserve_capacity(0);
        Poll::Ready(match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(_)) | None => {
                self.send
                    .send_data(Bytes::new(), true)
                    .map_or_else(
                        |e| Err(io::Error::new(io::ErrorKind::BrokenPipe, e)),
                        |_| Ok(()),
                    )
            }
            Some(Err(e)) => Err(io::Error::new(io::ErrorKind::BrokenPipe, e)),
        })
    }
}
