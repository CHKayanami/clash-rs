use bytes::{BufMut, Bytes, BytesMut};
use futures::{Future, ready};
use h2::{RecvStream, SendStream, client::ResponseFuture};
use http::StatusCode;
use std::{
    fmt::Debug,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{protocol::parse_stream_response, session::StreamLease};
use crate::proxy::{ProxyStream, transport::h2::shutdown_h2_send};

pub struct H2MuxStream {
    recv: Option<RecvStream>,
    recv_pending: Option<ResponseFuture>,
    send: SendStream<Bytes>,
    recv_buf: Bytes,
    _lease: Option<StreamLease>,
    /// Pending initial request bytes to prepend on first write
    request_bytes: Option<Bytes>,
    /// Whether we have verified the initial status response
    response_read: bool,
    write_closed: bool,
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
        request_bytes: Bytes,
        _lease: Option<StreamLease>,
    ) -> Self {
        Self {
            recv: None,
            recv_pending: Some(response_future),
            send,
            recv_buf: Bytes::new(),
            _lease,
            request_bytes: Some(request_bytes),
            response_read: false,
            write_closed: false,
        }
    }

    fn poll_resolve_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.recv.is_some() {
            return Poll::Ready(Ok(()));
        }

        let Some(response) = self.recv_pending.as_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe, "h2mux response is unavailable",
            )));
        };
        let response = ready!(Pin::new(response).poll(cx));
        self.recv_pending = None;
        let response = response.map_err(|e| {
            io::Error::new(io::ErrorKind::ConnectionReset, e)
        })?;
        if response.status() != StatusCode::OK {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("h2mux server returned status: {}", response.status()),
            )));
        }
        self.recv = Some(response.into_body());
        Poll::Ready(Ok(()))
    }

    fn poll_request_prefix(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(prefix) = self.request_bytes.as_ref() {
            if prefix.is_empty() {
                self.request_bytes = None;
                break;
            }
            let capacity = ready!(self.poll_send_capacity(cx, prefix.len()))?;
            let prefix = self.request_bytes.as_mut().expect("prefix is present");
            let n = prefix.len().min(capacity);
            let data = prefix.split_to(n);
            self.send.send_data(data, false)
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_send_capacity(&mut self, cx: &mut Context<'_>, len: usize) -> Poll<io::Result<usize>> {
        self.send.reserve_capacity(len);
        let capacity = self.send.capacity();
        if capacity > 0 {
            return Poll::Ready(Ok(capacity));
        }
        match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(capacity)) => Poll::Ready(Ok(capacity)),
            Some(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
            None => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "H2 stream closed"))),
        }
    }

    fn read_status_response(&mut self) -> io::Result<()> {
        let Some((size, error)) = parse_stream_response(&self.recv_buf)? else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        if let Some(message) = error {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused,
                format!("h2mux stream rejected: {message}")));
        }
        self.recv_buf = self.recv_buf.slice(size..);
        self.response_read = true;
        Ok(())
    }

    fn poll_h2_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<Bytes>>> {
        let recv = self.recv.as_mut().expect("recv should be resolved");
        match Pin::new(&mut *recv).poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                recv.flow_control().release_capacity(data.len())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
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

impl AsyncRead for H2MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !self.write_closed {
            ready!(self.poll_request_prefix(cx))?;
        }
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
                        if self.recv_buf.is_empty() {
                            self.recv_buf = data;
                        } else {
                            let mut new_buf = BytesMut::with_capacity(
                                self.recv_buf.len() + data.len(),
                            );
                            new_buf.put_slice(&self.recv_buf);
                            new_buf.put_slice(&data);
                            self.recv_buf = new_buf.freeze();
                        }

                        match self.read_status_response() {
                            Ok(()) => break,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                continue;
                            }
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

        loop {
            match self.poll_h2_stream(cx) {
                Poll::Ready(Ok(Some(data))) => {
                    if data.is_empty() {
                        continue;
                    }
                    let to_copy = data.len().min(buf.remaining());
                    buf.put_slice(&data[..to_copy]);
                    if to_copy < data.len() {
                        self.recv_buf = data.slice(to_copy..);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H2MuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe, "H2 stream write side is closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.poll_request_prefix(cx))?;
        let capacity = ready!(self.poll_send_capacity(cx, buf.len()))?;
        let n = buf.len().min(capacity);
        self.send.send_data(Bytes::copy_from_slice(&buf[..n]), false)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_request_prefix(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.write_closed {
            ready!(self.poll_request_prefix(cx))?;
        }
        let this = self.get_mut();
        shutdown_h2_send(&mut this.send, &mut this.write_closed, cx)
    }
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;
