use async_trait::async_trait;
use bytes::Bytes;
use futures::{Future, ready};
use h2::{RecvStream, SendStream, client::ResponseFuture};
use http::{HeaderMap, Request, StatusCode, Uri, Version, uri::PathAndQuery};
use percent_encoding::percent_decode_str;
use std::{
    fmt::{self, Debug},
    io::{self, Error, ErrorKind},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
};

use super::{Transport, h2_common::{ConnectionDriver, MAX_WRITE_SIZE, client_builder, poll_send_capacity, release_receive_capacity, shutdown_h2_send}};
use crate::{
    common::errors::map_io_error,
    proxy::{AnyStream, ProxyStream},
};
use frame::{Decoder, encode_frame};

mod frame;
#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct Client {
    pub host: String,
    pub path: PathAndQuery,
}

impl Client {
    pub fn new(host: String, path: PathAndQuery) -> Self {
        Self { host, path }
    }

    fn req(&self) -> io::Result<Request<()>> {
        let uri = Uri::builder()
            .scheme("https")
            .authority(self.host.as_str())
            .path_and_query(format!("{}/Tun", self.path.as_str()))
            .build()
            .map_err(map_io_error)?;
        Request::builder()
            .method("POST")
            .uri(uri)
            .version(Version::HTTP_2)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("user-agent", "tonic/0.10")
            .body(())
            .map_err(map_io_error)
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let req = self.req()?;
        let (client, connection) = client_builder()
            .handshake(stream)
            .await
            .map_err(map_io_error)?;
        let mut client = client.ready().await.map_err(map_io_error)?;
        let (response, send) =
            client.send_request(req, false).map_err(map_io_error)?;
        let connection_task = ConnectionDriver::spawn(connection, None);
        Ok(AnyStream::new(GrpcStream::new(response, send, connection_task)))
    }
}

pub struct GrpcStream {
    response: Option<ResponseFuture>,
    recv: Option<RecvStream>,
    send: SendStream<Bytes>,
    _driver: ConnectionDriver,
    buffer: Bytes,
    decoder: Decoder,
    pending_send: Bytes,
    write_closed: bool,
    status_received: bool,
    read_closed: bool,
    read_error: Option<(ErrorKind, String)>,
}

impl ProxyStream for GrpcStream {}

impl Debug for GrpcStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcStream")
            .field("send", &self.send)
            .field("buffer_len", &self.buffer.len())
            .field("pending_send_len", &self.pending_send.len())
            .field("write_closed", &self.write_closed)
            .finish()
    }
}

impl GrpcStream {
    fn new(
        response: ResponseFuture,
        send: SendStream<Bytes>,
        connection_task: ConnectionDriver,
    ) -> Self {
        Self {
            response: Some(response),
            recv: None,
            send,
            _driver: connection_task,
            buffer: Bytes::new(),
            decoder: Decoder::default(),
            pending_send: Bytes::new(),
            write_closed: false,
            status_received: false,
            read_closed: false,
            read_error: None,
        }
    }

    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.recv.is_some() {
            return Poll::Ready(Ok(()));
        }
        let response = self.response.as_mut().expect("response is pending");
        let response = ready!(Pin::new(response).poll(cx));
        self.response = None;
        let response = response
            .map_err(|e| Error::new(ErrorKind::ConnectionReset, e))?;
        if response.status() != StatusCode::OK {
            return Poll::Ready(Err(Error::new(
                ErrorKind::ConnectionRefused,
                format!("gRPC server returned HTTP {}", response.status()),
            )));
        }
        self.status_received = check_status(response.headers())?;
        let content_type = response.headers().get("content-type")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .unwrap_or_default();
        if content_type != "application/grpc"
            && !content_type.starts_with("application/grpc+")
        {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidData, "invalid gRPC response content-type",
            )));
        }
        self.recv = Some(response.into_body());
        Poll::Ready(Ok(()))
    }

    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_response(cx))?;
        let filled_before = buf.filled().len();
        // Yield even when a peer keeps sending empty DATA/messages.
        for _ in 0..64 {
            let before = self.buffer.len();
            let result = self.decoder.read(&mut self.buffer, buf);
            let consumed = before - self.buffer.len();
            let recv = self.recv.as_mut().expect("response resolved");
            if consumed > 0 {
                release_receive_capacity(recv, consumed)?;
            }
            result?;
            if buf.filled().len() > filled_before {
                return Poll::Ready(Ok(()));
            }
            match ready!(recv.poll_data(cx)) {
                Some(Ok(data)) => self.buffer = data,
                Some(Err(e)) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::ConnectionReset, e,
                    )));
                }
                None => {
                    if !self.decoder.is_complete() {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::UnexpectedEof, "incomplete gRPC frame",
                        )));
                    }
                    let trailers = ready!(recv.poll_trailers(cx))
                        .map_err(|e| Error::new(ErrorKind::ConnectionReset, e))?;
                    if let Some(trailers) = trailers {
                        self.status_received |= check_status(&trailers)?;
                    }
                    if !self.status_received {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::InvalidData, "missing gRPC status",
                        )));
                    }
                    self.read_closed = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_send_capacity(
        &mut self,
        cx: &mut Context<'_>,
        len: usize,
    ) -> Poll<io::Result<usize>> {
        match poll_send_capacity(&mut self.send, cx, len) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.close_write(error))),
            result => result,
        }
    }

    fn close_write(&mut self, error: Error) -> Error {
        self.write_closed = true;
        self.pending_send = Bytes::new();
        error
    }

    fn send_data(&mut self, data: Bytes) -> io::Result<()> {
        self.send.send_data(data, false)
            .map_err(|e| self.close_write(Error::new(ErrorKind::BrokenPipe, e)))
    }

    fn poll_send_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending_send.is_empty() {
            let capacity =
                ready!(self.poll_send_capacity(cx, self.pending_send.len()))?;
            let len = capacity.min(self.pending_send.len());
            let data = self.pending_send.split_to(len);
            self.send_data(data)?;
        }
        Poll::Ready(Ok(()))
    }
}

fn check_status(headers: &HeaderMap) -> io::Result<bool> {
    let Some(value) = headers.get("grpc-status") else {
        return Ok(false);
    };
    let status = value.to_str().ok()
        .filter(|value| {
            !value.is_empty() && (*value == "0" || !value.starts_with('0'))
                && value.bytes().all(|b| b.is_ascii_digit())
        })
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|status| *status <= 16)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid gRPC status"))?;
    if status != 0 {
        let message = headers.get("grpc-message")
            .and_then(|value| value.to_str().ok())
            .map(|value| percent_decode_str(value).decode_utf8_lossy());
        let kind = match status {
            4 => ErrorKind::TimedOut,
            7 | 16 => ErrorKind::PermissionDenied,
            _ => ErrorKind::Other,
        };
        return Err(Error::new(kind, match message {
            Some(message) => format!("gRPC status {status}: {message}"),
            None => format!("gRPC status {status}"),
        }));
    }
    Ok(true)
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 || this.read_closed {
            return Poll::Ready(Ok(()));
        }
        if let Some((kind, message)) = &this.read_error {
            return Poll::Ready(Err(Error::new(*kind, message.clone())));
        }
        let result = this.poll_read_inner(cx, buf);
        if let Poll::Ready(Err(error)) = &result {
            this.read_error = Some((error.kind(), error.to_string()));
        }
        result
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_closed {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe, "gRPC stream write side is closed",
            )));
        }
        ready!(this.poll_send_pending(cx))?;
        let len = buf.len().min(MAX_WRITE_SIZE);
        // Reserve before allocating; even a one-byte window must make progress.
        let capacity = ready!(this.poll_send_capacity(cx, len + 16))?;
        this.pending_send = encode_frame(&buf[..len]);
        let data = this.pending_send.split_to(capacity.min(this.pending_send.len()));
        this.send_data(data)?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().poll_send_pending(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_send_pending(cx))?;
        shutdown_h2_send(&mut this.send, &mut this.write_closed, cx)
    }
}
