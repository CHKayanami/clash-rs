//! TCP stream for communicating with shadowsocks' proxy server

use std::{
    io,
    pin::Pin,
    task::{self, Poll},
};

use bytes::{BufMut, BytesMut};
use cfg_if::cfg_if;
use futures::ready;
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "aead-cipher")]
use crate::relay::tcprelay::aead::MAX_PACKET_SIZE as AEAD_MAX_PACKET_SIZE;
#[cfg(feature = "aead-cipher-2022")]
use crate::relay::tcprelay::aead_2022::MAX_PACKET_SIZE as AEAD2022_MAX_PACKET_SIZE;

#[cfg(feature = "aead-cipher-2022")]
use crate::relay::{get_aead_2022_padding_size, write_aead_2022_padding};
use crate::{
    config::ServerConfig,
    context::SharedContext,
    crypto::{CipherCategory, CipherKind},
    relay::{
        socks5::Address,
        tcprelay::crypto_io::{CryptoRead, CryptoStream, CryptoWrite, StreamType},
    },
};

#[derive(Debug)]
enum ProxyClientStreamWriteState {
    Connect(Address),
    Connecting { buffer: BytesMut, payload_len: usize, written: usize },
    Connected,
}

#[derive(Debug)]
enum ProxyClientStreamReadState {
    #[cfg(feature = "aead-cipher-2022")]
    CheckRequestNonce,
    Established,
}

/// A stream for sending / receiving data stream from remote server via shadowsocks' proxy server
#[derive(Debug)]
#[pin_project]
pub struct ProxyClientStream<S> {
    #[pin]
    stream: CryptoStream<S>,
    writer_state: ProxyClientStreamWriteState,
    reader_state: ProxyClientStreamReadState,
    pending_payload_len: Option<usize>,
    context: SharedContext,
}

impl<S> ProxyClientStream<S> {
    /// Create a `ProxyClientStream` with a connected `stream` to a shadowsocks' server
    ///
    /// NOTE: `stream` must be connected to the server with the same configuration as `svr_cfg`, otherwise strange errors would occurs
    pub fn from_stream<A>(context: SharedContext, stream: S, svr_cfg: &ServerConfig, addr: A) -> Self
    where
        A: Into<Address>,
    {
        let addr = addr.into();
        let stream = CryptoStream::from_stream_with_identity(
            &context,
            stream,
            StreamType::Client,
            svr_cfg.method(),
            svr_cfg.key(),
            svr_cfg.identity_keys(),
            None,
        );

        #[cfg(not(feature = "aead-cipher-2022"))]
        let reader_state = ProxyClientStreamReadState::Established;

        #[cfg(feature = "aead-cipher-2022")]
        let reader_state = if svr_cfg.method().is_aead_2022() {
            // AEAD 2022 has a respond header
            ProxyClientStreamReadState::CheckRequestNonce
        } else {
            ProxyClientStreamReadState::Established
        };

        Self {
            stream,
            writer_state: ProxyClientStreamWriteState::Connect(addr),
            reader_state,
            pending_payload_len: None,
            context,
        }
    }

    /// Get reference to the underlying stream
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }

    /// Get mutable reference to the underlying stream
    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut()
    }

    /// Consumes the `ProxyClientStream` and return the underlying stream
    pub fn into_inner(self) -> S {
        self.stream.into_inner()
    }
}

impl<S> AsyncRead for ProxyClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        #[allow(unused_mut)]
        let mut this = self.project();

        #[allow(clippy::never_loop)]
        loop {
            match this.reader_state {
                ProxyClientStreamReadState::Established => {
                    return this
                        .stream
                        .poll_read_decrypted(cx, this.context, buf)
                        .map_err(Into::into);
                }
                #[cfg(feature = "aead-cipher-2022")]
                ProxyClientStreamReadState::CheckRequestNonce => {
                    ready!(this.stream.as_mut().poll_read_decrypted(cx, this.context, buf))?;

                    // REQUEST_NONCE should be in the respond packet (header) of AEAD-2022.
                    //
                    // If received_request_nonce() is None, then:
                    // 1. method.salt_len() == 0, no checking required.
                    // 2. TCP stream read() returns EOF before receiving the header, no checking required.
                    //
                    // poll_read_decrypted will wait until the first non-zero size data chunk.
                    let (data_chunk_count, _) = this.stream.current_data_chunk_remaining();
                    if data_chunk_count > 0 {
                        // data_chunk_count > 0, so the reader received at least 1 data chunk.

                        let sent_nonce = this.stream.sent_nonce();
                        let sent_nonce = if sent_nonce.is_empty() { None } else { Some(sent_nonce) };
                        if sent_nonce != this.stream.received_request_nonce() {
                            return Err(io::Error::other("received TCP response header with unmatched salt")).into();
                        }

                        *(this.reader_state) = ProxyClientStreamReadState::Established;
                    }

                    return Ok(()).into();
                }
            }
        }
    }
}

#[inline]
fn make_first_packet_buffer(method: CipherKind, addr: &Address, buf: &[u8]) -> (BytesMut, usize) {
    // Target Address should be sent with the first packet together,
    // which would prevent from being detected.

    let max_packet_size = match method.category() {
        #[cfg(feature = "aead-cipher")]
        CipherCategory::Aead => AEAD_MAX_PACKET_SIZE,
        #[cfg(feature = "aead-cipher-2022")]
        CipherCategory::Aead2022 => AEAD2022_MAX_PACKET_SIZE,
        CipherCategory::None => usize::MAX,
        #[cfg(feature = "stream-cipher")]
        CipherCategory::Stream => usize::MAX,
    };
    let addr_length = addr.serialized_len();
    let mut buffer = BytesMut::new();

    cfg_if! {
        if #[cfg(feature = "aead-cipher-2022")] {
            let padding_size = get_aead_2022_padding_size(buf);
            let header_length = if method.is_aead_2022() {
                addr_length + 2 + padding_size
            } else {
                addr_length
            };
        } else {
            let _ = method;
            let header_length = addr_length;
        }
    }

    let payload_len = buf.len().min(max_packet_size - header_length);
    buffer.reserve(header_length + payload_len);

    // STREAM / AEAD / AEAD2022 protocol, append the Address before payload
    addr.write_to_buf(&mut buffer);

    #[cfg(feature = "aead-cipher-2022")]
    if method.is_aead_2022() {
        buffer.put_u16(padding_size as u16);

        write_aead_2022_padding(&mut buffer, padding_size);
    }

    buffer.put_slice(&buf[..payload_len]);

    (buffer, payload_len)
}

impl<S> ProxyClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Returns whether the target address header has not yet been fully written.
    pub fn needs_handshake(&self) -> bool {
        !matches!(self.writer_state, ProxyClientStreamWriteState::Connected)
    }

    /// Send the Shadowsocks request header without waiting for application payload and flush it.
    pub fn poll_handshake(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_request(cx, Some(&[])))?;
        self.project().stream.poll_flush(cx).map_err(Into::into)
    }

    // None drains an existing request without starting one on an idle flush.
    fn poll_request(
        self: Pin<&mut Self>, cx: &mut task::Context<'_>, payload: Option<&[u8]>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();
        if let ProxyClientStreamWriteState::Connect(addr) = this.writer_state {
            let Some(payload) = payload else { return Poll::Ready(Ok(())); };
            let (buffer, payload_len) = make_first_packet_buffer(this.stream.method(), addr, payload);
            *this.writer_state = ProxyClientStreamWriteState::Connecting { buffer, payload_len, written: 0 };
        }
        if let ProxyClientStreamWriteState::Connecting { buffer, payload_len, written } = this.writer_state {
            while *written < buffer.len() {
                let n = ready!(this.stream.as_mut().poll_write_encrypted(cx, &buffer[*written..]))?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero, "failed to write shadowsocks request",
                    )));
                }
                *written += n;
            }
            // Flush/shutdown may complete a Pending write's request. Leave its
            // payload count for poll_write to acknowledge without resending it.
            if *payload_len > 0 {
                *this.pending_payload_len = Some(*payload_len);
            }
            *this.writer_state = ProxyClientStreamWriteState::Connected;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncWrite for ProxyClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let starting_request = !matches!(self.writer_state, ProxyClientStreamWriteState::Connected);
        ready!(self.as_mut().poll_request(cx, Some(buf)))?;
        if let Some(len) = self.as_mut().project().pending_payload_len.take() {
            return Poll::Ready(Ok(len));
        }
        // An empty first write sends ADDR; an application write following
        // an already-sent header must still send its own payload.
        if starting_request && buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.project().stream.poll_write_encrypted(cx, buf).map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_request(cx, None))?;
        self.project().stream.poll_flush(cx).map_err(Into::into)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_request(cx, Some(&[])))?;
        ready!(self.as_mut().project().stream.poll_flush(cx))?;
        self.project().stream.poll_shutdown(cx).map_err(Into::into)
    }
}
