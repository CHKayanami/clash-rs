//! Authenticated frame IO and connection-local Direct state.

use std::{
    fmt, future::Future, io, time::Duration,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep, sleep_until},
};

use crate::proxy::{AnyStream, ProxyStream, transport::VisionOptions};
use super::{FRAME_HEADER_LEN, IV_LEN};
use super::client::TicketUse;
use super::crypto::{AesCtr, StreamAead};
use self::direct::HeaderXor;

mod direct;
mod read;
mod write;

#[cfg(test)]
mod tests;

struct PendingWrite {
    offset: usize,
    plaintext_len: usize,
}

#[derive(Debug)]
enum ReadPhase {
    ServerRandom,
    Header,
    Body {
        header: [u8; FRAME_HEADER_LEN],
        ciphertext_len: usize,
    },
}

/// Constructors keep full and resumed handshake state consistent without
/// boxing the large cipher states into differently sized enum variants.
pub(super) struct StreamInit {
    send: StreamAead,
    recv: Option<StreamAead>,
    send_xor: Option<AesCtr>,
    recv_xor: Option<AesCtr>,
    resumption: Option<Resumption>,
}

struct Resumption {
    prewrite: Vec<u8>,
    ticket_use: TicketUse,
    timeout: Duration,
}

impl StreamInit {
    pub(super) fn established(
        send: StreamAead, recv: StreamAead,
        send_xor: Option<AesCtr>, recv_xor: Option<AesCtr>,
    ) -> Self {
        Self { send, recv: Some(recv), send_xor, recv_xor, resumption: None }
    }

    pub(super) fn resumed(
        send: StreamAead, send_xor: Option<AesCtr>, prewrite: Vec<u8>,
        ticket_use: TicketUse, timeout: Duration,
    ) -> Self {
        Self {
            send, recv: None, send_xor, recv_xor: None,
            resumption: Some(Resumption { prewrite, ticket_use, timeout }),
        }
    }
}

pub(super) struct SessionKeys {
    pub(super) material: [u8; 96],
    pub(super) use_aes: bool,
}

struct Failure {
    kind: io::ErrorKind,
    message: String,
}

pub struct EncryptionStream {
    inner: AnyStream,
    united_key: [u8; 96],
    use_aes: bool,
    send: StreamAead,
    recv: Option<StreamAead>,
    send_xor: Option<AesCtr>,
    recv_xor: Option<AesCtr>,
    xor_headers: bool,
    prewrite: Option<Vec<u8>>,
    pending_write: Option<PendingWrite>,
    read_phase: ReadPhase,
    read_wire: Vec<u8>,
    read_offset: usize,
    read_plaintext: Vec<u8>,
    read_plaintext_offset: usize,
    read_eof: bool,
    direct_read: bool,
    recv_header_xor: HeaderXor,
    direct_write: bool,
    send_header_xor: HeaderXor,
    /// Reused framed and random-mode Direct wire storage.
    write_wire: Vec<u8>,
    failure: Option<Failure>,
    handshake_deadline: Option<Pin<Box<Sleep>>>,
    handshake_timeout: Option<Duration>,
    ticket_use: Option<TicketUse>,
    vision: Option<VisionOptions>,
}

impl ProxyStream for EncryptionStream {}

impl EncryptionStream {
    #[cfg(test)]
    pub(in crate::proxy::vless) fn transport_alpn(&self) -> Option<&[u8]> {
        match &self.inner {
            AnyStream::BoringTls(tls) => tls.ssl().selected_alpn_protocol(),
            AnyStream::Tls(tls) => tls.get_ref().1.alpn_protocol(),
            _ => None,
        }
    }

    pub(crate) fn set_vision(&mut self, opts: VisionOptions) {
        self.vision = Some(opts);
    }

    pub(super) fn new(
        inner: AnyStream,
        keys: SessionKeys,
        init: StreamInit,
    ) -> Self {
        let StreamInit { send, recv, send_xor, recv_xor, resumption } = init;
        let (prewrite, ticket_use, handshake_timeout, read_phase, read_length) =
            match resumption {
                Some(Resumption { prewrite, ticket_use, timeout }) => (
                    Some(prewrite), Some(ticket_use), Some(timeout),
                    ReadPhase::ServerRandom, IV_LEN,
                ),
                None => (None, None, None, ReadPhase::Header, FRAME_HEADER_LEN),
            };
        Self {
            inner,
            united_key: keys.material,
            use_aes: keys.use_aes,
            xor_headers: send_xor.is_some() || recv_xor.is_some(),
            send,
            recv,
            send_xor,
            recv_xor,
            prewrite,
            pending_write: None,
            read_phase,
            read_wire: vec![0; read_length],
            read_offset: 0,
            read_plaintext: Vec::new(),
            read_plaintext_offset: 0,
            read_eof: false,
            direct_read: false,
            recv_header_xor: HeaderXor::default(),
            direct_write: false,
            send_header_xor: HeaderXor::default(),
            write_wire: Vec::new(),
            failure: None,
            handshake_deadline: None,
            handshake_timeout,
            ticket_use,
            vision: None,
        }
    }

    fn check_failure(&self) -> io::Result<()> {
        if let Some(failure) = &self.failure {
            return Err(io::Error::new(failure.kind, failure.message.clone()));
        }
        Ok(())
    }

    fn finish_poll<T>(&mut self, result: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if let Poll::Ready(Err(error)) = &result
            && self.failure.is_none() {
            self.failure = Some(Failure {
                kind: error.kind(), message: error.to_string(),
            });
            self.invalidate_ticket();
            self.pending_write = None;
            self.write_wire.clear();
            self.read_wire.clear();
            self.read_plaintext.clear();
            self.handshake_deadline = None;
            self.handshake_timeout = None;
        }
        result
    }

    fn poll_handshake_deadline(
        &mut self, cx: &mut Context<'_>, start: bool,
    ) -> io::Result<()> {
        if start && let Some(timeout) = self.handshake_timeout.take() {
            self.handshake_deadline = Some(Box::pin(sleep_until(
                Instant::now() + timeout,
            )));
        }
        if let Some(deadline) = &mut self.handshake_deadline
            && deadline.as_mut().poll(cx).is_ready() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "VLESS Encryption resumption timed out",
            ));
        }
        Ok(())
    }

    fn copy_plaintext(&mut self, output: &mut ReadBuf<'_>) -> bool {
        if self.read_plaintext_offset == self.read_plaintext.len() {
            return false;
        }
        let count = output
            .remaining()
            .min(self.read_plaintext.len() - self.read_plaintext_offset);
        output.put_slice(
            &self.read_plaintext[self.read_plaintext_offset..self.read_plaintext_offset + count],
        );
        self.read_plaintext_offset += count;
        if self.read_plaintext_offset == self.read_plaintext.len() {
            self.read_plaintext.clear();
            self.read_plaintext_offset = 0;
        }
        true
    }

    fn invalidate_ticket(&mut self) {
        if let Some(ticket_use) = self.ticket_use.take() {
            ticket_use.invalidate();
        }
    }
}

impl fmt::Debug for EncryptionStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlessEncryptionStream")
            .field("read_phase", &self.read_phase)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for EncryptionStream {
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = this.check_failure()
            .and_then(|()| this.poll_handshake_deadline(cx, output.remaining() > 0));
        let result = match result {
            Ok(()) => this.poll_read_inner(cx, output),
            Err(error) => Poll::Ready(Err(error)),
        };
        this.finish_poll(result)
    }
}

impl AsyncWrite for EncryptionStream {
    fn poll_write(
        self: Pin<&mut Self>, cx: &mut Context<'_>, input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = this.check_failure()
            .and_then(|()| this.poll_handshake_deadline(cx, !input.is_empty()));
        let result = match result {
            Ok(()) => this.poll_write_inner(cx, input),
            Err(error) => Poll::Ready(Err(error)),
        };
        this.finish_poll(result)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = this.check_failure()
            .and_then(|()| this.poll_handshake_deadline(cx, this.pending_write.is_some()));
        let result = match result {
            Ok(()) => this.poll_flush_inner(cx),
            Err(error) => Poll::Ready(Err(error)),
        };
        this.finish_poll(result)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = match this.check_failure() {
            Ok(()) => this.poll_shutdown_inner(cx),
            Err(error) => Poll::Ready(Err(error)),
        };
        this.finish_poll(result)
    }
}
