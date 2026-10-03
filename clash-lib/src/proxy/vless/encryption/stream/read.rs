//! Authenticated frame decoding and receive state transitions.

use std::{io, mem::{replace, swap, take}, pin::Pin, task::{Context, Poll}};
use tokio::io::{AsyncRead, ReadBuf};
use super::{EncryptionStream, ReadPhase};
use super::super::{FRAME_HEADER_LEN, MAX_FRAME_CIPHERTEXT, MAX_NONCE, TAG_LEN};
use super::super::crypto::{AesCtr, StreamAead};
use std::sync::atomic::Ordering;

impl EncryptionStream {
    pub(super) fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.vision.as_ref().is_some_and(|opts| opts.read_flag.load(Ordering::Acquire)) {
            return self.poll_direct_read(cx, output);
        }
        if output.remaining() == 0 || self.copy_plaintext(output) {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.read_eof {
                return Poll::Ready(Ok(()));
            }
            while self.read_offset < self.read_wire.len() {
                let start = self.read_offset;
                let (poll, read) = {
                    let this = &mut *self;
                    let mut wire_buf = ReadBuf::new(&mut this.read_wire[start..]);
                    let poll = Pin::new(&mut this.inner).poll_read(cx, &mut wire_buf);
                    (poll, wire_buf.filled().len())
                };
                match poll {
                    Poll::Ready(Ok(())) if read == 0 => {
                        if start == 0 && matches!(self.read_phase, ReadPhase::Header)
                            && self.ticket_use.is_none() {
                            self.read_eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        self.invalidate_ticket();
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated VLESS Encryption frame",
                        )));
                    }
                    Poll::Ready(Ok(())) => self.read_offset += read,
                    Poll::Ready(Err(error)) => {
                        self.invalidate_ticket();
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            let mut wire = take(&mut self.read_wire);
            self.read_offset = 0;
            match replace(&mut self.read_phase, ReadPhase::Header) {
                ReadPhase::ServerRandom => {
                    let recv = StreamAead::new(&wire, &self.united_key, self.use_aes)
                        .map_err(io::Error::other)?;
                    if self.xor_headers {
                        self.recv_xor = Some(AesCtr::new(
                            &self.united_key,
                            wire.as_slice().try_into().expect("server random length"),
                        ));
                    }
                    self.recv = Some(recv);
                    self.read_phase = ReadPhase::Header;
                    wire.clear();
                    wire.resize(FRAME_HEADER_LEN, 0);
                    self.read_wire = wire;
                }
                ReadPhase::Header => {
                    let mut header: [u8; FRAME_HEADER_LEN] = wire.as_slice()
                        .try_into()
                        .expect("VLESS Encryption frame header length");
                    if let Some(xor) = self.recv_xor.as_mut() {
                        xor.apply(&mut header);
                    }
                    let ciphertext_len = u16::from_be_bytes([header[3], header[4]]) as usize;
                    if header[..3] != [23, 3, 3]
                        || !(TAG_LEN + 1..=MAX_FRAME_CIPHERTEXT).contains(&ciphertext_len)
                    {
                        self.invalidate_ticket();
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid VLESS Encryption frame header",
                        )));
                    }
                    self.read_phase = ReadPhase::Body {
                        header,
                        ciphertext_len,
                    };
                    wire.clear();
                    wire.resize(ciphertext_len, 0);
                    self.read_wire = wire;
                }
                ReadPhase::Body {
                    header,
                    ciphertext_len,
                } => {
                    let rekey =
                        self.recv.as_ref().expect("receive AEAD initialized").nonce == MAX_NONCE;
                    let rekey_context = rekey.then(|| {
                        let mut context = Vec::with_capacity(header.len() + wire.len());
                        context.extend_from_slice(&header);
                        context.extend_from_slice(&wire);
                        context
                    });
                    let result = self
                        .recv
                        .as_mut()
                        .expect("receive AEAD initialized")
                        .open(&mut wire, &header);
                    let Ok(plaintext_len) = result else {
                        self.invalidate_ticket();
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "VLESS Encryption frame authentication failed",
                        )));
                    };
                    debug_assert_eq!(plaintext_len + TAG_LEN, ciphertext_len);
                    if let Some(context) = rekey_context {
                        self.recv = Some(
                            StreamAead::new(&context, &self.united_key, self.use_aes)
                                .map_err(io::Error::other)?,
                        );
                    }
                    wire.truncate(plaintext_len);
                    self.ticket_use = None;
                    self.handshake_deadline = None;
                    self.handshake_timeout = None;
                    swap(&mut self.read_plaintext, &mut wire);
                    self.read_plaintext_offset = 0;
                    self.read_phase = ReadPhase::Header;
                    wire.clear();
                    wire.resize(FRAME_HEADER_LEN, 0);
                    self.read_wire = wire;
                    if self.copy_plaintext(output) {
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }
}
