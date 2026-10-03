//! Frame encoding, retained writes and transport flush/shutdown.

use std::{io, pin::Pin, task::{Context, Poll}, sync::atomic::Ordering};
use tokio::io::AsyncWrite;
use super::{EncryptionStream, PendingWrite};
use super::super::{FRAME_HEADER_LEN, MAX_FRAME_PLAINTEXT, MAX_NONCE, TAG_LEN};
use super::super::crypto::{StreamAead, encode_length};

impl EncryptionStream {
    fn frame(&mut self, plaintext: &[u8]) -> io::Result<usize> {
        let plaintext_len = plaintext.len().min(MAX_FRAME_PLAINTEXT);
        let mut header = [23, 3, 3, 0, 0];
        header[3..].copy_from_slice(&encode_length(plaintext_len + TAG_LEN));
        let rekey = self.send.nonce == MAX_NONCE;
        self.write_wire.clear();
        if let Some(prewrite) = self.prewrite.take() {
            self.write_wire = prewrite;
        }
        let frame_start = self.write_wire.len();
        self.write_wire.extend_from_slice(&header);
        self.send.seal(
            &plaintext[..plaintext_len], &header, &mut self.write_wire,
        )?;
        if rekey {
            self.send = StreamAead::new(
                &self.write_wire[frame_start..], &self.united_key, self.use_aes,
            ).map_err(io::Error::other)?;
        }
        if let Some(xor) = self.send_xor.as_mut() {
            xor.apply(&mut self.write_wire[frame_start..frame_start + FRAME_HEADER_LEN]);
        }
        Ok(plaintext_len)
    }

    pub(super) fn poll_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let pending = self.pending_write.as_mut().expect("pending write exists");
        while pending.offset < self.write_wire.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_wire[pending.offset..]) {
                Poll::Ready(Ok(0)) => {
                    self.pending_write = None;
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(written)) => pending.offset += written,
                Poll::Ready(Err(error)) => {
                    self.pending_write = None;
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let done = self
            .pending_write
            .take()
            .expect("completed pending write exists");
        self.write_wire.clear();
        Poll::Ready(Ok(done.plaintext_len))
    }

}

impl EncryptionStream {
    pub(super) fn poll_write_inner(
        &mut self,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.vision.as_ref().is_some_and(|opts| opts.write_flag.load(Ordering::Acquire)) {
            return self.poll_direct_write(cx, input);
        }
        if self.pending_write.is_none() {
            if input.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let plaintext_len = self.frame(input)?;
            self.pending_write = Some(PendingWrite {
                offset: 0,
                plaintext_len,
            });
        }
        self.poll_pending_write(cx)
    }

    pub(super) fn poll_flush_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_write.is_some() {
            match self.poll_pending_write(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    pub(super) fn poll_shutdown_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_write.is_some() {
            match self.poll_pending_write(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
