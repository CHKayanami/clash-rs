use std::{io, mem, pin::Pin, task::{Context, Poll}};
use futures::task::noop_waker;
use tokio::io::AsyncWrite;
use crate::crypto::CipherKind;
#[cfg(feature = "aead-cipher")]
use super::aead::EncryptedWriter as AeadEncryptedWriter;
#[cfg(feature = "aead-cipher-2022")]
use super::aead_2022::EncryptedWriter as Aead2022EncryptedWriter;
#[cfg(feature = "stream-cipher")]
use super::stream::EncryptedWriter as StreamEncryptedWriter;
#[cfg(feature = "aead-cipher-2022")]
use super::crypto_io::StreamType;

struct BackpressuredWriter {
    block_next: bool,
    bytes: Vec<u8>,
}

impl AsyncWrite for BackpressuredWriter {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if mem::take(&mut self.block_next) {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.bytes.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn check_pending_write(mut write: impl FnMut(&mut Context<'_>, &mut BackpressuredWriter, &[u8]) -> Poll<io::Result<usize>>) {
    let mut output = BackpressuredWriter { block_next: false, bytes: Vec::new() };
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    // Exercise both the initial header/IV and subsequent packet states.
    for value in [42, 43] {
        output.block_next = true;
        let short = vec![value; 128];
        assert!(write(&mut cx, &mut output, &short).is_pending());
        let grown = vec![value; 4096];
        let Poll::Ready(Ok(consumed)) = write(&mut cx, &mut output, &grown) else {
            panic!("pending ciphertext did not finish writing");
        };
        assert_eq!(consumed, short.len(), "new plaintext must not be counted before it is encrypted");
        assert!(matches!(write(&mut cx, &mut output, &grown[consumed..]), Poll::Ready(Ok(3968))));
    }
}

#[cfg(feature = "aead-cipher-2022")]
#[test]
fn aead2022_pending_write_does_not_consume_newly_appended_plaintext() {
    let mut writer = Aead2022EncryptedWriter::new(StreamType::Client,
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM, &[7; 16], &[9; 16]);
    check_pending_write(|cx, output, data| writer.poll_write_encrypted(cx, output, data));
}

#[cfg(feature = "aead-cipher")]
#[test]
fn aead_pending_write_does_not_consume_newly_appended_plaintext() {
    let mut writer = AeadEncryptedWriter::new(CipherKind::AES_256_GCM, &[7; 32], &[9; 32]);
    check_pending_write(|cx, output, data| writer.poll_write_encrypted(cx, output, data));
}

#[cfg(feature = "stream-cipher")]
#[test]
fn stream_pending_write_does_not_consume_newly_appended_plaintext() {
    let mut writer = StreamEncryptedWriter::new(CipherKind::AES_128_CTR, &[7; 16], &[9; 16]);
    check_pending_write(|cx, output, data| writer.poll_write_encrypted(cx, output, data).map_err(Into::into));
}
