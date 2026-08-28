use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::proxy::AnyStream;

/// Options passed to `VisionStream` when XTLS-splice mode is active.
pub struct VisionOptions {
    pub read_flag: Arc<AtomicBool>,
    pub write_flag: Arc<AtomicBool>,
}

/// Splicable TLS stream wrapping BoringSSL's SslStream.
///
/// Switches from TLS-decrypted IO to raw underlying IO when signalled via
/// shared `Arc<AtomicBool>` flags. This allows XTLS-Vision to bypass outer TLS
/// once CMD_PADDING_DIRECT is negotiated.
pub struct SplicableTlsStream {
    tls: tokio_boring::SslStream<AnyStream>,

    // Shared with VisionStream: set when CMD_DIRECT is received from server.
    read_flag: Arc<AtomicBool>,
    read_spliced: bool,

    // Shared with VisionStream: set when CMD_DIRECT is sent to server.
    write_flag: Arc<AtomicBool>,
    write_spliced: bool,
}

impl crate::proxy::ProxyStream for SplicableTlsStream {}

impl SplicableTlsStream {
    pub fn new(
        tls: tokio_boring::SslStream<AnyStream>,
        read_flag: Arc<AtomicBool>,
        write_flag: Arc<AtomicBool>,
    ) -> Self {
        Self {
            tls,
            read_flag,
            read_spliced: false,
            write_flag,
            write_spliced: false,
        }
    }

    fn activate_read_splice(&mut self) {
        debug!("SplicableTlsStream: activating read splice (bypassing TLS to raw TCP)");
        self.read_spliced = true;
    }

    fn activate_write_splice(&mut self) {
        debug!("SplicableTlsStream: activating write splice (bypassing TLS to raw TCP)");
        self.write_spliced = true;
    }
}

impl AsyncRead for SplicableTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_spliced && self.read_flag.load(Ordering::Relaxed) {
            self.activate_read_splice();
        }

        if self.read_spliced {
            Pin::new(self.tls.get_mut()).poll_read(cx, buf)
        } else {
            Pin::new(&mut self.tls).poll_read(cx, buf)
        }
    }
}

impl AsyncWrite for SplicableTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.write_spliced && self.write_flag.load(Ordering::Relaxed) {
            self.activate_write_splice();
        }

        if self.write_spliced {
            Pin::new(self.tls.get_mut()).poll_write(cx, buf)
        } else {
            Pin::new(&mut self.tls).poll_write(cx, buf)
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_spliced {
            Pin::new(self.tls.get_mut()).poll_flush(cx)
        } else {
            Pin::new(&mut self.tls).poll_flush(cx)
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_spliced {
            Pin::new(self.tls.get_mut()).poll_shutdown(cx)
        } else {
            Pin::new(&mut self.tls).poll_shutdown(cx)
        }
    }
}
