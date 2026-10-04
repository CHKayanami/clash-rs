use std::{
    io,
    mem::replace,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::proxy::{AnyStream, ProxyStream};

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
    inner: TransportState,

    // Shared with VisionStream: set when CMD_DIRECT is received from server.
    read_flag: Arc<AtomicBool>,
    read_spliced: bool,

    // Shared with VisionStream: set when CMD_DIRECT is sent to server.
    write_flag: Arc<AtomicBool>,
    write_spliced: bool,
}

enum TransportState {
    Tls(tokio_boring::SslStream<AnyStream>),
    Raw(AnyStream),
}

impl ProxyStream for SplicableTlsStream {}

// A zero-sized ownership placeholder used only while dropping SSL. Boxing a
// zero-sized value allocates no storage. It must never service actual IO.
struct DetachedStream;

impl ProxyStream for DetachedStream {}

impl AsyncRead for DetachedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::NotConnected.into()))
    }
}

impl AsyncWrite for DetachedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::ErrorKind::NotConnected.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::NotConnected.into()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::NotConnected.into()))
    }
}

impl SplicableTlsStream {
    pub fn new(
        tls: tokio_boring::SslStream<AnyStream>,
        read_flag: Arc<AtomicBool>,
        write_flag: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner: TransportState::Tls(tls),
            read_flag,
            read_spliced: false,
            write_flag,
            write_spliced: false,
        }
    }

    fn activate_read_splice(&mut self) {
        debug!("SplicableTlsStream: activating read splice (bypassing TLS to raw TCP)");
        self.read_spliced = true;
        self.release_tls_if_spliced();
    }

    fn tls_mut(&mut self) -> &mut tokio_boring::SslStream<AnyStream> {
        match &mut self.inner {
            TransportState::Tls(tls) => tls,
            TransportState::Raw(_) => unreachable!("TLS retained until both directions splice"),
        }
    }

    fn raw_mut(&mut self) -> &mut AnyStream {
        match &mut self.inner {
            TransportState::Tls(tls) => tls.get_mut(),
            TransportState::Raw(raw) => raw,
        }
    }

    fn release_tls_if_spliced(&mut self) {
        if self.read_spliced && self.write_spliced
            && let TransportState::Tls(tls) = &mut self.inner
        {
            // Both directions have crossed frame boundaries: all decrypted
            // plaintext was drained and the final TLS write was flushed.
            // SslStream's destructor frees SSL/BIO without IO. Move its live
            // transport out before dropping the no-longer-used TLS state.
            debug_assert_eq!(tls.ssl().pending(), 0);
            let raw = replace(tls.get_mut(), AnyStream::dynamic(DetachedStream));
            self.inner = TransportState::Raw(raw);
        }
    }

    fn poll_activate_write_splice(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.write_spliced || !self.write_flag.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }
        // The final Vision frame must reach the transport before raw writes
        // or shutdown. Never send an outer TLS close_notify after CMD_DIRECT.
        futures::ready!(Pin::new(self.tls_mut()).poll_flush(cx))?;
        debug!("SplicableTlsStream: activating write splice (bypassing TLS to raw TCP)");
        self.write_spliced = true;
        self.release_tls_if_spliced();
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SplicableTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        if !this.read_spliced && this.read_flag.load(Ordering::Acquire) {
            // SSL_read may have only returned part of the last decrypted
            // record. Drain that plaintext before bypassing the TLS layer.
            if this.tls_mut().ssl().pending() > 0 {
                return Pin::new(this.tls_mut()).poll_read(cx, buf);
            }
            this.activate_read_splice();
        }

        if this.read_spliced {
            Pin::new(this.raw_mut()).poll_read(cx, buf)
        } else {
            Pin::new(this.tls_mut()).poll_read(cx, buf)
        }
    }
}

impl AsyncWrite for SplicableTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        futures::ready!(this.poll_activate_write_splice(cx))?;

        if this.write_spliced {
            Pin::new(this.raw_mut()).poll_write(cx, buf)
        } else {
            Pin::new(this.tls_mut()).poll_write(cx, buf)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        futures::ready!(this.poll_activate_write_splice(cx))?;
        if this.write_spliced {
            Pin::new(this.raw_mut()).poll_flush(cx)
        } else {
            Pin::new(this.tls_mut()).poll_flush(cx)
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        futures::ready!(this.poll_activate_write_splice(cx))?;
        if this.write_spliced {
            Pin::new(this.raw_mut()).poll_shutdown(cx)
        } else {
            Pin::new(this.tls_mut()).poll_shutdown(cx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::{pkey::PKey, ssl::{SslAcceptor, SslMethod}, x509::X509};
    use rcgen::{CertificateParams, KeyPair};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio_boring::{accept, SslStream};

    use crate::common::tls::boring::BoringTlsConnector;

    async fn tls_pair() -> (SplicableTlsStream, SslStream<DuplexStream>, VisionOptions) {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["localhost".into()]).unwrap()
            .self_signed(&key).unwrap();
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_certificate(&X509::from_der(cert.der()).unwrap()).unwrap();
        acceptor.set_private_key(&PKey::private_key_from_pem(key.serialize_pem().as_bytes()).unwrap()).unwrap();
        let acceptor = acceptor.build();
        let connector = BoringTlsConnector::new(false, true, None, None, None, None).unwrap();
        let (client_io, server_io) = duplex(65536);
        let (client, server) = tokio::join!(
            connector.connect("localhost", AnyStream::new(client_io)),
            accept(&acceptor, server_io),
        );
        let read_flag = Arc::new(AtomicBool::new(false));
        let write_flag = Arc::new(AtomicBool::new(false));
        let client = SplicableTlsStream::new(client.unwrap(), read_flag.clone(), write_flag.clone());
        (client, server.unwrap(), VisionOptions { read_flag, write_flag })
    }

    #[tokio::test]
    async fn read_splice_preserves_pending_plaintext() {
        let (mut client, mut server, flags) = tls_pair().await;
        server.write_all(b"headtail").await.unwrap();
        server.flush().await.unwrap();
        server.get_mut().write_all(b"raw").await.unwrap();
        server.get_mut().shutdown().await.unwrap();

        let mut head = [0; 4];
        client.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"head");
        assert_eq!(client.tls_mut().ssl().pending(), 4);
        flags.read_flag.store(true, Ordering::Release);
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"tailraw");
    }

    #[tokio::test]
    async fn shutdown_after_direct_does_not_send_tls_alert() {
        let (mut client, mut server, flags) = tls_pair().await;
        client.write_all(b"last-frame").await.unwrap();
        flags.write_flag.store(true, Ordering::Release);
        client.shutdown().await.unwrap();

        let mut last_frame = [0; 10];
        server.read_exact(&mut last_frame).await.unwrap();
        assert_eq!(&last_frame, b"last-frame");
        let mut raw = Vec::new();
        server.get_mut().read_to_end(&mut raw).await.unwrap();
        assert!(raw.is_empty(), "outer TLS close_notify leaked into raw transport");
    }

    #[tokio::test]
    async fn both_splice_orders_release_tls_and_preserve_io() {
        for write_first in [false, true] {
            let (mut client, mut server, flags) = tls_pair().await;
            server.write_all(b"headtail").await.unwrap();
            server.flush().await.unwrap();
            let mut data = [0; 4];
            client.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"head");

            if write_first {
                flags.write_flag.store(true, Ordering::Release);
                client.write_all(b"craw").await.unwrap();
                server.get_mut().read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"craw");
            }
            flags.read_flag.store(true, Ordering::Release);
            client.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"tail");
            assert!(matches!(client.inner, TransportState::Tls(_)));

            server.get_mut().write_all(b"sraw").await.unwrap();
            client.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"sraw");
            if !write_first {
                // Keep TLS alive while only the read direction has switched.
                assert!(matches!(client.inner, TransportState::Tls(_)));
                client.write_all(b"tls!").await.unwrap();
                server.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"tls!");
                flags.write_flag.store(true, Ordering::Release);
                client.write_all(b"craw").await.unwrap();
                server.get_mut().read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"craw");
            }
            assert!(matches!(client.inner, TransportState::Raw(_)));
            client.write_all(b"next").await.unwrap();
            client.shutdown().await.unwrap();
            server.get_mut().read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"next");
            let mut rest = Vec::new();
            server.get_mut().read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
        }
    }
}
