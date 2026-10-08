//! Record-level regression tests using real rustls streams over local duplex IO.

use super::{padding::PaddingFactory, session::AnyTlsClientSession, types::Command};
use crate::{proxy::AnyStream, session::SocksAddr};
use parking_lot::Mutex;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    client::TlsStream as ClientTlsStream,
    server::TlsStream as ServerTlsStream,
};
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::ServerName};

pub(super) type CapturedWrites = Arc<Mutex<Vec<u8>>>;

pub(super) struct CapturedIo {
    inner: DuplexStream,
    writes: CapturedWrites,
}

impl AsyncRead for CapturedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CapturedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                self.writes.lock().extend_from_slice(&buf[..n]);
                Poll::Ready(Ok(n))
            }
            result => result,
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(super) struct TlsPair {
    pub client: ClientTlsStream<CapturedIo>,
    pub server: ServerTlsStream<CapturedIo>,
    pub client_writes: CapturedWrites,
    pub server_writes: CapturedWrites,
}

pub(super) async fn tls_pair() -> TlsPair {
    crate::setup_default_crypto_provider();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots).with_no_client_auth();
    let server_config = ServerConfig::builder().with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], signing_key.into())
        .unwrap();
    let (client, server) = duplex(65536);
    let client_writes = CapturedWrites::default();
    let server_writes = CapturedWrites::default();
    let connector = TlsConnector::from(Arc::new(client_config));
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let (client, server) = tokio::join!(
        connector.connect(ServerName::try_from("localhost").unwrap(), CapturedIo {
            inner: client, writes: client_writes.clone(),
        }),
        acceptor.accept(CapturedIo { inner: server, writes: server_writes.clone() }),
    );
    client_writes.lock().clear();
    server_writes.lock().clear();
    TlsPair {
        client: client.unwrap(), server: server.unwrap(),
        client_writes, server_writes,
    }
}

pub(super) fn assert_single_application_record(writes: &CapturedWrites) {
    let wire = writes.lock();
    assert!(wire.len() >= 5, "missing TLS record header");
    assert_eq!(wire[0], 23, "expected TLS application data");
    let length = u16::from_be_bytes([wire[3], wire[4]]) as usize;
    assert_eq!(wire.len(), length + 5, "frame split across TLS records");
}

async fn read_frame(stream: &mut (impl AsyncRead + Unpin)) -> (u8, u32, Vec<u8>) {
    let command = stream.read_u8().await.unwrap();
    let id = stream.read_u32().await.unwrap();
    let length = stream.read_u16().await.unwrap() as usize;
    let mut data = vec![0u8; length];
    stream.read_exact(&mut data).await.unwrap();
    (command, id, data)
}

#[tokio::test]
async fn outbound_unpadded_small_frame_uses_one_tls_record() {
    let TlsPair { client, mut server, client_writes, .. } = tls_pair().await;
    let padding = Arc::new(PaddingFactory::new(b"stop=0").unwrap());
    let session = AnyTlsClientSession::new(AnyStream::dynamic(client), "test",
        padding).await.unwrap();
    let mut auth = [0u8; 34];
    server.read_exact(&mut auth).await.unwrap();
    let dest = SocksAddr::try_from(("example.com".to_owned(), 80))
        .unwrap();
    let mut app = session.open_stream(&dest).await.unwrap();
    for command in [Command::Settings, Command::Syn, Command::Psh] {
        assert_eq!(read_frame(&mut server).await.0, command as u8);
    }
    client_writes.lock().clear();
    app.write_all(b"hello").await.unwrap();
    let (command, id, data) = read_frame(&mut server).await;
    assert_eq!(command, Command::Psh as u8);
    assert_eq!(id, 1);
    assert_eq!(data, b"hello");
    assert_single_application_record(&client_writes);
}
