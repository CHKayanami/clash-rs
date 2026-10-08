use super::{make_handler, read_frame_raw};
use crate::{
    app::{dns::{MockClashResolver, ThreadSafeDNSResolver}, net::OutboundInterface},
    proxy::{
        AnyOutboundDatagram, AnyStream,
        anytls::{
            padding::PaddingFactory, session::AnyTlsClientSession, types::Command,
        },
        utils::RemoteConnector,
    },
    session::{Session, SocksAddr},
};
use async_trait::async_trait;
use futures::future::join_all;
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, atomic::{AtomicUsize, Ordering}},
};
use tokio::{
    io::{AsyncReadExt, duplex},
    spawn,
    sync::Barrier,
    time::{Duration, sleep, timeout},
};

#[derive(Debug, Default)]
struct CountingConnector {
    dials: AtomicUsize,
}

async fn consume_auth(stream: &mut (impl AsyncReadExt + Unpin)) {
    let mut hash = [0u8; 32];
    stream.read_exact(&mut hash).await.unwrap();
    let length = stream.read_u16().await.unwrap() as usize;
    let mut padding = vec![0u8; length];
    stream.read_exact(&mut padding).await.unwrap();
}

#[async_trait]
impl RemoteConnector for CountingConnector {
    async fn connect_stream(
        &self,
        _resolver: ThreadSafeDNSResolver,
        _address: &str,
        _port: u16,
        _tfo: bool,
        _iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] _packet_mark: Option<u32>,
    ) -> io::Result<AnyStream> {
        self.dials.fetch_add(1, Ordering::Relaxed);
        // Keep the dial pending while the other broken-stream retries arrive.
        sleep(Duration::from_millis(20)).await;
        let (client, mut server) = duplex(65536);
        spawn(async move {
            consume_auth(&mut server).await;
            let mut buffer = [0u8; 8192];
            while server.read(&mut buffer).await.is_ok_and(|n| n > 0) {}
        });
        Ok(AnyStream::new(client))
    }

    async fn connect_datagram(
        &self,
        _resolver: ThreadSafeDNSResolver,
        _src: Option<SocketAddr>,
        _destination: SocksAddr,
        _iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] _packet_mark: Option<u32>,
    ) -> io::Result<AnyOutboundDatagram> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported, "stream-only test connector",
        ))
    }
}

#[tokio::test]
async fn concurrent_broken_session_retries_share_one_dial() {
    timeout(Duration::from_secs(5), async {
        let handler = Arc::new(make_handler(false, false));
        let (client, mut server) = duplex(65536);
        let stale = AnyTlsClientSession::new(AnyStream::new(client), "secret",
            PaddingFactory::default_factory()).await.unwrap();
        stale.set_peer_version(2);
        handler.session_pool.add_session(stale).await;
        let server = spawn(async move {
            consume_auth(&mut server).await;
            let mut streams = 0;
            while streams < 8 {
                let (command, _, _) = read_frame_raw(&mut server).await;
                if command == Command::Syn as u8 {
                    streams += 1;
                }
            }
            // Break the transport with all eight open_stream calls awaiting ACK.
        });
        let resolver: ThreadSafeDNSResolver = Arc::new(MockClashResolver::new());
        let connector = Arc::new(CountingConnector::default());
        let start = Arc::new(Barrier::new(8));
        let mut requests = Vec::new();
        for _ in 0..8 {
            let handler = handler.clone();
            let resolver = resolver.clone();
            let connector = connector.clone();
            let start = start.clone();
            requests.push(spawn(async move {
                let sess = Session {
                    destination: SocksAddr::try_from(("example.com".to_owned(), 80))
                        .unwrap(),
                    ..Default::default()
                };
                start.wait().await;
                handler.open_stream_with_retry(resolver, connector.as_ref(),
                    &sess, &sess.destination).await.unwrap()
            }));
        }
        let results = join_all(requests).await;
        let streams: Vec<_> = results.into_iter().map(Result::unwrap).collect();
        assert_eq!(connector.dials.load(Ordering::Relaxed), 1);
        assert_eq!(streams.len(), 8);
        server.await.unwrap();
    }).await.unwrap();
}
