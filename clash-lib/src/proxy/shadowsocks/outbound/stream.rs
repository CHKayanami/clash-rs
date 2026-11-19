use std::{
    fmt::Debug,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use shadowsocks::ProxyClientStream;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::proxy::{AnyStream, ProxyStream};

pub struct ShadowSocksStream(pub ProxyClientStream<AnyStream>);
impl ProxyStream for ShadowSocksStream {
    fn needs_handshake(&self) -> bool {
        self.0.needs_handshake()
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_handshake(cx)
    }
}
impl Debug for ShadowSocksStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ShadowSocksStream").finish()
    }
}

impl AsyncRead for ShadowSocksStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for ShadowSocksStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };
    use shadowsocks::{
        ProxyClientStream, ServerConfig,
        config::ServerType,
        context::Context as SsContext,
        crypto::CipherKind,
        relay::{Address, tcprelay::ProxyServerStream},
    };
    use tokio::io::{
        AsyncReadExt, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
    };
    use crate::{
        app::{
            sniffer::PrefixedStream,
            dispatcher::TrafficTracker,
            remote_content_manager::ProxyManager,
        },
        common::io::{SlideBuffer, copy_bidirectional},
        proxy::{
            OutboundNode,
            mocks::MockDummyOutboundHandler,
            utils::test_utils::noop::NoopResolver,
        },
    };

    struct RecordingStream {
        inner: DuplexStream,
        writes: Arc<Mutex<Vec<usize>>>,
    }

    impl AsyncRead for RecordingStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for RecordingStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let res = Pin::new(&mut self.inner).poll_write(cx, buf);
            if let Poll::Ready(Ok(n)) = &res {
                self.writes.lock().unwrap().push(*n);
            }
            res
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl ProxyStream for RecordingStream {}

    fn ss_pair(
        addr: &Address,
    ) -> (
        AnyStream,
        ProxyServerStream<DuplexStream>,
        Arc<Mutex<Vec<usize>>>,
    ) {
        let (client_io, server_io) = duplex(4096);
        let writes = Arc::new(Mutex::new(Vec::new()));
        let cfg = ServerConfig::new(
            ("127.0.0.1", 8388),
            "test-password".to_owned(),
            CipherKind::AES_256_GCM,
        )
        .unwrap();
        let client = ProxyClientStream::from_stream(
            SsContext::new_shared(ServerType::Local),
            AnyStream::dynamic(RecordingStream {
                inner: client_io,
                writes: writes.clone(),
            }),
            &cfg,
            addr.clone(),
        );
        let server = ProxyServerStream::from_stream(
            SsContext::new_shared(ServerType::Server),
            server_io,
            CipherKind::AES_256_GCM,
            cfg.key(),
        );
        (AnyStream::new(ShadowSocksStream(client)), server, writes)
    }

    async fn forwarding_first_packet(cached: bool) {
        let addr: Address = ("example.test".to_owned(), 443).into();
        let (ss_stream, mut server, writes) = ss_pair(&addr);
        let (mut client_peer, inbound) = duplex(4096);

        let inbound = if cached {
            let mut prefix = SlideBuffer::new(11);
            prefix.extend_from_slice(b"ClientHello");
            AnyStream::new(PrefixedStream::new(prefix, AnyStream::new(inbound)))
        } else {
            client_peer.write_all(b"ClientHello").await.unwrap();
            AnyStream::new(inbound)
        };

        let copy = tokio::spawn(copy_bidirectional(
            inbound,
            ss_stream,
            1024,
            TrafficTracker::noop(),
        ));

        assert_eq!(server.handshake().await.unwrap(), addr);
        let mut req = [0u8; 11];
        server.read_exact(&mut req).await.unwrap();
        assert_eq!(&req, b"ClientHello");
        assert_eq!(writes.lock().unwrap().len(), if cached { 1 } else { 2 });

        server.write_all(b"ServerHello").await.unwrap();
        server.shutdown().await.unwrap();

        let mut resp = Vec::new();
        client_peer.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"ServerHello");
        client_peer.shutdown().await.unwrap();

        let (up, down) = copy.await.unwrap().unwrap();
        assert_eq!((up, down), (11, 11));
    }

    #[tokio::test]
    async fn copy_bidirectional_coalesces_ss_header_and_cached_packet() {
        forwarding_first_packet(true).await;
    }

    #[tokio::test]
    async fn copy_bidirectional_sends_ss_header_immediately_without_cache() {
        forwarding_first_packet(false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn copy_bidirectional_allows_ss_server_greeting_without_delay() {
        let addr: Address = ("example.test".to_owned(), 21).into();
        let (ss_stream, mut server, writes) = ss_pair(&addr);
        let (mut client_peer, inbound) = duplex(4096);

        let copy = tokio::spawn(copy_bidirectional(
            AnyStream::new(inbound),
            ss_stream,
            1024,
            TrafficTracker::noop(),
        ));

        let started = tokio::time::Instant::now();
        assert_eq!(server.handshake().await.unwrap(), addr);
        assert_eq!(tokio::time::Instant::now(), started);
        assert_eq!(writes.lock().unwrap().len(), 1);

        server.write_all(b"220 ready\r\n").await.unwrap();
        server.shutdown().await.unwrap();

        let mut greeting = Vec::new();
        client_peer.read_to_end(&mut greeting).await.unwrap();
        assert_eq!(greeting, b"220 ready\r\n");
        client_peer.shutdown().await.unwrap();

        let (up, down) = copy.await.unwrap().unwrap();
        assert_eq!((up, down), (0, 11));
    }

    #[tokio::test]
    async fn cached_upload_and_early_response_make_progress_under_backpressure() {
        let addr: Address = ("example.test".to_owned(), 80).into();
        let cfg = ServerConfig::new(
            ("127.0.0.1", 8388), String::new(), CipherKind::NONE,
        ).unwrap();
        let (client_io, server_io) = duplex(64);
        let stream = ProxyClientStream::from_stream(
            SsContext::new_shared(ServerType::Local), AnyStream::new(client_io),
            &cfg, addr.clone(),
        );
        let mut server = ProxyServerStream::from_stream(
            SsContext::new_shared(ServerType::Server), server_io,
            CipherKind::NONE, cfg.key(),
        );
        let mut prefix = SlideBuffer::new(1024);
        prefix.extend_from_slice(&[7; 1024]);
        let (mut peer, inbound) = duplex(64);
        let inbound = PrefixedStream::new(prefix, AnyStream::new(inbound));
        peer.shutdown().await.unwrap();

        let copy = copy_bidirectional(
            AnyStream::new(inbound), AnyStream::new(ShadowSocksStream(stream)),
            1024,
            TrafficTracker::noop(),
        );
        let receive = async {
            assert_eq!(server.handshake().await.unwrap(), addr);
            // The response is larger than the transport buffer. It must be
            // drained while the client's first request write is still Pending.
            server.write_all(&[9; 1024]).await.unwrap();
            let mut request = Vec::new();
            server.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, vec![7; 1024]);
            server.shutdown().await.unwrap();
        };
        let read = async {
            let mut response = Vec::new();
            peer.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, vec![9; 1024]);
        };
        let (copied, _, _) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(copy, receive, read)
        }).await.expect("bidirectional first-packet transfer stalled");
        assert_eq!(copied.unwrap(), (1024, 1024));
    }

    #[tokio::test]
    async fn http_url_test_over_ss_coalesces_header_and_request() {
        let addr: Address = ("example.test".to_owned(), 80).into();
        let (ss_stream, mut server, writes) = ss_pair(&addr);
        let cell = Arc::new(Mutex::new(Some(ss_stream)));

        let server_task = tokio::spawn(async move {
            assert_eq!(server.handshake().await.unwrap(), addr);
            let mut req = Vec::new();
            let mut buf = [0u8; 256];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = server.read(&mut buf).await.unwrap();
                assert!(n > 0);
                req.extend_from_slice(&buf[..n]);
            }
            assert!(req.starts_with(b"GET "));
            let resp = b"HTTP/1.1 204 No Content\r\n\
                Content-Length: 0\r\nConnection: close\r\n\r\n";
            server.write_all(resp).await.unwrap();
            server.flush().await.unwrap();
        });

        let manager = ProxyManager::new(Arc::new(NoopResolver), None);
        let mut handler = MockDummyOutboundHandler::new();
        handler.expect_name().return_const("ss-test".to_owned());
        handler.expect_connect_stream().returning(move |_, _| {
            Ok(cell.lock().unwrap().take().expect("single dial"))
        });

        manager
            .url_test(
                OutboundNode::protocol(Arc::new(handler)),
                "http://example.test/generate_204",
                Some(Duration::from_secs(5)),
            )
            .await
            .unwrap();

        server_task.await.unwrap();
        assert_eq!(writes.lock().unwrap().len(), 1);
    }
}
