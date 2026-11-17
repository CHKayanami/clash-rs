#[cfg(any(feature = "aead-cipher", feature = "aead-cipher-2022"))]
mod tests {
    use std::{io, time::Duration};

    use clash_shadowsocks::{
        ProxyClientStream, ServerConfig,
        config::ServerType,
        context::Context,
        crypto::CipherKind,
        relay::{Address, tcprelay::ProxyServerStream},
    };
    use tokio::{io::{AsyncReadExt, AsyncWriteExt, duplex}, time::timeout};

    async fn large_first_write(method: CipherKind, password: &str, max_size: usize) {
        let addr: Address = ("example.test".to_owned(), 443).into();
        let first_payload_limit = max_size - addr.serialized_len()
            - if cfg!(feature = "aead-cipher-2022") && max_size == 65535 { 2 } else { 0 };
        for size in [first_payload_limit, first_payload_limit + 1, max_size * 3] {
            let cfg = ServerConfig::new(("127.0.0.1", 8388), password.to_owned(), method).unwrap();
            // A tiny transport forces partial writes and Pending while the
            // peer reads, exercising the saved first-packet buffer as well.
            let (client_io, server_io) = duplex(64);
            let mut client = ProxyClientStream::from_stream(
                Context::new_shared(ServerType::Local), client_io, &cfg, addr.clone(),
            );
            let mut server = ProxyServerStream::from_stream(
                Context::new_shared(ServerType::Server), server_io, method, cfg.key(),
            );
            let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let send = async {
                let n = client.write(&payload).await?;
                assert_eq!(n, if method == CipherKind::NONE { size } else { size.min(first_payload_limit) });
                client.write_all(&payload[n..]).await?;
                client.shutdown().await
            };
            let receive = async {
                assert_eq!(server.handshake().await?, addr);
                let mut received = Vec::new();
                server.read_to_end(&mut received).await?;
                assert_eq!(received, payload);
                Ok::<(), io::Error>(())
            };
            let (sent, received) = timeout(Duration::from_secs(5), async {
                tokio::join!(send, receive)
            }).await.expect("TCP relay stalled");
            sent.unwrap();
            received.unwrap();
        }
    }

    #[tokio::test]
    async fn plain_large_first_write_preserves_payload() {
        large_first_write(CipherKind::NONE, "", 16383).await;
    }

    #[cfg(feature = "aead-cipher")]
    #[tokio::test]
    async fn aead_large_first_write_preserves_payload() {
        large_first_write(CipherKind::AES_256_GCM, "test-password", 16383).await;
    }

    #[cfg(feature = "aead-cipher-2022")]
    #[tokio::test]
    async fn aead2022_large_first_write_preserves_payload() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        large_first_write(
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
            &STANDARD.encode([7_u8; 32]),
            65535,
        ).await;
    }

    async fn read_first_allows_server_greeting(method: CipherKind, password: &str) {
        let cfg = ServerConfig::new(
            ("127.0.0.1", 8388), password.to_owned(), method,
        ).unwrap();
        let addr: Address = ("example.test".to_owned(), 443).into();
        // Keep room for the SS2022 fixed response header while still forcing
        // Pending writes for its padded request.
        let (client_io, server_io) = duplex(128);
        let mut client = ProxyClientStream::from_stream(
            Context::new_shared(ServerType::Local), client_io, &cfg, addr.clone(),
        );
        let mut server = ProxyServerStream::from_stream(
            Context::new_shared(ServerType::Server), server_io, method, cfg.key(),
        );
        let send = async {
            use std::pin::Pin;
            use futures::future::poll_fn;

            poll_fn(|cx| Pin::new(&mut client).poll_handshake(cx)).await?;
            let mut greeting = [0_u8; 5];
            client.read_exact(&mut greeting).await?;
            assert_eq!(&greeting, b"hello");
            Ok::<(), io::Error>(())
        };
        let receive = async {
            assert_eq!(server.handshake().await?, addr);
            server.write_all(b"hello").await
        };
        let (sent, received) = timeout(Duration::from_secs(5), async {
            tokio::join!(send, receive)
        }).await.expect("server greeting stalled");
        sent.unwrap();
        received.unwrap();
    }
    #[tokio::test]
    async fn plain_read_first_allows_server_greeting() {
        read_first_allows_server_greeting(CipherKind::NONE, "").await;
    }

    #[cfg(feature = "aead-cipher")]
    #[tokio::test]
    async fn aead_read_first_allows_server_greeting() {
        read_first_allows_server_greeting(CipherKind::AES_256_GCM, "test-password").await;
    }

    #[cfg(feature = "aead-cipher-2022")]
    #[tokio::test]
    async fn aead2022_read_first_allows_server_greeting() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        read_first_allows_server_greeting(
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM, &STANDARD.encode([7_u8; 32]),
        ).await;
    }

    #[tokio::test]
    async fn pending_handshake_preserves_following_write() {
        use std::{pin::Pin, task::Poll};
        use futures::future::poll_fn;

        let cfg = ServerConfig::new(("127.0.0.1", 8388), "".to_owned(), CipherKind::NONE).unwrap();
        let addr: Address = ("example.test".to_owned(), 443).into();
        let (client_io, server_io) = duplex(1);
        let mut client = ProxyClientStream::from_stream(
            Context::new_shared(ServerType::Local), client_io, &cfg, addr.clone(),
        );
        let mut server = ProxyServerStream::from_stream(
            Context::new_shared(ServerType::Server), server_io, CipherKind::NONE, cfg.key(),
        );
        // Leave a partially written explicit handshake before writing data.
        poll_fn(|cx| {
            assert!(Pin::new(&mut client).poll_handshake(cx).is_pending());
            Poll::Ready(())
        }).await;
        let send = async {
            client.write_all(b"request").await?;
            let mut reply = [0; 5];
            client.read_exact(&mut reply).await?;
            assert_eq!(&reply, b"hello");
            Ok::<(), io::Error>(())
        };
        let receive = async {
            assert_eq!(server.handshake().await?, addr);
            let mut request = [0; 7];
            server.read_exact(&mut request).await?;
            assert_eq!(&request, b"request");
            server.write_all(b"hello").await
        };
        let (sent, received) = timeout(Duration::from_secs(5), async {
            tokio::join!(send, receive)
        }).await.expect("interleaved handshake stalled");
        sent.unwrap();
        received.unwrap();
    }

    #[tokio::test]
    async fn read_before_write_does_not_block_or_drop_first_request() {
        use std::{pin::Pin, task::Poll};
        use futures::future::poll_fn;
        use tokio::io::{AsyncRead, ReadBuf};

        let cfg = ServerConfig::new(("127.0.0.1", 8388), "test-password".to_owned(), CipherKind::AES_256_GCM).unwrap();
        let addr: Address = ("example.test".to_owned(), 80).into();
        let (client_io, server_io) = duplex(256);
        let client = ProxyClientStream::from_stream(
            Context::new_shared(ServerType::Local), client_io, &cfg, addr.clone(),
        );
        let mut server = ProxyServerStream::from_stream(
            Context::new_shared(ServerType::Server), server_io, CipherKind::AES_256_GCM, cfg.key(),
        );
        let (mut rd, mut wr) = tokio::io::split(client);
        let (polled_tx, polled_rx) = tokio::sync::oneshot::channel();
        let reader = tokio::spawn(async move {
            poll_fn(|cx| {
                let mut storage = [0; 1];
                assert!(Pin::new(&mut rd).poll_read(cx, &mut ReadBuf::new(&mut storage)).is_pending());
                Poll::Ready(())
            }).await;
            polled_tx.send(()).unwrap();
            let mut reply = [0; 5];
            rd.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"hello");
        });
        polled_rx.await.unwrap();
        let writer = tokio::spawn(async move {
            wr.write_all(b"GET /").await.unwrap();
            wr.flush().await.unwrap();
        });
        let receive = async {
            assert_eq!(server.handshake().await?, addr);
            let mut request = [0; 5];
            server.read_exact(&mut request).await?;
            assert_eq!(&request, b"GET /");
            server.write_all(b"hello").await
        };
        let (_, _, received) = timeout(Duration::from_secs(5), async {
            tokio::join!(reader, writer, receive)
        }).await.expect("split read-before-write stalled");
        received.unwrap();
    }

}
