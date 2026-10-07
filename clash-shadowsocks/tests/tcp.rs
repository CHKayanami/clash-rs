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
                assert_eq!(n, size.min(first_payload_limit));
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

    #[cfg(feature = "aead-cipher-2022")]
    #[tokio::test]
    async fn aead2022_empty_first_write_allows_server_greeting() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let method = CipherKind::AEAD2022_BLAKE3_AES_256_GCM;
        let cfg = ServerConfig::new(
            ("127.0.0.1", 8388), STANDARD.encode([7_u8; 32]), method,
        ).unwrap();
        let addr: Address = ("example.test".to_owned(), 443).into();
        // The reader consumes the fixed response header (91 bytes for this
        // cipher) in one read; keep room for it while still forcing
        // Pending writes for a padded request.
        let (client_io, server_io) = duplex(128);
        let mut client = ProxyClientStream::from_stream(
            Context::new_shared(ServerType::Local), client_io, &cfg, addr.clone(),
        );
        let mut server = ProxyServerStream::from_stream(
            Context::new_shared(ServerType::Server), server_io, method, cfg.key(),
        );
        let send = async {
            assert_eq!(client.write(&[]).await?, 0);
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
}
