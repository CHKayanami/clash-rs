//! Adapted from honk (GPL-3.0-only); local regression tests added for ClashRS.

use super::*;
use super::super::*;
use crate::proxy::{AnyStream, transport::VisionOptions};

use super::super::client::TicketUse;
use std::{io, pin::Pin, sync::Arc, task::{Context, Poll}, time::Duration};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use boring::mlkem::{Algorithm as MlKemAlgorithm, MlKemPublicKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use super::super::crypto::{AesCtr, StreamAead, aes_gcm_hardware_available,
    encode_length, x25519, x25519_keypair};
use super::super::crypto::derive_key;
use super::super::options::{PaddingSpec, XorMode};

use std::sync::atomic::Ordering;

struct DirectReader<'a>(&'a mut EncryptionStream);

impl AsyncRead for DirectReader<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().0.poll_direct_read(cx, buf)
    }
}

#[test]
fn raw_context_derive_matches_blake3_for_utf8_context() {
    let context = b"VLESS";
    let material = b"shared secret";
    assert_eq!(
        derive_key(context, material),
        blake3::derive_key(std::str::from_utf8(context).unwrap(), material)
    );
    for length in [0, 32, 64, 1024, 1184, 2048, 4097] {
        let input = vec![7; length];
        assert_eq!(derive_key(context, &input), blake3::derive_key("VLESS", &input));
    }
}

#[test]
fn parses_x25519_config_and_padding() {
    let key = URL_SAFE_NO_PAD.encode([7u8; 32]);
    let options = EncryptionOptions::parse(&format!(
        "mlkem768x25519plus.xorpub.0rtt.100-111-1111.75-0-111.50-0-3333.{key}"
    ))
    .unwrap();
    assert_eq!(options.auth_keys.len(), 1);
    assert_eq!(options.mode, XorMode::XorPub);
    assert!(options.allow_0rtt);
    assert_eq!(
        options.padding_lengths,
        vec![
            PaddingSpec {
                probability: 100,
                min: 111,
                max: 1111
            },
            PaddingSpec {
                probability: 50,
                min: 0,
                max: 3333
            }
        ]
    );
    assert_eq!(
        options.padding_gaps,
        vec![PaddingSpec {
            probability: 75,
            min: 0,
            max: 111
        }]
    );
}

#[test]
fn padding_limits_reject_oversized_values_without_overflow() {
    let key = URL_SAFE_NO_PAD.encode([7; X25519_KEY_LEN]);
    for padding in [
        format!("100-35-{}", usize::MAX),
        "100-35-40000.0-0-0.100-35-40000".to_owned(),
        "100-35-65554".to_owned(),
    ] {
        assert!(EncryptionOptions::parse(&format!(
            "mlkem768x25519plus.native.1rtt.{padding}.{key}",
        )).is_err());
    }
    assert!(EncryptionOptions::parse(&format!(
        "mlkem768x25519plus.native.1rtt.100-65553-65553.{key}",
    )).is_ok());
}

#[test]
fn rejects_missing_or_malformed_keys_and_padding() {
    assert!(EncryptionOptions::parse("mlkem768x25519plus.native.1rtt").is_err());
    assert!(EncryptionOptions::parse("mlkem768x25519plus.native.1rtt.not-a-key").is_err());
    let key = URL_SAFE_NO_PAD.encode([7u8; 32]);
    assert!(EncryptionOptions::parse(&format!("mlkem768x25519plus.native.1rtt.50-1-2.{key}")).is_err());
}

#[test]
fn xor_stream_round_trips_across_segments() {
    let material = [9u8; 96];
    let iv = [4u8; 16];
    let mut encrypted = [1u8; 97];
    let original = encrypted;
    let mut sender = AesCtr::new(&material, &iv);
    sender.apply(&mut encrypted[..31]);
    sender.apply(&mut encrypted[31..]);
    let mut receiver = AesCtr::new(&material, &iv);
    receiver.apply(&mut encrypted);
    assert_eq!(encrypted, original);
}

#[tokio::test]
async fn frame_codec_round_trips_large_payload() {
    let key = vec![11u8; 96];
    let (client_io, server_io) = tokio::io::duplex(4096);
    let mut client = EncryptionStream::new(
        AnyStream::new(client_io),
        SessionKeys { material: key.clone().try_into().unwrap(), use_aes: true },
        StreamInit::established(
            StreamAead::new(b"client", &key, true).unwrap(),
            StreamAead::new(b"server", &key, true).unwrap(),
            None, None,
        ),
    );
    let mut server = EncryptionStream::new(
        AnyStream::new(server_io),
        SessionKeys { material: key.clone().try_into().unwrap(), use_aes: true },
        StreamInit::established(
            StreamAead::new(b"server", &key, true).unwrap(),
            StreamAead::new(b"client", &key, true).unwrap(),
            None, None,
        ),
    );
    let payload = vec![0x5a; MAX_FRAME_PLAINTEXT * 2 + 321];
    let expected = payload.clone();
    let server_task = tokio::spawn(async move {
        let mut received = vec![0; expected.len()];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        server.write_all(b"reply").await.unwrap();
        server.shutdown().await.unwrap();
    });
    client.write_all(&payload).await.unwrap();
    client.flush().await.unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"reply");
    server_task.await.unwrap();
}

#[tokio::test]
async fn direct_drains_authenticated_plaintext_and_keeps_encrypted_writes() {
    let key = vec![13_u8; 96];
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let mut server_recv = StreamAead::new(b"client", &key, true).unwrap();
    let mut stream = EncryptionStream::new(
        AnyStream::new(client_io),
        SessionKeys { material: key.clone().try_into().unwrap(), use_aes: true },
        StreamInit::established(
            StreamAead::new(b"client", &key, true).unwrap(),
            StreamAead::new(b"server", &key, true).unwrap(),
            None, None,
        ),
    );
    stream.read_plaintext = b"authenticated-".to_vec();
    server_io.write_all(b"outer").await.unwrap();
    server_io.shutdown().await.unwrap();

    let mut plaintext = Vec::new();
    DirectReader(&mut stream)
        .read_to_end(&mut plaintext)
        .await
        .unwrap();
    assert_eq!(plaintext, b"authenticated-outer");

    stream.write_all(b"uplink").await.unwrap();
    let mut header = [0_u8; FRAME_HEADER_LEN];
    server_io.read_exact(&mut header).await.unwrap();
    assert_eq!(header, [23, 3, 3, 0, 22]);
    let mut body = vec![0_u8; 22];
    server_io.read_exact(&mut body).await.unwrap();
    let length = server_recv.open(&mut body, &header).unwrap();
    assert_eq!(&body[..length], b"uplink");
}

#[tokio::test]
async fn direct_random_xor_continues_across_partial_headers() {
    let key = vec![17_u8; 96];
    let iv = [19_u8; IV_LEN];
    let mut sender = AesCtr::new(&key, &iv);
    let mut receiver = AesCtr::new(&key, &iv);

    let prior_plain = [23, 3, 3, 0, 17];
    let mut prior_wire = prior_plain;
    sender.apply(&mut prior_wire);
    receiver.apply(&mut prior_wire);
    assert_eq!(prior_wire, prior_plain);

    let mut plaintext = Vec::new();
    let mut wire = Vec::new();
    for body in [b"a".repeat(17), b"b".repeat(19)] {
        let mut header = [23, 3, 3, 0, body.len() as u8];
        plaintext.extend_from_slice(&header);
        plaintext.extend_from_slice(&body);
        sender.apply(&mut header);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&body);
    }

    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let mut stream = EncryptionStream::new(
        AnyStream::new(client_io),
        SessionKeys { material: key.clone().try_into().unwrap(), use_aes: true },
        StreamInit::established(
            StreamAead::new(b"client", &key, true).unwrap(),
            StreamAead::new(b"server", &key, true).unwrap(),
            None, Some(receiver),
        ),
    );
    server_io.write_all(&wire).await.unwrap();
    server_io.shutdown().await.unwrap();

    let mut output = Vec::new();
    let mut reader = DirectReader(&mut stream);
    loop {
        let mut byte = [0_u8; 1];
        if reader.read(&mut byte).await.unwrap() == 0 {
            break;
        }
        output.push(byte[0]);
    }

    assert_eq!(output, plaintext);
}

struct DirectWriter<'a>(&'a mut EncryptionStream);

impl AsyncWrite for DirectWriter<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().0.poll_direct_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_shutdown(cx)
    }
}

fn ready_stream(inner: tokio::io::DuplexStream, send_xor: Option<AesCtr>) -> EncryptionStream {
    let key = vec![23_u8; 96];
    EncryptionStream::new(
        AnyStream::new(inner),
        SessionKeys { material: key.clone().try_into().unwrap(), use_aes: true },
        StreamInit::established(
            StreamAead::new(b"client", &key, true).unwrap(),
            StreamAead::new(b"server", &key, true).unwrap(),
            send_xor, None,
        ),
    )
}

#[tokio::test]
async fn native_direct_write_passes_bytes_through_unframed() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let mut stream = ready_stream(client_io, None);
    DirectWriter(&mut stream)
        .write_all(b"raw-inner-tls")
        .await
        .unwrap();
    DirectWriter(&mut stream).shutdown().await.unwrap();
    let mut received = Vec::new();
    server_io.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, b"raw-inner-tls");
    assert_eq!(stream.write_wire.capacity(), 0);
}

/// Xray `XorConn.Write` skips any body whose plaintext header starts
/// 23,3,3 — even an invalid length — and skips nothing after other types.
#[tokio::test]
async fn random_direct_write_xors_headers_exactly_once_across_partial_writes() {
    let key = vec![17_u8; 96];
    let iv = [29_u8; IV_LEN];
    let mut plaintext = vec![23, 3, 3, 0, 5];
    plaintext.extend_from_slice(b"short");
    plaintext.extend_from_slice(&[23, 3, 3, 0, 17]);
    plaintext.extend_from_slice(&[0x42; 17]);
    plaintext.extend_from_slice(&[22, 3, 3, 0, 3]);
    plaintext.extend_from_slice(&[23, 3, 3, 0, 0]);
    let mut expected = plaintext.clone();
    let mut oracle = AesCtr::new(&key, &iv);
    for range in [0..5, 10..15, 32..37, 37..42] {
        oracle.apply(&mut expected[range]);
    }

    // A 3-byte pipe makes the outer writer accept short writes and return
    // Pending, so every caller retry goes through the pending-wire resend.
    let (client_io, mut server_io) = tokio::io::duplex(3);
    let mut stream = ready_stream(client_io, Some(AesCtr::new(&key, &iv)));
    let write = async {
        for chunk in plaintext.chunks(7) {
            DirectWriter(&mut stream).write_all(chunk).await.unwrap();
        }
        DirectWriter(&mut stream).shutdown().await.unwrap();
    };
    let mut received = Vec::new();
    let read = server_io.read_to_end(&mut received);
    let ((), read) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(write, read)
    })
    .await
    .expect("Direct write must finish every resend");
    read.unwrap();
    assert_eq!(received, expected);
}

#[tokio::test]
async fn random_direct_large_write_keeps_bounded_chunks_and_xor_state() {
    let key = vec![17_u8; 96];
    let iv = [29_u8; IV_LEN];
    let mut plaintext = vec![23, 3, 3, 0x23, 0x28];
    plaintext.extend_from_slice(&[0x42; 9000]);
    plaintext.extend_from_slice(&[23, 3, 3, 0x23, 0x28]);
    plaintext.extend_from_slice(&[0x43; 9000]);
    let mut expected = plaintext.clone();
    let mut oracle = AesCtr::new(&key, &iv);
    oracle.apply(&mut expected[..5]);
    oracle.apply(&mut expected[9005..9010]);

    let (client_io, mut server_io) = tokio::io::duplex(7);
    let mut stream = ready_stream(client_io, Some(AesCtr::new(&key, &iv)));
    let write = async {
        let mut offset = 0;
        while offset < plaintext.len() {
            let written = DirectWriter(&mut stream)
                .write(&plaintext[offset..])
                .await
                .unwrap();
            assert!((1..=MAX_FRAME_PLAINTEXT).contains(&written));
            offset += written;
        }
        DirectWriter(&mut stream).shutdown().await.unwrap();
    };
    let mut received = Vec::new();
    let read = server_io.read_to_end(&mut received);
    let ((), read) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(write, read)
    })
    .await
    .expect("large Direct write did not finish");
    read.unwrap();
    assert_eq!(received, expected);
}

#[tokio::test]
async fn direct_write_refuses_before_the_first_frame() {
    let (client_io, _server_io) = tokio::io::duplex(4096);
    let mut stream = ready_stream(client_io, None);
    stream.prewrite = Some(b"0-rtt-prologue".to_vec());
    let error = DirectWriter(&mut stream)
        .write_all(b"raw")
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}


#[tokio::test]
async fn handshake_establishes_keys_and_reuses_ticket() {
    let (public, private) = x25519_keypair();
    let options = EncryptionOptions::parse(&format!(
        "mlkem768x25519plus.native.0rtt.100-35-35.{}",
        URL_SAFE_NO_PAD.encode(public),
    )).unwrap();
    let client = EncryptionClient::new(options.clone());
    let use_aes = aes_gcm_hardware_available();
    let (client_io, mut server_io) = tokio::io::duplex(8192);
    let server = async {
        let mut iv = [0; IV_LEN];
        server_io.read_exact(&mut iv).await.unwrap();
        let mut relay = [0; X25519_KEY_LEN];
        server_io.read_exact(&mut relay).await.unwrap();
        let nfs_key = x25519(&private, &relay).unwrap();
        let mut nfs = StreamAead::new(&iv, &nfs_key, use_aes).unwrap();
        let mut length = vec![0; 18];
        server_io.read_exact(&mut length).await.unwrap();
        assert_eq!(nfs.open(&mut length, b"").unwrap(), 2);
        let mut pfs_public = vec![0; usize::from(u16::from_be_bytes([length[0], length[1]]))];
        server_io.read_exact(&mut pfs_public).await.unwrap();
        let size = nfs.open(&mut pfs_public, b"").unwrap();
        pfs_public.truncate(size);
        server_io.read_exact(&mut length).await.unwrap();
        nfs.open(&mut length, b"").unwrap();
        let mut padding = vec![0; usize::from(u16::from_be_bytes([length[0], length[1]]))];
        server_io.read_exact(&mut padding).await.unwrap();
        nfs.open(&mut padding, b"").unwrap();

        let mlkem = MlKemPublicKey::from_slice(MlKemAlgorithm::MlKem768, &pfs_public[..MLKEM_PUBLIC_KEY_LEN]).unwrap();
        let (ciphertext, mlkem_shared) = mlkem.encapsulate().unwrap();
        let (x_public, x_private) = x25519_keypair();
        let x_shared = x25519(&x_private, pfs_public[MLKEM_PUBLIC_KEY_LEN..].try_into().unwrap()).unwrap();
        let mut server_key = ciphertext;
        server_key.extend_from_slice(&x_public);
        let mut united_key = Vec::new();
        united_key.extend_from_slice(&mlkem_shared);
        united_key.extend_from_slice(&x_shared);
        united_key.extend_from_slice(&nfs_key);
        nfs.nonce = MAX_NONCE;
        nfs.nonce[NONCE_LEN - 1] -= 1;
        let mut response = Vec::new();
        nfs.seal(&server_key, b"", &mut response).unwrap();
        let mut send = StreamAead::new(&server_key, &united_key, use_aes).unwrap();
        let mut ticket = [5; TICKET_LEN];
        ticket[..2].copy_from_slice(&60u16.to_be_bytes());
        send.seal(&ticket, b"", &mut response).unwrap();
        send.seal(&encode_length(TAG_LEN), b"", &mut response).unwrap();
        send.seal(b"", b"", &mut response).unwrap();
        server_io.write_all(&response).await.unwrap();
        let mut stream = EncryptionStream::new(
            AnyStream::new(server_io),
            SessionKeys { material: united_key.try_into().unwrap(), use_aes },
            StreamInit::established(
                send,
                StreamAead::new(&pfs_public, &[
                mlkem_shared.as_slice(), x_shared.as_slice(), nfs_key.as_slice()
            ].concat(), use_aes).unwrap(),
                None, None,
            ),
        );
        let mut payload = [0; 5];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
        stream.write_all(&payload).await.unwrap();
    };
    let client_handshake = async {
        let mut stream = client.handshake(AnyStream::new(client_io)).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(client_handshake, server);
    }).await.unwrap();
    assert!(client.cached_ticket().is_some());
    assert!(EncryptionClient::new(options).cached_ticket().is_none());

    // Resumption returns before receiving server bytes, and a truncated
    // response invalidates the ticket instead of silently reconnecting.
    let (client_io, mut server_io) = tokio::io::duplex(8192);
    let mut stream = client.handshake(AnyStream::new(client_io)).await.unwrap();
    assert!(stream.prewrite.is_some());
    stream.write_all(b"resumed").await.unwrap();
    let mut prologue = [0; IV_LEN + X25519_KEY_LEN + 18 + TICKET_LEN + TAG_LEN];
    server_io.read_exact(&mut prologue).await.unwrap();
    let iv = &prologue[..IV_LEN];
    let relay = prologue[IV_LEN..IV_LEN + X25519_KEY_LEN].try_into().unwrap();
    let key = x25519(&private, relay).unwrap();
    let mut nfs = StreamAead::new(iv, &key, use_aes).unwrap();
    let offset = IV_LEN + X25519_KEY_LEN;
    nfs.open(&mut prologue[offset..offset + 18], b"").unwrap();
    assert_eq!(&prologue[offset..offset + 2], &32u16.to_be_bytes());
    nfs.open(&mut prologue[offset + 18..], b"").unwrap();
    assert_eq!(&prologue[offset + 18..offset + 18 + TICKET_LEN], &client.cached_ticket().unwrap());
    // A complete random prologue is not an authenticated server response.
    server_io.write_all(&[4; IV_LEN]).await.unwrap();
    server_io.shutdown().await.unwrap();
    assert_eq!(stream.read(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof);
    assert!(client.cached_ticket().is_none());
    assert_eq!(stream.write(b"retry").await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn authenticated_frames_reject_tampering() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let mut stream = ready_stream(client_io, None);
    let mut header = [23, 3, 3, 0, 0];
    header[3..].copy_from_slice(&encode_length(5 + TAG_LEN));
    let mut wire = header.to_vec();
    StreamAead::new(b"server", &[23; 96], true).unwrap()
        .seal(b"hello", &header, &mut wire).unwrap();
    *wire.last_mut().unwrap() ^= 1;
    server_io.write_all(&wire).await.unwrap();
    let error = stream.read(&mut [0; 5]).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    for _ in 0..2 {
        assert_eq!(stream.read(&mut [0; 5]).await.unwrap_err().kind(), error.kind());
        assert_eq!(stream.write(b"retry").await.unwrap_err().kind(), error.kind());
        assert_eq!(stream.flush().await.unwrap_err().kind(), error.kind());
        assert_eq!(stream.shutdown().await.unwrap_err().kind(), error.kind());
    }
}

#[tokio::test]
async fn vision_direct_keeps_buffered_plaintext_before_raw_transport() {
    use std::sync::atomic::AtomicBool;
    use crate::proxy::vless::{VisionStream, VlessStream};
    use crate::proxy::vless::stream::VLESS_COMMAND_TCP;
    use crate::session::SocksAddr;
    use uuid::Uuid;

    let (client_io, mut server_io) = tokio::io::duplex(8192);
    let mut encrypted = ready_stream(client_io, None);
    let read_flag = Arc::new(AtomicBool::new(false));
    let write_flag = Arc::new(AtomicBool::new(false));
    encrypted.set_vision(VisionOptions {
        read_flag: read_flag.clone(), write_flag: write_flag.clone(),
    });
    let uuid = "5415d8e0-df92-3655-afa4-b79de66413f5";
    let destination: SocksAddr = "1.2.3.4:443".parse().unwrap();
    let vless = VlessStream::new(
        AnyStream::new(encrypted), uuid, &destination,
        VLESS_COMMAND_TCP, Some("xtls-rprx-vision"),
    ).unwrap();
    let mut vision = VisionStream::new(AnyStream::new(vless), uuid, Some(VisionOptions {
        read_flag: read_flag.clone(), write_flag,
    })).unwrap();

    // One authenticated Encryption frame carries the response, Vision Direct
    // command and more plaintext than the consumer's first read can hold.
    let mut plaintext = vec![0, 0];
    plaintext.extend_from_slice(Uuid::parse_str(uuid).unwrap().as_bytes());
    plaintext.extend_from_slice(&[2, 0, 4, 0, 0]);
    plaintext.extend_from_slice(b"lastbuffered");
    let mut header = [23, 3, 3, 0, 0];
    header[3..].copy_from_slice(&encode_length(plaintext.len() + TAG_LEN));
    let mut wire = header.to_vec();
    StreamAead::new(b"server", &[23; 96], true).unwrap()
        .seal(&plaintext, &header, &mut wire).unwrap();
    wire.extend_from_slice(b"raw-tail");
    server_io.write_all(&wire).await.unwrap();
    server_io.shutdown().await.unwrap();
    let mut received = Vec::new();
    loop {
        let mut byte = [0; 1];
        if vision.read(&mut byte).await.unwrap() == 0 { break; }
        received.push(byte[0]);
    }
    assert!(read_flag.load(Ordering::Acquire));
    assert_eq!(&received, b"lastbufferedraw-tail");
}

#[tokio::test]
async fn handshake_deadline_covers_read_write_and_padding_waits() {
    let key = URL_SAFE_NO_PAD.encode([7; X25519_KEY_LEN]);
    let oversized_gap = format!("100-35-35.100-{0}-{0}", usize::MAX);
    for (capacity, padding) in [
        (1, "100-35-35"),
        (8192, "100-35-35"),
        (8192, "100-35-35.100-1000-1000.100-35-35"),
        (8192, oversized_gap.as_str()),
    ] {
        let options = EncryptionOptions::parse(&format!(
            "mlkem768x25519plus.native.1rtt.{padding}.{key}",
        )).unwrap();
        let client = EncryptionClient::new(options);
        let (client_io, _silent_server) = tokio::io::duplex(capacity);
        let result = client.handshake_with_timeout(
            AnyStream::new(client_io), Duration::from_millis(20),
        ).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(client.cached_ticket().is_none());
    }
}

#[tokio::test]
async fn resumption_deadline_is_terminal() {
    let options = EncryptionOptions::parse(&format!(
        "mlkem768x25519plus.native.0rtt.{}",
        URL_SAFE_NO_PAD.encode([7; X25519_KEY_LEN]),
    )).unwrap();
    let client = EncryptionClient::new(options);
    let key = vec![23; 96];
    let (client_io, _silent_server) = tokio::io::duplex(8192);
    let mut stream = EncryptionStream::new(
        AnyStream::new(client_io),
        SessionKeys { material: key.clone().try_into().unwrap(), use_aes: true },
        StreamInit::resumed(
            StreamAead::new(b"client", &key, true).unwrap(),
            None,
            vec![0; 16],
            TicketUse::new(client, [0; 64]),
            Duration::from_millis(20),
        ),
    );
    // Merely creating the stream must not consume its handshake budget.
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(stream.handshake_deadline.is_none());
    stream.write_all(b"first request").await.unwrap();
    assert!(stream.handshake_deadline.is_some());
    assert_eq!(stream.read(&mut [0; 1]).await.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(stream.read(&mut [0; 1]).await.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(stream.write(b"retry").await.unwrap_err().kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn invalid_headers_and_truncated_frames_remain_failed() {
    for wire in [vec![0; FRAME_HEADER_LEN], vec![23, 3, 3, 0, 17, 1]] {
        let (client_io, mut server_io) = tokio::io::duplex(8192);
        let mut stream = ready_stream(client_io, None);
        server_io.write_all(&wire).await.unwrap();
        server_io.shutdown().await.unwrap();
        let error = stream.read(&mut [0; 1]).await.unwrap_err();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap_err().kind(), error.kind());
        assert_eq!(stream.write(b"retry").await.unwrap_err().kind(), error.kind());
    }
}

#[tokio::test]
async fn frame_buffers_reuse_capacity_and_enum_dispatch_round_trips() {
    let (client_io, mut server_io) = tokio::io::duplex(65536);
    let stream = ready_stream(client_io, None);
    let mut stream = AnyStream::new(stream);
    assert!(matches!(stream, AnyStream::VlessEncryption(_)));
    let payload = vec![7; MAX_FRAME_PLAINTEXT];
    let mut receive = StreamAead::new(b"client", &[23; 96], true).unwrap();
    let mut send = StreamAead::new(b"server", &[23; 96], true).unwrap();
    let mut write_storage = None;
    let mut read_storage = None;
    for round in 0..4 {
        stream.write_all(&payload).await.unwrap();
        let mut header = [0; FRAME_HEADER_LEN];
        server_io.read_exact(&mut header).await.unwrap();
        let mut body = vec![0; MAX_FRAME_PLAINTEXT + TAG_LEN];
        server_io.read_exact(&mut body).await.unwrap();
        let length = receive.open(&mut body, &header).unwrap();
        assert_eq!(&body[..length], &payload);
        let mut response = header.to_vec();
        send.seal(&payload, &header, &mut response).unwrap();
        server_io.write_all(&response).await.unwrap();
        let mut echoed = vec![0; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        let AnyStream::VlessEncryption(codec) = &stream else { unreachable!() };
        let write_pointer = codec.write_wire.as_ptr();
        if let Some(previous) = write_storage {
            assert_eq!(write_pointer, previous);
        }
        write_storage = Some(write_pointer);
        if round >= 1 {
            let mut buffers = [codec.read_wire.as_ptr() as usize,
                codec.read_plaintext.as_ptr() as usize];
            buffers.sort();
            if let Some(previous) = read_storage {
                assert_eq!(buffers, previous);
            }
            read_storage = Some(buffers);
        }
    }
}

#[tokio::test]
async fn rekey_uses_original_frame_context_with_reused_storage() {
    let key = vec![23; 96];
    let (client_io, mut server_io) = tokio::io::duplex(8192);
    let mut stream = ready_stream(client_io, None);
    stream.send.nonce = MAX_NONCE;
    stream.recv.as_mut().unwrap().nonce = MAX_NONCE;
    let mut recv = StreamAead::new(b"client", &key, true).unwrap();
    let mut send = StreamAead::new(b"server", &key, true).unwrap();
    recv.nonce = MAX_NONCE;
    send.nonce = MAX_NONCE;
    for (round, payload) in [b"before".as_slice(), b"after".as_slice()].into_iter().enumerate() {
        stream.write_all(payload).await.unwrap();
        let mut header = [0; FRAME_HEADER_LEN];
        server_io.read_exact(&mut header).await.unwrap();
        let mut body = vec![0; payload.len() + TAG_LEN];
        server_io.read_exact(&mut body).await.unwrap();
        let mut context = header.to_vec();
        context.extend_from_slice(&body);
        let length = recv.open(&mut body, &header).unwrap();
        assert_eq!(&body[..length], payload);
        if round == 0 {
            recv = StreamAead::new(&context, &key, true).unwrap();
        }
        let mut response = header.to_vec();
        send.seal(payload, &header, &mut response).unwrap();
        if round == 0 {
            send = StreamAead::new(&response, &key, true).unwrap();
        }
        server_io.write_all(&response).await.unwrap();
        let mut echoed = vec![0; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
    }
}
