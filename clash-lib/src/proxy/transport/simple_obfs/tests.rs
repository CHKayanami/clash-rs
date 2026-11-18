use std::{io, pin::Pin, task::Context, time::Duration};

use futures::task::noop_waker;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, duplex},
    time::timeout,
};

use crate::proxy::AnyStream;

use super::{HTTPObfs, TLSObfs, http::MAX_RESPONSE_HEADER_SIZE};

#[tokio::test]
async fn http_response_header_can_span_reads_and_end_without_payload() {
    let (raw, mut peer) = duplex(256);
    let mut stream = HTTPObfs::new(AnyStream::new(raw), "example.test".into(), 80);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut bytes = [0; 5];
    for part in [&b"HTTP/1.1 101 Switching "[..], &b"Protocols\r\n\r"[..], &b"\n"[..]] {
        peer.write_all(part).await.unwrap();
        let mut read_buf = ReadBuf::new(&mut bytes);
        assert!(Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf).is_pending());
        assert!(read_buf.filled().is_empty());
    }
    peer.write_all(b"reply").await.unwrap();
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"reply");
}

#[tokio::test]
async fn http_header_limit_excludes_payload() {
    for oversized in [false, true] {
        let (raw, mut peer) = duplex(4096);
        let mut stream = HTTPObfs::new(AnyStream::new(raw), "example.test".into(), 80);
        let mut wire = b"HTTP/1.1 101 Switching Protocols\r\nX-Test: ".to_vec();
        wire.resize(MAX_RESPONSE_HEADER_SIZE - 4 + usize::from(oversized), b'x');
        wire.extend_from_slice(b"\r\n\r\nreply");
        let mut reply = [0; 5];
        let (_, result) = timeout(Duration::from_secs(2), async {
            tokio::join!(peer.write_all(&wire), stream.read_exact(&mut reply))
        }).await.unwrap();
        if oversized {
            assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
        } else {
            result.unwrap();
            assert_eq!(&reply, b"reply");
        }
    }
}

#[tokio::test]
async fn flush_can_finish_pending_write_without_resending_payload() {
    let payload = b"payload sent exactly once";
    for tls in [false, true] {
        let (raw, mut peer) = duplex(32);
        let raw = AnyStream::new(raw);
        let mut stream = if tls {
            AnyStream::new(TLSObfs::new(raw, "example.test".into()))
        } else {
            AnyStream::new(HTTPObfs::new(raw, "example.test".into(), 80))
        };
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_write(&mut cx, payload).is_pending());

        let send = async {
            stream.flush().await.unwrap();
            assert_eq!(stream.write(payload).await.unwrap(), payload.len());
            stream.shutdown().await.unwrap();
        };
        let mut wire = Vec::new();
        timeout(Duration::from_secs(2), async {
            let (_, received) = tokio::join!(send, peer.read_to_end(&mut wire));
            received.unwrap();
        }).await.unwrap();
        if tls {
            let len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
            assert_eq!(wire.len(), 5 + len, "only one TLS record should be sent");
        } else {
            let header_end = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            assert_eq!(&wire[header_end..], payload);
        }
    }
}

#[tokio::test]
async fn tls_eof_is_clean_only_at_a_record_boundary() {
    for tail in [&b""[..], &b"\x17"[..], &b"\x17\x03\x03\x00"[..], &b"\x17\x03\x03\x00\x02x"[..]] {
        let (raw, mut peer) = duplex(256);
        let mut stream = TLSObfs::new(AnyStream::new(raw), "example.test".into());
        peer.write_all(&[0; 105]).await.unwrap();
        peer.write_all(b"\x00\x05reply").await.unwrap();
        peer.write_all(tail).await.unwrap();
        peer.shutdown().await.unwrap();

        let mut reply = [0; 5];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        let result = stream.read_to_end(&mut Vec::new()).await;
        if tail.is_empty() {
            assert_eq!(result.unwrap(), 0);
        } else {
            assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::UnexpectedEof));
        }
    }
}
