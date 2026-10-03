use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn first_frame_reaches_peer_without_flush() {
    let (client, mut peer) = tokio::io::duplex(2048);
    let mut stream = PaddingStream::new(AnyStream::new(client));
    stream.write_all(b"first").await.unwrap();
    timeout(Duration::from_secs(1), async {
        assert_eq!(peer.read_u16().await.unwrap(), 5);
        let n = peer.read_u16().await.unwrap();
        assert!((MIN_PADDING..=MAX_PADDING).contains(&n));
        let mut data = [0; 5];
        peer.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"first");
        peer.read_exact(&mut vec![0; usize::from(n)]).await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn eager_write_preserves_pending_frame_under_backpressure() {
    timeout(Duration::from_secs(1), async {
        let (client, mut peer) = tokio::io::duplex(1);
        let mut stream = PaddingStream::new(AnyStream::new(client));
        // Eager drain writes one header byte, then returns Pending. The caller
        // must still see the whole payload accepted without waiting for a read.
        assert_eq!(stream.write(b"first").await.unwrap(), 5);
        let reader = tokio::spawn(async move {
            let mut wire = Vec::new();
            peer.read_to_end(&mut wire).await.unwrap();
            assert_eq!(&wire[..2], &[0, 5]);
            let n = usize::from(u16::from_be_bytes([wire[2], wire[3]]));
            assert_eq!(wire.len(), 4 + 5 + n);
            assert_eq!(&wire[4..9], b"first");
        });
        stream.shutdown().await.unwrap();
        reader.await.unwrap();
    }).await.unwrap();
}

struct ErrorOnceStream(bool);

impl ProxyStream for ErrorOnceStream {}

impl AsyncRead for ErrorOnceStream {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>)
        -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for ErrorOnceStream {
    fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8])
        -> Poll<io::Result<usize>> {
        if self.0 {
            Poll::Ready(Ok(buf.len()))
        } else {
            self.0 = true;
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn eager_write_errors_are_reported_on_the_next_operation() {
    for operation in 0..3 {
        let mut stream = PaddingStream::new(AnyStream::dynamic(ErrorOnceStream(false)));
        assert_eq!(stream.write(b"first").await.unwrap(), 5);
        let error = match operation {
            0 => stream.write(b"second").await.unwrap_err(),
            1 => stream.flush().await.unwrap_err(),
            _ => stream.shutdown().await.unwrap_err(),
        };
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }
}

#[tokio::test]
async fn writes_padding_frames_then_raw_data() {
    let (client, mut peer) = tokio::io::duplex(32);
    let reader = tokio::spawn(async move {
        // A large write must split into two u16-sized frames.
        for size in [65535, 1].into_iter().chain([1; 14]) {
            assert_eq!(peer.read_u16().await.unwrap(), size);
            let padding = peer.read_u16().await.unwrap();
            assert!((MIN_PADDING..=MAX_PADDING).contains(&padding));
            let mut payload = vec![0; size as usize];
            peer.read_exact(&mut payload).await.unwrap();
            assert!(payload.iter().all(|byte| *byte == b'x'));
            let mut padding = vec![0; padding as usize];
            peer.read_exact(&mut padding).await.unwrap();
        }
        let mut raw = [0; 3];
        peer.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"raw");
    });
    let mut stream = PaddingStream::new(AnyStream::new(client));
    stream.write_all(&vec![b'x'; 65536]).await.unwrap();
    for _ in 0..14 {
        stream.write_all(b"x").await.unwrap();
    }
    stream.write_all(b"raw").await.unwrap();
    stream.shutdown().await.unwrap();
    reader.await.unwrap();
}

#[tokio::test]
async fn reads_fragmented_padding_frames_then_raw_data() {
    let (client, mut peer) = tokio::io::duplex(1);
    let writer = tokio::spawn(async move {
        for _ in 0..FIRST_PADDINGS {
            // Independent wire fixture: data length=2, padding length=3.
            peer.write_all(&[0, 2, 0, 3, b'o', b'k', 7, 8, 9]).await.unwrap();
        }
        peer.write_all(b"raw").await.unwrap();
    });
    let mut stream = PaddingStream::new(AnyStream::new(client));
    let mut data = Vec::new();
    stream.read_to_end(&mut data).await.unwrap();
    assert_eq!(data, [b"ok".repeat(FIRST_PADDINGS), b"raw".to_vec()].concat());
    writer.await.unwrap();
}

#[tokio::test]
async fn rejects_truncated_padding_frame() {
    let (client, mut peer) = tokio::io::duplex(32);
    peer.write_all(&[0, 2, 0, 0, b'x']).await.unwrap();
    drop(peer);
    let mut stream = PaddingStream::new(AnyStream::new(client));
    let error = stream.read_to_end(&mut Vec::new()).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}
