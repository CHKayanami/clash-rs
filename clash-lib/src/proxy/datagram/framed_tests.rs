use super::*;
use futures::{future::poll_fn, task::noop_waker_ref};
use tokio::io::{AsyncReadExt, duplex};

#[tokio::test]
async fn partial_writes_preserve_frames_and_validation_prefix() {
    let mut batch = PacketBatch::default();
    for payload in [b"first".as_slice(), b"bad", b"last"] {
        batch.push(UdpPacket { data: Bytes::copy_from_slice(payload), ..Default::default() }).unwrap();
    }
    let mut frames = FramedBatch::default();
    frames.prepare(&batch, |packet, header| {
        if packet.data == b"bad"[..] { return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad packet")); }
        header.extend_from_slice(b"header");
        Ok(())
    });
    let (mut writer, mut reader) = duplex(2);
    let mut cx = Context::from_waker(noop_waker_ref());
    assert!(frames.poll_write(&mut writer, &mut cx).is_pending());
    let receive = async {
        let mut bytes = [0; 11];
        reader.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"headerfirst");
    };
    let send = poll_fn(|cx| frames.poll_write(&mut writer, cx));
    let (result, ()) = tokio::join!(send, receive);
    assert_eq!(result.sent, 1);
    assert_eq!(result.error.unwrap().kind(), io::ErrorKind::InvalidInput);
    assert!(!frames.is_active());
}

struct WriteProbe { data: Vec<u8>, flushes: usize, writes: usize, vectored: bool }
impl AsyncWrite for WriteProbe {
    fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        self.writes += 1; self.data.extend_from_slice(bytes); Poll::Ready(Ok(bytes.len()))
    }
    fn poll_write_vectored(mut self: Pin<&mut Self>, _: &mut Context<'_>, slices: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        self.writes += 1;
        let mut size = 0;
        for slice in slices { self.data.extend_from_slice(slice); size += slice.len(); }
        Poll::Ready(Ok(size))
    }
    fn is_write_vectored(&self) -> bool { self.vectored }
    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes += 1; Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}

#[test]
fn vectored_and_buffered_batches_flush_once() {
    for vectored in [false, true] {
        let mut batch = PacketBatch::default();
        for _ in 0..16 { batch.push(UdpPacket::default()).unwrap(); }
        let mut frames = FramedBatch::default();
        frames.prepare(&batch, |_, header| { header.extend_from_slice(b"h"); Ok(()) });
        let mut writer = WriteProbe { data: Vec::new(), flushes: 0, writes: 0, vectored };
        let mut cx = Context::from_waker(noop_waker_ref());
        let Poll::Ready(result) = frames.poll_write(&mut writer, &mut cx) else { panic!("batch pending") };
        assert_eq!(result.sent, 16);
        assert!(result.error.is_none());
        assert_eq!(writer.data, b"hhhhhhhhhhhhhhhh");
        assert_eq!(writer.flushes, 1);
        assert_eq!(writer.writes, 1);
    }
}

#[test]
fn repeated_batches_reuse_header_payload_and_coalescing_storage() {
    for vectored in [false, true] {
        let mut batch = PacketBatch::default();
        for _ in 0..16 {
            batch.push(UdpPacket { data: Bytes::from_static(b"payload"), ..Default::default() }).unwrap();
        }
        let mut frames = FramedBatch::default();
        let mut storage = None;
        for _ in 0..3 {
            frames.prepare(&batch, |_, header| { header.extend_from_slice(b"header"); Ok(()) });
            let mut writer = WriteProbe { data: Vec::new(), flushes: 0, writes: 0, vectored };
            let mut cx = Context::from_waker(noop_waker_ref());
            let Poll::Ready(result) = frames.poll_write(&mut writer, &mut cx) else { panic!("send pending") };
            assert_eq!(result.sent, 16);
            assert_eq!(writer.data, b"headerpayload".repeat(16));
            let current = (frames.headers.as_ptr(), frames.headers.capacity(),
                frames.payloads.as_ptr(), frames.payloads.capacity(),
                frames.coalesced.as_ptr(), frames.coalesced.capacity());
            if let Some(previous) = storage { assert_eq!(current, previous); }
            storage = Some(current);
        }
    }
}

struct FailedFlush { writes: usize }
impl AsyncWrite for FailedFlush {
    fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        self.writes += 1; Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidInput, "flush failed")))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}

#[test]
fn flush_failure_is_terminal_and_never_retries_encoded_frames() {
    let mut batch = PacketBatch::default();
    for _ in 0..2 { batch.push(UdpPacket::default()).unwrap(); }
    let mut frames = FramedBatch::default();
    frames.prepare(&batch, |_, header| { header.extend_from_slice(b"header"); Ok(()) });
    let mut writer = FailedFlush { writes: 0 };
    let mut cx = Context::from_waker(noop_waker_ref());
    let Poll::Ready(result) = frames.poll_write(&mut writer, &mut cx) else { panic!("send pending") };
    assert!(result.fatal);
    assert_eq!(result.error.unwrap().kind(), io::ErrorKind::InvalidInput);
    assert_eq!(writer.writes, 1);
    assert!(frames.is_active());
    let Poll::Ready(result) = frames.poll_write(&mut writer, &mut cx) else { panic!("send pending") };
    assert!(result.fatal);
    assert_eq!(writer.writes, 1);
}
