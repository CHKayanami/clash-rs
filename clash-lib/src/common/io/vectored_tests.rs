use super::*;
use std::io::Cursor;

struct PartialWriter {
    data: Vec<u8>,
    limit: usize,
    vectored: bool,
    pending_write: bool,
    pending_flush: bool,
    vectored_calls: usize,
}

impl AsyncWrite for PartialWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if std::mem::take(&mut self.pending_write) {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = buf.len().min(self.limit);
        self.data.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.vectored_calls += 1;
        if std::mem::take(&mut self.pending_write) {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let mut written = 0;
        for buf in bufs {
            let n = buf.len().min(self.limit - written);
            self.data.extend_from_slice(&buf[..n]);
            written += n;
        }
        Poll::Ready(Ok(written))
    }

    fn is_write_vectored(&self) -> bool {
        self.vectored
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if std::mem::take(&mut self.pending_flush) {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[tokio::test]
async fn wrapped_buffer_handles_partial_vectored_writes_and_pending() {
    let expected = b"tail!!head1234";
    for vectored in [false, true] {
        for limit in [1, 6, 7, 14] {
            let mut buffer = CopyBuffer::new_with_capacity(1024).unwrap();
            buffer.start_index = 1018;
            buffer.cache_length = expected.len();
            buffer.read_done = true;
            buffer.buf[1018..].copy_from_slice(&expected[..6]);
            buffer.buf[..8].copy_from_slice(&expected[6..]);
            let mut reader = Cursor::new(Vec::<u8>::new());
            let mut writer = PartialWriter {
                data: Vec::new(),
                limit,
                vectored,
                pending_write: true,
                pending_flush: true,
                vectored_calls: 0,
            };
            let mut reported = 0;
            let count = futures::future::poll_fn(|cx| {
                buffer.poll_copy(
                    cx,
                    Pin::new(&mut reader),
                    Pin::new(&mut writer),
                    None,
                    Some(&mut |n| reported += n),
                )
            })
            .await
            .unwrap();
            assert_eq!(writer.data, expected);
            assert_eq!(count, expected.len() as u64);
            assert_eq!(reported, expected.len());
            assert_eq!(buffer.cache_length, 0);
            assert_eq!(buffer.start_index, 0);
            assert_eq!(writer.vectored_calls > 0, vectored);
            if vectored && limit == expected.len() {
                assert_eq!(writer.vectored_calls, 2); // Pending, then both slices.
            }
        }
    }
}

#[tokio::test]
async fn wrapped_buffer_rejects_zero_vectored_write() {
    let mut buffer = CopyBuffer::new_with_capacity(1024).unwrap();
    buffer.start_index = 1023;
    buffer.cache_length = 2;
    buffer.read_done = true;
    let mut reader = Cursor::new(Vec::<u8>::new());
    let mut writer = PartialWriter {
        data: Vec::new(),
        limit: 0,
        vectored: true,
        pending_write: false,
        pending_flush: false,
        vectored_calls: 0,
    };
    let error = futures::future::poll_fn(|cx| {
        buffer.poll_copy(
            cx,
            Pin::new(&mut reader),
            Pin::new(&mut writer),
            None,
            None,
        )
    })
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    assert_eq!(buffer.amount_transferred(), 0);
}
