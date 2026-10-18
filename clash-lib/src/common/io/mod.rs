mod buffered;
mod copy;
mod timeout;
mod transfer;
#[cfg(feature = "allocation-tests")]
pub(crate) mod measurement;
pub use copy::copy_bidirectional;
pub(crate) mod datagram_relay;

#[cfg(any(test, feature = "allocation-tests"))]
use std::future::Future;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::BytesMut;
use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
mod splice;

pub use clash_common::SlideBuffer;

use crate::{
    app::dispatcher::TrafficTracker,
};

#[derive(Debug)]
pub enum CopyBidirectionalError {
    LeftClosed(std::io::Error),
    RightClosed(std::io::Error),
    Other(std::io::Error),
}

impl std::fmt::Display for CopyBidirectionalError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CopyBidirectionalError::LeftClosed(e) => {
                write!(f, "left side closed with error: {e}")
            }
            CopyBidirectionalError::RightClosed(e) => {
                write!(f, "right side closed with error: {e}")
            }
            CopyBidirectionalError::Other(e) => {
                write!(f, "error: {e}")
            }
        }
    }
}

impl std::error::Error for CopyBidirectionalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CopyBidirectionalError::LeftClosed(e) => Some(e),
            CopyBidirectionalError::RightClosed(e) => Some(e),
            CopyBidirectionalError::Other(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for CopyBidirectionalError {
    fn from(e: std::io::Error) -> Self {
        CopyBidirectionalError::Other(e)
    }
}

pub const DEFAULT_BUF_SIZE: usize = 16 * 1024;
const COPY_IDLE_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug)]
pub struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    amt: u64,
    start_index: usize,
    cache_length: usize,
    buf: Box<[u8]>,
}

impl Default for CopyBuffer {
    fn default() -> Self {
        Self::new_with_capacity(DEFAULT_BUF_SIZE)
    }
}

impl CopyBuffer {
    #[allow(unused)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_capacity(size: usize) -> Self {
        let size = size.max(1024);
        let buf = clash_common::allocate_boxed_slice(size);
        Self {
            read_done: false,
            need_flush: false,
            amt: 0,
            start_index: 0,
            cache_length: 0,
            buf,
        }
    }

    pub fn amount_transferred(&self) -> u64 {
        self.amt
    }

    #[allow(unused)]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
        active: &mut bool,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        let capacity = self.buf.len();
        loop {
            let mut read_pending = false;
            let mut write_pending = false;

            // 1. Read as much as possible into the circular buffer.
            while !self.read_done && self.cache_length < capacity {
                let unused_start_index =
                    (self.start_index + self.cache_length) % capacity;
                let unused_end_index_exclusive =
                    if unused_start_index < self.start_index {
                        self.start_index
                    } else {
                        self.buf.len()
                    };

                let me = &mut *self;
                let mut buf = ReadBuf::new(
                    &mut me.buf[unused_start_index..unused_end_index_exclusive],
                );
                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(())) => {
                        let n = buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            self.cache_length += n;
                            *active = true;
                        }
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        read_pending = true;
                        break;
                    }
                }
            }

            // 2. Write out buffered data from the circular buffer.
            while self.cache_length > 0 {
                let used_start_index = self.start_index;
                let used_end_index_exclusive =
                    std::cmp::min(self.start_index + self.cache_length, capacity);

                let me = &mut *self;
                let head_length = me.cache_length
                    - (used_end_index_exclusive - used_start_index);
                let result = if head_length > 0 && writer.is_write_vectored() {
                    let slices = [
                        io::IoSlice::new(
                            &me.buf[used_start_index..used_end_index_exclusive],
                        ),
                        io::IoSlice::new(&me.buf[..head_length]),
                    ];
                    writer.as_mut().poll_write_vectored(cx, &slices)
                } else {
                    writer.as_mut().poll_write(
                        cx,
                        &me.buf[used_start_index..used_end_index_exclusive],
                    )
                };
                match result {
                    Poll::Ready(Ok(written)) => {
                        if written == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "write zero byte into writer",
                            )));
                        } else {
                            self.cache_length -= written;
                            if self.cache_length == 0 {
                                self.start_index = 0;
                            } else {
                                self.start_index =
                                    (self.start_index + written) % capacity;
                            }
                            self.amt += written as u64;
                            self.need_flush = true;
                            *active = true;
                        }
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        write_pending = true;
                        break;
                    }
                }
            }

            // Flush before waiting for I/O or finishing, allowing ready input
            // to batch writes without delaying request/response protocols.
            if self.need_flush && (read_pending || write_pending || self.read_done) {
                ready!(writer.as_mut().poll_flush(cx))?;
                self.need_flush = false;
            }

            // 4. If all data is written and EOF is reached, complete transfer.
            if self.read_done && self.cache_length == 0 {
                return Poll::Ready(Ok(self.amt));
            }

            // 5. If waiting for I/O, yield control to executor.
            if read_pending || write_pending {
                return Poll::Pending;
            }
        }
    }
}

#[cfg(feature = "allocation-tests")]
pub(crate) use buffered::layout as copy_state_layout;

/// Copies both directions, shutting down the opposing writer on EOF.
/// Successful writes refresh the remaining direction's half-close timeout.
#[cfg(any(test, feature = "allocation-tests"))]
pub fn copy_buf_bidirectional_with_timeout<'a, A, B>(
    a: &'a mut A, b: &'a mut B, size: usize,
    upload_timeout: Duration, download_timeout: Duration, tracker: TrafficTracker,
) -> impl Future<Output = Result<(u64, u64), CopyBidirectionalError>> + 'a
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    buffered::BufferedCopy::new(a, b, size, upload_timeout, download_timeout, tracker)
}

pub trait ReadExactBase {
    /// inner stream to be polled
    type I: AsyncRead + Unpin;
    /// prepare the inner stream, read buffer and read position
    fn decompose(&mut self) -> (&mut Self::I, &mut BytesMut, &mut usize);
}

pub trait ReadExt: ReadExactBase {
    fn poll_read_exact(
        &mut self,
        cx: &mut std::task::Context,
        size: usize,
    ) -> Poll<std::io::Result<()>>;
}

impl<T: ReadExactBase> ReadExt for T {
    fn poll_read_exact(
        &mut self,
        cx: &mut std::task::Context,
        size: usize,
    ) -> Poll<std::io::Result<()>> {
        let (raw, read_buf, read_pos) = self.decompose();
        if read_buf.len() < size {
            read_buf.resize(size, 0);
        }
        loop {
            if *read_pos < size {
                let mut buf = ReadBuf::new(&mut read_buf[*read_pos..size]);
                ready!(Pin::new(&mut *raw).poll_read(cx, &mut buf))?;
                let read = buf.filled().len();
                if read == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected eof",
                    )));
                }
                *read_pos += read;
            } else {
                assert!(*read_pos == size);
                *read_pos = 0;
                return Poll::Ready(Ok(()));
            }
        }
    }
}

pub trait ReadExactSlideBase {
    /// inner stream to be polled
    type I: AsyncRead + Unpin;
    /// prepare the inner stream and slide buffer
    fn decompose(&mut self) -> (&mut Self::I, &mut SlideBuffer);
}

pub trait ReadExactSlideExt: ReadExactSlideBase {
    fn poll_read_exact(
        &mut self,
        cx: &mut std::task::Context,
        size: usize,
    ) -> Poll<std::io::Result<()>>;
}

impl<T: ReadExactSlideBase> ReadExactSlideExt for T {
    fn poll_read_exact(
        &mut self,
        cx: &mut std::task::Context,
        size: usize,
    ) -> Poll<std::io::Result<()>> {
        let (raw, buf) = self.decompose();
        if buf.capacity() < size {
            buf.ensure_capacity(size);
        }
        loop {
            if buf.len() < size {
                let want = size - buf.len();
                if buf.remaining_capacity() < want {
                    buf.compact();
                }
                let mut read_buf = ReadBuf::new(&mut buf.write_slice()[..want]);
                ready!(Pin::new(&mut *raw).poll_read(cx, &mut read_buf))?;
                let read = read_buf.filled().len();
                if read == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected eof",
                    )));
                }
                buf.advance_write(read);
            } else {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

#[cfg(test)]
mod half_close_tests;
#[cfg(test)]
mod vectored_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_copy_buffer_initialization() {
        let small = CopyBuffer::new_with_capacity(4096);
        assert_eq!(small.capacity(), 4096);
        assert_eq!(small.amount_transferred(), 0);

        let default_buf = CopyBuffer::new();
        assert_eq!(default_buf.capacity(), DEFAULT_BUF_SIZE);

        let large = CopyBuffer::new_with_capacity(128 * 1024);
        assert_eq!(large.capacity(), 128 * 1024);
        assert_eq!(large.amount_transferred(), 0);
    }

    #[tokio::test]
    async fn test_copy_buffer_transfer() {
        let test_data = vec![0x42_u8; 64 * 1024];
        let mut reader = Cursor::new(test_data.clone());
        let mut writer = Vec::new();

        let mut copy_buf = CopyBuffer::new_with_capacity(16 * 1024);

        let res = futures::future::poll_fn(|cx| {
            copy_buf.poll_copy(
                cx,
                Pin::new(&mut reader),
                Pin::new(&mut writer),
                &mut false,
            )
        })
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 64 * 1024);
        assert_eq!(writer, test_data);
        assert_eq!(copy_buf.amount_transferred(), 64 * 1024);
    }

    #[tokio::test]
    async fn test_copy_buffer_wrap_around_multi_mb() {
        // Transfer 1MB of pseudo-random data through a small 8KB circular buffer
        let test_data: Vec<u8> =
            (0..(1024 * 1024)).map(|i| (i % 251) as u8).collect();
        let mut reader = Cursor::new(test_data.clone());
        let mut writer = Vec::new();

        let mut copy_buf = CopyBuffer::new_with_capacity(8 * 1024);

        let res = futures::future::poll_fn(|cx| {
            copy_buf.poll_copy(
                cx,
                Pin::new(&mut reader),
                Pin::new(&mut writer),
                &mut false,
            )
        })
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 1024 * 1024);
        assert_eq!(writer, test_data);
        assert_eq!(copy_buf.amount_transferred(), 1024 * 1024);
    }

    struct MockSlideStream<R> {
        reader: R,
        buf: SlideBuffer,
    }

    impl<R: AsyncRead + Unpin> ReadExactSlideBase for MockSlideStream<R> {
        type I = R;
        fn decompose(&mut self) -> (&mut Self::I, &mut SlideBuffer) {
            (&mut self.reader, &mut self.buf)
        }
    }

    #[tokio::test]
    async fn test_read_exact_slide() {
        let data = b"hello beautiful world";
        let mut stream = MockSlideStream {
            reader: Cursor::new(data.to_vec()),
            buf: SlideBuffer::new(8),
        };

        futures::future::poll_fn(|cx| stream.poll_read_exact(cx, 5))
            .await
            .unwrap();
        assert_eq!(stream.buf.as_slice(), b"hello");
        stream.buf.consume(5);

        futures::future::poll_fn(|cx| stream.poll_read_exact(cx, 10))
            .await
            .unwrap();
        assert_eq!(stream.buf.as_slice(), b" beautiful");
        stream.buf.consume(10);

        futures::future::poll_fn(|cx| stream.poll_read_exact(cx, 6))
            .await
            .unwrap();
        assert_eq!(stream.buf.as_slice(), b" world");
    }
}
