/// copy of https://github.com/eycorsican/leaf/blob/a77a1e497ae034f3a2a89c8628d5e7ebb2af47f0/leaf/src/common/io.rs
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
#[cfg(all(target_os = "linux", feature = "zero_copy"))]
pub use splice::zero_copy_bidirectional;

pub use clash_common::{PooledBuffer, SlideBuffer};

use crate::{app::dispatcher::TrackedStream, proxy::ClientStream};

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

#[derive(Debug)]
pub struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    amt: u64,
    start_index: usize,
    cache_length: usize,
    size: usize,
    buf: Box<[u8]>,
}

impl Default for CopyBuffer {
    fn default() -> Self {
        Self::new_with_capacity(DEFAULT_BUF_SIZE).unwrap()
    }
}

impl CopyBuffer {
    #[allow(unused)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_capacity(size: usize) -> Result<Self, std::io::Error> {
        let size = size.max(1024);
        let buf = clash_common::allocate_boxed_slice(size);
        Ok(Self {
            read_done: false,
            need_flush: false,
            amt: 0,
            start_index: 0,
            cache_length: 0,
            size,
            buf,
        })
    }

    pub fn amount_transferred(&self) -> u64 {
        self.amt
    }

    #[allow(unused)]
    pub fn capacity(&self) -> usize {
        self.size
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
        mut last_active: Option<&mut tokio::time::Instant>,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            let mut read_pending = false;
            let mut write_pending = false;

            // 1. Read as much as possible into the circular buffer.
            while !self.read_done && self.cache_length < self.size {
                let unused_start_index = (self.start_index + self.cache_length) % self.size;
                let unused_end_index_exclusive = if unused_start_index < self.start_index {
                    self.start_index
                } else {
                    self.size
                };

                let me = &mut *self;
                let mut buf =
                    ReadBuf::new(&mut me.buf[unused_start_index..unused_end_index_exclusive]);
                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(())) => {
                        let n = buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            self.cache_length += n;
                            if let Some(last_active) = last_active.as_mut() {
                                **last_active = tokio::time::Instant::now();
                            }
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
                    std::cmp::min(self.start_index + self.cache_length, self.size);

                let me = &mut *self;
                match writer
                    .as_mut()
                    .poll_write(cx, &me.buf[used_start_index..used_end_index_exclusive])
                {
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
                                self.start_index = (self.start_index + written) % self.size;
                            }
                            self.amt += written as u64;
                            self.need_flush = true;
                            if let Some(last_active) = last_active.as_mut() {
                                **last_active = tokio::time::Instant::now();
                            }
                        }
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        write_pending = true;
                        break;
                    }
                }
            }

            // 3. Flush if needed
            if self.need_flush {
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

enum TransferState {
    Running(CopyBuffer),
    ShuttingDown(u64),
    Done,
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_to_b: TransferState,
    b_to_a: TransferState,
    a_to_b_count: u64,
    b_to_a_count: u64,
    a_to_b_delay: Option<Pin<Box<tokio::time::Sleep>>>,
    b_to_a_delay: Option<Pin<Box<tokio::time::Sleep>>>,
    a_to_b_timeout_duration: Duration,
    b_to_a_timeout_duration: Duration,
    idle_timeout: Pin<Box<tokio::time::Sleep>>,
    idle_timeout_duration: Duration,
    last_active: tokio::time::Instant,
}

impl<A, B> Future for CopyBidirectional<'_, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = Result<(u64, u64), CopyBidirectionalError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Unpack self into mut refs to each field to avoid borrow check issues.
        let CopyBidirectional {
            a,
            b,
            a_to_b,
            b_to_a,
            a_to_b_count,
            b_to_a_count,
            a_to_b_delay,
            b_to_a_delay,
            a_to_b_timeout_duration,
            b_to_a_timeout_duration,
            idle_timeout,
            idle_timeout_duration,
            last_active,
        } = &mut *self;

        let mut a = Pin::new(a);
        let mut b = Pin::new(b);

        // Check idle timeout
        let deadline = *last_active + *idle_timeout_duration;
        if tokio::time::Instant::now() >= deadline {
            return Poll::Ready(Err(CopyBidirectionalError::Other(
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection idle timeout",
                ),
            )));
        }

        // Align sleep timer deadline with last active change to avoid frequency reset bugs
        if idle_timeout.deadline() != deadline {
            idle_timeout.as_mut().reset(deadline);
        }
        let _ = idle_timeout.as_mut().poll(cx);

        loop {
            match a_to_b {
                TransferState::Running(buf) => {
                    let res =
                        buf.poll_copy(cx, a.as_mut(), b.as_mut(), Some(last_active));
                    match res {
                        Poll::Ready(Ok(count)) => {
                            *a_to_b = TransferState::ShuttingDown(count);
                            continue;
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(
                                CopyBidirectionalError::LeftClosed(err),
                            ));
                        }
                        Poll::Pending => {
                            if let Some(delay) = a_to_b_delay {
                                match delay.as_mut().poll(cx) {
                                    Poll::Ready(()) => {
                                        *a_to_b = TransferState::ShuttingDown(
                                            buf.amount_transferred(),
                                        );
                                        continue;
                                    }
                                    Poll::Pending => (),
                                }
                            }
                        }
                    }
                }
                TransferState::ShuttingDown(count) => {
                    let res = b.as_mut().poll_shutdown(cx);
                    match res {
                        Poll::Ready(Ok(())) => {
                            *a_to_b_count += *count;
                            *a_to_b = TransferState::Done;
                            b_to_a_delay.replace(Box::pin(tokio::time::sleep(
                                *b_to_a_timeout_duration,
                            )));
                            continue;
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(
                                CopyBidirectionalError::LeftClosed(err),
                            ));
                        }
                        Poll::Pending => (),
                    }
                }
                TransferState::Done => (),
            }

            match b_to_a {
                TransferState::Running(buf) => {
                    let res =
                        buf.poll_copy(cx, b.as_mut(), a.as_mut(), Some(last_active));
                    match res {
                        Poll::Ready(Ok(count)) => {
                            *b_to_a = TransferState::ShuttingDown(count);
                            continue;
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(
                                CopyBidirectionalError::RightClosed(err),
                            ));
                        }
                        Poll::Pending => {
                            if let Some(delay) = b_to_a_delay {
                                match delay.as_mut().poll(cx) {
                                    Poll::Ready(()) => {
                                        *b_to_a = TransferState::ShuttingDown(
                                            buf.amount_transferred(),
                                        );
                                        continue;
                                    }
                                    Poll::Pending => (),
                                }
                            }
                        }
                    }
                }
                TransferState::ShuttingDown(count) => {
                    let res = a.as_mut().poll_shutdown(cx);
                    match res {
                        Poll::Ready(Ok(())) => {
                            *b_to_a_count += *count;
                            *b_to_a = TransferState::Done;
                            a_to_b_delay.replace(Box::pin(tokio::time::sleep(
                                *a_to_b_timeout_duration,
                            )));
                            continue;
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(
                                CopyBidirectionalError::RightClosed(err),
                            ));
                        }
                        Poll::Pending => (),
                    }
                }
                TransferState::Done => (),
            }

            match (&a_to_b, &b_to_a) {
                (TransferState::Done, TransferState::Done) => break,
                _ => return Poll::Pending,
            }
        }

        Poll::Ready(Ok((*a_to_b_count, *b_to_a_count)))
    }
}

pub async fn copy_bidirectional(
    mut a: Box<dyn ClientStream>,
    mut b: TrackedStream,
    size: usize,
    a_to_b_timeout_duration: Duration,
    b_to_a_timeout_duration: Duration,
) -> Result<(u64, u64), CopyBidirectionalError> {
    use tokio::io::AsyncWriteExt;

    // zero copy is only available on linux
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    let res = {
        // for zero copy, we need to track the download and upload amount with the
        // assistance of the tracker it's somehow ugly, but i could not
        // figure out a better way
        let (r_tracker, w_tracker) = b.trackers();
        let a_raw = a.underlying_socket();
        let b_raw = b.underlying_socket();
        match (a_raw, b_raw) {
            // zero copy is only available when both streams are raw TcpStream
            (Some(a), Some(b_stream)) => {
                tracing::trace!("using zero copy for bidirectional copy");
                zero_copy_bidirectional(
                    a,
                    b_stream,
                    r_tracker,
                    w_tracker,
                    a_to_b_timeout_duration,
                    b_to_a_timeout_duration,
                )
                .await
            }
            _ => {
                copy_buf_bidirectional_with_timeout(
                    &mut a,
                    &mut b,
                    size,
                    a_to_b_timeout_duration,
                    b_to_a_timeout_duration,
                )
                .await
            }
        }
    };
    #[cfg(not(all(target_os = "linux", feature = "zero_copy")))]
    let res = {
        copy_buf_bidirectional_with_timeout(
            &mut a,
            &mut b,
            size,
            a_to_b_timeout_duration,
            b_to_a_timeout_duration,
        )
        .await
    };

    let _ = a.shutdown().await;
    let _ = b.shutdown().await;

    res
}

pub async fn copy_buf_bidirectional_with_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    size: usize,
    a_to_b_timeout_duration: Duration,
    b_to_a_timeout_duration: Duration,
) -> Result<(u64, u64), CopyBidirectionalError>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let idle_timeout_duration = Duration::from_secs(180);
    CopyBidirectional {
        a,
        b,
        a_to_b: TransferState::Running(CopyBuffer::new_with_capacity(size)?),
        b_to_a: TransferState::Running(CopyBuffer::new_with_capacity(size)?),
        a_to_b_count: 0,
        b_to_a_count: 0,
        a_to_b_delay: None,
        b_to_a_delay: None,
        a_to_b_timeout_duration,
        b_to_a_timeout_duration,
        idle_timeout: Box::pin(tokio::time::sleep(idle_timeout_duration)),
        idle_timeout_duration,
        last_active: tokio::time::Instant::now(),
    }
    .await
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
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_copy_buffer_initialization() {
        let small = CopyBuffer::new_with_capacity(4096).unwrap();
        assert_eq!(small.capacity(), 4096);
        assert_eq!(small.amount_transferred(), 0);

        let default_buf = CopyBuffer::new();
        assert_eq!(default_buf.capacity(), DEFAULT_BUF_SIZE);

        let large = CopyBuffer::new_with_capacity(128 * 1024).unwrap();
        assert_eq!(large.capacity(), 128 * 1024);
        assert_eq!(large.amount_transferred(), 0);
    }

    #[tokio::test]
    async fn test_copy_buffer_transfer() {
        let test_data = vec![0x42_u8; 64 * 1024];
        let mut reader = Cursor::new(test_data.clone());
        let mut writer = Vec::new();

        let mut copy_buf = CopyBuffer::new_with_capacity(16 * 1024).unwrap();

        let res = futures::future::poll_fn(|cx| {
            copy_buf.poll_copy(
                cx,
                Pin::new(&mut reader),
                Pin::new(&mut writer),
                None,
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
        let test_data: Vec<u8> = (0..(1024 * 1024)).map(|i| (i % 251) as u8).collect();
        let mut reader = Cursor::new(test_data.clone());
        let mut writer = Vec::new();

        let mut copy_buf = CopyBuffer::new_with_capacity(8 * 1024).unwrap();

        let res = futures::future::poll_fn(|cx| {
            copy_buf.poll_copy(
                cx,
                Pin::new(&mut reader),
                Pin::new(&mut writer),
                None,
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
