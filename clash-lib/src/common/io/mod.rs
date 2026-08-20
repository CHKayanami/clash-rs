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

const INITIAL_COPY_BUFFER_SIZE: usize = 8 * 1024;
const POOL_SHARDS: usize = 16;
const BUFFER_POOL_MAX_SIZE_PER_SHARD: usize = 16;

static BUFFER_POOLS: std::sync::LazyLock<[std::sync::Mutex<Vec<BytesMut>>; POOL_SHARDS]> =
    std::sync::LazyLock::new(|| std::array::from_fn(|_| std::sync::Mutex::new(Vec::new())));

thread_local! {
    static TLS_SHARD_HINT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[inline]
fn get_shard_index() -> usize {
    TLS_SHARD_HINT.with(|hint| {
        let idx = hint.get();
        hint.set((idx + 1) % POOL_SHARDS);
        idx
    })
}

/// Pooled buffer that returns to pool on drop instead of deallocating (shoes-style RAII).
#[derive(Debug)]
pub struct PooledBuffer {
    buffer: BytesMut,
    shard: usize,
}

impl PooledBuffer {
    /// Get a buffer from the pool or create a new one.
    pub fn with_capacity(cap: usize) -> Self {
        let shard = get_shard_index();
        if let Ok(mut pool) = BUFFER_POOLS[shard].lock() {
            if let Some(mut buffer) = pool.pop() {
                if buffer.capacity() < cap {
                    buffer.reserve(cap - buffer.capacity());
                }
                buffer.resize(cap, 0);
                return Self { buffer, shard };
            }
        }
        let mut buffer = BytesMut::with_capacity(cap);
        buffer.resize(cap, 0);
        Self { buffer, shard }
    }

    #[inline]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    #[inline]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl std::ops::Deref for PooledBuffer {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.buffer[..]
    }
}

impl std::ops::DerefMut for PooledBuffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer[..]
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Ok(mut pool) = BUFFER_POOLS[self.shard].lock() {
            if pool.len() < BUFFER_POOL_MAX_SIZE_PER_SHARD {
                let mut buffer = std::mem::replace(&mut self.buffer, BytesMut::new());
                buffer.clear();
                pool.push(buffer);
            }
        }
    }
}

#[derive(Debug)]
pub struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    target_cap: usize,
    buf: PooledBuffer,
}

impl CopyBuffer {
    #[allow(unused)]
    pub fn new() -> Self {
        Self {
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
            target_cap: 2 * 1024,
            buf: PooledBuffer::with_capacity(2 * 1024),
        }
    }

    pub fn new_with_capacity(target_cap: usize) -> Result<Self, std::io::Error> {
        let initial_size = target_cap.min(INITIAL_COPY_BUFFER_SIZE);
        Ok(Self {
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
            target_cap,
            buf: PooledBuffer::with_capacity(initial_size),
        })
    }

    pub fn amount_transferred(&self) -> u64 {
        self.amt
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
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                // If previous read filled the entire buffer, jump directly to target_cap in a single step
                if self.cap == self.buf.len() && self.buf.len() < self.target_cap {
                    self.buf = PooledBuffer::with_capacity(self.target_cap);
                }

                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf[..]);

                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(_)) => (),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        // Try flushing when the reader has no progress to avoid
                        // deadlock when the reader
                        // depends on buffered writer.
                        if self.need_flush {
                            ready!(writer.as_mut().poll_flush(cx))?;
                            self.need_flush = false;
                        }

                        return Poll::Pending;
                    }
                }

                let n = buf.filled().len();
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.pos = 0;
                    self.cap = n;
                    if let Some(last_active) = last_active.as_mut() {
                        **last_active = tokio::time::Instant::now();
                    }
                }
            }

            // If our buffer has some data, let's write it out!
            while self.pos < self.cap {
                let me = &mut *self;
                let i =
                    ready!(writer.as_mut().poll_write(cx, &me.buf[me.pos..me.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                    self.need_flush = true;
                    if let Some(last_active) = last_active.as_mut() {
                        **last_active = tokio::time::Instant::now();
                    }
                }
            }

            // If pos larger than cap, this loop will never stop.
            // In particular, user's wrong poll_write implementation returning
            // incorrect written length may lead to thread blocking.
            debug_assert!(
                self.pos <= self.cap,
                "writer returned length larger than input slice"
            );

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if self.pos == self.cap && self.read_done {
                ready!(writer.as_mut().poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_copy_buffer_initial_capacity() {
        let small = CopyBuffer::new_with_capacity(4096).unwrap();
        assert_eq!(small.buf.len(), 4096);
        assert_eq!(small.target_cap, 4096);

        let large = CopyBuffer::new_with_capacity(128 * 1024).unwrap();
        assert_eq!(large.buf.len(), INITIAL_COPY_BUFFER_SIZE);
        assert_eq!(large.target_cap, 128 * 1024);
    }

    #[tokio::test]
    async fn test_copy_buffer_adaptive_grow() {
        let test_data = vec![0x42_u8; 64 * 1024];
        let mut reader = Cursor::new(test_data.clone());
        let mut writer = Vec::new();

        let mut copy_buf = CopyBuffer::new_with_capacity(64 * 1024).unwrap();
        assert_eq!(copy_buf.buf.len(), 8192);

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
        // After transferring data larger than 8KB in full reads, buffer should have grown to target_cap
        assert_eq!(copy_buf.buf.len(), 64 * 1024);
        assert_eq!(copy_buf.amount_transferred(), 64 * 1024);
    }

    #[test]
    fn test_pooled_buffer_recycle() {
        let buf = PooledBuffer::with_capacity(32 * 1024);
        assert_eq!(buf.len(), 32 * 1024);
        assert!(buf.buffer.capacity() >= 32 * 1024);
        drop(buf);

        // Can acquire again seamlessly
        let buf2 = PooledBuffer::with_capacity(16 * 1024);
        assert_eq!(buf2.len(), 16 * 1024);
        drop(buf2);
    }
}
