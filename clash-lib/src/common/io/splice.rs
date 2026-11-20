/// ref: https://github.com/Hanaasagi/tokio-splice & clash_lib/src/common/io/mod.rs
use std::{
    io::{self, Error, ErrorKind},
    os::unix::io::{AsRawFd, RawFd},
    pin::Pin,
    task::{Context, Poll, ready},
};

use libc;
#[cfg(test)]
use futures::future::poll_fn;
use tokio::io::{AsyncRead, AsyncWrite, Interest};

use tokio::net::{TcpStream, UnixStream};

use super::{CopyBidirectionalError, CopyBuffer as BufferedCopy, SlideBuffer, TrafficTracker};
#[cfg(test)]
use super::DEFAULT_BUF_SIZE;

use super::transfer::{Buffer, CopyState as TransferCopyState, Direction};

/// the size of PIPE_BUF
const PIPE_SIZE: usize = 65536;

type Result<T> = std::result::Result<T, CopyBidirectionalError>;

/// splice()  moves  data between two file descriptors without copying between
/// kernel address space and user address space. It transfers up to len bytes of
/// data from the file descriptor fd_in to the file descriptor fd_out, where one
/// of the  file  descriptors must refer to a pipe. The following semantics
/// apply for fd_in and off_in: •  If fd_in refers to a pipe, then off_in must
/// be NULL. •  If  fd_in does not refer to a pipe and off_in is NULL, then
/// bytes are read from fd_in starting from the file offset, and    the file
/// offset is adjusted appropriately. •  If fd_in does not refer to a pipe and
/// off_in is not NULL, then off_in must point to a buffer which specifies the
/// start‐    ing offset from which bytes will be read from fd_in; in this case,
/// the file offset of fd_in is not changed. The flags argument is a bit mask
/// that is composed by ORing together zero or more of the following values:
/// SPLICE_F_MOVE
///        Attempt  to move pages instead of copying.  This is only a hint to
/// the kernel: pages may still be copied if the ker‐        nel cannot move the
/// pages from the pipe, or if the pipe buffers don't refer to full pages.  The
/// initial  implementa‐        tion  of this flag was buggy: therefore starting
/// in Linux 2.6.21 it is a no-op (but is still permitted in a splice()
///        call); in the future, a correct implementation may be restored.
/// SPLICE_F_NONBLOCK
///        Do not block on I/O.  This makes the splice pipe operations
/// nonblocking, but splice() may nevertheless block because        the file
/// descriptors that are spliced to/from may block (unless they have the
/// O_NONBLOCK flag set). SPLICE_F_MORE
///        More  data  will  be  coming in a subsequent splice.  This is a
/// helpful hint when the fd_out refers to a socket (see        also the
/// description of MSG_MORE in send(2), and the description of TCP_CORK in
/// tcp(7)). SPLICE_F_GIFT
///        Unused for splice(); see vmsplice(2).
#[inline]
fn splice(fd_in: RawFd, fd_out: RawFd, size: usize) -> isize {
    unsafe {
        libc::splice(
            fd_in,
            std::ptr::null_mut::<libc::loff_t>(),
            fd_out,
            std::ptr::null_mut::<libc::loff_t>(),
            size,
            // NOTE: https://stackoverflow.com/questions/7463689/most-efficient-way-to-copy-a-file-in-linux/7464280#7464280
            // Both the man page for splice and the comments in the kernel source
            // say that the SPLICE_F_MOVE flag should provide this functionality.
            // Unfortunately, the support for SPLICE_F_MOVE was yanked in 2.6.21
            // (back in 2007) and never replaced. If you search the
            // kernel sources, you will find SPLICE_F_MOVE is not actually
            // referenced anywhere. The bottom line is that splice from
            // one file to another calls memcpy to move the data; it is not
            // zero-copy. libc::SPLICE_F_MORE | libc::SPLICE_F_NONBLOCK,
            // // | libc::SPLICE_F_MOVE,
            libc::SPLICE_F_NONBLOCK,
        )
    }
}

/// Linux Pipe
#[repr(C)]
struct Pipe(RawFd, RawFd);

impl Pipe {
    /// Create a pipe
    fn new() -> io::Result<Self> {
        let mut pipe = std::mem::MaybeUninit::<[libc::c_int; 2]>::uninit();
        unsafe {
            // pipe() creates a pipe, a unidirectional data channel that can be used
            // for interprocess communication. The array pipefd is used
            // to return two file descriptors referring to the ends of the pipe.
            // pipefd[0] refers to the read end of the pipe.
            // pipefd[1] refers to the write end of the pipe.
            // Data written to the write end of the pipe is buffered by the kernel
            // until it is read from the read end of the pipe.  For
            // further details, see pipe(7).
            //
            // O_DIRECT (since Linux 3.4)
            //    Create a pipe that performs I/O in "packet" mode.  Each write(2) to
            // the pipe is dealt with as a separate packet, and
            //    read(2)s from the pipe will read one packet at a time.  Note the
            // following points:    •  Writes  of  greater than PIPE_BUF
            // bytes (see pipe(7)) will be split into multiple packets.  The constant
            // PIPE_BUF       is defined in <limits.h>.
            //    •  If a read(2) specifies a buffer size that is smaller than the
            // next packet, then the requested number of bytes are
            //       read,  and the excess bytes in the packet are discarded.
            // Specifying a buffer size of PIPE_BUF will be sufficient
            //       to read the largest possible packets (see the previous point).
            //    •  Zero-length packets are not supported.  (A read(2) that
            // specifies a buffer size of zero is a no-op,  and  returns
            //         0.)
            if libc::pipe2(
                pipe.as_mut_ptr() as *mut libc::c_int,
                // libc::O_DIRECT |libc::O_CLOEXEC | libc::O_NONBLOCK,
                libc::O_CLOEXEC | libc::O_NONBLOCK,
            ) < 0
            {
                return Err(Error::last_os_error());
            }
            let [r_fd, w_fd] = pipe.assume_init();
            libc::fcntl(w_fd, libc::F_SETPIPE_SZ, PIPE_SIZE);
            Ok(Pipe(r_fd, w_fd))
        }
    }

    #[inline]
    fn read_fd(&self) -> RawFd {
        self.0
    }

    #[inline]
    fn write_fd(&self) -> RawFd {
        self.1
    }

    fn read_pending(&mut self, mut pending: &mut [u8]) -> io::Result<()> {
        while !pending.is_empty() {
            // The slice is valid for writes, and this direction exclusively owns
            // the pipe. Its tracked pending length bounds the read.
            let n = unsafe {
                libc::read(self.read_fd(), pending.as_mut_ptr().cast(), pending.len())
            };
            if n > 0 {
                pending = &mut pending[n as usize..];
            } else if n == 0 {
                return Err(Error::new(ErrorKind::UnexpectedEof, "splice pipe ended early"));
            } else {
                let error = Error::last_os_error();
                if error.kind() != ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
            libc::close(self.1);
        }
    }
}

pub(super) enum CopyBuffer {
    Splice(SpliceBuffer),
    Buffered { buffer: BufferedCopy, already_written: u64 },
}

enum SpliceOutcome {
    Complete(u64),
    Buffered,
}

fn splice_unavailable(error: &Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS))
}

pub(super) struct SpliceBuffer {
    read_done: bool,
    read_from_socket: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Pipe,
    prefix: Option<SlideBuffer>,
    buffer_size: usize,
}

impl SpliceBuffer {
    fn new(buf: Pipe, prefix: Option<SlideBuffer>, buffer_size: usize) -> Self {
        Self {
            read_done: false,
            read_from_socket: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf,
            prefix: prefix.filter(|prefix| !prefix.is_empty()),
            buffer_size,
        }
    }

    fn poll_fill_buf<R: Stream + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        stream: &mut R,
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(stream.poll_read_ready_n(cx))?;

            let res: std::result::Result<_, std::io::Error> =
                stream.try_io_n(Interest::READABLE, || {
                    match splice(
                        stream.as_raw_fd(),
                        self.buf.write_fd(),
                        isize::MAX as usize,
                    ) {
                        size if size >= 0 => Ok(size as usize),
                        _ => {
                            let err = Error::last_os_error();
                            match err.raw_os_error() {
                                Some(e)
                                    if e == libc::EWOULDBLOCK
                                        || e == libc::EAGAIN =>
                                {
                                    Err(ErrorKind::WouldBlock.into())
                                }
                                _ => Err(err),
                            }
                        }
                    }
                });

            match res {
                Ok(size) => return Poll::Ready(Ok(size)),
                Err(e) => {
                    if e.kind() == ErrorKind::WouldBlock {
                        continue;
                    }

                    return Poll::Ready(Err(e));
                }
            }
        }
    }

    fn poll_write_buf<W: Stream + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        stream: &mut W,
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(stream.poll_write_ready_n(cx)?);

            let res = stream.try_io_n(Interest::WRITABLE, || {
                match splice(
                    self.buf.read_fd(),
                    stream.as_raw_fd(),
                    self.cap - self.pos,
                ) {
                    size if size >= 0 => Ok(size as usize),
                    _ => {
                        let err = Error::last_os_error();
                        match err.raw_os_error() {
                            Some(e)
                                if e == libc::EWOULDBLOCK || e == libc::EAGAIN =>
                            {
                                Err(ErrorKind::WouldBlock.into())
                            }
                            _ => Err(err),
                        }
                    }
                }
            });

            match res {
                Ok(size) => return Poll::Ready(Ok(size)),
                Err(e) => {
                    if e.kind() == ErrorKind::WouldBlock {
                        continue;
                    }

                    return Poll::Ready(Err(e));
                }
            }
        }
    }

    fn poll_flush_buf<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        stream: &mut W,
    ) -> Poll<Result<()>> {
        Pin::new(stream).poll_flush(cx).map_err(|e| e.into())
    }

    fn recover_buffer(&mut self) -> io::Result<BufferedCopy> {
        let pending = self.cap - self.pos;
        let mut buffer = BufferedCopy::new_with_capacity(self.buffer_size.max(pending));
        self.buf.read_pending(&mut buffer.buf[..pending])?;
        buffer.cache_length = pending;
        buffer.need_flush = self.need_flush;
        Ok(buffer)
    }
}

impl SpliceBuffer {
    fn poll_copy<R: Stream + Unpin, W: Stream + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        r: &mut R,
        w: &mut W,
        active: &mut bool,
    ) -> Poll<Result<SpliceOutcome>> {
        while let Some(prefix) = self.prefix.as_mut() {
            let size = ready!(Pin::new(&mut *w).poll_write(cx, prefix.as_slice()))?;
            if size == 0 {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::WriteZero,
                    "write zero byte while forwarding prefix",
                )
                .into()));
            }
            prefix.consume(size);
            self.amt += size as u64;
            self.need_flush = true;
            *active = true;
            if prefix.is_empty() {
                self.prefix = None;
            }
        }
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                self.pos = 0;
                self.cap = 0;

                match self.poll_fill_buf(cx, r) {
                    Poll::Ready(Ok(size)) => {
                        self.cap = size;
                        self.read_done = size == 0;
                        self.read_from_socket |= size > 0;
                        *active = true;
                    }
                    Poll::Ready(Err(error)) => {
                        if !self.read_from_socket && splice_unavailable(&error) {
                            tracing::debug!(%error, "splice read unavailable, using buffered copy");
                            return Poll::Ready(Ok(SpliceOutcome::Buffered));
                        }
                        return Poll::Ready(Err(error.into()));
                    }
                    Poll::Pending => {
                        // Try flushing when the reader has no progress to avoid
                        // deadlock when the reader depends
                        // on buffered writer.
                        if self.need_flush {
                            ready!(self.poll_flush_buf(cx, w))?;
                            self.need_flush = false;
                        }

                        return Poll::Pending;
                    }
                };
            }

            while self.pos < self.cap {
                let size = match ready!(self.poll_write_buf(cx, w)) {
                    Ok(size) => size,
                    Err(error) if splice_unavailable(&error) => {
                        tracing::debug!(%error, "splice write unavailable, using buffered copy");
                        return Poll::Ready(Ok(SpliceOutcome::Buffered));
                    }
                    Err(error) => return Poll::Ready(Err(error.into())),
                };

                if size == 0 {
                    return Poll::Ready(Err(CopyBidirectionalError::Other(
                        Error::new(
                            ErrorKind::WriteZero,
                            "write zero byte into writer",
                        ),
                    )));
                } else {
                    self.pos += size;
                    self.amt += size as u64;
                    self.need_flush = true;
                    *active = true;
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
                ready!(self.poll_flush_buf(cx, w))?;
                return Poll::Ready(Ok(SpliceOutcome::Complete(self.amt)));
            }
        }
    }
}

/// `AsyncRead` + `AsyncWrite` + `AsRawFd` Wrapper for stream.
/// This trait is auto implemented for `TcpStream` and `UnixStream`.
pub trait Stream: AsyncRead + AsyncWrite + AsRawFd {
    fn poll_read_ready_n(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
    fn poll_write_ready_n(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
    fn try_io_n<R>(
        &self,
        interest: Interest,
        f: impl FnOnce() -> std::result::Result<R, std::io::Error>,
    ) -> std::result::Result<R, std::io::Error>;
}

/// Copies data in both directions between `a` and `b`.
///
/// This function returns a future that will read from both streams,
/// writing any data read to the opposing stream.
/// This happens in both directions concurrently.
#[cfg(test)]
pub(super) async fn zero_copy_bidirectional<A: Stream + Unpin, B: Stream + Unpin>(
    a: &mut A, b: &mut B, tracker: TrafficTracker,
) -> Result<(u64, u64)> {
    let mut state = Pipes::new()?.into_copy(None, None, DEFAULT_BUF_SIZE, tracker);
    poll_fn(|cx| state.poll(a, b, cx)).await
}

macro_rules! impl_stream_for {
    ($stream:ident) => {
        impl Stream for $stream {
            #[inline]
            fn poll_read_ready_n(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.poll_read_ready(cx)
            }

            #[inline]
            fn poll_write_ready_n(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.poll_write_ready(cx)
            }

            #[inline]
            fn try_io_n<R>(
                &self,
                interest: Interest,
                f: impl FnOnce() -> std::result::Result<R, std::io::Error>,
            ) -> std::result::Result<R, std::io::Error> {
                self.try_io(interest, f)
            }
        }
    };
}

impl_stream_for!(TcpStream);
impl_stream_for!(UnixStream);

pub(super) type CopyState = TransferCopyState<CopyBuffer>;

pub(super) struct Pipes(Pipe, Pipe);

impl Pipes {
    pub(super) fn new() -> io::Result<Self> {
        Ok(Self(Pipe::new()?, Pipe::new()?))
    }

    pub(super) fn into_copy(
        self, upload_prefix: Option<SlideBuffer>, download_prefix: Option<SlideBuffer>,
        size: usize, tracker: TrafficTracker,
    ) -> CopyState {
        CopyState::new(
            CopyBuffer::Splice(SpliceBuffer::new(self.0, upload_prefix, size)),
            CopyBuffer::Splice(SpliceBuffer::new(self.1, download_prefix, size)),
            tracker,
        )
    }
}

impl<R: Stream + Unpin, W: Stream + Unpin> Buffer<R, W> for CopyBuffer {
    fn amount_transferred(&self) -> u64 {
        match self {
            Self::Splice(buffer) => buffer.amt,
            Self::Buffered { buffer, already_written } => {
                already_written + buffer.amount_transferred()
            }
        }
    }

    fn poll_copy(
        &mut self, cx: &mut Context<'_>, reader: &mut R, writer: &mut W,
        active: &mut bool, direction: Direction,
    ) -> Poll<Result<u64>> {
        loop {
            match self {
                Self::Splice(buffer) => match ready!(buffer.poll_copy(cx, reader, writer, active))? {
                    SpliceOutcome::Complete(count) => return Poll::Ready(Ok(count)),
                    SpliceOutcome::Buffered => {
                        // Preserve pending pipe bytes and the count of writes already accepted.
                        *self = Self::Buffered {
                            buffer: buffer.recover_buffer()?,
                            already_written: buffer.amt,
                        };
                    }
                },
                Self::Buffered { buffer, already_written } => {
                    let count = ready!(Buffer::poll_copy(
                        buffer, cx, reader, writer, active, direction,
                    ))?;
                    return Poll::Ready(Ok(*already_written + count));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
    use tokio::time::timeout;

    use super::*;

    struct TestSocket {
        socket: UnixStream,
        unsupported: Option<(Interest, i32)>,
        rejected: Cell<bool>,
        flushed: bool,
    }

    impl TestSocket {
        fn new(socket: UnixStream, unsupported: Option<(Interest, i32)>) -> Self {
            Self { socket, unsupported, rejected: Cell::new(false), flushed: false }
        }
    }

    impl AsRawFd for TestSocket {
        fn as_raw_fd(&self) -> RawFd { self.socket.as_raw_fd() }
    }

    impl AsyncRead for TestSocket {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>)
            -> Poll<io::Result<()>>
        { Pin::new(&mut self.socket).poll_read(cx, buf) }
    }

    impl AsyncWrite for TestSocket {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8])
            -> Poll<io::Result<usize>>
        { Pin::new(&mut self.socket).poll_write(cx, buf) }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushed = true;
            Pin::new(&mut self.socket).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.socket).poll_shutdown(cx)
        }
    }

    impl Stream for TestSocket {
        fn poll_read_ready_n(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.socket.poll_read_ready_n(cx)
        }

        fn poll_write_ready_n(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.socket.poll_write_ready_n(cx)
        }

        fn try_io_n<R>(&self, interest: Interest, f: impl FnOnce() -> io::Result<R>)
            -> io::Result<R>
        {
            if let Some((unsupported, errno)) = self.unsupported
                && interest == unsupported
            {
                self.rejected.set(true);
                return Err(Error::from_raw_os_error(errno));
            }
            self.socket.try_io_n(interest, f)
        }
    }

    #[tokio::test]
    async fn unsupported_source_splice_falls_back_after_prefix() {
        check_splice_fallback(Interest::READABLE, libc::EINVAL, b"upload").await;
    }

    #[tokio::test]
    async fn unsupported_destination_splice_recovers_pending_pipe_bytes() {
        let payload: Vec<_> = (0..8_192).map(|offset| (offset % 251) as u8).collect();
        check_splice_fallback(Interest::WRITABLE, libc::EINVAL, &payload).await;
    }

    #[tokio::test]
    async fn splice_fallback_flushes_prefix_without_socket_data() {
        check_splice_fallback(Interest::READABLE, libc::ENOSYS, b"").await;
    }

    async fn check_splice_fallback(interest: Interest, errno: i32, payload: &[u8]) {
        let (mut client, source) = UnixStream::pair().unwrap();
        let (target, mut server) = UnixStream::pair().unwrap();
        let mut source = TestSocket::new(
            source, (interest == Interest::READABLE).then_some((interest, errno)),
        );
        let mut target = TestSocket::new(
            target, (interest == Interest::WRITABLE).then_some((interest, errno)),
        );
        let mut prefix = SlideBuffer::new(6);
        prefix.extend_from_slice(b"prefix");
        let mut copy = Pipes::new().unwrap().into_copy(
            Some(prefix), None, 1024, TrafficTracker::noop(),
        );

        client.write_all(payload).await.unwrap();
        client.shutdown().await.unwrap();
        // Reach the injected read failure before splice can flush while waiting.
        source.socket.readable().await.unwrap();
        server.write_all(b"reply").await.unwrap();
        server.shutdown().await.unwrap();
        let relay = poll_fn(|cx| copy.poll(&mut source, &mut target, cx));
        let receive = async {
            let mut upload = Vec::new();
            server.read_to_end(&mut upload).await.unwrap();
            assert_eq!(upload.strip_prefix(b"prefix"), Some(payload));
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"reply");
        };
        let (counts, ()) = timeout(Duration::from_secs(3), async {
            tokio::join!(relay, receive)
        }).await.unwrap();
        assert_eq!(counts.unwrap(), ((6 + payload.len()) as u64, 5));
        assert!(source.rejected.get() || target.rejected.get());
        assert!(target.flushed);
    }
}
