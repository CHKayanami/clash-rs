//! Owned TCP forwarding with no references into the future's own fields.
use std::{future::Future, mem::replace, pin::Pin, task::{Context, Poll}, time::Duration};
use tokio::net::TcpStream;
use crate::proxy::{AnyStream, ProxyStream, dispatch_stream};
use super::{buffered::{self, CopyState}, CopyBidirectionalError, TrafficTracker};
#[cfg(all(target_os = "linux", feature = "zero_copy"))]
use super::splice;

type CopyResult = Result<(u64, u64), CopyBidirectionalError>;

struct Settings {
    size: usize,
    upload_timeout: Duration,
    download_timeout: Duration,
    tracker: TrafficTracker,
}

enum Mode {
    Buffered(CopyState),
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    Splice(splice::CopyState),
}

impl Mode {
    fn initialize<A: ProxyStream>(a: &mut A, b: &mut AnyStream, settings: Settings)
        -> Result<Self, CopyBidirectionalError>
    {
        #[cfg(all(target_os = "linux", feature = "zero_copy"))]
        if a.zero_copy_socket().is_some() && b.zero_copy_socket().is_some() {
            let upload_prefix = a.take_read_prefix();
            let download_prefix = b.take_read_prefix();
            tracing::trace!("using zero copy for bidirectional copy");
            return Ok(Self::Splice(splice::new(
                upload_prefix, download_prefix, settings.tracker,
                settings.upload_timeout, settings.download_timeout,
            )?));
        }
        #[cfg(not(all(target_os = "linux", feature = "zero_copy")))]
        let _ = (a, b);
        Ok(Self::Buffered(buffered::new(
            settings.size, settings.upload_timeout, settings.download_timeout, settings.tracker,
        )))
    }

    fn poll<A: ProxyStream>(&mut self, a: &mut A, b: &mut AnyStream, cx: &mut Context<'_>)
        -> Poll<CopyResult>
    {
        match self {
            // Match once per poll; the inner copy loop retains concrete I/O.
            Self::Buffered(state) => dispatch_stream!(b, |stream| state.poll(a, stream, cx)),
            #[cfg(all(target_os = "linux", feature = "zero_copy"))]
            Self::Splice(state) => {
                // The owners retain the sockets throughout forwarding. Splice
                // state owns only pipes/prefixes, never socket references or FDs.
                let a = a.zero_copy_socket().expect("selected zero-copy input");
                let b = b.zero_copy_socket().expect("selected zero-copy output");
                state.poll(a, b, cx)
            }
        }
    }
}

enum Phase {
    Initializing(Settings),
    Copying(Mode),
    Done,
}

struct StreamCopy<A> {
    // Drop buffers, timers and pipes before dropping the stream owners.
    phase: Phase,
    a: A,
    b: AnyStream,
}

impl<A> StreamCopy<A> {
    fn new(a: A, b: AnyStream, settings: Settings) -> Self {
        Self { phase: Phase::Initializing(settings), a, b }
    }
}

impl<A: ProxyStream> Future for StreamCopy<A> {
    type Output = CopyResult;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Self { phase, a, b } = self.get_mut();
        loop {
            match phase {
                Phase::Initializing(_) => {
                    let Phase::Initializing(settings) = replace(phase, Phase::Done)
                    else { unreachable!(); };
                    *phase = match Mode::initialize(a, b, settings) {
                        Ok(mode) => Phase::Copying(mode),
                        Err(error) => return Poll::Ready(Err(error)),
                    };
                }
                Phase::Copying(mode) => match mode.poll(a, b, cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => {
                        // Successful transfers already shut down both writers.
                        // Errors must release owners without waiting for another
                        // protocol shutdown outside the copy timeout machinery.
                        *phase = Phase::Done;
                        return Poll::Ready(result);
                    }
                },
                Phase::Done => panic!("TCP copy polled after completion"),
            }
        }
    }
}

enum BidirectionalCopy {
    Tcp(StreamCopy<TcpStream>),
    Other(StreamCopy<AnyStream>),
}

impl Future for BidirectionalCopy {
    type Output = CopyResult;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Tcp(copy) => Pin::new(copy).poll(cx),
            Self::Other(copy) => Pin::new(copy).poll(cx),
        }
    }
}

/// Own both endpoints and initialize resources only when first polled.
/// Plain TCP inputs keep their concrete copy loop; other inputs use AnyStream.
pub fn copy_bidirectional(
    a: AnyStream, b: AnyStream, size: usize,
    upload_timeout: Duration, download_timeout: Duration, tracker: TrafficTracker,
) -> impl Future<Output = CopyResult> + Send {
    let settings = Settings { size, upload_timeout, download_timeout, tracker };
    match a {
        AnyStream::Tcp(stream) => BidirectionalCopy::Tcp(StreamCopy::new(stream, b, settings)),
        stream => BidirectionalCopy::Other(StreamCopy::new(stream, b, settings)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io, sync::{Arc, atomic::{AtomicUsize, Ordering}}};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct TestStream {
        shutdowns: Arc<AtomicUsize>,
        fail: bool,
    }

    impl AsyncRead for TestStream {
        fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>)
            -> Poll<io::Result<()>>
        {
            if self.fail {
                Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8])
            -> Poll<io::Result<usize>>
        { Poll::Pending }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>>
        { Poll::Pending }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdowns.fetch_add(1, Ordering::Relaxed);
            if self.fail { Poll::Pending } else { Poll::Ready(Ok(())) }
        }
    }

    impl ProxyStream for TestStream {}

    #[tokio::test]
    async fn copy_error_does_not_wait_for_protocol_shutdown() {
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let stream = || AnyStream::Dynamic(Box::new(TestStream {
            shutdowns: shutdowns.clone(), fail: true,
        }));
        let mut task = tokio_test::task::spawn(copy_bidirectional(
            stream(), stream(), 1024, Duration::from_secs(10),
            Duration::from_secs(10), TrafficTracker::noop(),
        ));
        assert!(matches!(
            task.poll(), Poll::Ready(Err(CopyBidirectionalError::LeftClosed(_)))
        ));
        assert_eq!(shutdowns.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn successful_copy_shuts_down_each_writer_once() {
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let stream = || AnyStream::Dynamic(Box::new(TestStream {
            shutdowns: shutdowns.clone(), fail: false,
        }));
        let counts = copy_bidirectional(
            stream(), stream(), 1024, Duration::from_secs(10),
            Duration::from_secs(10), TrafficTracker::noop(),
        ).await.unwrap();
        assert_eq!(counts, (0, 0));
        assert_eq!(shutdowns.load(Ordering::Relaxed), 2);
    }
}
