//! Owned TCP forwarding with no references into the future's own fields.
use std::{future::Future, io, mem::replace, pin::Pin, task::{Context, Poll}, time::Duration};
use tokio::{net::TcpStream, time::{Sleep, sleep}};
use crate::proxy::{AnyStream, ProxyStream, dispatch_stream};
use super::{buffered::{self, CopyState}, CopyBidirectionalError, TrafficTracker};
#[cfg(all(target_os = "linux", feature = "zero_copy"))]
use super::splice;

type CopyResult = Result<(u64, u64), CopyBidirectionalError>;
/// Bounds the handshake step; when both endpoints wait, they share one budget.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

struct Settings {
    size: usize,
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
            )?));
        }
        #[cfg(not(all(target_os = "linux", feature = "zero_copy")))]
        let _ = (a, b);
        Ok(Self::Buffered(buffered::new(settings.size, settings.tracker)))
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
    Handshaking {
        settings: Settings,
        a_done: bool,
        timer: Option<Pin<Box<Sleep>>>,
    },
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
        Self {
            phase: Phase::Handshaking { settings, a_done: false, timer: None },
            a,
            b,
        }
    }
}

fn poll_handshake_side<S: ProxyStream + ?Sized>(
    stream: &mut S,
    timer: &mut Option<Pin<Box<Sleep>>>,
    cx: &mut Context<'_>,
    side: fn(io::Error) -> CopyBidirectionalError,
) -> Poll<Result<(), CopyBidirectionalError>> {
    match stream.poll_handshake(cx) {
        Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
        Poll::Ready(Err(error)) => Poll::Ready(Err(side(error))),
        Poll::Pending => {
            let timer = timer.get_or_insert_with(|| Box::pin(sleep(HANDSHAKE_TIMEOUT)));
            if timer.as_mut().poll(cx).is_ready() {
                Poll::Ready(Err(side(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stream handshake timed out",
                ))))
            } else {
                Poll::Pending
            }
        }
    }
}

impl<A: ProxyStream> Future for StreamCopy<A> {
    type Output = CopyResult;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Self { phase, a, b } = self.get_mut();
        loop {
            match phase {
                Phase::Handshaking { a_done, timer, .. } => {
                    if !*a_done {
                        match poll_handshake_side(
                            a, timer, cx, CopyBidirectionalError::LeftClosed,
                        ) {
                            Poll::Ready(Ok(())) => {}
                            Poll::Ready(Err(error)) => {
                                *phase = Phase::Done;
                                return Poll::Ready(Err(error));
                            }
                            Poll::Pending => return Poll::Pending,
                        }
                        *a_done = true;
                    }
                    let zero_copy_eligible = {
                        #[cfg(all(target_os = "linux", feature = "zero_copy"))]
                        { a.zero_copy_socket().is_some() && b.zero_copy_socket().is_some() }
                        #[cfg(not(all(target_os = "linux", feature = "zero_copy")))]
                        { false }
                    };
                    // Only existing cached data may defer the outbound header.
                    // Let normal bidirectional copying drive that first write,
                    // including backpressure, flush and traffic accounting.
                    let coalesce = b.needs_handshake() && a.has_read_prefix()
                        && !zero_copy_eligible;
                    if !coalesce {
                        match poll_handshake_side(
                            b, timer, cx, CopyBidirectionalError::RightClosed,
                        ) {
                            Poll::Ready(Ok(())) => {}
                            Poll::Ready(Err(error)) => {
                                *phase = Phase::Done;
                                return Poll::Ready(Err(error));
                            }
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let Phase::Handshaking { settings, .. } = replace(phase, Phase::Done)
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
    #[cfg(feature = "tun")]
    Tun(Pin<Box<dyn Future<Output = CopyResult> + Send>>),
}

impl Future for BidirectionalCopy {
    type Output = CopyResult;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Tcp(copy) => Pin::new(copy).poll(cx),
            Self::Other(copy) => Pin::new(copy).poll(cx),
            #[cfg(feature = "tun")]
            Self::Tun(copy) => copy.as_mut().poll(cx),
        }
    }
}

/// Own both endpoints and initialize resources only when first polled.
/// Plain TCP inputs keep their concrete copy loop; other inputs use AnyStream.
pub fn copy_bidirectional(
    a: AnyStream, b: AnyStream, size: usize, tracker: TrafficTracker,
) -> impl Future<Output = CopyResult> + Send {
    #[cfg(feature = "tun")]
    // Bypasses StreamCopy (and poll_handshake) because `b` is plain `AnyStream::Tcp`.
    // Re-add explicit handshake handling if non-TCP targets ever take this path.
    let (a, b) = match (a, b) {
        (a, AnyStream::Tcp(socket)) => match a.into_tun() {
            Ok((stream, prefix)) => {
                tracing::trace!("handing native TCP relay to TUN stack");
                let counter = Box::new(move |upload, download| {
                    tracker.push_upload(upload);
                    tracker.push_download(download);
                });
                return BidirectionalCopy::Tun(Box::pin(async move {
                    stream.forward(socket, prefix, counter)
                        .await.map_err(CopyBidirectionalError::Other)
                }));
            }
            Err(a) => (a, AnyStream::Tcp(socket)),
        },
        pair => pair,
    };
    let settings = Settings { size, tracker };
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
            stream(), stream(), 1024, TrafficTracker::noop(),
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
            stream(), stream(), 1024, TrafficTracker::noop(),
        ).await.unwrap();
        assert_eq!(counts, (0, 0));
        assert_eq!(shutdowns.load(Ordering::Relaxed), 2);
    }

    struct HandshakeGateStream {
        inner: tokio::io::DuplexStream,
        remaining_pending: usize,
        fail: bool,
        handshaked: Arc<AtomicUsize>,
    }

    impl AsyncRead for HandshakeGateStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            assert!(
                self.handshaked.load(Ordering::SeqCst) > 0,
                "poll_read called before handshake completed"
            );
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for HandshakeGateStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl ProxyStream for HandshakeGateStream {
        fn needs_handshake(&self) -> bool {
            self.handshaked.load(Ordering::SeqCst) == 0
        }

        fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.fail {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "handshake failed",
                )));
            }
            if self.remaining_pending > 0 {
                self.remaining_pending -= 1;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.handshaked.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn copy_bidirectional_completes_handshakes_before_reading() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

        let (a_client, mut a_peer) = duplex(64);
        let (b_client, mut b_peer) = duplex(64);
        let a_done = Arc::new(AtomicUsize::new(0));
        let b_done = Arc::new(AtomicUsize::new(0));

        let a = AnyStream::dynamic(HandshakeGateStream {
            inner: a_client,
            remaining_pending: 1,
            fail: false,
            handshaked: a_done.clone(),
        });
        let b = AnyStream::dynamic(HandshakeGateStream {
            inner: b_client,
            remaining_pending: 2,
            fail: false,
            handshaked: b_done.clone(),
        });

        let copy = tokio::spawn(copy_bidirectional(
            a,
            b,
            1024,
            TrafficTracker::noop(),
        ));

        // Server speaks first before client sends anything.
        b_peer.write_all(b"greeting").await.unwrap();
        b_peer.shutdown().await.unwrap();
        let mut got = Vec::new();
        a_peer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"greeting");
        a_peer.shutdown().await.unwrap();

        let (up, down) = copy.await.unwrap().unwrap();
        assert_eq!((up, down), (0, 8));
        assert_eq!(a_done.load(Ordering::SeqCst), 1);
        assert_eq!(b_done.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn copy_bidirectional_maps_handshake_errors_to_side() {
        use tokio::io::duplex;

        let (a_client, _a_peer) = duplex(64);
        let (b_client, _b_peer) = duplex(64);
        let left_err = copy_bidirectional(
            AnyStream::dynamic(HandshakeGateStream {
                inner: a_client,
                remaining_pending: 0,
                fail: true,
                handshaked: Arc::new(AtomicUsize::new(0)),
            }),
            AnyStream::dynamic(HandshakeGateStream {
                inner: b_client,
                remaining_pending: 0,
                fail: false,
                handshaked: Arc::new(AtomicUsize::new(0)),
            }),
            1024,
            TrafficTracker::noop(),
        )
        .await
        .unwrap_err();
        assert!(matches!(left_err, CopyBidirectionalError::LeftClosed(_)));

        let (a_client, _a_peer) = duplex(64);
        let (b_client, _b_peer) = duplex(64);
        let mut copy = tokio_test::task::spawn(copy_bidirectional(
            AnyStream::dynamic(HandshakeGateStream {
                inner: a_client,
                remaining_pending: 0,
                fail: false,
                handshaked: Arc::new(AtomicUsize::new(0)),
            }),
            AnyStream::dynamic(HandshakeGateStream {
                inner: b_client,
                remaining_pending: 0,
                fail: true,
                handshaked: Arc::new(AtomicUsize::new(0)),
            }),
            1024,
            TrafficTracker::noop(),
        ));
        let right_err = match copy.poll() {
            Poll::Ready(Err(err)) => err,
            other => panic!("expected right handshake error, got {other:?}"),
        };
        assert!(matches!(right_err, CopyBidirectionalError::RightClosed(_)));
    }

    struct StalledHandshakeStream {
        inner: tokio::io::DuplexStream,
        always_pending: bool,
    }

    impl AsyncRead for StalledHandshakeStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for StalledHandshakeStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl ProxyStream for StalledHandshakeStream {
        fn needs_handshake(&self) -> bool {
            self.always_pending
        }

        fn poll_handshake(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.always_pending {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn copy_bidirectional_times_out_stalled_handshake() {
        use tokio::{io::duplex, time::advance};

        for stall_left in [true, false] {
            let (a_client, _a_peer) = duplex(64);
            let (b_client, _b_peer) = duplex(64);
            let mut copy = tokio_test::task::spawn(copy_bidirectional(
                AnyStream::dynamic(StalledHandshakeStream {
                    inner: a_client,
                    always_pending: stall_left,
                }),
                AnyStream::dynamic(StalledHandshakeStream {
                    inner: b_client,
                    always_pending: !stall_left,
                }),
                1024,
                TrafficTracker::noop(),
            ));

            assert!(copy.poll().is_pending());
            advance(HANDSHAKE_TIMEOUT - Duration::from_millis(1)).await;
            assert!(!copy.is_woken());
            assert!(copy.poll().is_pending());

            advance(Duration::from_millis(1)).await;
            assert!(copy.is_woken());
            let err = match copy.poll() {
                Poll::Ready(Err(err)) => err,
                other => panic!("expected handshake timeout error, got {other:?}"),
            };
            match (stall_left, err) {
                (true, CopyBidirectionalError::LeftClosed(io_err))
                | (false, CopyBidirectionalError::RightClosed(io_err)) => {
                    assert_eq!(io_err.kind(), io::ErrorKind::TimedOut);
                }
                (_, other) => panic!("unexpected error variant: {other:?}"),
            }
        }
    }
    #[tokio::test(start_paused = true)]
    async fn handshake_sides_share_one_timeout_budget() {
        use tokio::{io::duplex, time::advance};

        let (a_client, _a_peer) = duplex(64);
        let (b_client, _b_peer) = duplex(64);
        let mut copy = tokio_test::task::spawn(copy_bidirectional(
            AnyStream::dynamic(HandshakeGateStream {
                inner: a_client,
                remaining_pending: 1,
                fail: false,
                handshaked: Arc::new(AtomicUsize::new(0)),
            }),
            AnyStream::dynamic(StalledHandshakeStream {
                inner: b_client,
                always_pending: true,
            }),
            1024,
            TrafficTracker::noop(),
        ));
        assert!(copy.poll().is_pending());
        advance(Duration::from_secs(9)).await;
        assert!(copy.poll().is_pending());
        advance(Duration::from_secs(1)).await;
        assert!(copy.is_woken());
        assert!(matches!(copy.poll(), Poll::Ready(Err(
            CopyBidirectionalError::RightClosed(error)
        )) if error.kind() == io::ErrorKind::TimedOut));
    }

}
