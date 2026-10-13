//! Owned TCP forwarding with no references into the future's own fields.
use std::{future::Future, mem::replace, pin::Pin, task::{Context, Poll}, time::Duration};
use tokio::{io::AsyncWrite, net::TcpStream};
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
    ShutdownLeft(CopyResult),
    ShutdownRight(CopyResult),
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
                        Err(error) => Phase::ShutdownLeft(Err(error)),
                    };
                }
                Phase::Copying(mode) => match mode.poll(a, b, cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => *phase = Phase::ShutdownLeft(result),
                },
                Phase::ShutdownLeft(_) => {
                    if Pin::new(&mut *a).poll_shutdown(cx).is_pending() {
                        return Poll::Pending;
                    }
                    let Phase::ShutdownLeft(result) = replace(phase, Phase::Done)
                    else { unreachable!(); };
                    *phase = Phase::ShutdownRight(result);
                }
                Phase::ShutdownRight(_) => {
                    if Pin::new(&mut *b).poll_shutdown(cx).is_pending() {
                        return Poll::Pending;
                    }
                    let Phase::ShutdownRight(result) = replace(phase, Phase::Done)
                    else { unreachable!(); };
                    return Poll::Ready(result);
                }
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
