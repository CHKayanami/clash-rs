//! Buffered I/O plugs into the shared copy and timeout state machine.
use std::{pin::Pin, task::{Context, Poll}, time::Duration};
#[cfg(any(test, feature = "allocation-tests"))]
use std::{future::Future, mem::replace};
use tokio::io::{AsyncRead, AsyncWrite};
use super::{CopyBuffer, CopyBidirectionalError, TrafficTracker};
use super::transfer::{Buffer, CopyState as TransferCopyState, Direction};
#[cfg(feature = "allocation-tests")]
use super::transfer::TransferState;

pub(super) type CopyState = TransferCopyState<CopyBuffer>;

pub(super) fn new(
    size: usize, upload_timeout: Duration, download_timeout: Duration, tracker: TrafficTracker,
) -> CopyState {
    CopyState::new(
        CopyBuffer::new_with_capacity(size), CopyBuffer::new_with_capacity(size),
        upload_timeout, download_timeout, tracker,
    )
}

impl<R, W> Buffer<R, W> for CopyBuffer
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    fn amount_transferred(&self) -> u64 { self.amount_transferred() }

    fn poll_copy(
        &mut self, cx: &mut Context<'_>, reader: &mut R, writer: &mut W,
        active: &mut bool, direction: Direction,
    ) -> Poll<Result<u64, CopyBidirectionalError>> {
        self.poll_copy(cx, Pin::new(reader), Pin::new(writer), active)
            .map_err(|error| direction.error(error))
    }
}

/// Initialization and running state share storage; construction does no I/O.
#[cfg(any(test, feature = "allocation-tests"))]
enum Phase {
    Initializing { size: usize, upload_timeout: Duration, download_timeout: Duration, tracker: TrafficTracker },
    Running(CopyState),
    Failed,
}

#[cfg(any(test, feature = "allocation-tests"))]
pub(super) struct BufferedCopy<'a, A: ?Sized, B: ?Sized> {
    phase: Phase,
    a: &'a mut A,
    b: &'a mut B,
}

#[cfg(any(test, feature = "allocation-tests"))]
impl<'a, A: ?Sized, B: ?Sized> BufferedCopy<'a, A, B> {
    pub(super) fn new(
        a: &'a mut A, b: &'a mut B, size: usize,
        upload_timeout: Duration, download_timeout: Duration, tracker: TrafficTracker,
    ) -> Self {
        Self { phase: Phase::Initializing { size, upload_timeout, download_timeout, tracker }, a, b }
    }
}

#[cfg(any(test, feature = "allocation-tests"))]
impl<A, B> Future for BufferedCopy<'_, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = Result<(u64, u64), CopyBidirectionalError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if matches!(this.phase, Phase::Initializing { .. }) {
            let Phase::Initializing { size, upload_timeout, download_timeout, tracker } =
                replace(&mut this.phase, Phase::Failed)
            else { unreachable!(); };
            this.phase = Phase::Running(new(size, upload_timeout, download_timeout, tracker));
        }
        match &mut this.phase {
            Phase::Running(state) => state.poll(this.a, this.b, cx),
            _ => panic!("buffered copy polled after initialization failed"),
        }
    }
}

#[cfg(feature = "allocation-tests")]
pub(crate) fn layout() -> [(&'static str, usize); 3] {
    [
        ("TCP copy buffer state", size_of::<CopyBuffer>()),
        ("TCP transfer state", size_of::<TransferState<CopyBuffer>>()),
        ("TCP bidirectional core state", size_of::<CopyState>()),
    ]
}
