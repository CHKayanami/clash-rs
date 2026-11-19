//! Shared direction state, accounting and shutdown for buffered and splice I/O.
use std::{io::{Error, ErrorKind}, pin::Pin, task::{Context, Poll}, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use super::{CopyBidirectionalError, TrafficTracker, timeout::CopyTimeouts};

#[derive(Clone, Copy)]
pub(super) enum Direction {
    Upload,
    Download,
}

impl Direction {
    pub(super) fn error(self, error: Error) -> CopyBidirectionalError {
        match self {
            Self::Upload => CopyBidirectionalError::LeftClosed(error),
            Self::Download => CopyBidirectionalError::RightClosed(error),
        }
    }

    fn track(self, tracker: &TrafficTracker, written: usize) {
        match self {
            Self::Upload => tracker.push_upload(written),
            Self::Download => tracker.push_download(written),
        }
    }

    fn opposite(self) -> Self {
        match self {
            Self::Upload => Self::Download,
            Self::Download => Self::Upload,
        }
    }
}

pub(super) trait Buffer<R: ?Sized, W: ?Sized> {
    fn amount_transferred(&self) -> u64;
    fn poll_copy(
        &mut self, cx: &mut Context<'_>, reader: &mut R, writer: &mut W,
        active: &mut bool, direction: Direction,
    ) -> Poll<Result<u64, CopyBidirectionalError>>;
}

pub(super) enum TransferState<C> {
    Running(C),
    ShuttingDown(u64),
    Done(u64),
}

struct DirectionContext<'a> {
    timeouts: &'a mut CopyTimeouts,
    tracker: &'a TrafficTracker,
    direction: Direction,
}

impl<C> TransferState<C> {
    fn poll<R, W>(
        &mut self, reader: &mut R, writer: &mut W, cx: &mut Context<'_>,
        context: DirectionContext<'_>, opposite: &Self,
    ) -> Result<bool, CopyBidirectionalError>
    where
        C: Buffer<R, W>,
        R: ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    {
        let DirectionContext { timeouts, tracker, direction } = context;
        loop {
            match self {
                Self::Running(buffer) => {
                    let before = buffer.amount_transferred();
                    let mut active = false;
                    let result = buffer.poll_copy(cx, reader, writer, &mut active, direction);
                    timeouts.record_activity(active);
                    let written = buffer.amount_transferred() - before;
                    // Account successful writes even if a later I/O operation
                    // in the same poll fails. Reads never refresh half-close.
                    if written > 0 {
                        direction.track(tracker, written as usize);
                        timeouts.wrote(direction);
                    }
                    let count = match result {
                        Poll::Ready(Ok(count)) => count,
                        Poll::Ready(Err(error)) => return Err(error),
                        Poll::Pending if timeouts.half_close_expired() => {
                            buffer.amount_transferred()
                        }
                        Poll::Pending => return Ok(false),
                    };
                    *self = Self::ShuttingDown(count);
                    timeouts.stop_half_close();
                }
                Self::ShuttingDown(count) => {
                    match Pin::new(&mut *writer).poll_shutdown(cx) {
                        Poll::Ready(Ok(())) => {
                            *self = Self::Done(*count);
                            if matches!(opposite, Self::Running(_)) {
                                timeouts.start_half_close(direction.opposite());
                                return Ok(true);
                            }
                            return Ok(false);
                        }
                        Poll::Ready(Err(error)) => return Err(direction.error(error)),
                        Poll::Pending => return Ok(false),
                    }
                }
                Self::Done(_) => return Ok(false),
            }
        }
    }
}

pub(super) struct CopyState<C> {
    upload: TransferState<C>,
    download: TransferState<C>,
    timeouts: CopyTimeouts,
    tracker: TrafficTracker,
    download_first: bool,
}

impl<C> CopyState<C> {
    pub(super) fn new(
        upload: C, download: C, upload_timeout: Duration,
        download_timeout: Duration, tracker: TrafficTracker,
    ) -> Self {
        Self {
            upload: TransferState::Running(upload),
            download: TransferState::Running(download),
            timeouts: CopyTimeouts::new(upload_timeout, download_timeout),
            tracker,
            download_first: false,
        }
    }

    /// Returns `true` if this poll started the opposite direction's half-close timer.
    fn poll_direction<R, W>(
        &mut self, a: &mut R, b: &mut W, cx: &mut Context<'_>, direction: Direction,
    ) -> Result<bool, CopyBidirectionalError>
    where
        C: Buffer<R, W> + Buffer<W, R>,
        R: AsyncRead + AsyncWrite + Unpin + ?Sized,
        W: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        let context = DirectionContext {
            timeouts: &mut self.timeouts,
            tracker: &self.tracker,
            direction,
        };
        match direction {
            Direction::Upload => self.upload.poll(a, b, cx, context, &self.download),
            Direction::Download => self.download.poll(b, a, cx, context, &self.upload),
        }
    }

    pub(super) fn poll<R, W>(
        &mut self, a: &mut R, b: &mut W, cx: &mut Context<'_>,
    ) -> Poll<Result<(u64, u64), CopyBidirectionalError>>
    where
        C: Buffer<R, W> + Buffer<W, R>,
        R: AsyncRead + AsyncWrite + Unpin + ?Sized,
        W: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        // Preserve idle-error priority, then allow ready I/O to refresh the
        // half-close deadline before checking it, as with separate timers.
        if self.timeouts.idle_expired() {
            return Poll::Ready(Err(CopyBidirectionalError::Other(Error::new(
                ErrorKind::TimedOut, "connection idle timeout",
            ))));
        }
        // Both directions share the task's I/O budget. Alternate who gets it first.
        let [first, second] = if self.download_first {
            [Direction::Download, Direction::Upload]
        } else {
            [Direction::Upload, Direction::Download]
        };
        self.download_first = !self.download_first;
        self.poll_direction(a, b, cx, first)?;
        if self.poll_direction(a, b, cx, second)? {
            // The first direction was polled before its deadline was installed.
            // Revisit it so zero-duration timeouts also finish immediately.
            self.poll_direction(a, b, cx, first)?;
        }
        if let (TransferState::Done(upload), TransferState::Done(download)) =
            (&self.upload, &self.download)
        {
            return Poll::Ready(Ok((*upload, *download)));
        }
        self.timeouts.poll_wait(cx);
        Poll::Pending
    }
}

#[cfg(test)]
#[path = "transfer_tests.rs"]
mod tests;
