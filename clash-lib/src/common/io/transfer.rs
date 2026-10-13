//! Shared direction state, accounting and shutdown for buffered and splice I/O.
use std::{io::{Error, ErrorKind}, pin::Pin, task::{Context, Poll}, time::Duration};
use tokio::{io::{AsyncRead, AsyncWrite}, time::Instant};
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
}

pub(super) trait Buffer<R: ?Sized, W: ?Sized> {
    fn amount_transferred(&self) -> u64;
    fn poll_copy(
        &mut self, cx: &mut Context<'_>, reader: &mut R, writer: &mut W,
        last_active: &mut Instant, direction: Direction,
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
    fn is_running(&self) -> bool { matches!(self, Self::Running(_)) }
    fn is_done(&self) -> bool { matches!(self, Self::Done(_)) }

    fn poll<R, W>(
        &mut self, reader: &mut R, writer: &mut W, cx: &mut Context<'_>,
        context: DirectionContext<'_>,
    ) -> Poll<Result<u64, CopyBidirectionalError>>
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
                    let result = buffer.poll_copy(
                        cx, reader, writer, &mut timeouts.last_active, direction,
                    );
                    let written = buffer.amount_transferred() - before;
                    // Account successful writes even if a later I/O operation
                    // in the same poll fails. Reads never refresh half-close.
                    if written > 0 {
                        direction.track(tracker, written as usize);
                        timeouts.wrote(direction);
                    }
                    let count = match result {
                        Poll::Ready(Ok(count)) => count,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending if timeouts.half_close_expired() => {
                            buffer.amount_transferred()
                        }
                        Poll::Pending => return Poll::Pending,
                    };
                    *self = Self::ShuttingDown(count);
                    timeouts.stop_half_close();
                }
                Self::ShuttingDown(count) => {
                    match Pin::new(&mut *writer).poll_shutdown(cx) {
                        Poll::Ready(Ok(())) => *self = Self::Done(*count),
                        Poll::Ready(Err(error)) => {
                            return Poll::Ready(Err(direction.error(error)));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Self::Done(count) => return Poll::Ready(Ok(*count)),
            }
        }
    }
}

pub(super) struct CopyState<C> {
    upload: TransferState<C>,
    download: TransferState<C>,
    timeouts: CopyTimeouts,
    tracker: TrafficTracker,
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
        loop {
            let upload_was_done = self.upload.is_done();
            if let Poll::Ready(Err(error)) = self.upload.poll(a, b, cx, DirectionContext {
                timeouts: &mut self.timeouts,
                tracker: &self.tracker,
                direction: Direction::Upload,
            }) {
                return Poll::Ready(Err(error));
            }
            if !upload_was_done && self.upload.is_done() && self.download.is_running() {
                self.timeouts.start_half_close(Direction::Download);
            }

            let download_was_done = self.download.is_done();
            if let Poll::Ready(Err(error)) = self.download.poll(b, a, cx, DirectionContext {
                timeouts: &mut self.timeouts,
                tracker: &self.tracker,
                direction: Direction::Download,
            }) {
                return Poll::Ready(Err(error));
            }
            if !download_was_done && self.download.is_done() && self.upload.is_running() {
                self.timeouts.start_half_close(Direction::Upload);
                // The upload was polled before this deadline was installed.
                // Revisit it so zero-duration timeouts also finish immediately.
                continue;
            }
            if let (TransferState::Done(upload), TransferState::Done(download)) =
                (&self.upload, &self.download)
            {
                return Poll::Ready(Ok((*upload, *download)));
            }
            self.timeouts.poll_wait(cx);
            return Poll::Pending;
        }
    }
}

#[cfg(test)]
#[path = "transfer_tests.rs"]
mod tests;
