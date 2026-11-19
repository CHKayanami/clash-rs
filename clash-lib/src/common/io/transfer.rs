//! Shared direction state, accounting and shutdown for buffered and splice I/O.
use std::{io::{Error, ErrorKind}, pin::Pin, task::{Context, Poll}};
use tokio::io::{AsyncRead, AsyncWrite};
use super::{CopyBidirectionalError, TrafficTracker, timeout::IdleTimeout};

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
        active: &mut bool, direction: Direction,
    ) -> Poll<Result<u64, CopyBidirectionalError>>;
}

pub(super) enum TransferState<C> {
    Running(C),
    ShuttingDown(u64),
    Done(u64),
}

struct DirectionContext<'a> {
    idle_timeout: &'a mut IdleTimeout,
    tracker: &'a TrafficTracker,
    direction: Direction,
}

impl<C> TransferState<C> {
    fn poll<R, W>(
        &mut self, reader: &mut R, writer: &mut W, cx: &mut Context<'_>,
        context: DirectionContext<'_>,
    ) -> Result<(), CopyBidirectionalError>
    where
        C: Buffer<R, W>,
        R: ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    {
        let DirectionContext { idle_timeout, tracker, direction } = context;
        loop {
            match self {
                Self::Running(buffer) => {
                    let before = buffer.amount_transferred();
                    let mut active = false;
                    let result = buffer.poll_copy(cx, reader, writer, &mut active, direction);
                    idle_timeout.record_activity(active);
                    let written = buffer.amount_transferred() - before;
                    // Account successful writes even if a later I/O operation
                    // in the same poll fails.
                    if written > 0 {
                        direction.track(tracker, written as usize);
                    }
                    let count = match result {
                        Poll::Ready(Ok(count)) => count,
                        Poll::Ready(Err(error)) => return Err(error),
                        Poll::Pending => return Ok(()),
                    };
                    *self = Self::ShuttingDown(count);
                }
                Self::ShuttingDown(count) => {
                    match Pin::new(&mut *writer).poll_shutdown(cx) {
                        Poll::Ready(Ok(())) => *self = Self::Done(*count),
                        Poll::Ready(Err(error)) => return Err(direction.error(error)),
                        Poll::Pending => return Ok(()),
                    }
                }
                Self::Done(_) => return Ok(()),
            }
        }
    }
}

pub(super) struct CopyState<C> {
    upload: TransferState<C>,
    download: TransferState<C>,
    idle_timeout: IdleTimeout,
    tracker: TrafficTracker,
    download_first: bool,
}

impl<C> CopyState<C> {
    pub(super) fn new(upload: C, download: C, tracker: TrafficTracker) -> Self {
        Self {
            upload: TransferState::Running(upload),
            download: TransferState::Running(download),
            idle_timeout: IdleTimeout::new(),
            tracker,
            download_first: false,
        }
    }

    fn poll_direction<R, W>(
        &mut self, a: &mut R, b: &mut W, cx: &mut Context<'_>, direction: Direction,
    ) -> Result<(), CopyBidirectionalError>
    where
        C: Buffer<R, W> + Buffer<W, R>,
        R: AsyncRead + AsyncWrite + Unpin + ?Sized,
        W: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        let context = DirectionContext {
            idle_timeout: &mut self.idle_timeout,
            tracker: &self.tracker,
            direction,
        };
        match direction {
            Direction::Upload => self.upload.poll(a, b, cx, context),
            Direction::Download => self.download.poll(b, a, cx, context),
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
        if self.idle_timeout.expired() {
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
        self.poll_direction(a, b, cx, second)?;
        if let (TransferState::Done(upload), TransferState::Done(download)) =
            (&self.upload, &self.download)
        {
            return Poll::Ready(Ok((*upload, *download)));
        }
        self.idle_timeout.poll_wait(cx);
        Poll::Pending
    }
}

#[cfg(test)]
#[path = "transfer_tests.rs"]
mod tests;
