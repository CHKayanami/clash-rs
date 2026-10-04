use std::{future::{Future, poll_fn}, io, pin::Pin,
    sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}},
    task::{Context, Poll}, time::Duration};
use bytes::Bytes;
use h2::{Ping, RecvStream, SendStream, client::{Builder, Connection}};
use tokio::{io::{AsyncRead, AsyncWrite}, spawn, sync::Notify, task::JoinHandle,
    time::{sleep, timeout}};
use tracing::debug;

pub(crate) const MAX_WRITE_SIZE: usize = 16 * 1024;
pub(crate) const RECEIVE_WINDOW: u32 = 1024 * 1024;
pub(crate) const SEND_BUFFER_SIZE: usize = 64 * 1024;

pub(crate) fn client_builder() -> Builder {
    let mut builder = Builder::new();
    builder.initial_connection_window_size(RECEIVE_WINDOW)
        .initial_window_size(RECEIVE_WINDOW)
        .max_send_buffer_size(SEND_BUFFER_SIZE)
        .enable_push(false);
    builder
}

#[derive(Default)]
pub(crate) struct ConnectionState {
    limit: AtomicUsize,
    closed: AtomicBool,
    changed: Notify,
}

impl ConnectionState {
    pub(crate) fn update(&self, limit: usize) {
        if self.limit.load(Ordering::Acquire) != limit
            && self.limit.swap(limit, Ordering::AcqRel) != limit {
            self.changed.notify_waiters();
        }
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    pub(crate) fn closed(&self) -> bool { self.closed.load(Ordering::Acquire) }
    pub(crate) fn limit(&self) -> usize { self.limit.load(Ordering::Acquire) }

    pub(crate) async fn initialized(&self) -> io::Result<()> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.closed() { return Err(io::ErrorKind::BrokenPipe.into()); }
            if self.limit() != 0 { return Ok(()); }
            changed.await;
        }
    }
}

struct CloseGuard(Arc<ConnectionState>);
impl Drop for CloseGuard {
    fn drop(&mut self) { self.0.close(); }
}

/// Drive socket I/O and observe SETTINGS in the same task. Owners decide
/// whether a connection is dedicated, pooled, or eligible for replacement.
pub(crate) async fn drive_connection<T>(
    mut connection: Connection<T, Bytes>, state: Arc<ConnectionState>,
    keep_alive: Option<Duration>,
) where T: AsyncRead + AsyncWrite + Unpin,
{
    let _closed = CloseGuard(state.clone());
    let ping = keep_alive.and_then(|_| connection.ping_pong());
    let driver = poll_fn(|cx| {
        let result = Pin::new(&mut connection).poll(cx);
        state.update(connection.max_concurrent_send_streams());
        result.map_err(io::Error::other)
    });
    let result = if let (Some(interval), Some(mut ping)) = (keep_alive, ping) {
        let heartbeat = async move {
            loop {
                sleep(interval).await;
                let result = timeout(Duration::from_secs(10), ping.ping(Ping::opaque())).await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "H2 keepalive timed out"))?
                    .map_err(io::Error::other);
                if let Err(error) = result { break Err(error); }
            }
        };
        tokio::select! { result = driver => result, result = heartbeat => result }
    } else { driver.await };
    if let Err(error) = result { debug!(%error, "H2 connection closed"); }
}

pub(crate) struct ConnectionDriver {
    task: JoinHandle<()>,
    state: Arc<ConnectionState>,
}

impl ConnectionDriver {
    pub(crate) fn spawn<T>(connection: Connection<T, Bytes>, keep_alive: Option<Duration>) -> Self
    where T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let state = Arc::new(ConnectionState::default());
        let task = spawn(drive_connection(connection, state.clone(), keep_alive));
        Self { task, state }
    }

    pub(crate) fn state(&self) -> Arc<ConnectionState> { self.state.clone() }
    pub(crate) fn closed(&self) -> bool { self.state.closed() }
    pub(crate) fn abort(&self) { self.state.close(); self.task.abort(); }
}

impl Drop for ConnectionDriver {
    fn drop(&mut self) { self.abort(); }
}

#[cfg(test)]
#[path = "h2_common_tests.rs"]
mod tests;

pub(crate) fn poll_send_capacity(
    send: &mut SendStream<Bytes>, cx: &mut Context<'_>, length: usize,
) -> Poll<io::Result<usize>> {
    if length == 0 { return Poll::Ready(Ok(0)); }
    let length = length.min(MAX_WRITE_SIZE);
    send.reserve_capacity(length);
    match send.poll_capacity(cx) {
        // h2 promises positive capacity for Ready; zero-window updates
        // register the waker and return Pending internally.
        Poll::Ready(Some(Ok(0))) => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData, "H2 reported zero send capacity as ready",
        ))),
        Poll::Ready(Some(Ok(capacity))) => Poll::Ready(Ok(capacity.min(length))),
        Poll::Ready(Some(Err(error))) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, error))),
        Poll::Ready(None) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "H2 send stream closed"))),
        Poll::Pending => {
            let capacity = send.capacity().min(length);
            if capacity > 0 { Poll::Ready(Ok(capacity)) } else { Poll::Pending }
        }
    }
}

pub(crate) async fn send_bytes(
    send: &mut SendStream<Bytes>, mut data: Bytes, end_stream: bool,
) -> io::Result<()> {
    if data.is_empty() && end_stream {
        return send.send_data(data, true).map_err(io::Error::other);
    }
    while !data.is_empty() {
        let length = poll_fn(|cx| poll_send_capacity(send, cx, data.len())).await?;
        let last = end_stream && length == data.len();
        send.send_data(data.split_to(length), last).map_err(io::Error::other)?;
    }
    Ok(())
}

/// Callers decide whether capacity is released for a bounded buffered frame
/// or only for bytes consumed by the protocol decoder.
pub(crate) fn release_receive_capacity(recv: &mut RecvStream, length: usize) -> io::Result<()> {
    recv.flow_control().release_capacity(length)
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionReset, error))
}

pub(crate) fn shutdown_h2_send(
    send: &mut SendStream<Bytes>, write_closed: &mut bool, cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    if *write_closed { return Poll::Ready(Ok(())); }
    send.reserve_capacity(0);
    match send.poll_capacity(cx) {
        Poll::Ready(None) => { *write_closed = true; Poll::Ready(Ok(())) }
        Poll::Ready(Some(Err(error))) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, error))),
        Poll::Ready(Some(Ok(_))) | Poll::Pending => {
            // Empty END_STREAM needs no flow-control capacity.
            send.send_data(Bytes::new(), true)
                .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error))?;
            *write_closed = true;
            Poll::Ready(Ok(()))
        }
    }
}
