//! Bound both HTTP flow-control waits and stalled writes on the transport.
use std::{collections::BTreeMap, io, pin::Pin, sync::{Arc, Mutex}, task::{Context, Poll}, time::Duration};
use bytes::Bytes;
use http_body_util::Full;
use tokio::{io::{AsyncRead, AsyncWrite, ReadBuf}, sync::{Notify, OwnedSemaphorePermit}, time::{Instant, sleep_until}};

#[derive(Default)]
struct Pending {
    next_id: u64,
    deadlines: BTreeMap<u64, Instant>,
}

pub(super) struct WriteDeadline {
    timeout: Duration,
    pending: Mutex<Pending>,
    changed: Notify,
}

impl WriteDeadline {
    pub fn new(timeout: Duration) -> Arc<Self> {
        Arc::new(Self { timeout, pending: Mutex::default(), changed: Notify::new() })
    }

    fn register(self: &Arc<Self>) -> Registration {
        let mut pending = self.pending.lock().unwrap();
        let id = pending.next_id;
        pending.next_id = id.wrapping_add(1);
        pending.deadlines.insert(id, Instant::now() + self.timeout);
        drop(pending);
        self.changed.notify_one();
        Registration { owner: self.clone(), id }
    }

    pub async fn expired(&self) {
        loop {
            let changed = self.changed.notified();
            let deadline = self.pending.lock().unwrap().deadlines
                .first_key_value().map(|(_, deadline)| *deadline);
            if let Some(deadline) = deadline {
                tokio::select! {
                    _ = sleep_until(deadline) => {
                        if self.pending.lock().unwrap().deadlines.first_key_value()
                            .is_some_and(|(_, deadline)| *deadline <= Instant::now())
                        { return; }
                    },
                    _ = changed => {}
                }
            } else { changed.await; }
        }
    }

    pub fn body(self: &Arc<Self>, data: Bytes, permit: Option<OwnedSemaphorePermit>) -> ResponseBody {
        // The owner follows DATA bytes through Hyper/h2's send queues, even
        // after the HTTP body itself has been consumed and dropped.
        Full::new(Bytes::from_owner(ResponseData {
            data, _registration: self.register(), _permit: permit,
        }))
    }

    pub fn io<S>(self: &Arc<Self>, inner: S) -> WriteIo<S> {
        WriteIo { inner, deadline: self.clone(), write_blocked: None, flush_blocked: None }
    }
}

struct Registration {
    owner: Arc<WriteDeadline>,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.owner.pending.lock().unwrap().deadlines.remove(&self.id);
        self.owner.changed.notify_one();
    }
}

pub(super) type ResponseBody = Full<Bytes>;

struct ResponseData {
    data: Bytes,
    _registration: Registration,
    _permit: Option<OwnedSemaphorePermit>,
}

impl AsRef<[u8]> for ResponseData {
    fn as_ref(&self) -> &[u8] { &self.data }
}

pub(super) struct WriteIo<S> {
    inner: S,
    deadline: Arc<WriteDeadline>,
    write_blocked: Option<Registration>,
    flush_blocked: Option<Registration>,
}

fn progress<T>(deadline: &Arc<WriteDeadline>, blocked: &mut Option<Registration>, result: &Poll<io::Result<T>>) {
    if result.is_pending() {
        if blocked.is_none() { *blocked = Some(deadline.register()); }
    } else { *blocked = None; }
}

impl<S: AsyncRead + Unpin> AsyncRead for WriteIo<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteIo<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, data);
        progress(&this.deadline, &mut this.write_blocked, &result);
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        progress(&this.deadline, &mut this.flush_blocked, &result);
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_shutdown(cx);
        progress(&this.deadline, &mut this.flush_blocked, &result);
        result
    }

    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, data);
        progress(&this.deadline, &mut this.write_blocked, &result);
        result
    }

    fn is_write_vectored(&self) -> bool { self.inner.is_write_vectored() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::sync::Semaphore;
    use tokio::time::timeout;

    #[tokio::test]
    async fn stalled_write_expires_and_progress_removes_deadline() {
        let deadline = WriteDeadline::new(Duration::from_millis(30));
        let (stream, mut peer) = duplex(1);
        let mut stream = deadline.io(stream);
        stream.write_all(&[1]).await.unwrap();
        tokio::select! {
            biased;
            result = stream.write_all(&[2]) => panic!("unexpected write: {result:?}"),
            result = timeout(Duration::from_secs(1), deadline.expired()) => result.unwrap(),
        }
        let mut byte = [0];
        peer.read_exact(&mut byte).await.unwrap();
        stream.write_all(&[2]).await.unwrap();
        assert!(timeout(Duration::from_millis(50), deadline.expired()).await.is_err());
    }

    #[tokio::test]
    async fn response_holds_admission_and_tracks_flow_control_wait() {
        let deadline = WriteDeadline::new(Duration::from_millis(30));
        let permits = Arc::new(Semaphore::new(1));
        let body = deadline.body(Bytes::from_static(b"response"), Some(permits.clone().try_acquire_owned().unwrap()));
        assert_eq!(permits.available_permits(), 0);
        timeout(Duration::from_secs(1), deadline.expired()).await.unwrap();
        drop(body);
        assert_eq!(permits.available_permits(), 1);
        assert!(timeout(Duration::from_millis(50), deadline.expired()).await.is_err());
    }
}
