//! Native socket handoff. All I/O is polled by the owning stack task; neither
//! protocol buffer slices nor raw descriptors escape a synchronous poll operation.
use super::{buffers::Buffers, driver::OUTPUT_BYTES, protocol as tcp};
use crate::{
    tcp::listener::{TcpStreamHandle, closed_error},
    tcp::stream::TcpStream,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::atomic::Ordering,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep, sleep_until};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream as NativeTcpStream,
    sync::oneshot,
};

pub type ForwardCounter = Box<dyn FnMut(usize, usize) + Send + Sync>;
type ForwardResult = io::Result<(u64, u64)>;

pub(crate) struct ForwardRequest {
    pub socket: NativeTcpStream,
    pub prefix: Vec<u8>,
    pub counter: ForwardCounter,
    pub done: oneshot::Sender<ForwardResult>,
    pub upload_timeout: Duration,
    pub download_timeout: Duration,
}

pub(crate) struct Forward {
    request: ForwardRequest,
    offset: usize,
    upload: u64,
    download: u64,
    upload_done: bool,
    download_done: bool,
    last_active: Instant,
    half_close: Option<Instant>,
    timer: Pin<Box<Sleep>>,
}

impl TcpStream {
    /// Transfer exclusive socket I/O to this stream's stack. Dropping the future
    /// aborts the handoff; the native socket is never read by two owners.
    pub async fn forward(
        self,
        socket: NativeTcpStream,
        prefix: Vec<u8>,
        counter: ForwardCounter,
        upload_timeout: Duration,
        download_timeout: Duration,
    ) -> ForwardResult {
        let (done, result) = oneshot::channel();
        let mut guard = ForwardGuard {
            stream: self,
            completed: false,
        };
        {
            let mut pending = guard.stream.handle.forward.lock().unwrap();
            if guard.stream.handle.socket_closed.load(Ordering::Acquire) {
                return Err(closed_error());
            }
            *pending = Some(ForwardRequest {
                socket,
                prefix,
                counter,
                done,
                upload_timeout,
                download_timeout,
            });
            guard
                .stream
                .handle
                .forward_pending
                .store(true, Ordering::Release);
        }
        guard.stream.handle.notify();
        let result = result.await.unwrap_or_else(|_| Err(closed_error()));
        guard.completed = true;
        result
    }
}

struct ForwardGuard {
    stream: TcpStream,
    completed: bool,
}
impl Drop for ForwardGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.stream.handle.abort.store(true, Ordering::Release);
            self.stream.handle.notify();
        }
    }
}

impl Forward {
    pub fn new(request: ForwardRequest) -> Self {
        let last_active = Instant::now();
        Self {
            request,
            offset: 0,
            upload: 0,
            download: 0,
            upload_done: false,
            download_done: false,
            last_active,
            half_close: None,
            timer: Box::pin(sleep_until(last_active + Duration::from_secs(180))),
        }
    }

    pub fn finish(self, result: io::Result<()>) {
        let _ = self
            .request
            .done
            .send(result.map(|()| (self.upload, self.download)));
    }

    pub fn poll(
        &mut self,
        socket: &mut tcp::Socket<'_>,
        handle: &TcpStreamHandle,
        cx: &mut Context<'_>,
        now: Instant,
        flush: &mut dyn FnMut(&mut tcp::Socket<'_>) -> bool,
    ) -> Poll<io::Result<()>> {
        let before = (self.upload, self.download);
        let result = self
            .pump_upload(socket, handle, cx, now)
            .and_then(|()| self.pump_download(socket, handle, cx, now, flush));
        let upload = (self.upload - before.0) as usize;
        let download = (self.download - before.1) as usize;
        if upload > 0 || download > 0 {
            (self.request.counter)(upload, download);
        }
        result?;
        if !self.download_done
            && handle.write_shutdown.load(Ordering::Acquire)
            && handle
                .send_buffer
                .get()
                .is_none_or(|buffer| buffer.is_empty())
        {
            // Handoff must preserve an earlier application write shutdown,
            // but only after draining every write accepted by the stream.
            self.download_done = true;
            self.half_close = Some(now + self.request.upload_timeout);
            socket.close();
        }
        if past_handshake(socket) && !socket.may_send() && !self.download_done {
            return Poll::Ready(Err(closed_error()));
        }
        if self.upload_done && self.download_done {
            return Poll::Ready(Ok(()));
        }
        if self.half_close.is_some_and(|deadline| now >= deadline) {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        let idle = self.last_active + Duration::from_secs(180);
        if now >= idle {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        let deadline = self.half_close.map_or(idle, |half| half.min(idle));
        if deadline < self.timer.deadline() || self.timer.is_elapsed() {
            self.timer.as_mut().reset(deadline);
        }
        if self.timer.as_mut().poll(cx).is_ready() {
            self.timer.as_mut().reset(deadline);
            let _ = self.timer.as_mut().poll(cx);
        }
        Poll::Pending
    }

    fn pump_upload(
        &mut self,
        socket: &mut tcp::Socket<'_>,
        handle: &TcpStreamHandle,
        cx: &mut Context<'_>,
        now: Instant,
    ) -> io::Result<()> {
        let mut budget: usize = 64 * 1024;
        // Prefix bytes and already-published adapter bytes precede protocol RX.
        while !self.upload_done && budget > 0 {
            if self.offset < self.request.prefix.len() {
                let end = (self.offset + budget).min(self.request.prefix.len());
                match Pin::new(&mut self.request.socket)
                    .poll_write(cx, &self.request.prefix[self.offset..end])
                {
                    Poll::Ready(Ok(0)) => {
                        return Err(io::ErrorKind::WriteZero.into());
                    }
                    Poll::Ready(Ok(n)) => {
                        self.offset += n;
                        self.count(n, 0, now);
                        budget -= n;
                    }
                    Poll::Ready(Err(error)) => return Err(error),
                    Poll::Pending => break,
                }
                continue;
            }
            if self.offset > 0 {
                // Reuse storage while draining adapter bytes across bounded chunks.
                self.request.prefix.clear();
                self.offset = 0;
            }
            if let Some(buffer) = handle.recv_buffer.get()
                && !buffer.is_empty()
            {
                // A stream used for sniffing can have adapter bytes queued at
                // handoff. Drain them in bounded chunks before protocol RX.
                self.request.prefix.resize(16 * 1024, 0);
                let n = buffer.dequeue_slice(&mut self.request.prefix);
                self.request.prefix.truncate(n);
                continue;
            }
            // No adapter consumer remains after handoff.
            handle.recv_pending.store(false, Ordering::Relaxed);
            if self.request.prefix.capacity() > 0 {
                self.request.prefix = Vec::new();
            }
            if socket.can_recv() {
                let mut written = Poll::Pending;
                socket
                    .recv(|data| {
                        written = Pin::new(&mut self.request.socket)
                            .poll_write(cx, &data[..data.len().min(budget)]);
                        let n = match &written {
                            Poll::Ready(Ok(n)) => *n,
                            _ => 0,
                        };
                        (n, ())
                    })
                    .map_err(|_| closed_error())?;
                match written {
                    Poll::Ready(Ok(0)) => {
                        return Err(io::ErrorKind::WriteZero.into());
                    }
                    Poll::Ready(Ok(n)) => {
                        self.count(n, 0, now);
                        budget -= n;
                    }
                    Poll::Ready(Err(error)) => return Err(error),
                    Poll::Pending => break,
                }
            } else if !socket.may_recv() && past_handshake(socket) {
                match Pin::new(&mut self.request.socket).poll_shutdown(cx) {
                    Poll::Ready(Ok(())) => {
                        self.upload_done = true;
                        self.half_close = Some(now + self.request.download_timeout);
                    }
                    Poll::Ready(Err(error)) => return Err(error),
                    Poll::Pending => break,
                }
            } else {
                break;
            }
        }
        if budget == 0 {
            handle.notify();
        }
        Ok(())
    }

    fn pump_download(
        &mut self,
        socket: &mut tcp::Socket<'_>,
        handle: &TcpStreamHandle,
        cx: &mut Context<'_>,
        now: Instant,
        flush: &mut dyn FnMut(&mut tcp::Socket<'_>) -> bool,
    ) -> io::Result<()> {
        let mut total_budget = OUTPUT_BYTES;
        let mut pending = false;
        let mut shutdown = false;
        let mut capped = false;
        while !self.download_done && socket.can_send() && total_budget > 0 {
            let mut budget = Buffers::read_budget(socket)
                .min(64 * 1024)
                .min(total_budget);
            if budget == 0 {
                if !flush(socket) {
                    break;
                }
                budget = Buffers::read_budget(socket)
                    .min(64 * 1024)
                    .min(total_budget);
                if budget == 0 {
                    break;
                }
            }
            let batch_budget = budget;
            while !self.download_done && socket.can_send() && budget > 0 {
                // Drain writes accepted by the generic stream before handoff.
                if let Some(buffer) = handle.send_buffer.get()
                    && !buffer.is_empty()
                {
                    let n = socket
                        .send(|data| {
                            let length = data.len().min(budget);
                            let n = buffer.dequeue_slice(&mut data[..length]);
                            (n, n)
                        })
                        .map_err(|_| closed_error())?;
                    budget = budget.saturating_sub(n);
                    continue;
                }
                // An explicit shutdown forbids new native downloads. Any writes
                // accepted before handoff were drained by the branch above.
                if handle.write_shutdown.load(Ordering::Acquire) {
                    shutdown = true;
                    break;
                }
                let mut read = Poll::Pending;
                let n = socket
                    .send(|data| {
                        let length = data.len().min(budget);
                        let mut buffer = ReadBuf::new(&mut data[..length]);
                        read = Pin::new(&mut self.request.socket)
                            .poll_read(cx, &mut buffer);
                        let n = buffer.filled().len();
                        (n, n)
                    })
                    .map_err(|_| closed_error())?;
                match read {
                    Poll::Ready(Ok(())) if n == 0 => {
                        self.download_done = true;
                        self.half_close = Some(now + self.request.upload_timeout);
                        socket.close();
                    }
                    Poll::Ready(Ok(())) => {
                        self.count(0, n, now);
                        budget -= n;
                    }
                    Poll::Ready(Err(error)) => return Err(error),
                    Poll::Pending => {
                        pending = true;
                        break;
                    }
                }
            }
            let read_bytes = batch_budget - budget;
            // A full batch has not polled the native stream to Pending yet.
            // Keep reading on the next service if send credit remains.
            capped = budget == 0;
            total_budget -= read_bytes;
            let sent = if read_bytes > 0 || self.download_done {
                flush(socket)
            } else {
                false
            };
            if self.download_done || pending || shutdown || read_bytes == 0 || !sent
            {
                break;
            }
        }
        if !self.download_done
            && !pending
            && !shutdown
            && (total_budget == 0 || capped)
            && socket.can_send()
            && Buffers::read_budget(socket) > 0
        {
            handle.notify();
        }
        Ok(())
    }

    fn count(&mut self, upload: usize, download: usize, now: Instant) {
        self.last_active = now;
        if self.half_close.is_some() {
            let timeout = if upload > 0 {
                self.request.upload_timeout
            } else {
                self.request.download_timeout
            };
            self.half_close = Some(self.last_active + timeout);
        }
        self.upload += upload as u64;
        self.download += download as u64;
    }
}

pub(crate) fn past_handshake(socket: &tcp::Socket<'_>) -> bool {
    !matches!(
        socket.state(),
        tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::{
        listener::new_stream,
        ready::{Ready, ReadyQueue},
    };
    use futures::task::noop_waker;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    async fn native_pair() -> (NativeTcpStream, NativeTcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = NativeTcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn half_close_timeout_is_an_abort_instead_of_graceful_completion() {
        let (native, _peer) = native_pair().await;
        let (done, _result) = oneshot::channel();
        let mut forward = Forward::new(ForwardRequest {
            socket: native,
            prefix: Vec::new(),
            counter: Box::new(|_, _| {}),
            done,
            upload_timeout: Duration::ZERO,
            download_timeout: Duration::ZERO,
        });
        forward.download_done = true;
        forward.half_close = Some(Instant::now());
        let ready = Ready::new(1, Arc::new(ReadyQueue::default()));
        let (_stream, handle) = new_stream(
            "192.0.2.1:1234".parse().unwrap(),
            "198.51.100.1:80".parse().unwrap(),
            ready,
        );
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 16384]),
            tcp::SocketBuffer::new(vec![0; 16384]),
        );
        socket.listen(80).unwrap();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(
            matches!(forward.poll(&mut socket, &handle, &mut cx, Instant::now(), &mut |_| false),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::TimedOut)
        );
        assert!(!forward.upload_done);
    }
}
