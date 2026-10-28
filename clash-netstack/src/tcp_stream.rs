use crate::tcp_listener::TcpStreamHandle;
use log::trace;
use std::{
    io::{Error, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll, ready},
};

pub struct TcpStream {
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,

    pub(crate) handle: Arc<TcpStreamHandle>,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        trace!(
            "TcpStream dropped: {} <-> {}",
            self.local_addr, self.remote_addr
        );

        // socket_dropped tells the stack task to drain send_buffer and issue FIN.
        // read_closed / write_closed unblock any concurrent poll_read / poll_write.
        self.handle.socket_dropped.store(true, Ordering::Release);
        self.handle.read_closed.store(true, Ordering::Release);
        self.handle.write_closed.store(true, Ordering::Release);
        self.handle.recv_waker.wake();
        self.handle.send_waker.wake();
        self.handle.notify();
    }
}

impl TcpStream {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn split(self) -> (tokio::io::ReadHalf<Self>, tokio::io::WriteHalf<Self>) {
        let (r, w) = tokio::io::split(self);
        (r, w)
    }

    fn notify_tcp_socket_ready(&self) {
        self.handle.notify();
    }
}

impl std::fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpStream")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .finish()
    }
}

impl tokio::io::AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        trace!(
            "TcpStream::poll_read called: {} <-> {}",
            self.local_addr, self.remote_addr
        );
        if buf.remaining() == 0 { return Poll::Ready(Ok(())); }
        let read_buf = self.handle.recv();

        if read_buf.is_empty() {
            // Register waker FIRST, then re-check to close the TOCTOU window.
            // If the stack task enqueues data between is_empty() and register(),
            // wake() is a no-op (no waker stored). The re-check below detects
            // the buffer is now non-empty and falls through to read it.
            self.handle.recv_waker.register(cx.waker());
            if read_buf.is_empty() {
                // Return EOF when smoltcp is done (socket removed) OR when the
                // read half was explicitly closed (peer FIN / local drop).
                if self
                    .handle
                    .socket_closed
                    .load(std::sync::atomic::Ordering::Acquire)
                    || self.handle.read_closed.load(Ordering::Acquire)
                {
                    trace!("TcpStream::poll_read: socket closed, returning EOF");
                    return std::task::Poll::Ready(Ok(()));
                }
                trace!(
                    "TcpStream::poll_read: recv buffer is empty, waiting for data"
                );
                return std::task::Poll::Pending;
            }
        }

        let n = read_buf.dequeue_slice(buf.initialize_unfilled());
        buf.advance(n);

        if n > 0 && self.handle.recv_pending.swap(false, Ordering::AcqRel) {
            self.notify_tcp_socket_ready();
        }
        trace!("TcpStream::poll_read: (proxy)read {n} bytes from recv buffer");

        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.handle.write_closed.load(Ordering::Acquire)
            || self.handle.write_shutdown.load(Ordering::Acquire)
        {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "TCP stream write half closed",
            )));
        }

        let send_buf = self.handle.send();

        if send_buf.is_full() {
            // Register waker FIRST, then re-check to close the TOCTOU window.
            // If the stack task drains the buffer between is_full() and register(),
            // wake() is a no-op (no waker stored). The re-check below detects
            // the buffer is now non-full and falls through to enqueue data.
            self.handle.send_waker.register(cx.waker());
            if send_buf.is_full() {
                trace!(
                    "TcpStream::poll_write: send buffer is full, waiting for space"
                );
                self.notify_tcp_socket_ready();
                return std::task::Poll::Pending;
            }
        }

        let n = send_buf.enqueue_slice(buf);

        self.notify_tcp_socket_ready();
        trace!("TcpStream::poll_write: (proxy)write {n} bytes to send buffer");

        Poll::Ready(Ok(n))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // poll_write already publishes every accepted write to the engine.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        trace!("TcpStream::poll_shutdown called, client side closing");
        self.handle.write_shutdown.store(true, Ordering::Release);
        self.handle.notify();
        self.handle.send_waker.wake();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp_listener::TcpStreamHandle;
    use futures::task::noop_waker_ref;
    use tokio::io::{AsyncRead, AsyncWrite};
    use crate::ready::{Ready, ReadyQueue};

    fn build_stream() -> (TcpStream, Arc<ReadyQueue>) {
        let queue = Arc::new(ReadyQueue::default());
        let ready = Ready::new(1, queue.clone());
        (TcpStream {
            local_addr: "127.0.0.1:12345".parse().unwrap(),
            remote_addr: "127.0.0.1:80".parse().unwrap(),
            handle: Arc::new(TcpStreamHandle::new(ready)),
        }, queue)
    }

    fn noop_cx() -> Context<'static> {
        Context::from_waker(noop_waker_ref())
    }

    #[test]
    fn drop_marks_stream_closed_after_stack_stops() {
        let (stream, rx) = build_stream();
        let handle = stream.handle.clone();
        drop(rx);
        drop(stream);
        assert!(handle.socket_dropped.load(Ordering::Acquire));
        assert!(handle.read_closed.load(Ordering::Acquire));
        assert!(handle.write_closed.load(Ordering::Acquire));
    }

    #[test]
    fn drop_notifies_running_stack() {
        let (stream, rx) = build_stream();
        drop(stream);
        assert!(rx.pop().is_some());
    }

    #[test]
    fn poll_read_returns_eof_after_peer_close() {
        let (mut stream, _rx) = build_stream();
        stream.handle.read_closed.store(true, Ordering::Release);
        let mut cx = noop_cx();
        let mut bytes = [0u8; 16];
        let mut buf = tokio::io::ReadBuf::new(&mut bytes);

        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut buf);

        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(buf.filled().len(), 0);
    }

    #[test]
    fn poll_shutdown_marks_write_shutdown() {
        let (mut stream, rx) = build_stream();
        let mut cx = noop_cx();

        let result = Pin::new(&mut stream).poll_shutdown(&mut cx);

        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert!(stream.handle.write_shutdown.load(Ordering::Acquire));
        assert!(rx.pop().is_some());
        assert!(rx.pop().is_none());
    }

    #[test]
    fn poll_write_fails_after_write_close() {
        let (mut stream, _rx) = build_stream();
        stream.handle.write_closed.store(true, Ordering::Release);
        let mut cx = noop_cx();

        let result = Pin::new(&mut stream).poll_write(&mut cx, b"hello");

        assert!(
            matches!(result, Poll::Ready(Err(err)) if err.kind() == ErrorKind::BrokenPipe)
        );
    }

    #[test]
    fn poll_flush_still_succeeds_when_notifier_closed() {
        let (mut stream, rx) = build_stream();
        drop(rx);
        let mut cx = noop_cx();

        let result = Pin::new(&mut stream).poll_flush(&mut cx);

        assert!(matches!(result, Poll::Ready(Ok(()))));
    }
    #[test]
    fn reads_only_reschedule_engine_when_protocol_receive_data_is_waiting() {
        let (mut stream, ready) = build_stream();
        let mut cx = noop_cx();
        for pending in [false, true] {
            stream.handle.recv().enqueue_slice(b"data");
            stream.handle.recv_pending.store(pending, Ordering::Release);
            let mut storage = [0; 4];
            let mut buffer = tokio::io::ReadBuf::new(&mut storage);
            assert!(Pin::new(&mut stream).poll_read(&mut cx, &mut buffer).is_ready());
            assert_eq!(buffer.filled(), b"data");
            assert_eq!(ready.pop().is_some(), pending);
        }
    }

    #[test]
    fn flushing_an_accepted_write_does_not_schedule_a_second_service() {
        let (mut stream, ready) = build_stream();
        let mut cx = noop_cx();
        assert!(Pin::new(&mut stream).poll_write(&mut cx, b"data").is_ready());
        assert!(ready.pop().is_some());
        assert!(Pin::new(&mut stream).poll_flush(&mut cx).is_ready());
        assert!(ready.pop().is_none());
    }

}
