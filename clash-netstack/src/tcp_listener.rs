use std::{io, net::SocketAddr, pin::Pin, sync::{Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering}}, task::{Context, Poll}};
use futures::{Stream, task::AtomicWaker};
use tokio::{sync::mpsc, task::JoinHandle};
use crate::{Packet, ready::{Ready, ReadyQueue}, ring_buffer::LockFreeRingBuffer,
    tcp_engine::Engine, tcp_forward::ForwardRequest, tcp_stream::TcpStream};

// Adapter queues decouple protocol relays from the growable protocol buffers.
const STREAM_BUFFER_SIZE: usize = 16 * 1024;

pub(crate) struct TcpStreamHandle {
    pub recv_buffer: OnceLock<LockFreeRingBuffer>,
    pub recv_waker: AtomicWaker,
    pub send_buffer: OnceLock<LockFreeRingBuffer>,
    pub send_waker: AtomicWaker,
    pub socket_dropped: AtomicBool,
    pub socket_closed: AtomicBool,
    pub read_closed: AtomicBool,
    pub write_closed: AtomicBool,
    pub write_shutdown: AtomicBool,
    pub abort: AtomicBool,
    pub ready: Arc<Ready>,
    pub forward: Mutex<Option<ForwardRequest>>,
    pub forward_pending: AtomicBool,
}

impl TcpStreamHandle {
    pub fn new(ready: Arc<Ready>) -> Self {
        Self {
            recv_buffer: OnceLock::new(), recv_waker: AtomicWaker::new(),
            send_buffer: OnceLock::new(), send_waker: AtomicWaker::new(),
            socket_dropped: AtomicBool::new(false), socket_closed: AtomicBool::new(false),
            read_closed: AtomicBool::new(false), write_closed: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false), abort: AtomicBool::new(false), ready,
            forward: Mutex::new(None), forward_pending: AtomicBool::new(false),
        }
    }

    pub fn recv(&self) -> &LockFreeRingBuffer {
        self.recv_buffer.get_or_init(|| LockFreeRingBuffer::new(STREAM_BUFFER_SIZE))
    }

    pub fn send(&self) -> &LockFreeRingBuffer {
        self.send_buffer.get_or_init(|| LockFreeRingBuffer::new(STREAM_BUFFER_SIZE))
    }

    pub fn notify(&self) { self.ready.schedule(); }

    pub fn close(&self) {
        self.socket_closed.store(true, Ordering::Release);
        self.read_closed.store(true, Ordering::Release);
        self.write_closed.store(true, Ordering::Release);
        self.recv_waker.wake();
        self.send_waker.wake();
    }
}

pub struct TcpListener {
    socket_stream: mpsc::Receiver<TcpStream>,
    task_handle: JoinHandle<()>,
}

impl Drop for TcpListener {
    fn drop(&mut self) { self.task_handle.abort(); }
}

impl TcpListener {
    pub fn new(inbound: mpsc::Receiver<Packet>, outbound: mpsc::Sender<Packet>) -> Self {
        let (sender, socket_stream) = mpsc::channel(256);
        let ready = Arc::new(ReadyQueue::default());
        let task_handle = tokio::spawn(async move {
            if let Err(error) = Engine::new(outbound, ready).run(inbound, sender).await {
                log::debug!("TCP stack stopped: {error}");
            }
        });
        Self { socket_stream, task_handle }
    }
}

impl Stream for TcpListener {
    type Item = TcpStream;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<TcpStream>> {
        self.get_mut().socket_stream.poll_recv(cx)
    }
}

pub(crate) fn new_stream(source: SocketAddr, destination: SocketAddr,
    ready: Arc<Ready>) -> (TcpStream, Arc<TcpStreamHandle>) {
    let handle = Arc::new(TcpStreamHandle::new(ready));
    (TcpStream { local_addr: source, remote_addr: destination, handle: handle.clone() }, handle)
}

pub(crate) fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "TCP stack connection closed")
}
