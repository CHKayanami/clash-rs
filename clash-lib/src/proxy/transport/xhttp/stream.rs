use std::{future::Future, io, pin::Pin,
    sync::{Arc, atomic::{AtomicBool, Ordering}}, task::{Context, Poll}};
use bytes::Bytes;
use futures::{Stream, ready, task::AtomicWaker};
use hyper::body::Body;
use parking_lot::Mutex;
use tokio::{io::{AsyncRead, AsyncWrite, ReadBuf}, sync::{mpsc, oneshot}};
use tokio_util::{io::StreamReader, sync::PollSender};

use crate::proxy::ProxyStream;
use super::{connection::{ResponseBody, Tasks}, pool::Lease, upload::Command};

#[derive(Default)]
pub(super) struct Shared {
    failure: Mutex<Option<(io::ErrorKind, String)>>,
    failed: AtomicBool,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

impl Shared {
    pub(super) fn fail(&self, error: io::Error) {
        let mut failure = self.failure.lock();
        if failure.is_none() { *failure = Some((error.kind(), error.to_string())); }
        self.failed.store(true, Ordering::Release);
        drop(failure);
        self.read_waker.wake();
        self.write_waker.wake();
    }

    fn check(&self) -> io::Result<()> {
        if !self.failed.load(Ordering::Acquire) { return Ok(()); }
        match &*self.failure.lock() {
            Some((kind, message)) => Err(io::Error::new(*kind, message.clone())),
            None => Ok(()),
        }
    }
}

enum Download {
    Waiting(oneshot::Receiver<ResponseBody>),
    Reading(ResponseBody),
    Done,
}
impl Stream for Download {
    type Item = io::Result<Bytes>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match &mut *self {
                Self::Waiting(receiver) => {
                    match ready!(Pin::new(receiver).poll(cx)) {
                        Ok(body) => *self = Self::Reading(body),
                        Err(_) => return Poll::Ready(Some(Err(io::ErrorKind::BrokenPipe.into()))),
                    }
                }
                Self::Reading(body) => match ready!(Pin::new(&mut body.body).poll_frame(cx)) {
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() && !data.is_empty() {
                            return Poll::Ready(Some(Ok(data)));
                        }
                    }
                    Some(Err(error)) => {
                        *self = Self::Done;
                        return Poll::Ready(Some(Err(io::Error::other(error))));
                    }
                    None => { *self = Self::Done; return Poll::Ready(None); }
                },
                Self::Done => return Poll::Ready(None),
            }
        }
    }
}

struct Control {
    shutdown: bool,
    reply: oneshot::Receiver<()>,
}

pub struct XHttpStream {
    reader: StreamReader<Download, Bytes>,
    sender: PollSender<Command>,
    control: Option<Control>,
    closed: bool,
    shared: Arc<Shared>,
    _tasks: Tasks,
    _leases: Vec<Lease>,
}

impl ProxyStream for XHttpStream {}

impl XHttpStream {
    pub(super) fn new(
        body: oneshot::Receiver<ResponseBody>, sender: mpsc::Sender<Command>, shared: Arc<Shared>,
        tasks: Tasks, leases: Vec<Lease>,
    ) -> Self {
        Self {
            reader: StreamReader::new(Download::Waiting(body)), sender: PollSender::new(sender),
            control: None, closed: false, shared, _tasks: tasks, _leases: leases,
        }
    }

    fn poll_control(&mut self, cx: &mut Context<'_>, shutdown: bool) -> Poll<io::Result<()>> {
        self.shared.write_waker.register(cx.waker());
        self.shared.check()?;
        loop {
            if self.closed { return Poll::Ready(Ok(())); }
            if let Some(control) = &mut self.control {
                if ready!(Pin::new(&mut control.reply).poll(cx)).is_err() {
                    self.shared.check()?;
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
                let done = self.control.take().expect("completed XHTTP control");
                self.closed = done.shutdown;
                if done.shutdown || !shutdown { return Poll::Ready(Ok(())); }
            }
            ready!(self.sender.poll_reserve(cx))
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            let (reply, receiver) = oneshot::channel();
            let command = if shutdown { Command::Shutdown(reply) } else { Command::Flush(reply) };
            self.sender.send_item(command)
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            self.control = Some(Control { shutdown, reply: receiver });
        }
    }
}

impl AsyncRead for XHttpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 { return Poll::Ready(Ok(())); }
        self.shared.read_waker.register(cx.waker());
        self.shared.check()?;
        let result = Pin::new(&mut self.reader).poll_read(cx, buf);
        if let Poll::Ready(Err(error)) = &result {
            self.shared.fail(io::Error::new(error.kind(), error.to_string()));
        }
        result
    }
}

impl AsyncWrite for XHttpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() { return Poll::Ready(Ok(0)); }
        self.shared.write_waker.register(cx.waker());
        self.shared.check()?;
        if self.control.is_some() { ready!(self.poll_control(cx, false))?; }
        if self.closed { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); }
        ready!(self.sender.poll_reserve(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let length = buf.len().min(16_384);
        self.sender.send_item(Command::Data(Bytes::copy_from_slice(&buf[..length])))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Poll::Ready(Ok(length))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_control(cx, false)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_control(cx, true)
    }
}
