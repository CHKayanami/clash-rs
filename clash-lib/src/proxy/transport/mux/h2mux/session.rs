use bytes::Bytes;
use futures::future::poll_fn;
use h2::client::{Builder, SendRequest};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::task::AbortHandle;
use tokio::sync::Mutex;
use tracing::debug;

use super::{
    padding::PaddingStream,
    protocol::{SessionRequest, StreamRequest, build_h2_connect_request},
    stream::H2MuxStream,
};
use crate::{
    common::errors::map_io_error,
    proxy::{AnyStream, transport::mux::MuxOption},
    session::SocksAddr,
};

pub struct StreamLease {
    session: Arc<H2MuxSession>,
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        self.session.active_streams.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct H2MuxSession {
    send_request: Mutex<SendRequest<Bytes>>,
    active_streams: AtomicUsize,
    closed: Arc<AtomicBool>,
    driver: AbortHandle,
    opt: MuxOption,
}

impl H2MuxSession {
    pub async fn new(
        mut carrier: AnyStream,
        opt: MuxOption,
    ) -> io::Result<Arc<Self>> {
        // Send sing-box session request header over raw carrier stream
        let session_req = SessionRequest::new_h2mux(opt.padding);
        session_req.write(&mut carrier).await?;
        if opt.padding {
            carrier = AnyStream::new(PaddingStream::new(carrier));
        }

        let mut builder = Builder::new();
        builder.initial_window_size(4 * 1024 * 1024);
        builder.initial_connection_window_size(16 * 1024 * 1024);
        builder.max_concurrent_streams(1024);
        builder.enable_push(false);

        let (send_request, connection) =
            builder.handshake(carrier).await.map_err(map_io_error)?;

        let closed = Arc::new(AtomicBool::new(false));
        let closed_clone = closed.clone();

        let driver = tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!("h2mux connection closed: {}", e);
            }
            closed_clone.store(true, Ordering::Release);
        });

        Ok(Arc::new(Self {
            send_request: Mutex::new(send_request),
            active_streams: AtomicUsize::new(0),
            closed,
            driver: driver.abort_handle(),
            opt,
        }))
    }

    /// Stop using a carrier immediately after a connection-level failure.
    pub fn retire(&self) {
        self.closed.store(true, Ordering::Release);
        self.driver.abort();
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn active_streams(&self) -> usize {
        self.active_streams.load(Ordering::Relaxed)
    }

    pub fn is_available(&self) -> bool {
        if self.is_closed() {
            return false;
        }
        let active = self.active_streams();
        if self.opt.max_streams > 0 && active >= self.opt.max_streams {
            return false;
        }
        true
    }

    fn reserve_stream(self: &Arc<Self>) -> io::Result<StreamLease> {
        self.active_streams.try_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
            if self.opt.max_streams > 0 && active >= self.opt.max_streams {
                None
            } else {
                active.checked_add(1)
            }
        }).map_err(|_| io::Error::new(io::ErrorKind::WouldBlock,
            "h2mux stream limit reached"))?;
        Ok(StreamLease { session: self.clone() })
    }

    pub async fn open_stream(
        self: &Arc<Self>,
        destination: &SocksAddr,
        is_udp: bool,
    ) -> io::Result<AnyStream> {
        // Validate the destination before opening an H2 stream. A malformed
        // address is a caller error and must not retire a healthy carrier.
        let request_bytes =
            Bytes::from(StreamRequest::new(destination.clone(), is_udp).encode()?);
        let req = build_h2_connect_request()?;
        if self.is_closed() {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "h2mux session is closed"));
        }
        // Reserve before any await; cancellation and errors release the slot.
        let lease = self.reserve_stream()?;
        let (resp, send_stream) = {
            // Keep this handle's pending-open state across requests. Cloning
            // SendRequest resets that state and bypasses peer backpressure.
            let mut sender = self.send_request.lock().await;
            poll_fn(|cx| sender.poll_ready(cx)).await.map_err(map_io_error)?;
            sender.send_request(req, false).map_err(map_io_error)?
        };
        let stream = H2MuxStream::new(resp, send_stream, request_bytes, Some(lease));

        Ok(AnyStream::new(stream))
    }
}

impl Drop for H2MuxSession {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
