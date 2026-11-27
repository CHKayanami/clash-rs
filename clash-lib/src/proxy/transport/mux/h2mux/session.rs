use bytes::Bytes;
use futures::future::poll_fn;
use h2::client::SendRequest;
use parking_lot::Mutex as ParkingMutex;
use std::{
    io,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{runtime::Handle, sync::Mutex, time::timeout};

use super::{
    padding::PaddingStream,
    pool::PoolInner,
    protocol::{SessionRequest, StreamRequest, build_h2_connect_request},
    stream::H2MuxStream,
};
use crate::{
    common::errors::map_io_error,
    proxy::{
        AnyStream,
        transport::{
            h2_common::{ConnectionDriver, ConnectionState, client_builder},
            mux::MuxOption,
        },
    },
    session::SocksAddr,
};

const H2MUX_CLOSING_BIT: usize = 1usize << (usize::BITS - 1);
const H2MUX_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub struct StreamLease {
    session: Arc<H2MuxSession>,
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        self.session.release_lease();
    }
}

pub struct H2MuxSession {
    send_request: Arc<Mutex<Option<SendRequest<Bytes>>>>,
    active_streams: AtomicUsize,
    driver_state: Arc<ConnectionState>,
    driver: ParkingMutex<Option<ConnectionDriver>>,
    keep_idle: Arc<AtomicBool>,
    pool: Weak<PoolInner>,
    runtime: Handle,
    drain_timeout_ms: AtomicU64,
    opt: MuxOption,
}

impl H2MuxSession {
    #[cfg(test)]
    pub async fn new(
        carrier: AnyStream,
        opt: MuxOption,
    ) -> io::Result<Arc<Self>> {
        Self::new_managed(
            carrier,
            opt,
            Arc::new(AtomicBool::new(true)),
            Weak::new(),
        )
        .await
    }

    pub(super) async fn new_managed(
        mut carrier: AnyStream,
        opt: MuxOption,
        keep_idle: Arc<AtomicBool>,
        pool: Weak<PoolInner>,
    ) -> io::Result<Arc<Self>> {
        // Send sing-box session request header over raw carrier stream
        let session_req = SessionRequest::new_h2mux(opt.padding);
        session_req.write(&mut carrier).await?;
        if opt.padding {
            carrier = AnyStream::new(PaddingStream::new(carrier));
        }

        let mut builder = client_builder();
        builder.initial_window_size(4 * 1024 * 1024);
        builder.initial_connection_window_size(16 * 1024 * 1024);
        builder.max_concurrent_streams(1024);

        let (send_request, connection) =
            builder.handshake(carrier).await.map_err(map_io_error)?;

        let driver = ConnectionDriver::spawn(connection, None);
        let driver_state = driver.state();

        Ok(Arc::new(Self {
            send_request: Arc::new(Mutex::new(Some(send_request))),
            active_streams: AtomicUsize::new(0),
            driver_state,
            driver: ParkingMutex::new(Some(driver)),
            keep_idle,
            pool,
            runtime: Handle::current(),
            drain_timeout_ms: AtomicU64::new(
                H2MUX_DRAIN_TIMEOUT.as_millis() as u64,
            ),
            opt,
        }))
    }

    fn drain_timeout(&self) -> Duration {
        Duration::from_millis(self.drain_timeout_ms.load(Ordering::Relaxed))
    }

    #[cfg(test)]
    pub(super) fn set_drain_timeout_for_test(&self, timeout: Duration) {
        self.drain_timeout_ms
            .store(timeout.as_millis().max(1) as u64, Ordering::Relaxed);
    }

    /// Stop using a carrier immediately after a connection-level failure.
    pub fn retire(&self) {
        self.active_streams
            .fetch_or(H2MUX_CLOSING_BIT, Ordering::SeqCst);
        self.driver_state.close();
        self.driver.lock().take();
        if let Ok(mut sender) = self.send_request.try_lock() {
            sender.take();
        }
    }

    pub fn is_closing(&self) -> bool {
        (self.active_streams.load(Ordering::Acquire) & H2MUX_CLOSING_BIT) != 0
    }

    pub fn is_closed(&self) -> bool {
        self.is_closing() || self.driver_state.closed()
    }

    #[cfg(test)]
    pub fn active_streams(&self) -> usize {
        self.active_streams.load(Ordering::Acquire) & !H2MUX_CLOSING_BIT
    }

    /// Returns `(active_streams, can_accept_more)` if the session is still open.
    pub(super) fn live_status(&self) -> Option<(usize, bool)> {
        let raw = self.active_streams.load(Ordering::Acquire);
        if (raw & H2MUX_CLOSING_BIT) != 0 || self.driver_state.closed() {
            return None;
        }
        let available = self.opt.max_streams == 0 || raw < self.opt.max_streams;
        Some((raw, available))
    }

    #[cfg(test)]
    pub fn is_available(&self) -> bool {
        self.live_status().is_some_and(|(_, available)| available)
    }

    fn should_keep_idle(&self) -> bool {
        self.keep_idle.load(Ordering::SeqCst)
    }

    pub(super) fn try_claim_idle_close(&self) -> bool {
        self.active_streams
            .compare_exchange(
                0,
                H2MUX_CLOSING_BIT,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    pub(super) fn begin_graceful_close(&self) {
        self.active_streams
            .fetch_or(H2MUX_CLOSING_BIT, Ordering::SeqCst);
        let Some(mut driver) = self.driver.lock().take() else {
            return;
        };
        let send_request = self.send_request.clone();
        let drain_timeout = self.drain_timeout();
        // Do not capture `Arc<H2MuxSession>`: external callers and active
        // `StreamLease`s own session lifetime; the driver task only keeps the
        // HTTP/2 connection running until queued frames flush or drain times out.
        self.runtime.spawn(async move {
            {
                let mut guard = send_request.lock().await;
                guard.take();
            }
            let _ = timeout(drain_timeout, driver.wait()).await;
            drop(driver);
        });
    }

    fn release_lease(self: &Arc<Self>) {
        let keep_idle = self.should_keep_idle();
        let mut closed_now = false;
        let mut became_zero = false;
        let _ = self.active_streams.try_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |val| {
                let closing = (val & H2MUX_CLOSING_BIT) != 0;
                let count = (val & !H2MUX_CLOSING_BIT).saturating_sub(1);
                let next_closing = closing || (!keep_idle && count == 0);
                closed_now = !closing && next_closing;
                became_zero = !next_closing && count == 0;
                Some(if next_closing {
                    H2MUX_CLOSING_BIT | count
                } else {
                    count
                })
            },
        );
        if closed_now {
            if let Some(pool) = self.pool.upgrade() {
                pool.remove_session(self);
            }
            self.begin_graceful_close();
        } else if became_zero && !self.should_keep_idle() && self.try_claim_idle_close()
        {
            // Re-check `keep_idle` / `evicted` after publishing zero (SeqCst)
            // so a concurrent `set_keep_idle(false)` or eviction cannot miss.
            if let Some(pool) = self.pool.upgrade() {
                pool.remove_session(self);
            }
            self.begin_graceful_close();
        }
    }

    pub(super) fn reserve_stream(self: &Arc<Self>) -> io::Result<StreamLease> {
        let mut closing = false;
        self.active_streams
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |val| {
                if (val & H2MUX_CLOSING_BIT) != 0 {
                    closing = true;
                    return None;
                }
                if self.opt.max_streams > 0 && val >= self.opt.max_streams {
                    return None;
                }
                val.checked_add(1)
            })
            .map_err(|_| {
                if closing {
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "h2mux session is closing",
                    )
                } else {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "h2mux stream limit reached",
                    )
                }
            })?;
        Ok(StreamLease {
            session: self.clone(),
        })
    }

    #[cfg(test)]
    pub async fn open_stream(
        self: &Arc<Self>,
        destination: &SocksAddr,
        is_udp: bool,
    ) -> io::Result<AnyStream> {
        let lease = self.reserve_stream()?;
        self.open_stream_with_lease(destination, is_udp, lease).await
    }

    pub(super) async fn open_stream_with_lease(
        self: &Arc<Self>,
        destination: &SocksAddr,
        is_udp: bool,
        lease: StreamLease,
    ) -> io::Result<AnyStream> {
        // Validate the destination before opening an H2 stream. A malformed
        // address is a caller error and must not retire a healthy carrier.
        let request_bytes =
            Bytes::from(StreamRequest::new(destination.clone(), is_udp).encode()?);
        let req = build_h2_connect_request()?;
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "h2mux session is closed",
            ));
        }
        let (resp, send_stream) = {
            // Keep this handle's pending-open state across requests. Cloning
            // SendRequest resets that state and bypasses peer backpressure.
            let mut sender = self.send_request.lock().await;
            let sender = sender.as_mut().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "h2mux session is closed",
                )
            })?;
            poll_fn(|cx| sender.poll_ready(cx))
                .await
                .map_err(map_io_error)?;
            sender.send_request(req, false).map_err(map_io_error)?
        };
        let stream =
            H2MuxStream::new(resp, send_stream, request_bytes, Some(lease));

        Ok(AnyStream::new(stream))
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
