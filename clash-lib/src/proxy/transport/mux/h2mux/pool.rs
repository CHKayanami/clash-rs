use parking_lot::RwLock;
use std::{future::Future, io, sync::Arc};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::{datagram::H2MuxDatagram, session::H2MuxSession};
use crate::{
    proxy::{AnyStream, transport::mux::MuxOption},
    session::SocksAddr,
};

pub struct H2MuxPool {
    opt: MuxOption,
    sessions: RwLock<Vec<Arc<H2MuxSession>>>,
    connecting: Mutex<()>,
}

impl H2MuxPool {
    pub fn new(opt: MuxOption) -> Arc<Self> {
        Arc::new(Self {
            opt,
            sessions: RwLock::new(Vec::new()),
            connecting: Mutex::new(()),
        })
    }

    pub fn supports_udp(&self) -> bool {
        !self.opt.only_tcp
    }

    pub async fn open_datagram<F, Fut>(
        &self,
        destination: &SocksAddr,
        dial_carrier: F,
    ) -> io::Result<H2MuxDatagram>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: Future<Output = io::Result<AnyStream>> + Send,
    {
        if !self.supports_udp() {
            return Err(io::Error::new(io::ErrorKind::Unsupported,
                "h2mux UDP disabled by only-tcp"));
        }
        let stream = self.open_stream(destination, true, dial_carrier).await?;
        Ok(H2MuxDatagram::new(stream))
    }

    fn choose_session(
        sessions: &[Arc<H2MuxSession>],
        min_streams: usize,
        max_conns: usize,
    ) -> (Option<Arc<H2MuxSession>>, bool) {
        let best = sessions
            .iter()
            .filter(|s| s.is_available())
            .min_by_key(|s| s.active_streams())
            .cloned();
        let live_count = sessions.iter().filter(|s| !s.is_closed()).count();
        let should_create = live_count < max_conns
            && best
                .as_ref()
                .is_none_or(|s| s.active_streams() >= min_streams);
        (best, should_create)
    }

    pub async fn open_stream<F, Fut>(
        &self,
        destination: &SocksAddr,
        is_udp: bool,
        dial_carrier: F,
    ) -> io::Result<AnyStream>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: Future<Output = io::Result<AnyStream>> + Send,
    {
        let max_conns = if self.opt.max_connections == 0 {
            4
        } else {
            self.opt.max_connections
        };
        let min_streams = if self.opt.min_streams == 0 {
            4
        } else {
            self.opt.min_streams
        };

        let mut last_error = None;
        for attempt in 0..2 {
            let (existing, should_create) = {
                let sessions = self.sessions.read();
                Self::choose_session(&sessions, min_streams, max_conns)
            };
            let session = if should_create {
                // Only new connections wait on this lock. If another dial is
                // already in progress, an available carrier can be reused.
                let creation_guard = match self.connecting.try_lock() {
                    Ok(guard) => Some(guard),
                    Err(_) if existing.is_some() => None,
                    Err(_) => Some(self.connecting.lock().await),
                };
                if let Some(_creation_guard) = creation_guard {
                    // Another creator may have filled the slot while we waited.
                    let (existing, should_create) = {
                        let sessions = self.sessions.read();
                        Self::choose_session(&sessions, min_streams, max_conns)
                    };
                    if should_create {
                        debug!("dialing new carrier connection for h2mux session");
                        let carrier = dial_carrier().await?;
                        let new_session =
                            H2MuxSession::new(carrier, self.opt.clone()).await?;
                        let mut sessions = self.sessions.write();
                        sessions.retain(|s| !s.is_closed());
                        sessions.push(new_session.clone());
                        new_session
                    } else {
                        existing.ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::WouldBlock,
                                "h2mux connection and stream limits reached",
                            )
                        })?
                    }
                } else {
                    existing.expect("available session was checked above")
                }
            } else {
                existing.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "h2mux connection and stream limits reached",
                    )
                })?
            };

            match session.open_stream(destination, is_udp).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    warn!("h2mux open_stream failed (attempt {attempt}): {e}");
                    if e.kind() == io::ErrorKind::WouldBlock {
                        last_error = Some(e);
                        continue;
                    }
                    if e.kind() == io::ErrorKind::InvalidInput {
                        return Err(e);
                    }
                    session.retire();
                    let mut sessions = self.sessions.write();
                    sessions.retain(|s| !Arc::ptr_eq(s, &session) && !s.is_closed());
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "failed to open h2mux stream after retry",
            )
        }))
    }
}
