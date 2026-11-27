use parking_lot::RwLock;
use std::{
    future::Future,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::{
    datagram::H2MuxDatagram,
    session::{H2MuxSession, StreamLease},
};
use crate::{
    proxy::{AnyStream, transport::mux::MuxOption},
    session::SocksAddr,
};

pub(super) struct PoolInner {
    opt: MuxOption,
    sessions: RwLock<Vec<Arc<H2MuxSession>>>,
    connecting: Mutex<()>,
    keep_idle: Arc<AtomicBool>,
}

impl PoolInner {
    pub(super) fn remove_session(&self, target: &Arc<H2MuxSession>) {
        let mut sessions = self.sessions.write();
        sessions.retain(|s| !Arc::ptr_eq(s, target) && !s.is_closed());
    }

    fn close_idle_connections(&self) {
        let mut to_close = Vec::new();
        {
            let mut sessions = self.sessions.write();
            let mut i = 0;
            while i < sessions.len() {
                if sessions[i].is_closed() {
                    sessions.swap_remove(i);
                } else if sessions[i].try_claim_idle_close() {
                    to_close.push(sessions.swap_remove(i));
                } else {
                    i += 1;
                }
            }
        }
        for session in to_close {
            session.begin_graceful_close();
        }
    }
}

impl Drop for PoolInner {
    fn drop(&mut self) {
        self.keep_idle.store(false, Ordering::SeqCst);
        let sessions = std::mem::take(self.sessions.get_mut());
        for session in sessions {
            if session.try_claim_idle_close() {
                session.begin_graceful_close();
            }
        }
    }
}

pub struct H2MuxPool {
    inner: Arc<PoolInner>,
}

impl Drop for H2MuxPool {
    fn drop(&mut self) {
        self.inner.keep_idle.store(false, Ordering::SeqCst);
        self.inner.close_idle_connections();
    }
}

impl H2MuxPool {
    pub fn new(opt: MuxOption) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(PoolInner {
                opt,
                sessions: RwLock::new(Vec::new()),
                connecting: Mutex::new(()),
                keep_idle: Arc::new(AtomicBool::new(true)),
            }),
        })
    }

    pub fn supports_udp(&self) -> bool {
        !self.inner.opt.only_tcp
    }

    pub fn set_keep_idle(&self, keep: bool) {
        self.inner.keep_idle.store(keep, Ordering::SeqCst);
        if !keep {
            self.close_idle_connections();
        }
    }

    pub fn close_idle_connections(&self) {
        self.inner.close_idle_connections();
    }

    #[cfg(test)]
    pub(super) fn session_count_for_test(&self) -> usize {
        self.inner.sessions.read().len()
    }

    #[cfg(test)]
    pub(super) fn sessions_for_test(&self) -> Vec<Arc<H2MuxSession>> {
        self.inner.sessions.read().clone()
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
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "h2mux UDP disabled by only-tcp",
            ));
        }
        let stream = self.open_stream(destination, true, dial_carrier).await?;
        Ok(H2MuxDatagram::new(stream))
    }

    fn choose_session(
        sessions: &[Arc<H2MuxSession>],
        min_streams: usize,
        max_conns: usize,
    ) -> (Option<Arc<H2MuxSession>>, bool) {
        let mut live_count = 0usize;
        let mut best: Option<(&Arc<H2MuxSession>, usize)> = None;
        for session in sessions {
            let Some((active, available)) = session.live_status() else {
                continue;
            };
            live_count += 1;
            if available && best.is_none_or(|(_, min_active)| active < min_active) {
                best = Some((session, active));
            }
        }
        let should_create = live_count < max_conns
            && best.is_none_or(|(_, active)| active >= min_streams);
        (best.map(|(session, _)| session.clone()), should_create)
    }

    async fn acquire_session<F, Fut>(
        &self,
        min_streams: usize,
        max_conns: usize,
        dial_carrier: &F,
    ) -> io::Result<(Arc<H2MuxSession>, StreamLease)>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: Future<Output = io::Result<AnyStream>> + Send,
    {
        loop {
            let (existing, should_create) = {
                let sessions = self.inner.sessions.read();
                Self::choose_session(&sessions, min_streams, max_conns)
            };
            let candidate = if should_create {
                // Only new connections wait on this lock. If another dial is
                // already in progress, an available carrier can be reused.
                let creation_guard = match self.inner.connecting.try_lock() {
                    Ok(guard) => Some(guard),
                    Err(_) if existing.is_some() => None,
                    Err(_) => Some(self.inner.connecting.lock().await),
                };
                if let Some(_creation_guard) = creation_guard {
                    let (existing, should_create) = {
                        let sessions = self.inner.sessions.read();
                        Self::choose_session(&sessions, min_streams, max_conns)
                    };
                    if should_create {
                        debug!("dialing new carrier connection for h2mux session");
                        let carrier = dial_carrier().await?;
                        let new_session = H2MuxSession::new_managed(
                            carrier,
                            self.inner.opt.clone(),
                            self.inner.keep_idle.clone(),
                            Arc::downgrade(&self.inner),
                        )
                        .await?;
                        let lease = new_session.reserve_stream()?;
                        {
                            let mut sessions = self.inner.sessions.write();
                            sessions.retain(|s| !s.is_closed());
                            sessions.push(new_session.clone());
                        }
                        return Ok((new_session, lease));
                    }
                    existing
                } else {
                    existing
                }
            } else {
                existing
            };
            let Some(session) = candidate else {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "h2mux connection and stream limits reached",
                ));
            };
            match session.reserve_stream() {
                Ok(lease) => return Ok((session, lease)),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
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
        let max_conns = if self.inner.opt.max_connections == 0 {
            4
        } else {
            self.inner.opt.max_connections
        };
        let min_streams = if self.inner.opt.min_streams == 0 {
            4
        } else {
            self.inner.opt.min_streams
        };

        let mut last_error = None;
        for attempt in 0..2 {
            let (session, lease) =
                self.acquire_session(min_streams, max_conns, &dial_carrier).await?;

            match session
                .open_stream_with_lease(destination, is_udp, lease)
                .await
            {
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
                    self.inner.remove_session(&session);
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
