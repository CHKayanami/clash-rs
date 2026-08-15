use std::{
    future::Future,
    io,
    sync::Arc,
};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::session::H2MuxSession;
use crate::{
    proxy::{AnyStream, transport::mux::MuxOption},
    session::SocksAddr,
};

pub struct H2MuxPool {
    opt: MuxOption,
    sessions: Mutex<Vec<Arc<H2MuxSession>>>,
}

impl H2MuxPool {
    pub fn new(opt: MuxOption) -> Arc<Self> {
        Arc::new(Self {
            opt,
            sessions: Mutex::new(Vec::new()),
        })
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

        for attempt in 0..2 {
            let session = {
                let mut sessions = self.sessions.lock().await;
                // Retain only alive sessions
                sessions.retain(|s| !s.is_closed());

                // Find candidate with lowest active stream count
                let mut best_idx = None;
                let mut min_active = usize::MAX;

                for (i, s) in sessions.iter().enumerate() {
                    if s.is_available() {
                        let active = s.active_streams();
                        if active < min_active {
                            min_active = active;
                            best_idx = Some(i);
                        }
                    }
                }

                // If no available session or all sessions have >= min_streams and we can add more connections
                let need_new = match best_idx {
                    None => true,
                    Some(_) if min_active >= min_streams && sessions.len() < max_conns => true,
                    _ => false,
                };

                if need_new && sessions.len() < max_conns {
                    drop(sessions);
                    debug!("dialing new carrier connection for h2mux session");
                    let carrier = dial_carrier().await?;
                    let new_session = H2MuxSession::new(carrier, self.opt.clone()).await?;
                    let mut sessions = self.sessions.lock().await;
                    sessions.retain(|s| !s.is_closed());
                    sessions.push(new_session.clone());
                    new_session
                } else if let Some(i) = best_idx {
                    sessions[i].clone()
                } else {
                    // All sessions full and max_connections reached: try creating or return error
                    drop(sessions);
                    let carrier = dial_carrier().await?;
                    let new_session = H2MuxSession::new(carrier, self.opt.clone()).await?;
                    let mut sessions = self.sessions.lock().await;
                    sessions.retain(|s| !s.is_closed());
                    sessions.push(new_session.clone());
                    new_session
                }
            };

            match session.open_stream(destination, is_udp).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    warn!("h2mux open_stream failed (attempt {attempt}): {e}");
                    let mut sessions = self.sessions.lock().await;
                    sessions.retain(|s| !Arc::ptr_eq(s, &session) && !s.is_closed());
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "failed to open h2mux stream after retry",
        ))
    }
}
