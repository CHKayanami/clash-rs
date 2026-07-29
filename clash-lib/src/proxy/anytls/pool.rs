//! Configurable TLS Connection Pool (SessionPool) for AnyTLS outbound

use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;

use super::session::AnyTlsClientSession;

#[derive(Debug, Clone)]
pub struct SessionPoolConfig {
    /// Core connections (minimum sessions kept alive)
    pub min_connections: usize,
    /// Maximum connections allowed in pool
    pub max_connections: usize,
    /// Maximum streams per TLS connection before opening a new connection
    pub max_streams_per_connection: usize,
    /// Idle session timeout
    pub idle_timeout: Duration,
    /// Periodic idle session check interval for active background cleanup
    pub idle_session_check_interval: Duration,
}

impl Default for SessionPoolConfig {
    fn default() -> Self {
        Self {
            min_connections: 1,
            max_connections: 16,
            // A value of 1 meant every connection dialled its own TLS session,
            // so the multiplexing this protocol exists for never happened — and
            // the resulting handshake-per-connection is exactly the traffic
            // shape AnyTLS is meant to hide.
            //
            // The protocol has no per-stream flow control, so the only
            // backpressure available is to stop reading the shared TLS socket:
            // a stalled stream holds up the others on its session. This value
            // trades that head-of-line risk against the obfuscation benefit.
            max_streams_per_connection: 8,
            idle_timeout: Duration::from_secs(60),
            idle_session_check_interval: Duration::from_secs(30),
        }
    }
}

struct SessionPoolInner {
    config: SessionPoolConfig,
    sessions: RwLock<Vec<Arc<AnyTlsClientSession>>>,
}

impl SessionPoolInner {
    /// Prune closed sessions and idle sessions exceeding idle_timeout when pool size > min_connections
    fn prune_sessions(&self) {
        let mut sessions = self.sessions.write();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut i = 0;
        while i < sessions.len() {
            let session = &sessions[i];
            let is_closed = session.is_closed();
            let streams_count = session.active_streams_count();
            let idle_secs = now.saturating_sub(session.last_active_secs());

            let should_prune_idle = streams_count == 0
                && idle_secs >= self.config.idle_timeout.as_secs()
                && sessions.len() > self.config.min_connections;

            if is_closed || should_prune_idle {
                sessions.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }
}

#[derive(Clone)]
pub struct SessionPool {
    inner: Arc<SessionPoolInner>,
}

impl SessionPool {
    pub fn new(config: SessionPoolConfig) -> Self {
        let inner = Arc::new(SessionPoolInner {
            config,
            sessions: RwLock::new(Vec::new()),
        });

        // Spawn periodic active cleanup task
        let inner_weak = Arc::downgrade(&inner);
        let check_interval = inner.config.idle_session_check_interval;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            loop {
                interval.tick().await;
                let inner = match inner_weak.upgrade() {
                    Some(i) => i,
                    None => break, // Exit cleanly when SessionPool is dropped
                };
                inner.prune_sessions();
            }
        });

        Self { inner }
    }

    #[allow(dead_code)]
    pub fn config(&self) -> &SessionPoolConfig {
        &self.inner.config
    }

    /// Explicitly trigger active session pruning
    #[allow(dead_code)]
    pub fn prune_sessions(&self) {
        self.inner.prune_sessions();
    }

    /// Get an available active session with streams count < max_streams_per_connection.
    /// Returns None if a new session needs to be dialed.
    pub async fn get_available_session(&self) -> Option<Arc<AnyTlsClientSession>> {
        self.inner.prune_sessions();

        let guard = self.inner.sessions.read();
        let mut best_session: Option<(usize, Arc<AnyTlsClientSession>)> = None;

        for session in guard.iter() {
            if session.is_closed() {
                continue;
            }

            let stream_count = session.active_streams_count();
            if stream_count < self.inner.config.max_streams_per_connection {
                match &best_session {
                    None => {
                        best_session = Some((stream_count, Arc::clone(session)));
                    }
                    Some((best_count, _)) => {
                        if stream_count < *best_count {
                            best_session = Some((stream_count, Arc::clone(session)));
                        }
                    }
                }
            }
        }

        if let Some((_, session)) = best_session {
            return Some(session);
        }

        if guard.len() >= self.inner.config.max_connections {
            let mut min_streams_session: Option<(usize, Arc<AnyTlsClientSession>)> =
                None;
            for session in guard.iter() {
                if session.is_closed() {
                    continue;
                }
                let count = session.active_streams_count();
                match &min_streams_session {
                    None => {
                        min_streams_session = Some((count, Arc::clone(session)));
                    }
                    Some((min_c, _)) => {
                        if count < *min_c {
                            min_streams_session = Some((count, Arc::clone(session)));
                        }
                    }
                }
            }
            if let Some((_, session)) = min_streams_session {
                return Some(session);
            }
        }

        None
    }

    /// Add a newly created session to the pool
    pub async fn add_session(&self, session: Arc<AnyTlsClientSession>) {
        self.inner.prune_sessions();
        let mut guard = self.inner.sessions.write();
        // Backstop for the cap. `get_available_session` enforces it on the read
        // path, but nothing stopped concurrent creators from pushing past it.
        if guard.len() >= self.inner.config.max_connections {
            tracing::debug!(
                "anytls session pool at capacity ({}), dropping the extra \
                 session",
                self.inner.config.max_connections
            );
            return;
        }
        guard.push(session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::anytls::padding::PaddingFactory;
    use crate::session::SocksAddr;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_pool_defaults() {
        let pool = SessionPool::new(SessionPoolConfig::default());
        assert_eq!(pool.config().min_connections, 1);
        assert_eq!(pool.config().max_connections, 16);
        assert_eq!(pool.config().max_streams_per_connection, 8);
        assert_eq!(pool.config().idle_timeout, Duration::from_secs(60));
        assert_eq!(
            pool.config().idle_session_check_interval,
            Duration::from_secs(30)
        );
        assert!(pool.get_available_session().await.is_none());
    }

    #[tokio::test]
    async fn test_pool_session_reuse_and_concurrency_limit() {
        let config = SessionPoolConfig {
            min_connections: 1,
            max_connections: 2,
            max_streams_per_connection: 2,
            idle_timeout: Duration::from_secs(60),
            idle_session_check_interval: Duration::from_secs(30),
        };
        let pool = SessionPool::new(config);
        let padding = PaddingFactory::default_factory();

        let (c1, _s1) = duplex(4096);
        let sess1 =
            AnyTlsClientSession::new(Box::new(c1), "secret", padding.clone())
                .await
                .unwrap();
        pool.add_session(Arc::clone(&sess1)).await;

        let s = pool.get_available_session().await.unwrap();
        assert!(Arc::ptr_eq(&s, &sess1));

        let dst = SocksAddr::try_from(("1.1.1.1".to_owned(), 80)).unwrap();
        let _st1 = sess1.open_stream(&dst).await.unwrap();
        let _st2 = sess1.open_stream(&dst).await.unwrap();

        assert!(pool.get_available_session().await.is_none());

        let (c2, _s2) = duplex(4096);
        let sess2 = AnyTlsClientSession::new(Box::new(c2), "secret", padding)
            .await
            .unwrap();
        pool.add_session(Arc::clone(&sess2)).await;

        let s_avail = pool.get_available_session().await.unwrap();
        assert!(Arc::ptr_eq(&s_avail, &sess2));
    }

    #[tokio::test]
    async fn test_pool_active_background_pruning() {
        let config = SessionPoolConfig {
            min_connections: 0,
            max_connections: 5,
            max_streams_per_connection: 5,
            idle_timeout: Duration::from_millis(50),
            idle_session_check_interval: Duration::from_millis(50),
        };
        let pool = SessionPool::new(config);
        let padding = PaddingFactory::default_factory();

        let (c1, _s1) = duplex(4096);
        let sess1 = AnyTlsClientSession::new(Box::new(c1), "secret", padding)
            .await
            .unwrap();
        pool.add_session(Arc::clone(&sess1)).await;

        tokio::time::sleep(Duration::from_millis(150)).await;

        // Background task should have actively pruned sess1
        pool.inner.prune_sessions();
        let guard = pool.inner.sessions.read();
        assert_eq!(guard.len(), 0);
    }
}
