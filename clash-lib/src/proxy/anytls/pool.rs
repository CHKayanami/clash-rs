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
        let mut i = 0;
        while i < sessions.len() {
            let session = &sessions[i];
            let is_closed = session.is_closed();
            let should_prune_idle = sessions.len() > self.config.min_connections
                && session.idle_duration().is_some_and(|idle| {
                    idle >= self.config.idle_timeout
                });

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
        let guard = self.inner.sessions.read();
        let mut selected = None;
        let mut minimum = usize::MAX;
        for session in guard.iter().filter(|session| !session.is_closed()) {
            let count = session.total_streams_count();
            if count < minimum
                && count < self.inner.config.max_streams_per_connection
            {
                minimum = count;
                selected = Some(session);
            }
        }
        if let Some(session) = selected {
            if session.try_reserve_stream(self.inner.config.max_streams_per_connection)
            {
                return Some(Arc::clone(session));
            }
            // Another caller won the reservation; try the remaining sessions.
            for session in guard.iter().filter(|session| !session.is_closed()) {
                if session.try_reserve_stream(self.inner.config.max_streams_per_connection)
                {
                    return Some(Arc::clone(session));
                }
            }
        }

        // 若连接池已达到最大连接数限制，回退到全局负载最小的会话并强制分配
        if guard.iter().filter(|session| !session.is_closed()).count()
            >= self.inner.config.max_connections
        {
            if let Some(session) = guard.iter()
                .filter(|session| !session.is_closed())
                .min_by_key(|session| session.total_streams_count())
            {
                session.force_reserve_stream();
                return Some(Arc::clone(session));
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
    use crate::proxy::AnyStream;
    use super::*;
    use crate::proxy::anytls::padding::PaddingFactory;
    use crate::session::SocksAddr;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::time::advance;

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

        fn spawn_mock_server(mut server: tokio::io::DuplexStream) {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                while let Ok(n) = server.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let mut settings = crate::proxy::anytls::types::StringMap::new();
                    settings.insert("v", "1");
                    let frame = crate::proxy::anytls::types::Frame::with_data(
                        crate::proxy::anytls::types::Command::ServerSettings,
                        0,
                        bytes::Bytes::from(settings.to_bytes()),
                    );
                    let mut b = bytes::BytesMut::new();
                    frame.encode_into(&mut b);
                    if server.write_all(&b).await.is_err() {
                        break;
                    }
                }
            });
        }

        let (c1, s1) = duplex(4096);
        spawn_mock_server(s1);
        let sess1 =
            AnyTlsClientSession::new(AnyStream::new(c1), "secret", padding.clone())
                .await
                .unwrap();
        pool.add_session(Arc::clone(&sess1)).await;

        let s = pool.get_available_session().await.unwrap();
        assert!(Arc::ptr_eq(&s, &sess1));

        let dst = SocksAddr::try_from(("1.1.1.1".to_owned(), 80)).unwrap();
        let _st1 = sess1.open_stream(&dst).await.unwrap();
        let _st2 = sess1.open_stream(&dst).await.unwrap();

        assert!(pool.get_available_session().await.is_none());

        let (c2, s2) = duplex(4096);
        spawn_mock_server(s2);
        let sess2 = AnyTlsClientSession::new(AnyStream::new(c2), "secret", padding)
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
        let sess1 = AnyTlsClientSession::new(AnyStream::new(c1), "secret", padding)
            .await
            .unwrap();
        pool.add_session(Arc::clone(&sess1)).await;

        tokio::time::sleep(Duration::from_millis(150)).await;

        // Background task should have actively pruned sess1
        pool.inner.prune_sessions();
        let guard = pool.inner.sessions.read();
        assert_eq!(guard.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_idle_timeout_starts_when_last_stream_exits() {
        let pool = SessionPool::new(SessionPoolConfig {
            min_connections: 0,
            ..SessionPoolConfig::default()
        });
        let (client, _server) = duplex(65536);
        let session = AnyTlsClientSession::new(AnyStream::new(client), "secret",
            PaddingFactory::default_factory()).await.unwrap();
        pool.add_session(Arc::clone(&session)).await;
        let reserved = pool.get_available_session().await.unwrap();
        let dest = SocksAddr::try_from(("example.com".to_owned(), 80)).unwrap();
        let stream = reserved.open_stream(&dest).await.unwrap();
        advance(Duration::from_secs(120)).await;
        pool.prune_sessions();
        assert_eq!(pool.inner.sessions.read().len(), 1);
        drop(stream);
        assert_eq!(session.total_streams_count(), 0);
        assert_eq!(session.idle_duration(), Some(Duration::ZERO));
        advance(Duration::from_secs(59)).await;
        pool.prune_sessions();
        assert_eq!(pool.inner.sessions.read().len(), 1);
        advance(Duration::from_secs(1)).await;
        pool.prune_sessions();
        assert!(pool.inner.sessions.read().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn test_releasing_last_reservation_restarts_idle_timeout() {
        let (client, _server) = duplex(65536);
        let session = AnyTlsClientSession::new(AnyStream::new(client), "secret",
            PaddingFactory::default_factory()).await.unwrap();
        assert!(session.try_reserve_stream(1));
        advance(Duration::from_secs(120)).await;
        session.release_reserved_stream();
        assert_eq!(session.idle_duration(), Some(Duration::ZERO));
    }

    #[tokio::test(start_paused = true)]
    async fn test_pending_reservation_keeps_session_busy_after_stream_closes() {
        let pool = SessionPool::new(SessionPoolConfig {
            min_connections: 0,
            ..SessionPoolConfig::default()
        });
        let (client, _server) = duplex(65536);
        let session = AnyTlsClientSession::new(
            AnyStream::new(client), "secret", PaddingFactory::default_factory(),
        ).await.unwrap();
        pool.add_session(Arc::clone(&session)).await;
        let reserved = pool.get_available_session().await.unwrap();
        let dest = SocksAddr::try_from(("example.com".to_owned(), 80)).unwrap();
        let stream = reserved.open_stream(&dest).await.unwrap();
        let pending = pool.get_available_session().await.unwrap();
        advance(Duration::from_secs(120)).await;
        drop(stream);
        assert_eq!(session.idle_duration(), None);
        pool.prune_sessions();
        assert_eq!(pool.inner.sessions.read().len(), 1);
        advance(Duration::from_secs(120)).await;
        pending.release_reserved_stream();
        assert_eq!(session.idle_duration(), Some(Duration::ZERO));
        pool.prune_sessions();
        assert_eq!(pool.inner.sessions.read().len(), 1);
        advance(Duration::from_secs(60)).await;
        pool.prune_sessions();
        assert!(pool.inner.sessions.read().is_empty());
    }

}
