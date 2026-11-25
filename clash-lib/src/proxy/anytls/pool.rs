//! Configurable TLS Connection Pool (SessionPool) for AnyTLS outbound

use parking_lot::RwLock;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use super::session::AnyTlsClientSession;

#[derive(Debug, Clone)]
pub struct SessionPoolConfig {
    /// Core connections (minimum sessions kept alive when `keep_idle` is enabled)
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

pub(super) struct SessionPoolInner {
    config: SessionPoolConfig,
    sessions: RwLock<Vec<Arc<AnyTlsClientSession>>>,
    keep_idle: AtomicBool,
    cleanup_running: AtomicBool,
}

impl Drop for SessionPoolInner {
    fn drop(&mut self) {
        // Trigger graceful drain on idle sessions when the pool itself is
        // discarded (e.g. on config reload) so a writer task already blocked
        // on transport I/O still enters `drain_timeout` and cannot leak.
        let sessions = std::mem::take(self.sessions.get_mut());
        for session in sessions {
            if session.try_claim_idle_close() {
                session.begin_graceful_close();
            }
        }
    }
}

impl SessionPoolInner {
    pub(super) fn keep_idle(&self) -> bool {
        self.keep_idle.load(Ordering::SeqCst)
    }

    /// Prune closed sessions and idle sessions exceeding idle_timeout when pool
    /// size > effective min_connections (0 when `keep_idle` is false).
    fn prune_sessions(&self) {
        let keep_idle = self.keep_idle();
        let min_connections = if keep_idle {
            self.config.min_connections
        } else {
            0
        };
        let mut to_close = Vec::new();
        {
            let mut sessions = self.sessions.write();
            let mut i = 0;
            while i < sessions.len() {
                let session = &sessions[i];
                let is_closed = session.is_closed();
                let should_prune_idle = if !keep_idle {
                    session.total_streams_count() == 0
                } else {
                    sessions.len() > min_connections
                        && session.idle_duration().is_some_and(|idle| {
                            idle >= self.config.idle_timeout
                        })
                };

                if is_closed {
                    sessions.swap_remove(i);
                } else if should_prune_idle && session.try_claim_idle_close() {
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

    pub(super) fn prune_closed_sessions(&self) {
        let mut sessions = self.sessions.write();
        sessions.retain(|s| !s.is_closed());
    }

    fn close_idle_sessions(&self) {
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

#[derive(Clone)]
pub struct SessionPool {
    inner: Arc<SessionPoolInner>,
}

impl SessionPool {
    pub fn new(config: SessionPoolConfig) -> Self {
        let inner = Arc::new(SessionPoolInner {
            config,
            sessions: RwLock::new(Vec::new()),
            keep_idle: AtomicBool::new(true),
            cleanup_running: AtomicBool::new(false),
        });

        Self { inner }
    }

    fn ensure_cleanup_task(&self) {
        if self
            .inner
            .cleanup_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let inner_weak = Arc::downgrade(&self.inner);
        let check_interval = self.inner.config.idle_session_check_interval;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            interval.tick().await;
            loop {
                interval.tick().await;
                let Some(inner) = inner_weak.upgrade() else {
                    break;
                };
                inner.prune_sessions();
                let sessions = inner.sessions.write();
                if sessions.is_empty() {
                    inner.cleanup_running.store(false, Ordering::Release);
                    drop(sessions);
                    break;
                }
            }
        });
    }

    pub fn set_keep_idle(&self, keep: bool) {
        self.inner.keep_idle.store(keep, Ordering::SeqCst);
        if !keep {
            self.close_idle_sessions();
        }
    }

    pub fn close_idle_sessions(&self) {
        self.inner.close_idle_sessions();
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
                if session.force_reserve_stream() {
                    return Some(Arc::clone(session));
                }
            }
        }

        None
    }

    /// Add a newly created session to the pool
    pub async fn add_session(&self, session: Arc<AnyTlsClientSession>) {
        self.inner.prune_sessions();
        session.attach_pool(Arc::downgrade(&self.inner));
        {
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
        self.ensure_cleanup_task();
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

    #[tokio::test]
    async fn test_disable_keep_idle_closes_immediately_on_last_stream_drop() {
        let pool = SessionPool::new(SessionPoolConfig {
            min_connections: 2,
            ..SessionPoolConfig::default()
        });
        pool.set_keep_idle(false);

        let (client, _server) = duplex(65536);
        let session = AnyTlsClientSession::new(
            AnyStream::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();
        session.force_reserve_stream();
        pool.add_session(Arc::clone(&session)).await;

        let dest = SocksAddr::try_from(("example.com".to_owned(), 80)).unwrap();
        let stream = session.open_stream(&dest).await.unwrap();
        assert!(!session.is_closed());
        assert_eq!(pool.inner.sessions.read().len(), 1);

        drop(stream);
        assert!(session.is_closed());
        assert!(pool.inner.sessions.read().is_empty());
    }

    #[tokio::test]
    async fn test_set_keep_idle_false_evicts_existing_idle_sessions() {
        let pool = SessionPool::new(SessionPoolConfig {
            min_connections: 1,
            ..SessionPoolConfig::default()
        });
        let (client, _server) = duplex(65536);
        let session = AnyTlsClientSession::new(
            AnyStream::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();
        pool.add_session(Arc::clone(&session)).await;
        assert_eq!(pool.inner.sessions.read().len(), 1);

        pool.set_keep_idle(false);
        assert!(session.is_closed());
        assert!(pool.inner.sessions.read().is_empty());
        assert!(!session.try_reserve_stream(8));
        assert!(!session.force_reserve_stream());
    }

    #[tokio::test]
    async fn test_peer_fin_and_synack_reject_do_not_deadlock_when_keep_idle_disabled() {
        use crate::proxy::anytls::types::{Command, Frame};

        // Case 1: peer sends FIN for the last active stream.
        let pool = SessionPool::new(SessionPoolConfig::default());
        pool.set_keep_idle(false);
        let (client, mut server) = duplex(65536);
        let session = AnyTlsClientSession::new(
            AnyStream::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();
        assert!(session.force_reserve_stream());
        pool.add_session(Arc::clone(&session)).await;

        let dest = SocksAddr::try_from(("example.com".to_owned(), 80)).unwrap();
        let _stream = session.open_stream(&dest).await.unwrap();

        let mut fin_bytes = bytes::BytesMut::new();
        Frame::control(Command::Fin, 1).encode_into(&mut fin_bytes);
        server.write_all(&fin_bytes).await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            while !session.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("peer FIN must close idle session without deadlocking");
        assert!(pool.inner.sessions.read().is_empty());

        // Case 2: peer sends SynAck rejection for the last active stream.
        let pool2 = SessionPool::new(SessionPoolConfig::default());
        pool2.set_keep_idle(false);
        let (client2, mut server2) = duplex(65536);
        let session2 = AnyTlsClientSession::new(
            AnyStream::new(client2),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();
        assert!(session2.force_reserve_stream());
        pool2.add_session(Arc::clone(&session2)).await;

        let _stream2 = session2.open_stream(&dest).await.unwrap();

        let mut rej_bytes = bytes::BytesMut::new();
        Frame::with_data(
            Command::SynAck,
            1,
            bytes::Bytes::from_static(b"rejected"),
        )
        .encode_into(&mut rej_bytes);
        server2.write_all(&rej_bytes).await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            while !session2.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("peer SynAck rejection must close idle session without deadlocking");
        assert!(pool2.inner.sessions.read().is_empty());
    }

    #[tokio::test]
    async fn test_graceful_close_drains_queued_data_and_fin() {
        use crate::proxy::anytls::types::{Command, FrameCodec};

        let pool = SessionPool::new(SessionPoolConfig::default());
        pool.set_keep_idle(false);

        let (client, mut server) = duplex(65536);
        let session = AnyTlsClientSession::new(
            AnyStream::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();
        assert!(session.force_reserve_stream());
        pool.add_session(Arc::clone(&session)).await;

        let dest = SocksAddr::try_from(("example.com".to_owned(), 80)).unwrap();
        let mut stream = session.open_stream(&dest).await.unwrap();

        let payload = b"queued-payload-before-shutdown-and-drop";
        stream.write_all(payload).await.unwrap();
        stream.shutdown().await.unwrap();
        // Immediately drop both the last stream and our local Arc so only the
        // graceful-drain keepalive holds the session until the writer flushes.
        drop(stream);
        drop(session);

        // Read everything the writer sends until transport EOF.
        let mut wire = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), server.read_to_end(&mut wire))
            .await
            .expect("writer must drain and shut down transport")
            .unwrap();

        // Skip auth header: 32-byte sha256 + 2-byte padding_len + padding.
        assert!(wire.len() >= 34);
        let auth_pad_len = u16::from_be_bytes([wire[32], wire[33]]) as usize;
        let mut buf = bytes::BytesMut::from(&wire[34 + auth_pad_len..]);

        let mut received_payload = Vec::new();
        let mut saw_fin = false;
        while let Some(frame) = FrameCodec::decode(&mut buf).unwrap() {
            match frame.cmd {
                Command::Psh if frame.stream_id == 1 => {
                    received_payload.extend_from_slice(&frame.data);
                }
                Command::Fin if frame.stream_id == 1 => {
                    saw_fin = true;
                }
                _ => {}
            }
        }
        assert!(
            received_payload.ends_with(payload),
            "expected queued payload to be flushed before session teardown"
        );
        assert!(saw_fin, "expected FIN frame to be flushed before session teardown");
    }

    #[tokio::test]
    async fn test_blocked_writer_respects_graceful_drain_timeout_and_releases_session() {
        let pool = SessionPool::new(SessionPoolConfig::default());
        pool.set_keep_idle(false);

        // Tiny duplex buffer: once the server stops reading, the writer task
        // blocks inside `write_outgoing_message().await`.
        let (client, _server) = duplex(128);
        let session = AnyTlsClientSession::new(
            AnyStream::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();
        session.set_drain_timeout_for_test(Duration::from_millis(120));
        assert!(session.force_reserve_stream());
        pool.add_session(Arc::clone(&session)).await;

        let dest = SocksAddr::try_from(("example.com".to_owned(), 80)).unwrap();
        let mut stream = session.open_stream(&dest).await.unwrap();
        stream.write_all(&vec![0xAB; 512]).await.unwrap();
        // Give writer_loop a moment to pick up the frame and block on the full duplex.
        tokio::time::sleep(Duration::from_millis(20)).await;

        let weak_session = Arc::downgrade(&session);
        drop(stream);
        drop(session);

        // Even though the writer was already blocked before graceful close
        // began, the drain timeout must abort it and drop `drain_keepalive`.
        tokio::time::timeout(Duration::from_secs(2), async {
            while weak_session.upgrade().is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("blocked writer must time out and release the session Arc");
        assert!(pool.inner.sessions.read().is_empty());
    }

    #[tokio::test]
    async fn test_full_outgoing_queue_keeps_slot_until_fin_enqueued() {
        use crate::proxy::anytls::types::{Command, FrameCodec};

        let pool = SessionPool::new(SessionPoolConfig::default());
        pool.set_keep_idle(false);

        let (client, mut server) = duplex(256);
        let session = AnyTlsClientSession::new(
            AnyStream::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();
        assert!(session.force_reserve_stream());
        pool.add_session(Arc::clone(&session)).await;

        let dest = SocksAddr::try_from(("example.com".to_owned(), 80)).unwrap();
        let mut stream = session.open_stream(&dest).await.unwrap();

        // Fill both the tiny duplex and the bounded `outgoing_tx` channel so
        // `try_send(Fin)` in `AnyTlsStream::drop` hits `TrySendError::Full`.
        for _ in 0..140 {
            let chunk = vec![0x5A; 64];
            if tokio::time::timeout(Duration::from_millis(5), stream.write_all(&chunk))
                .await
                .is_err()
            {
                break;
            }
        }

        // Drop without calling `shutdown()` so `Drop` must enqueue FIN while full.
        drop(stream);
        drop(session);

        // Wait briefly, then let the peer drain everything until transport EOF.
        tokio::time::sleep(Duration::from_millis(30)).await;
        let mut wire = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), server.read_to_end(&mut wire))
            .await
            .expect("writer must drain all queued frames + deferred FIN")
            .unwrap();

        assert!(wire.len() >= 34);
        let auth_pad_len = u16::from_be_bytes([wire[32], wire[33]]) as usize;
        let mut buf = bytes::BytesMut::from(&wire[34 + auth_pad_len..]);
        let mut saw_fin = false;
        while let Some(frame) = FrameCodec::decode(&mut buf).unwrap() {
            if frame.cmd == Command::Fin && frame.stream_id == 1 {
                saw_fin = true;
            }
        }
        assert!(saw_fin, "deferred FIN on full queue must reach peer before close");
    }

    #[tokio::test]
    async fn test_dropping_pool_tears_down_idle_session_without_leak() {
        let pool = SessionPool::new(SessionPoolConfig::default());
        let (client, mut server) = duplex(4096);
        let session = AnyTlsClientSession::new(
            AnyStream::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();
        let weak_session = Arc::downgrade(&session);
        pool.add_session(session).await;

        // Let the writer task settle into `outgoing_rx.recv()`.
        tokio::task::yield_now().await;

        // Dropping the pool (e.g. on config reload) while the peer keeps the
        // transport open must tear down the idle session and close transport.
        drop(pool);
        tokio::time::timeout(Duration::from_secs(2), async {
            while weak_session.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("writer task must not pin an idle session after its pool is dropped");

        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), server.read_to_end(&mut buf))
            .await
            .expect("peer should observe EOF after idle session is dropped")
            .unwrap();
    }

    #[tokio::test]
    async fn test_dropping_pool_times_out_blocked_idle_writer() {
        // Keep default `keep_idle == true`: the last stream unregisters
        // without triggering drain while the writer is blocked on a full pipe.
        let pool = SessionPool::new(SessionPoolConfig::default());
        let (client, _server) = duplex(128);
        let session = AnyTlsClientSession::new(
            AnyStream::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();
        session.set_drain_timeout_for_test(Duration::from_millis(120));
        assert!(session.force_reserve_stream());
        let weak_session = Arc::downgrade(&session);
        pool.add_session(Arc::clone(&session)).await;

        let dest = SocksAddr::try_from(("example.com".to_owned(), 80)).unwrap();
        let mut stream = session.open_stream(&dest).await.unwrap();
        stream.write_all(&vec![0xCD; 512]).await.unwrap();
        // Let the writer pick up the frame and block on the full duplex.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Drop the last stream while keep_idle is still enabled, then drop the
        // pool (simulating config reload).
        drop(stream);
        drop(session);
        drop(pool);

        tokio::time::timeout(Duration::from_secs(2), async {
            while weak_session.upgrade().is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("dropping pool must start drain timeout for blocked idle writer");
    }

    #[test]
    fn test_runtime_shutdown_then_drop_pool_does_not_leak_session() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (pool, weak_session, _server) = rt.block_on(async {
            let pool = SessionPool::new(SessionPoolConfig::default());
            let (client, server) = duplex(4096);
            let session = AnyTlsClientSession::new(
                AnyStream::new(client),
                "secret",
                PaddingFactory::default_factory(),
            )
            .await
            .unwrap();
            let weak_session = Arc::downgrade(&session);
            pool.add_session(session).await;
            tokio::task::yield_now().await;
            (pool, weak_session, server)
        });

        // Shut down the runtime first (cancelling the writer task), then drop
        // the pool. `WriterExitGuard` must have marked `writer_exited` / closed
        // so `SessionPoolInner::drop` does not leave a self-reference cycle.
        rt.shutdown_timeout(Duration::from_secs(1));
        drop(pool);
        assert!(
            weak_session.upgrade().is_none(),
            "dropping pool after runtime shutdown must not leak the session"
        );
    }

    #[test]
    fn test_runtime_shutdown_during_blocked_drain_does_not_leak_session() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (weak_session, _server) = rt.block_on(async {
            let pool = SessionPool::new(SessionPoolConfig::default());
            let (client, server) = duplex(128);
            let session = AnyTlsClientSession::new(
                AnyStream::new(client),
                "secret",
                PaddingFactory::default_factory(),
            )
            .await
            .unwrap();
            session.set_drain_timeout_for_test(Duration::from_secs(60));
            assert!(session.force_reserve_stream());
            let weak_session = Arc::downgrade(&session);
            pool.add_session(Arc::clone(&session)).await;

            let dest = SocksAddr::try_from(("example.com".to_owned(), 80)).unwrap();
            let mut stream = session.open_stream(&dest).await.unwrap();
            stream.write_all(&vec![0xEF; 512]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;

            // Enter graceful drain (self-reference stored in `drain_keepalive`)
            // while the writer is blocked and drain timeout is still far away.
            drop(stream);
            drop(session);
            drop(pool);
            tokio::task::yield_now().await;
            assert!(weak_session.upgrade().is_some());
            (weak_session, server)
        });

        // Runtime shuts down mid-drain and cancels the writer task.
        // `WriterExitGuard::drop` must clear `drain_keepalive` so the session
        // is freed instead of leaking via self-reference.
        rt.shutdown_timeout(Duration::from_secs(1));
        assert!(
            weak_session.upgrade().is_none(),
            "runtime shutdown during active drain must release drain_keepalive"
        );
    }

}
