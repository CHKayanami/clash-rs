//! RFC 7766 TCP/TLS DNS query pipelining session multiplexer.

use bytes::Bytes;
use crate::app::dns::query::QueryContext;

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;

use super::owned_task::OwnedTask;

const MAX_PENDING: usize = 1024;
const ID_QUARANTINE: Duration = Duration::from_secs(3);
const ID_BITMAP_WORDS: usize = (u16::MAX as usize + 1) / u64::BITS as usize;

struct Pending {
    question: Bytes,
    original_id: [u8; 2],
    reply: oneshot::Sender<Vec<u8>>,
}

struct State {
    closed: bool,
    pending: HashMap<u16, Pending>,
    retired: VecDeque<(Instant, u16)>,
    retired_ids: [u64; ID_BITMAP_WORDS],
}

pub struct PipelinedSession<W> {
    writer: tokio::sync::Mutex<W>,
    state: Arc<Mutex<State>>,
    driver: Mutex<Option<OwnedTask>>,
}

struct WriteGuard<'a, W> {
    session: &'a PipelinedSession<W>,
    complete: bool,
}

impl<W> Drop for WriteGuard<'_, W> {
    fn drop(&mut self) {
        if !self.complete {
            let mut state = self.session.state.lock();
            state.closed = true;
            state.pending.clear();
        }
    }
}

struct PendingGuard<'a, W: AsyncWrite + Send + Unpin + 'static> {
    session: &'a PipelinedSession<W>,
    id: u16,
    disarmed: bool,
}

impl<'a, W: AsyncWrite + Send + Unpin + 'static> PendingGuard<'a, W> {
    fn new(session: &'a PipelinedSession<W>, id: u16) -> Self {
        Self {
            session,
            id,
            disarmed: false,
        }
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl<W: AsyncWrite + Send + Unpin + 'static> Drop for PendingGuard<'_, W> {
    fn drop(&mut self) {
        if !self.disarmed {
            self.session.unregister(self.id);
        }
    }
}

impl<W: AsyncWrite + Send + Unpin + 'static> PipelinedSession<W> {
    pub fn new<R>(mut reader: R, writer: W, active_tasks: Arc<AtomicUsize>) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
    {
        let state = Arc::new(Mutex::new(State {
            closed: false,
            pending: HashMap::new(),
            retired: VecDeque::new(),
            retired_ids: [0; ID_BITMAP_WORDS],
        }));

        let state_clone = Arc::clone(&state);
        let task = OwnedTask::spawn(
            async move {
                Self::read_loop(state_clone, &mut reader).await;
            },
            active_tasks,
        );

        Self {
            writer: tokio::sync::Mutex::new(writer),
            state,
            driver: Mutex::new(Some(task)),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.state.lock().closed
    }

    pub async fn exchange(
        &self,
        context: &QueryContext,
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        let query = context.wire();
        let (receiver, id) = {
            let question = context.shared_question_wire();
            let original_id = context.txid().get().to_be_bytes();
            let (reply, receiver) = oneshot::channel();
            let mut state = self.state.lock();
            if state.closed {
                anyhow::bail!("Pipelined DNS session is closed");
            }
            Self::purge_retired(&mut state);
            if state.pending.len() >= MAX_PENDING {
                anyhow::bail!("Pipelined DNS session saturated");
            }
            let id = Self::allocate_id(&state)
                .ok_or_else(|| anyhow::anyhow!("DNS IDs exhausted"))?;
            state.pending.insert(
                id,
                Pending {
                    question,
                    original_id,
                    reply,
                },
            );
            (receiver, id)
        };
        let mut guard = PendingGuard::new(self, id);

        let mut wire = Vec::with_capacity(query.len() + 2);
        wire.extend_from_slice(&(query.len() as u16).to_be_bytes());
        wire.extend_from_slice(query);
        wire[2..4].copy_from_slice(&id.to_be_bytes());

        tokio::time::timeout(timeout, async {
            let write_res = {
                let mut writer = self.writer.lock().await;
                if self.is_closed() {
                    anyhow::bail!("Pipelined DNS session is closed");
                }
                let mut write_guard = WriteGuard {
                    session: self,
                    complete: false,
                };
                let result = writer.write_all(&wire).await;
                write_guard.complete = result.is_ok();
                result
            };

            if let Err(e) = write_res {
                self.mark_closed();
                return Err(anyhow::anyhow!("DNS pipe write error: {e}"));
            }

            match receiver.await {
                Ok(response) => {
                    guard.disarm();
                    Ok(response)
                }
                Err(_) => {
                    anyhow::bail!(
                        "Pipelined DNS session closed while waiting for response"
                    )
                }
            }
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("Pipelined DNS query timed out after {timeout:?}")
        })?
    }

    pub async fn shutdown(&self, timeout: Duration) {
        self.mark_closed();
        let task = self.driver.lock().take();
        if let Some(task) = task {
            task.shutdown(timeout).await;
        }
    }

    async fn read_loop<R: AsyncRead + Send + Unpin>(
        state: Arc<Mutex<State>>,
        reader: &mut R,
    ) {
        loop {
            let mut len_buf = [0u8; 2];
            if reader.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            if len < 12 {
                break;
            }
            let mut msg_buf = vec![0u8; len];
            if reader.read_exact(&mut msg_buf).await.is_err() {
                break;
            }
            Self::handle_response(&state, &msg_buf);
        }

        Self::mark_closed_state(&state);
    }

    fn handle_response(state: &Arc<Mutex<State>>, buffer: &[u8]) {
        let id = u16::from_be_bytes([buffer[0], buffer[1]]);
        let pending = {
            let mut state = state.lock();
            let matches = question_end(buffer).is_ok_and(|end| {
                state
                    .pending
                    .get(&id)
                    .is_some_and(|p| p.question == buffer[12..end])
            });
            if matches {
                let pending = state.pending.remove(&id);
                if pending.is_some() {
                    Self::retire_id(&mut state, id);
                }
                pending
            } else {
                None
            }
        };
        if let Some(pending) = pending {
            let mut response = buffer.to_vec();
            response[..2].copy_from_slice(&pending.original_id);
            let _ = pending.reply.send(response);
        }
    }

    fn unregister(&self, id: u16) {
        let mut state = self.state.lock();
        if state.pending.remove(&id).is_some() {
            Self::retire_id(&mut state, id);
        }
    }

    fn mark_closed(&self) {
        Self::mark_closed_state(&self.state);
    }

    fn mark_closed_state(state: &Arc<Mutex<State>>) {
        let mut state = state.lock();
        state.closed = true;
        state.pending.clear();
    }

    fn purge_retired(state: &mut State) {
        let now = Instant::now();
        while state
            .retired
            .front()
            .is_some_and(|(expiry, _)| *expiry <= now)
        {
            if let Some((_, id)) = state.retired.pop_front() {
                let word = (id / 64) as usize;
                let bit = id % 64;
                state.retired_ids[word] &= !(1 << bit);
            }
        }
    }

    fn retire_id(state: &mut State, id: u16) {
        let word = (id / 64) as usize;
        let bit = id % 64;
        state.retired_ids[word] |= 1 << bit;
        state
            .retired
            .push_back((Instant::now() + ID_QUARANTINE, id));
    }

    fn allocate_id(state: &State) -> Option<u16> {
        for _ in 0..128 {
            let id = rand::random::<u16>();
            let word = (id / 64) as usize;
            let bit = id % 64;
            let retired = state.retired_ids[word] & (1 << bit) != 0;
            if !retired && !state.pending.contains_key(&id) {
                return Some(id);
            }
        }
        None
    }
}

fn question_end(query: &[u8]) -> anyhow::Result<usize> {
    let mut pos = 12;
    if !crate::app::dns::wire::skip_dns_name(query, &mut pos)
        || pos + 4 > query.len()
    {
        anyhow::bail!("malformed DNS question");
    }
    Ok(pos + 4)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use crate::app::dns::query::{IngressProfile, QueryContext};
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::PipelinedSession;

    fn build_test_query(id: u16, name: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&id.to_be_bytes()); // ID
        msg.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1
        msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        msg.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        msg.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        msg.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        for part in name.split('.') {
            msg.push(part.len() as u8);
            msg.extend_from_slice(part.as_bytes());
        }
        msg.push(0x00); // root label
        msg.extend_from_slice(&[0x00, 0x01]); // Type A
        msg.extend_from_slice(&[0x00, 0x01]); // Class IN
        msg
    }

    #[tokio::test]
    async fn test_pipelined_multiplexing_concurrent() {
        let (client_stream, mut server_stream) = tokio::io::duplex(64 * 1024);
        let (reader, writer) = tokio::io::split(client_stream);
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let session = Arc::new(PipelinedSession::new(reader, writer, active_tasks));

        // Server mock loop: reads frames and responds with reversed or randomized order
        let server_task = tokio::spawn(async move {
            let mut queries = Vec::new();
            for _ in 0..5 {
                let mut len_buf = [0u8; 2];
                server_stream.read_exact(&mut len_buf).await.unwrap();
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0u8; len];
                server_stream.read_exact(&mut buf).await.unwrap();
                queries.push(buf);
            }

            // Send responses in reverse order
            for query in queries.into_iter().rev() {
                let mut resp = query;
                resp[2] |= 0x80; // QR = 1 (response)
                let len = resp.len() as u16;
                server_stream.write_all(&len.to_be_bytes()).await.unwrap();
                server_stream.write_all(&resp).await.unwrap();
            }
        });

        let mut handles = Vec::new();
        for i in 0..5u16 {
            let session = Arc::clone(&session);
            handles.push(tokio::spawn(async move {
                let orig_id = 0x1000 + i;
                let q = build_test_query(orig_id, &format!("domain{i}.com"));
                let resp =
                    session.exchange(&QueryContext::parse(Bytes::copy_from_slice(&q), IngressProfile::Internal).unwrap(), Duration::from_secs(2)).await.unwrap();
                assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), orig_id);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }
        server_task.await.unwrap();
        session.shutdown(Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn test_pipelined_session_eof_handling() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(client_stream);
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let session = Arc::new(PipelinedSession::new(reader, writer, active_tasks));

        // Drop server stream to simulate immediate EOF
        drop(server_stream);

        tokio::time::sleep(Duration::from_millis(50)).await;
        let q = build_test_query(0x1234, "example.com");
        let res = session.exchange(&QueryContext::parse(Bytes::copy_from_slice(&q), IngressProfile::Internal).unwrap(), Duration::from_millis(100)).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_pipelined_cancellation_safety() {
        let (client_stream, _server_stream) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(client_stream);
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let session = Arc::new(PipelinedSession::new(reader, writer, active_tasks));

        let q = build_test_query(0x1234, "example.com");

        // Start exchange and cancel it after short duration (simulating outer select!/timeout drop)
        {
            let context = QueryContext::parse(Bytes::copy_from_slice(&q), IngressProfile::Internal).unwrap();
            let fut = session.exchange(&context, Duration::from_secs(5));
            tokio::pin!(fut);
            tokio::select! {
                _ = &mut fut => {}
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }

        // Pending map should be cleaned up by PendingGuard
        assert_eq!(session.state.lock().pending.len(), 0);
        session.shutdown(Duration::from_millis(50)).await;
    }
    #[tokio::test]
    async fn response_timeout_preserves_other_pending_queries() {
        let (client, mut server) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(client);
        let session = Arc::new(PipelinedSession::new(
            reader,
            writer,
            Arc::new(AtomicUsize::new(0)),
        ));
        let slow_query = build_test_query(1, "slow.test");
        let fast_query = build_test_query(2, "fast.test");
        let slow_session = session.clone();
        let slow = tokio::spawn(async move {
            slow_session
                .exchange(&QueryContext::parse(Bytes::copy_from_slice(&slow_query), IngressProfile::Internal).unwrap(), Duration::from_millis(30))
                .await
        });
        let fast_session = session.clone();
        let fast = tokio::spawn(async move {
            fast_session
                .exchange(&QueryContext::parse(Bytes::copy_from_slice(&fast_query), IngressProfile::Internal).unwrap(), Duration::from_secs(1))
                .await
        });
        let mut fast_response = None;
        for _ in 0..2 {
            let length = server.read_u16().await.unwrap() as usize;
            let mut query = vec![0; length];
            server.read_exact(&mut query).await.unwrap();
            if query[13..17] == *b"fast" {
                query[2] |= 0x80;
                fast_response = Some(query);
            }
        }
        assert!(slow.await.unwrap().is_err());
        assert!(!session.is_closed());
        let response = fast_response.unwrap();
        server.write_u16(response.len() as u16).await.unwrap();
        server.write_all(&response).await.unwrap();
        assert_eq!(fast.await.unwrap().unwrap()[..2], [0, 2]);
        session.shutdown(Duration::ZERO).await;
    }

    #[tokio::test]
    async fn blocked_writer_times_out_and_closes_partial_frame() {
        let (client, _server) = tokio::io::duplex(1);
        let (reader, writer) = tokio::io::split(client);
        let session =
            PipelinedSession::new(reader, writer, Arc::new(AtomicUsize::new(0)));
        let query = build_test_query(1, "blocked.test");
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            session.exchange(&QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap(), Duration::from_millis(20)),
        )
        .await
        .expect("write must be covered by exchange timeout");
        assert!(result.is_err());
        assert!(session.is_closed());
        assert!(session.state.lock().pending.is_empty());
        session.shutdown(Duration::ZERO).await;
    }

    #[tokio::test]
    async fn cancelling_queued_writer_keeps_session_usable() {
        let (client, _server) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(client);
        let session =
            PipelinedSession::new(reader, writer, Arc::new(AtomicUsize::new(0)));
        let _lock = session.writer.lock().await;
        assert!(
            session
                .exchange(&QueryContext::parse(Bytes::copy_from_slice(&build_test_query(1, "queued.test")), IngressProfile::Internal).unwrap(), Duration::from_millis(20))
                .await
                .is_err()
        );
        assert!(!session.is_closed());
        assert!(session.state.lock().pending.is_empty());
        session.shutdown(Duration::ZERO).await;
    }
}
