//! Bounded connected DNS-over-UDP exchange pool with lock-free fixed slot array routing.

use bytes::Bytes;
use crate::app::dns::query::QueryContext;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use futures::stream::SplitStream;
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

use super::dial::DialContext;
use super::owned_task::OwnedTask;
use crate::proxy::AnyOutboundDatagram;
use crate::proxy::datagram::UdpPacket;

const SLOT_COUNT: usize = 1024;
const SLOT_MASK: usize = SLOT_COUNT - 1; // 0x3FF (10 bits)
const ID_QUARANTINE: Duration = Duration::from_secs(3);
// Retire the full wire ID rather than its slot, so completed slots can immediately
// use another salt. Millisecond deadlines keep the per-slot history compact.

struct SlotData {
    question: Bytes,
    original_id: [u8; 2],
    reply: Option<oneshot::Sender<Vec<u8>>>,
    retired_until: [u64; 64],
}

impl Default for SlotData {
    fn default() -> Self {
        Self {
            question: Bytes::new(),
            original_id: [0; 2],
            reply: None,
            retired_until: [0; 64],
        }
    }
}

struct Slot {
    in_use: AtomicBool,
    salt: AtomicU8,
    data: Mutex<SlotData>,
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            in_use: AtomicBool::new(false),
            salt: AtomicU8::new(0),
            data: Mutex::new(SlotData::default()),
        }
    }
}

enum UdpSender {
    Direct(Arc<UdpSocket>),
    Proxied(tokio::sync::mpsc::Sender<UdpPacket>),
}

pub struct UdpPool {
    sender: UdpSender,
    slots: Box<[Slot; SLOT_COUNT]>,
    cursor: AtomicUsize,
    closed: AtomicBool,
    cancelled: tokio_util::sync::CancellationToken,
    tasks: Mutex<Vec<OwnedTask>>,
    target_addr: SocketAddr,
    timeout: Duration,
    epoch: Instant,
}

struct SlotGuard<'a> {
    pool: &'a UdpPool,
    wire_id: u16,
    disarmed: bool,
}

impl<'a> SlotGuard<'a> {
    fn new(pool: &'a UdpPool, wire_id: u16) -> Self {
        Self {
            pool,
            wire_id,
            disarmed: false,
        }
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        if !self.disarmed {
            self.pool.unregister(self.wire_id);
        }
    }
}

impl UdpPool {
    pub async fn new_direct(
        address: SocketAddr,
        so_mark: Option<u32>,
        iface: Option<&crate::app::net::OutboundInterface>,
        timeout: Duration,
        active_tasks: Arc<AtomicUsize>,
    ) -> anyhow::Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::from_std(super::dial::direct_udp_socket(
            address, iface, so_mark,
        )?)?);
        socket.connect(address).await?;

        let slots = (0..SLOT_COUNT)
            .map(|_| Slot::default())
            .collect::<Vec<_>>()
            .into_boxed_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("size mismatch"));

        let pool = Arc::new(Self {
            sender: UdpSender::Direct(Arc::clone(&socket)),
            slots,
            cursor: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            cancelled: tokio_util::sync::CancellationToken::new(),
            tasks: Mutex::new(Vec::new()),
            target_addr: address,
            timeout,
            epoch: Instant::now(),
        });

        let task = OwnedTask::spawn(
            Self::direct_receive_loop(Arc::downgrade(&pool), socket),
            active_tasks,
        );
        pool.tasks.lock().push(task);

        Ok(pool)
    }

    pub async fn new_proxied(
        dial: &DialContext,
        address: SocketAddr,
        active_tasks: Arc<AtomicUsize>,
    ) -> anyhow::Result<Arc<Self>> {
        let dgram = dial.dial_udp(address).await?;
        Ok(Self::from_datagram(
            dgram,
            address,
            dial.query_timeout,
            active_tasks,
        ))
    }

    fn from_datagram(
        dgram: AnyOutboundDatagram,
        address: SocketAddr,
        timeout: Duration,
        active_tasks: Arc<AtomicUsize>,
    ) -> Arc<Self> {
        let (sink, stream) = dgram.split();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<UdpPacket>(1024);

        let slots = (0..SLOT_COUNT)
            .map(|_| Slot::default())
            .collect::<Vec<_>>()
            .into_boxed_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("size mismatch"));

        let pool = Arc::new(Self {
            sender: UdpSender::Proxied(tx),
            slots,
            cursor: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            cancelled: tokio_util::sync::CancellationToken::new(),
            tasks: Mutex::new(Vec::new()),
            target_addr: address,
            timeout,
            epoch: Instant::now(),
        });

        let send_pool = Arc::downgrade(&pool);
        let cancelled = pool.cancelled.clone();
        let send_task = OwnedTask::spawn(
            async move {
                let mut sink = sink;
                while let Some(packet) = tokio::select! {
                    _ = cancelled.cancelled() => return,
                    packet = rx.recv() => packet,
                } {
                    let result = tokio::select! {
                        _ = cancelled.cancelled() => return,
                        result = sink.send(packet) => result,
                    };
                    if let Err(e) = result {
                        tracing::debug!("proxied UDP sender loop ended: {e}");
                        if let Some(pool) = send_pool.upgrade() {
                            pool.mark_closed();
                        }
                        return;
                    }
                }
            },
            Arc::clone(&active_tasks),
        );

        let recv_task = OwnedTask::spawn(
            Self::proxied_receive_loop(
                Arc::downgrade(&pool),
                stream,
                pool.cancelled.clone(),
            ),
            active_tasks,
        );

        {
            let mut tasks = pool.tasks.lock();
            tasks.push(send_task);
            tasks.push(recv_task);
        }

        pool
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn mark_closed(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.cancelled.cancel();
        for slot in self.slots.iter() {
            let mut data = slot.data.lock();
            data.reply = None;
            data.question = Bytes::new();
            slot.in_use.store(false, Ordering::Release);
        }
    }

    pub async fn close(&self) {
        self.mark_closed();
        let tasks = std::mem::take(&mut *self.tasks.lock());
        for task in tasks {
            task.shutdown(Duration::ZERO).await;
        }
    }

    pub async fn exchange(&self, context: &QueryContext) -> anyhow::Result<Vec<u8>> {
        let query = context.wire();
        if self.is_closed() {
            anyhow::bail!("UDP DNS exchange pool is closed");
        }

        let original_id = context.txid().get().to_be_bytes();
        let question = context.shared_question_wire();
        let (reply, receiver) = oneshot::channel();

        let id = self.allocate_slot(question, original_id, reply)?;
        let mut guard = SlotGuard::new(self, id);

        let mut wire = query.to_vec();
        wire[..2].copy_from_slice(&id.to_be_bytes());

        tokio::time::timeout(self.timeout, async {
            let send_res = match &self.sender {
                UdpSender::Direct(socket) => {
                    socket.send(&wire).await.map(|_| ()).map_err(Into::into)
                }
                UdpSender::Proxied(tx) => {
                    let src_addr: SocketAddr = if self.target_addr.is_ipv4() {
                        SocketAddr::from(([0, 0, 0, 0], 0))
                    } else {
                        SocketAddr::from(([0; 16], 0))
                    };
                    let packet = UdpPacket {
                        data: bytes::Bytes::from(wire),
                        src_addr: src_addr.into(),
                        dst_addr: self.target_addr.into(),
                        inbound_user: None,
                    };
                    tx.send(packet)
                        .await
                        .map_err(|_| anyhow::anyhow!("proxy UDP send error"))
                }
            };

            if let Err(error) = send_res {
                return Err(error);
            }

            match receiver.await {
                Ok(response) => {
                    guard.disarm();
                    Ok(response)
                }
                Err(_) => anyhow::bail!("UDP DNS receive loop stopped"),
            }
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("UDP DNS query timed out after {:?}", self.timeout)
        })?
    }

    fn allocate_slot(
        &self,
        question: Bytes,
        original_id: [u8; 2],
        reply: oneshot::Sender<Vec<u8>>,
    ) -> anyhow::Result<u16> {
        let start = self.cursor.fetch_add(1, Ordering::Relaxed);
        let now = self.epoch.elapsed().as_millis() as u64;

        for offset in 0..SLOT_COUNT {
            let idx = (start + offset) & SLOT_MASK;
            let slot = &self.slots[idx];

            if slot
                .in_use
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                let mut data = slot.data.lock();
                if self.is_closed() {
                    slot.in_use.store(false, Ordering::Release);
                    anyhow::bail!("UDP DNS exchange pool is closed");
                }
                let previous = slot.salt.load(Ordering::Relaxed);
                let Some(salt) = (1..=64)
                    .map(|offset| previous.wrapping_add(offset) & 0x3F)
                    .find(|salt| data.retired_until[*salt as usize] <= now)
                else {
                    slot.in_use.store(false, Ordering::Release);
                    continue;
                };

                slot.salt.store(salt, Ordering::Relaxed);
                data.question = question;
                data.original_id = original_id;
                data.reply = Some(reply);

                let wire_id = ((salt as u16) << 10) | (idx as u16);
                return Ok(wire_id);
            }
        }

        anyhow::bail!("UDP DNS exchange pool saturated")
    }

    async fn direct_receive_loop(pool: Weak<Self>, socket: Arc<UdpSocket>) {
        let mut buffer = [0u8; 8192];
        loop {
            let Ok(Ok(length)) = tokio::time::timeout(
                Duration::from_secs(1),
                socket.recv(&mut buffer),
            )
            .await
            else {
                if pool.strong_count() == 0 {
                    break;
                }
                continue;
            };
            if length < 12 {
                continue;
            }
            let Some(pool) = pool.upgrade() else {
                break;
            };
            pool.handle_response(&buffer[..length]);
        }
    }

    async fn proxied_receive_loop(
        pool: Weak<Self>,
        mut stream: SplitStream<AnyOutboundDatagram>,
        cancelled: tokio_util::sync::CancellationToken,
    ) {
        while let Some(packet) = tokio::select! {
            _ = cancelled.cancelled() => return,
            packet = stream.next() => packet,
        } {
            let buffer = packet.data;
            if buffer.len() < 12 {
                continue;
            }
            let Some(pool) = pool.upgrade() else {
                break;
            };
            pool.handle_response(&buffer);
        }
        if let Some(pool) = pool.upgrade() {
            pool.mark_closed();
        }
    }

    fn handle_response(&self, buffer: &[u8]) {
        if buffer.len() < 12 {
            return;
        }
        let wire_id = u16::from_be_bytes([buffer[0], buffer[1]]);
        let slot_idx = (wire_id & (SLOT_MASK as u16)) as usize;
        let expected_salt = ((wire_id >> 10) & 0x3F) as u8;

        let slot = &self.slots[slot_idx];
        if (slot.salt.load(Ordering::Relaxed) & 0x3F) != expected_salt
            || !slot.in_use.load(Ordering::Acquire)
        {
            return;
        }

        let pending_reply = {
            let mut data = slot.data.lock();
            if (slot.salt.load(Ordering::Relaxed) & 0x3F) != expected_salt {
                return;
            }
            let matches = Self::question_end(buffer)
                .is_ok_and(|end| data.question.as_ref() == &buffer[12..end]);
            if matches {
                let reply = data.reply.take();
                data.question = Bytes::new();
                let original_id = data.original_id;
                data.retired_until[expected_salt as usize] =
                    (self.epoch.elapsed() + ID_QUARANTINE).as_millis() as u64;
                slot.in_use.store(false, Ordering::Release);
                reply.map(|r| (r, original_id))
            } else {
                None
            }
        };

        if let Some((reply, original_id)) = pending_reply {
            let mut response = buffer.to_vec();
            response[..2].copy_from_slice(&original_id);
            let _ = reply.send(response);
        }
    }

    fn unregister(&self, wire_id: u16) {
        let slot_idx = (wire_id & (SLOT_MASK as u16)) as usize;
        let expected_salt = ((wire_id >> 10) & 0x3F) as u8;
        let slot = &self.slots[slot_idx];

        let mut data = slot.data.lock();
        if (slot.salt.load(Ordering::Relaxed) & 0x3F) == expected_salt {
            data.reply = None;
            data.question = Bytes::new();
            data.retired_until[expected_salt as usize] =
                (self.epoch.elapsed() + ID_QUARANTINE).as_millis() as u64;
            slot.in_use.store(false, Ordering::Release);
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
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use crate::app::dns::query::{IngressProfile, QueryContext};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use tokio::net::UdpSocket;

    use super::UdpPool;

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

    fn proxied_fixture(
        timeout: Duration,
    ) -> (
        Arc<UdpPool>,
        tokio::sync::mpsc::Sender<crate::proxy::datagram::UdpPacket>,
        tokio::sync::mpsc::Receiver<crate::proxy::datagram::UdpPacket>,
        Arc<AtomicUsize>,
    ) {
        let (outgoing, receiver) = tokio::sync::mpsc::channel(8);
        let (sender, incoming) = tokio::sync::mpsc::channel(8);
        let active = Arc::new(AtomicUsize::new(0));
        let datagram = crate::proxy::AnyOutboundDatagram::dynamic(
            crate::proxy::datagram::ChannelDatagram::new(outgoing, incoming),
        );
        let pool = UdpPool::from_datagram(
            datagram,
            "127.0.0.1:53".parse().unwrap(),
            timeout,
            active.clone(),
        );
        (pool, sender, receiver, active)
    }

    #[tokio::test]
    async fn proxy_eof_fails_pending_queries_and_stops_both_tasks() {
        let (pool, incoming, mut outgoing, active) =
            proxied_fixture(Duration::from_secs(10));
        let query_pool = pool.clone();
        let query = tokio::spawn(async move {
            query_pool.exchange(&QueryContext::parse(Bytes::copy_from_slice(&build_test_query(7, "eof.test")), IngressProfile::Internal).unwrap()).await
        });
        outgoing.recv().await.unwrap();
        drop(incoming);
        tokio::time::timeout(Duration::from_secs(1), async {
            assert!(query.await.unwrap().is_err());
            while active.load(std::sync::atomic::Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(pool.is_closed());
        pool.close().await;
    }

    #[tokio::test]
    async fn proxy_send_failure_fails_pending_queries_and_stops_reader() {
        let (pool, _incoming, outgoing, active) =
            proxied_fixture(Duration::from_secs(10));
        drop(outgoing);
        tokio::time::timeout(Duration::from_secs(1), async {
            assert!(
                pool.exchange(&QueryContext::parse(Bytes::copy_from_slice(&build_test_query(7, "send.test")), IngressProfile::Internal).unwrap())
                    .await
                    .is_err()
            );
            while active.load(std::sync::atomic::Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(pool.is_closed());
        pool.close().await;
    }

    #[tokio::test]
    async fn proxy_response_timeout_preserves_healthy_association() {
        let (pool, incoming, mut outgoing, _active) =
            proxied_fixture(Duration::from_millis(100));
        assert!(
            pool.exchange(&QueryContext::parse(Bytes::copy_from_slice(&build_test_query(7, "timeout.test")), IngressProfile::Internal).unwrap())
                .await
                .is_err()
        );
        assert!(!pool.is_closed());
        outgoing.recv().await.unwrap();
        let query_pool = pool.clone();
        let query = tokio::spawn(async move {
            query_pool
                .exchange(&QueryContext::parse(Bytes::copy_from_slice(&build_test_query(8, "healthy.test")), IngressProfile::Internal).unwrap())
                .await
        });
        let packet = outgoing.recv().await.unwrap();
        let mut wire = packet.data.to_vec();
        wire[2] |= 0x80;
        incoming
            .send(crate::proxy::datagram::UdpPacket::new(
                wire.into(),
                packet.dst_addr,
                packet.src_addr,
            ))
            .await
            .unwrap();
        assert_eq!(query.await.unwrap().unwrap()[..2], [0, 8]);
        pool.close().await;
    }

    #[tokio::test]
    async fn test_udp_pool_slot_array_exchange_concurrent() {
        // Bind a mock server UDP socket
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr: SocketAddr = server_socket.local_addr().unwrap();

        // Spawn mock server
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            for _ in 0..10 {
                let (len, peer) = server_socket.recv_from(&mut buf).await.unwrap();
                let mut resp = buf[..len].to_vec();
                resp[2] |= 0x80; // QR = 1
                // Add dummy answer
                resp[7] = 1; // ANCOUNT = 1
                resp.extend_from_slice(&[0xc0, 0x0c]); // Pointer to question name
                resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // Type A, Class IN
                resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL 60
                resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
                resp.extend_from_slice(&[1, 2, 3, 4]); // 1.2.3.4

                server_socket.send_to(&resp, peer).await.unwrap();
            }
        });

        let active_tasks = Arc::new(AtomicUsize::new(0));
        let pool = UdpPool::new_direct(
            server_addr,
            None,
            None,
            Duration::from_secs(2),
            active_tasks,
        )
        .await
        .unwrap();

        let mut handles = Vec::new();
        for i in 0..10u16 {
            let pool = Arc::clone(&pool);
            handles.push(tokio::spawn(async move {
                let orig_id = 0x2000 + i;
                let q = build_test_query(orig_id, &format!("domain{i}.test"));
                let resp = pool.exchange(&QueryContext::parse(Bytes::copy_from_slice(&q), IngressProfile::Internal).unwrap()).await.unwrap();
                assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), orig_id);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }
        server_task.await.unwrap();
        pool.close().await;
    }

    #[tokio::test]
    async fn test_udp_pool_slot_salt_wrap_around() {
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr: SocketAddr = server_socket.local_addr().unwrap();
        let pool = UdpPool::new_direct(
            server_addr,
            None,
            None,
            Duration::from_secs(2),
            active_tasks,
        )
        .await
        .unwrap();

        let query = build_test_query(1, "example.com");
        let question = Bytes::copy_from_slice(&query[12..UdpPool::question_end(&query).unwrap()]);

        // Repeatedly allocate the SAME slot (slot 0) over 130 times (more than 64 salt cycles)
        // by locking the slot data and clearing retired_until.
        for i in 0..130 {
            // Force cursor to 0 so we always allocate slot 0
            pool.cursor.store(0, std::sync::atomic::Ordering::Relaxed);
            {
                let slot = &pool.slots[0];
                let mut data = slot.data.lock();
                data.retired_until = [0; 64];
            }

            let (reply, rx) = tokio::sync::oneshot::channel();
            let wire_id = pool
                .allocate_slot(question.clone(), [0x12, 0x34], reply)
                .expect("slot allocation should succeed even after 64+ reuses");

            let slot_idx = (wire_id & (super::SLOT_MASK as u16)) as usize;
            assert_eq!(slot_idx, 0);

            let expected_salt = ((wire_id >> 10) & 0x3F) as u8;
            assert_eq!(expected_salt, (i + 1) as u8 & 0x3F);

            // Construct a valid DNS response packet with wire_id
            let mut resp = query.clone();
            resp[..2].copy_from_slice(&wire_id.to_be_bytes());
            resp[2] |= 0x80; // QR = 1

            // Handle response should successfully match salt and deliver reply
            pool.handle_response(&resp);

            let received = rx.await.expect(
                "reply must be delivered even after 64+ reuses of the same slot",
            );
            assert_eq!(received[..2], [0x12, 0x34]);
        }

        pool.close().await;
    }

    #[tokio::test]
    async fn test_udp_pool_cancellation_safety() {
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr: SocketAddr = server_socket.local_addr().unwrap();
        let pool = UdpPool::new_direct(
            server_addr,
            None,
            None,
            Duration::from_millis(50),
            active_tasks,
        )
        .await
        .unwrap();

        let query = build_test_query(1, "timeout.com");

        // Timeout should unregister slot cleanly
        let res = pool.exchange(&QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap()).await;
        assert!(res.is_err());

        // Cancellation by dropping future before completion
        let query2 = build_test_query(2, "cancelled.com");
        {
            let context = QueryContext::parse(Bytes::copy_from_slice(&query2), IngressProfile::Internal).unwrap();
            let exchange_fut = pool.exchange(&context);
            tokio::pin!(exchange_fut);
            tokio::select! {
                _ = &mut exchange_fut => {}
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }

        // The slot used should have been unregistered and in_use reset to false
        let used_slots = pool
            .slots
            .iter()
            .filter(|s| s.in_use.load(std::sync::atomic::Ordering::Relaxed))
            .count();
        assert_eq!(
            used_slots, 0,
            "All slots should be freed after timeout or cancellation"
        );

        pool.close().await;
    }
    #[tokio::test]
    async fn completed_slots_are_reused_without_accepting_old_ids() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pool = UdpPool::new_direct(
            server.local_addr().unwrap(),
            None,
            None,
            Duration::from_secs(2),
            Arc::new(AtomicUsize::new(0)),
        )
        .await
        .unwrap();
        let query = build_test_query(7, "reuse.test");
        let question = Bytes::copy_from_slice(&query[12..UdpPool::question_end(&query).unwrap()]);
        let mut old: Option<u16> = None;
        // More completed queries than slots, without waiting for quarantine expiry.
        for _ in 0..(super::SLOT_COUNT * 2) {
            let (sender, mut receiver) = tokio::sync::oneshot::channel();
            let id = pool
                .allocate_slot(question.clone(), [0, 7], sender)
                .unwrap();
            let mut response = query.clone();
            response[2] |= 0x80;
            if let Some(old_id) = old {
                response[..2].copy_from_slice(&old_id.to_be_bytes());
                pool.handle_response(&response);
                assert!(matches!(
                    receiver.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty)
                ));
            }
            response[..2].copy_from_slice(&id.to_be_bytes());
            pool.handle_response(&response);
            assert_eq!(receiver.await.unwrap()[..2], [0, 7]);
            old = Some(id);
        }
        // A specific slot must avoid all its retired salts before wrapping.
        let mut ids = std::collections::HashSet::new();
        for _ in 0..64 {
            pool.cursor.store(0, std::sync::atomic::Ordering::Relaxed);
            let (sender, _receiver) = tokio::sync::oneshot::channel();
            let id = pool
                .allocate_slot(question.clone(), [0, 7], sender)
                .unwrap();
            assert!(ids.insert(id));
            pool.unregister(id);
        }
        pool.close().await;
    }
}
