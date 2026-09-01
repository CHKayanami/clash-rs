//! Bounded connected DNS-over-UDP exchange pool with lock-free fixed slot array routing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
use crate::session::{Network, Session, Type};

const SLOT_COUNT: usize = 1024;
const SLOT_MASK: usize = SLOT_COUNT - 1; // 0x3FF (10 bits)
const ID_QUARANTINE: Duration = Duration::from_secs(3);

#[derive(Default)]
struct SlotData {
    question: Vec<u8>,
    original_id: [u8; 2],
    reply: Option<oneshot::Sender<Vec<u8>>>,
    retired_until: Option<Instant>,
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
    tasks: Mutex<Vec<OwnedTask>>,
    target_addr: SocketAddr,
    timeout: Duration,
}

impl UdpPool {
    pub async fn new_direct(
        address: SocketAddr,
        so_mark: Option<u32>,
        iface: Option<&str>,
        timeout: Duration,
        active_tasks: Arc<AtomicUsize>,
    ) -> anyhow::Result<Arc<Self>> {
        let domain = if address.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        #[allow(unused_variables)]
        if let Some(mark) = so_mark {
            #[cfg(target_os = "linux")]
            let _ = socket.set_mark(mark);
        }
        #[allow(unused_variables)]
        if let Some(iface_name) = iface {
            #[cfg(target_os = "linux")]
            let _ = socket.bind_device(Some(iface_name.as_bytes()));
        }
        let unspecified = if address.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        socket.bind(&SocketAddr::new(unspecified, 0).into())?;
        let socket = Arc::new(UdpSocket::from_std(socket.into())?);
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
            tasks: Mutex::new(Vec::new()),
            target_addr: address,
            timeout,
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
        let Some(ref outbound) = dial.outbound else {
            anyhow::bail!("missing outbound for proxied UDP pool");
        };
        let src: SocketAddr = if address.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sess = Session {
            source: src,
            network: Network::Udp,
            typ: Type::Ignore,
            destination: address.into(),
            so_mark: dial.so_mark,
            iface: dial.iface.clone(),
            ..Default::default()
        };
        let resolver = dial
            .resolver
            .clone()
            .unwrap_or_else(|| Arc::new(crate::app::dns::SystemResolver::new(false).unwrap()));

        let dgram = outbound.connect_datagram(&sess, resolver).await?;
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
            tasks: Mutex::new(Vec::new()),
            target_addr: address,
            timeout: dial.query_timeout,
        });

        let send_task = OwnedTask::spawn(
            async move {
                let mut sink = sink;
                while let Some(packet) = rx.recv().await {
                    if let Err(e) = sink.send(packet).await {
                        tracing::debug!("proxied UDP sender loop ended: {e}");
                        break;
                    }
                }
            },
            Arc::clone(&active_tasks),
        );

        let recv_task = OwnedTask::spawn(
            Self::proxied_receive_loop(Arc::downgrade(&pool), stream),
            active_tasks,
        );

        {
            let mut tasks = pool.tasks.lock();
            tasks.push(send_task);
            tasks.push(recv_task);
        }

        Ok(pool)
    }

    pub async fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        for slot in self.slots.iter() {
            let mut data = slot.data.lock();
            data.reply = None;
            slot.in_use.store(false, Ordering::Release);
        }
        let tasks = std::mem::take(&mut *self.tasks.lock());
        for task in tasks {
            task.shutdown(Duration::ZERO).await;
        }
    }

    pub async fn exchange(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        if query.len() < 12 {
            anyhow::bail!("malformed DNS query");
        }
        if self.closed.load(Ordering::Relaxed) {
            anyhow::bail!("UDP DNS exchange pool is closed");
        }

        let original_id = [query[0], query[1]];
        let question = query[12..Self::question_end(query)?].to_vec();
        let (reply, receiver) = oneshot::channel();

        let id = self.allocate_slot(question, original_id, reply)?;

        let mut wire = query.to_vec();
        wire[..2].copy_from_slice(&id.to_be_bytes());

        let send_res = match &self.sender {
            UdpSender::Direct(socket) => socket.send(&wire).await.map(|_| ()).map_err(Into::into),
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
                tx.send(packet).await.map_err(|_| anyhow::anyhow!("proxy UDP send error"))
            }
        };

        if let Err(error) = send_res {
            self.unregister(id);
            return Err(error);
        }

        match tokio::time::timeout(self.timeout, receiver).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => anyhow::bail!("UDP DNS receive loop stopped"),
            Err(_) => {
                self.unregister(id);
                anyhow::bail!("UDP DNS query timed out after {:?}", self.timeout)
            }
        }
    }

    fn allocate_slot(
        &self,
        question: Vec<u8>,
        original_id: [u8; 2],
        reply: oneshot::Sender<Vec<u8>>,
    ) -> anyhow::Result<u16> {
        let start = self.cursor.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();

        for offset in 0..SLOT_COUNT {
            let idx = (start + offset) & SLOT_MASK;
            let slot = &self.slots[idx];

            if slot
                .in_use
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                let mut data = slot.data.lock();
                if let Some(retired) = data.retired_until {
                    if now < retired {
                        slot.in_use.store(false, Ordering::Release);
                        continue;
                    }
                }

                let salt = slot.salt.fetch_add(1, Ordering::Relaxed).wrapping_add(1) & 0x3F;
                data.question = question;
                data.original_id = original_id;
                data.reply = Some(reply);
                data.retired_until = None;

                let wire_id = ((salt as u16) << 10) | (idx as u16);
                return Ok(wire_id);
            }
        }

        anyhow::bail!("UDP DNS exchange pool saturated")
    }

    async fn direct_receive_loop(pool: Weak<Self>, socket: Arc<UdpSocket>) {
        let mut buffer = [0u8; 8192];
        loop {
            let Ok(Ok(length)) =
                tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut buffer)).await
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
    ) {
        while let Some(packet) = stream.next().await {
            let buffer = packet.data;
            if buffer.len() < 12 {
                continue;
            }
            let Some(pool) = pool.upgrade() else {
                break;
            };
            pool.handle_response(&buffer);
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
        if slot.salt.load(Ordering::Relaxed) != expected_salt
            || !slot.in_use.load(Ordering::Acquire)
        {
            return;
        }

        let pending_reply = {
            let mut data = slot.data.lock();
            if slot.salt.load(Ordering::Relaxed) != expected_salt {
                return;
            }
            let matches = Self::question_end(buffer).is_ok_and(|end| {
                data.question == buffer[12..end]
            });
            if matches {
                let reply = data.reply.take();
                let original_id = data.original_id;
                data.retired_until = Some(Instant::now() + ID_QUARANTINE);
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
        if slot.salt.load(Ordering::Relaxed) == expected_salt {
            data.reply = None;
            data.retired_until = Some(Instant::now() + ID_QUARANTINE);
            slot.in_use.store(false, Ordering::Release);
        }
    }

    fn question_end(query: &[u8]) -> anyhow::Result<usize> {
        let mut pos = 12;
        if !crate::app::dns::wire::skip_dns_name(query, &mut pos) || pos + 4 > query.len() {
            anyhow::bail!("malformed DNS question");
        }
        Ok(pos + 4)
    }
}

#[cfg(test)]
mod tests {
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
                let resp = pool.exchange(&q).await.unwrap();
                assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), orig_id);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }
        server_task.await.unwrap();
        pool.close().await;
    }
}
