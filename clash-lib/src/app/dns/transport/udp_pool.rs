//! Bounded connected DNS-over-UDP exchange pool.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, oneshot};

use super::dial::DialContext;
use super::owned_task::OwnedTask;
use crate::app::dispatcher::BoxedChainedDatagram;
use crate::proxy::datagram::UdpPacket;
use crate::session::{Network, Session, Type};

const MAX_PENDING: usize = 1024;
const ID_QUARANTINE: Duration = Duration::from_secs(3);
const ID_BITMAP_WORDS: usize = (u16::MAX as usize + 1) / u64::BITS as usize;

struct Pending {
    question: Vec<u8>,
    original_id: [u8; 2],
    reply: oneshot::Sender<Vec<u8>>,
}

struct State {
    closed: bool,
    pending: HashMap<u16, Pending>,
    retired: VecDeque<(Instant, u16)>,
    retired_ids: [u64; ID_BITMAP_WORDS],
}

enum UdpSender {
    Direct(Arc<UdpSocket>),
    Proxied(Mutex<SplitSink<BoxedChainedDatagram, UdpPacket>>),
}

pub struct UdpPool {
    sender: UdpSender,
    state: Mutex<State>,
    receive_task: Mutex<Option<OwnedTask>>,
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

        let pool = Arc::new(Self {
            sender: UdpSender::Direct(Arc::clone(&socket)),
            state: Mutex::new(State {
                closed: false,
                pending: HashMap::new(),
                retired: VecDeque::new(),
                retired_ids: [0; ID_BITMAP_WORDS],
            }),
            receive_task: Mutex::new(None),
            target_addr: address,
            timeout,
        });

        let task = OwnedTask::spawn(
            Self::direct_receive_loop(Arc::downgrade(&pool), socket),
            active_tasks,
        );
        pool.receive_task.lock().await.replace(task);

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

        let pool = Arc::new(Self {
            sender: UdpSender::Proxied(Mutex::new(sink)),
            state: Mutex::new(State {
                closed: false,
                pending: HashMap::new(),
                retired: VecDeque::new(),
                retired_ids: [0; ID_BITMAP_WORDS],
            }),
            receive_task: Mutex::new(None),
            target_addr: address,
            timeout: dial.query_timeout,
        });

        let task = OwnedTask::spawn(
            Self::proxied_receive_loop(Arc::downgrade(&pool), stream),
            active_tasks,
        );
        pool.receive_task.lock().await.replace(task);

        Ok(pool)
    }

    pub async fn close(&self) {
        {
            let mut state = self.state.lock().await;
            state.closed = true;
            state.pending.clear();
        }
        let task = self.receive_task.lock().await.take();
        if let Some(task) = task {
            task.shutdown(Duration::ZERO).await;
        }
    }

    pub async fn exchange(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        if query.len() < 12 {
            anyhow::bail!("malformed DNS query");
        }

        let original_id = [query[0], query[1]];
        let question = query[12..Self::question_end(query)?].to_vec();
        let (reply, receiver) = oneshot::channel();
        let id = {
            let mut state = self.state.lock().await;
            if state.closed {
                anyhow::bail!("UDP DNS exchange pool is closed");
            }
            Self::purge_retired(&mut state);
            if state.pending.len() >= MAX_PENDING {
                anyhow::bail!("UDP DNS exchange pool saturated");
            }
            let id = Self::allocate_id(&state)
                .ok_or_else(|| anyhow::anyhow!("UDP DNS IDs exhausted"))?;
            state.pending.insert(
                id,
                Pending {
                    question,
                    original_id,
                    reply,
                },
            );
            id
        };

        let mut wire = query.to_vec();
        wire[..2].copy_from_slice(&id.to_be_bytes());

        let send_res = match &self.sender {
            UdpSender::Direct(socket) => socket.send(&wire).await.map(|_| ()).map_err(Into::into),
            UdpSender::Proxied(sink) => {
                let packet = UdpPacket {
                    data: bytes::Bytes::from(wire),
                    src_addr: SocketAddr::from(([0, 0, 0, 0], 0)).into(),
                    dst_addr: self.target_addr.into(),
                    inbound_user: None,
                };
                let mut sink = sink.lock().await;
                sink.send(packet).await.map_err(|e| anyhow::anyhow!("proxy UDP send: {e}"))
            }
        };

        if let Err(error) = send_res {
            self.unregister(id).await;
            return Err(error);
        }

        match tokio::time::timeout(self.timeout, receiver).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => anyhow::bail!("UDP DNS receive loop stopped"),
            Err(_) => {
                self.unregister(id).await;
                anyhow::bail!("UDP DNS query timed out after {:?}", self.timeout)
            }
        }
    }

    async fn direct_receive_loop(pool: Weak<Self>, socket: Arc<UdpSocket>) {
        let mut buffer = vec![0; 65535];
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
            pool.handle_response(&buffer[..length]).await;
        }
    }

    async fn proxied_receive_loop(
        pool: Weak<Self>,
        mut stream: SplitStream<BoxedChainedDatagram>,
    ) {
        while let Some(packet) = stream.next().await {
            let buffer = packet.data;
            if buffer.len() < 12 {
                continue;
            }
            let Some(pool) = pool.upgrade() else {
                break;
            };
            pool.handle_response(&buffer).await;
        }
    }

    async fn handle_response(&self, buffer: &[u8]) {
        let id = u16::from_be_bytes([buffer[0], buffer[1]]);
        let pending = {
            let mut state = self.state.lock().await;
            let matches = Self::question_end(buffer).is_ok_and(|end| {
                state
                    .pending
                    .get(&id)
                    .is_some_and(|pending| pending.question == buffer[12..end])
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

    async fn unregister(&self, id: u16) {
        let mut state = self.state.lock().await;
        if state.pending.remove(&id).is_some() {
            Self::retire_id(&mut state, id);
        }
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
        state.retired.push_back((Instant::now() + ID_QUARANTINE, id));
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

    fn question_end(query: &[u8]) -> anyhow::Result<usize> {
        let mut pos = 12;
        if !crate::app::dns::wire::skip_dns_name(query, &mut pos) || pos + 4 > query.len() {
            anyhow::bail!("malformed DNS question");
        }
        Ok(pos + 4)
    }
}
