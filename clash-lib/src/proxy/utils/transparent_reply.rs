use std::{
    array::from_fn, collections::{HashSet, hash_map::RandomState}, future::Future, hash::BuildHasher, io,
    net::SocketAddr, num::NonZeroUsize, ops::Deref, sync::{Arc, atomic::{AtomicU64, Ordering}},
    task::{Context, Poll, ready}, time::Duration,
};

use lru::LruCache;
use parking_lot::Mutex;
use tokio::{
    net::UdpSocket, sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::consume_budget, time::{Instant, timeout_at},
};
use futures::future::BoxFuture;
use tracing::warn;

use super::{ToCanonical, udp_batch::try_send_replies};
use crate::{
    proxy::datagram::{UdpPacket, batch::{BatchResult, MAX_DIRECT_BATCH_PACKETS}},
    session::SocksAddr,
};

const MAX_REPLY_SOCKETS: usize = 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

struct Entry {
    socket: Arc<ReplyFd>,
    last_used: Instant,
}

struct ReplySocketCache {
    sockets: LruCache<SocketAddr, Entry>,
    creating: HashSet<SocketAddr>,
}

impl ReplySocketCache {
    fn get(&mut self, source: SocketAddr, now: Instant) -> Option<Arc<ReplyFd>> {
        if let Some(entry) = self.sockets.get_mut(&source) {
            if now.saturating_duration_since(entry.last_used) < IDLE_TIMEOUT
                || Arc::strong_count(&entry.socket) > 1 {
                entry.last_used = now;
                return Some(entry.socket.clone());
            }
            // Remove the expired descriptor before opening its replacement.
            self.sockets.pop(&source);
        }
        None
    }

    fn expire(&mut self, now: Instant) {
        while self
            .sockets
            .peek_lru()
            .is_some_and(|(_, entry)| {
                now.saturating_duration_since(entry.last_used) >= IDLE_TIMEOUT
                    && Arc::strong_count(&entry.socket) == 1
            })
        {
            self.sockets.pop_lru();
        }
    }
}

enum ReplySocket {
    Ready(Arc<ReplyFd>),
    Pending(watch::Receiver<()>),
}

struct ReplySocketShard {
    cache: Mutex<ReplySocketCache>,
    slots: Arc<Semaphore>,
    created: watch::Sender<()>,
}

struct ReplyFd {
    socket: UdpSocket,
    // Fields drop in declaration order: close the socket before returning
    // its descriptor credit. Writers can outlive the cache entry.
    _permit: OwnedSemaphorePermit,
}

impl Deref for ReplyFd {
    type Target = UdpSocket;

    fn deref(&self) -> &Self::Target { &self.socket }
}

impl ReplySocketShard {
    fn new(capacity: NonZeroUsize) -> Self {
        Self {
            cache: Mutex::new(ReplySocketCache {
                sockets: LruCache::new(capacity), creating: HashSet::new(),
            }),
            slots: Arc::new(Semaphore::new(capacity.get())),
            created: watch::Sender::new(()),
        }
    }

    fn socket(&self, source: SocketAddr, create: impl FnOnce() -> io::Result<UdpSocket>)
        -> io::Result<ReplySocket>
    {
        let mut cache = self.cache.lock();
        if let Some(socket) = cache.get(source, Instant::now()) {
            return Ok(ReplySocket::Ready(socket));
        }
        if cache.creating.contains(&source) {
            return Ok(ReplySocket::Pending(self.created.subscribe()));
        }
        let permit = self.reserve_fd(&mut cache)?;
        cache.creating.insert(source);
        drop(cache);

        let reservation = SocketReservation { shard: self, source, active: true };
        // Release the permit before notifying waiters if bind fails.
        let permit = permit;
        let socket = ReplyFd { socket: create()?, _permit: permit };
        Ok(ReplySocket::Ready(reservation.publish(socket)))
    }

    fn reserve_fd(&self, cache: &mut ReplySocketCache) -> io::Result<OwnedSemaphorePermit> {
        loop {
            if let Ok(permit) = self.slots.clone().try_acquire_owned() {
                return Ok(permit);
            }
            // Keep active sockets cached for reuse. Removing an idle socket
            // returns its permit before any other creator can take it.
            let Some(address) = cache.sockets.iter().rev()
                .find(|(_, entry)| Arc::strong_count(&entry.socket) == 1)
                .map(|(address, _)| *address)
            else {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "UDP reply socket budget exhausted",
                ));
            };
            cache.sockets.pop(&address);
        }
    }
}

struct SocketReservation<'a> {
    shard: &'a ReplySocketShard,
    source: SocketAddr,
    active: bool,
}

impl SocketReservation<'_> {
    fn publish(mut self, socket: ReplyFd) -> Arc<ReplyFd> {
        let socket = Arc::new(socket);
        let mut cache = self.shard.cache.lock();
        debug_assert!(cache.sockets.len() < cache.sockets.cap().get());
        cache.sockets.put(self.source, Entry {
            socket: socket.clone(), last_used: Instant::now(),
        });
        cache.creating.remove(&self.source);
        self.active = false;
        drop(cache);
        self.shard.created.send_modify(|_| {});
        socket
    }
}

impl Drop for SocketReservation<'_> {
    fn drop(&mut self) {
        if self.active {
            self.shard.cache.lock().creating.remove(&self.source);
            self.shard.created.send_modify(|_| {});
        }
    }
}

const CACHE_SHARDS: usize = 8;
const WRITE_TIMEOUT: Duration = Duration::from_millis(100);

pub(crate) struct ReplySockets {
    shards: [ReplySocketShard; CACHE_SHARDS],
    shard_hash: RandomState,
    create: Box<dyn Fn(SocketAddr) -> io::Result<UdpSocket> + Send + Sync>,
    timed_out_packets: AtomicU64,
}

impl ReplySockets {
    pub(crate) fn new(
        create: impl Fn(SocketAddr) -> io::Result<UdpSocket> + Send + Sync + 'static,
    ) -> Self {
        let capacity = NonZeroUsize::new(MAX_REPLY_SOCKETS / CACHE_SHARDS).unwrap();
        Self {
            shards: from_fn(|_| ReplySocketShard::new(capacity)),
            shard_hash: RandomState::new(),
            create: Box::new(create),
            timed_out_packets: AtomicU64::new(0),
        }
    }

    fn socket(&self, source: SocketAddr) -> io::Result<ReplySocket> {
        let source = source.to_canonical();
        let index = self.shard_hash.hash_one(source) as usize % CACHE_SHARDS;
        self.shards[index].socket(source, || (self.create)(source))
    }

    pub(crate) fn sweep(&self) {
        let now = Instant::now();
        for shard in &self.shards { shard.cache.lock().expire(now); }
    }

    fn report_timeout(&self, dropped: usize) {
        let previous = self.timed_out_packets.fetch_add(dropped as u64, Ordering::Relaxed);
        let total = previous.wrapping_add(dropped as u64);
        if total.leading_zeros() != previous.leading_zeros() {
            warn!(dropped, total, "transparent UDP reply timed out waiting for socket");
        }
    }
}

/// Owned by a single UDP association. Only one receive batch can be in flight.
pub(crate) struct ReplyWriter {
    sockets: Arc<ReplySockets>,
    pending: Option<BoxFuture<'static, ()>>,
}

impl ReplyWriter {
    pub(crate) fn new(sockets: Arc<ReplySockets>) -> Self {
        Self { sockets, pending: None }
    }

    pub(crate) fn submit(&mut self, packets: &mut Vec<UdpPacket>) {
        debug_assert!(self.pending.is_none());
        packets.retain_mut(|packet| {
            if let (SocksAddr::Ip(source), SocksAddr::Ip(destination)) =
                (&mut packet.src_addr, &mut packet.dst_addr) {
                *source = source.to_canonical();
                *destination = destination.to_canonical();
                true
            } else {
                warn!("transparent UDP reply contains a non-IP address");
                false
            }
        });
        // Preserve receive order within a source while combining packets
        // that use the same socket. Insertion keeps small batches in place.
        for index in 1..packets.len() {
            let source = reply_source(&packets[index]);
            if reply_source(&packets[index - 1]) > source {
                let position = packets[..index].partition_point(|packet| reply_source(packet) <= source);
                packets[position..=index].rotate_right(1);
            }
        }
        let mut cursor = ReplyCursor::default();
        if cursor.try_send(&self.sockets, packets).is_pending() {
            // Keep the relay's receive allocation; only the unsent suffix
            // needs ownership across the readiness wait.
            let pending = packets.split_off(cursor.offset);
            cursor.group.as_mut().unwrap().end -= cursor.offset;
            cursor.offset = 0;
            self.pending = Some(Box::pin(send_pending(
                self.sockets.clone(), pending, cursor, Instant::now() + WRITE_TIMEOUT,
            )));
        }
        packets.clear();
    }

    pub(crate) fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(pending) = &mut self.pending {
            ready!(pending.as_mut().poll(cx));
            self.pending = None;
        }
        Poll::Ready(())
    }
}

fn reply_source(packet: &UdpPacket) -> SocketAddr {
    let SocksAddr::Ip(source) = packet.src_addr else { unreachable!("validated reply source"); };
    source
}

struct ReplyGroup {
    source: SocketAddr,
    end: usize,
    socket: ReplySocket,
}

#[derive(Default)]
struct ReplyCursor {
    offset: usize,
    group: Option<ReplyGroup>,
}

impl ReplyCursor {
    fn try_send(&mut self, sockets: &ReplySockets, packets: &[UdpPacket]) -> Poll<()> {
        while self.offset < packets.len() {
            if self.group.is_none() {
                let source = reply_source(&packets[self.offset]);
                let count = packets[self.offset..].iter().take(MAX_DIRECT_BATCH_PACKETS)
                    .take_while(|packet| reply_source(packet) == source).count();
                let end = self.offset + count;
                match sockets.socket(source) {
                    Ok(socket) => self.group = Some(ReplyGroup { source, end, socket }),
                    Err(error) => {
                        warn!("failed to create UDP reply socket for {source}: {error}");
                        self.offset = end;
                        continue;
                    }
                }
            }
            let group = self.group.as_ref().unwrap();
            let ReplySocket::Ready(socket) = &group.socket else { return Poll::Pending; };
            let result = ready!(try_send_replies(
                socket, group.source.is_ipv6(), &packets[self.offset..group.end],
            ));
            self.complete(result);
        }
        Poll::Ready(())
    }

    fn complete(&mut self, result: BatchResult) {
        let group = self.group.as_ref().unwrap();
        self.offset += result.sent;
        if let Some(error) = result.error {
            warn!("failed to send UDP reply from {}: {error}", group.source);
            self.offset += 1;
        }
        if self.offset == group.end { self.group = None; }
    }
}

async fn send_pending(
    sockets: Arc<ReplySockets>, packets: Vec<UdpPacket>, mut cursor: ReplyCursor,
    deadline: Instant,
) {
    loop {
        let group = cursor.group.as_mut().unwrap();
        let recreate_group = matches!(group.socket, ReplySocket::Pending(_));
        // Each association registers its own waiter on a shared socket.
        let result = match &mut group.socket {
            ReplySocket::Ready(socket) => wait_until_ready(deadline, socket.writable()).await,
            ReplySocket::Pending(created) => wait_until_ready(deadline, async {
                created.changed().await.map_err(|_| io::ErrorKind::BrokenPipe.into())
            }).await,
        };
        match result {
            Some(Ok(())) if recreate_group => cursor.group = None,
            Some(Ok(())) => {}
            Some(Err(error)) => cursor.complete(BatchResult::failed(error)),
            None => {
                // The next source still gets an immediate send attempt,
                // without restarting the batch's wait deadline.
                sockets.report_timeout(group.end - cursor.offset);
                cursor.offset = group.end;
                cursor.group = None;
            }
        }
        if cursor.try_send(&sockets, &packets).is_ready() { return; }
        consume_budget().await;
    }
}

async fn wait_until_ready(
    deadline: Instant, writable: impl Future<Output = io::Result<()>>,
) -> Option<io::Result<()>> {
    if Instant::now() >= deadline { return None; }
    timeout_at(deadline, writable).await.ok()
}

#[cfg(test)]
mod tests;
