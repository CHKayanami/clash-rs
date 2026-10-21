use std::{io, net::SocketAddr, num::NonZeroUsize, sync::Arc, time::Duration};
use clash_ebpf::EbpfListener;
use lru::LruCache;
use tokio::{net::UdpSocket, sync::mpsc, time::{Instant, interval_at}};
use crate::proxy::{datagram::UdpPacket, utils::udp_batch::send_replies};
use clash_common::udp::MAX_BATCH;

const MAX_REPLY_SOCKETS: usize = 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

struct Entry { socket: Arc<UdpSocket>, last_used: Instant }
struct ReplySocketCache { sockets: LruCache<SocketAddr, Entry> }

impl Default for ReplySocketCache {
    fn default() -> Self {
        Self { sockets: LruCache::new(NonZeroUsize::new(MAX_REPLY_SOCKETS).unwrap()) }
    }
}

impl ReplySocketCache {
    fn get_or_create(&mut self, source: SocketAddr, now: Instant,
        create: impl FnOnce() -> io::Result<UdpSocket>,
    ) -> io::Result<Arc<UdpSocket>> {
        if let Some(entry) = self.sockets.get_mut(&source) {
            if now.saturating_duration_since(entry.last_used) < IDLE_TIMEOUT {
                entry.last_used = now;
                return Ok(entry.socket.clone());
            }
            // Remove the expired descriptor before opening its replacement.
            self.sockets.pop(&source);
        }
        if self.sockets.len() == self.sockets.cap().get() { self.sockets.pop_lru(); }
        let socket = Arc::new(create()?);
        self.sockets.put(source, Entry { socket: socket.clone(), last_used: now });
        Ok(socket)
    }

    fn expire(&mut self, now: Instant) {
        while self.sockets.peek_lru()
            .is_some_and(|(_, entry)| now.saturating_duration_since(entry.last_used) >= IDLE_TIMEOUT) {
            self.sockets.pop_lru();
        }
    }
}

pub(super) async fn relay(listener: Arc<EbpfListener>, mut packets: mpsc::Receiver<UdpPacket>) {
    let mut sockets = ReplySocketCache::default();
    let mut batch = Vec::with_capacity(MAX_BATCH);
    let mut sweep = interval_at(Instant::now() + SWEEP_INTERVAL, SWEEP_INTERVAL);
    loop {
        let count = tokio::select! {
            count = packets.recv_many(&mut batch, MAX_BATCH) => count,
            _ = sweep.tick() => { sockets.expire(Instant::now()); continue; },
        };
        if count == 0 { break; }
        let now = Instant::now();
        send_replies(&batch, |source| {
            sockets.get_or_create(source, now, || listener.create_reply_socket(source))
        }).await;
        batch.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket as StdUdpSocket;

    fn socket() -> io::Result<UdpSocket> {
        let socket = StdUdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket)
    }

    #[tokio::test]
    async fn reply_socket_cache_enforces_capacity_and_reuses_recent_sources() {
        let mut cache = ReplySocketCache { sockets: LruCache::new(NonZeroUsize::new(2).unwrap()) };
        let a = SocketAddr::from(([192, 0, 2, 1], 1));
        let b = SocketAddr::from(([192, 0, 2, 1], 2));
        let c = SocketAddr::from(([192, 0, 2, 1], 3));
        let first = cache.get_or_create(a, Instant::now(), socket).unwrap().local_addr().unwrap();
        cache.get_or_create(b, Instant::now(), socket).unwrap();
        assert_eq!(cache.get_or_create(a, Instant::now(), || panic!("must reuse socket"))
            .unwrap().local_addr().unwrap(), first);
        cache.get_or_create(c, Instant::now(), socket).unwrap();
        assert_eq!(cache.sockets.len(), 2);
        assert!(cache.sockets.contains(&a));
        assert!(!cache.sockets.contains(&b));
    }

    #[tokio::test(start_paused = true)]
    async fn expired_hit_is_removed_even_if_replacement_fails() {
        let mut cache = ReplySocketCache::default();
        let source = SocketAddr::from(([192, 0, 2, 1], 1));
        let old = cache.get_or_create(source, Instant::now(), socket).unwrap();
        tokio::time::advance(IDLE_TIMEOUT).await;
        assert!(cache.get_or_create(source, Instant::now(), || {
            Err(io::Error::other("replacement failed"))
        }).is_err());
        assert!(!cache.sockets.contains(&source));
        let new = cache.get_or_create(source, Instant::now(), socket).unwrap();
        assert!(!Arc::ptr_eq(&old, &new));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_sockets_are_reclaimed_without_new_sources() {
        let mut cache = ReplySocketCache::default();
        let a = SocketAddr::from(([192, 0, 2, 1], 1));
        let b = SocketAddr::from(([192, 0, 2, 1], 2));
        cache.get_or_create(a, Instant::now(), socket).unwrap();
        cache.get_or_create(b, Instant::now(), socket).unwrap();
        tokio::time::advance(IDLE_TIMEOUT / 2).await;
        cache.get_or_create(b, Instant::now(), || panic!("must reuse socket")).unwrap();
        tokio::time::advance(IDLE_TIMEOUT / 2).await;
        cache.expire(Instant::now());
        assert!(!cache.sockets.contains(&a));
        assert!(cache.sockets.contains(&b));
    }
}
