use std::{io, net::SocketAddr, num::NonZeroUsize, sync::Arc, time::Duration};
use clash_ebpf::EbpfListener;
use lru::LruCache;
use tokio::{net::UdpSocket, sync::mpsc, time::{Instant, interval_at}};
use tracing::warn;
use crate::proxy::datagram::UdpPacket;

const MAX_REPLY_SOCKETS: usize = 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

struct Entry { socket: UdpSocket, last_used: Instant }
struct ReplySocketCache { sockets: LruCache<SocketAddr, Entry> }

impl Default for ReplySocketCache {
    fn default() -> Self {
        Self { sockets: LruCache::new(NonZeroUsize::new(MAX_REPLY_SOCKETS).unwrap()) }
    }
}

impl ReplySocketCache {
    fn get_or_create(&mut self, source: SocketAddr, now: Instant,
        create: impl FnOnce() -> io::Result<UdpSocket>,
    ) -> io::Result<&UdpSocket> {
        if self.sockets.peek(&source)
            .is_some_and(|entry| now.saturating_duration_since(entry.last_used) >= IDLE_TIMEOUT) {
            self.sockets.pop(&source);
        }
        if !self.sockets.contains(&source) {
            // Release a descriptor before opening another one at capacity.
            if self.sockets.len() == self.sockets.cap().get() { self.sockets.pop_lru(); }
            self.sockets.put(source, Entry { socket: create()?, last_used: now });
        }
        let entry = self.sockets.get_mut(&source).unwrap();
        entry.last_used = now;
        Ok(&entry.socket)
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
    let mut batch = Vec::with_capacity(32);
    let mut sweep = interval_at(Instant::now() + SWEEP_INTERVAL, SWEEP_INTERVAL);
    loop {
        let count = tokio::select! {
            count = packets.recv_many(&mut batch, 32) => count,
            _ = sweep.tick() => { sockets.expire(Instant::now()); continue; },
        };
        if count == 0 { break; }
        for packet in batch.drain(..) {
            let (Some(source), Some(client)) =
                (packet.src_addr.try_into_socket_addr(), packet.dst_addr.try_into_socket_addr())
                else { warn!("eBPF UDP reply contains a non-IP address"); continue; };
            match sockets.get_or_create(source, Instant::now(), || listener.create_reply_socket(source)) {
                Ok(socket) => {
                    if let Err(error) = socket.send_to(&packet.data, client).await {
                        warn!("failed to send transparent UDP reply from {source}: {error}");
                    }
                },
                // A normal listener socket would return the wrong source IP or
                // port. Drop explicitly rather than silently changing addresses.
                Err(error) => warn!("failed to create transparent UDP reply socket for {source}: {error}"),
            }
        }
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
