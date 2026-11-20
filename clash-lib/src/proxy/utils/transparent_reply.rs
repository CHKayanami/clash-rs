use std::{io, net::SocketAddr, num::NonZeroUsize, sync::Arc, time::Duration};
use lru::LruCache;
use tokio::{net::UdpSocket, time::Instant};
use super::ToCanonical;

#[cfg(all(target_os = "linux", any(feature = "tproxy", feature = "ebpf")))]
use tokio::{sync::mpsc, time::interval_at};
#[cfg(all(target_os = "linux", any(feature = "tproxy", feature = "ebpf")))]
use crate::proxy::{
    datagram::{UdpPacket, batch::MAX_BATCH_PACKETS},
    utils::udp_batch::{SendWorkspace, send_replies},
};

const MAX_REPLY_SOCKETS: usize = 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(all(target_os = "linux", any(feature = "tproxy", feature = "ebpf")))]
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

struct Entry {
    socket: Arc<UdpSocket>,
    last_used: Instant,
}

struct ReplySocketCache {
    sockets: LruCache<SocketAddr, Entry>,
}

impl Default for ReplySocketCache {
    fn default() -> Self {
        Self {
            sockets: LruCache::new(NonZeroUsize::new(MAX_REPLY_SOCKETS).unwrap()),
        }
    }
}

impl ReplySocketCache {
    fn get_or_create(
        &mut self,
        source: SocketAddr,
        now: Instant,
        create: impl FnOnce() -> io::Result<UdpSocket>,
    ) -> io::Result<Arc<UdpSocket>> {
        let source = source.to_canonical();
        if let Some(entry) = self.sockets.get_mut(&source) {
            if now.saturating_duration_since(entry.last_used) < IDLE_TIMEOUT {
                entry.last_used = now;
                return Ok(entry.socket.clone());
            }
            // Remove the expired descriptor before opening its replacement.
            self.sockets.pop(&source);
        }
        let socket = Arc::new(create()?);
        self.sockets.put(
            source,
            Entry {
                socket: socket.clone(),
                last_used: now,
            },
        );
        Ok(socket)
    }

    #[cfg(any(test, all(target_os = "linux", any(feature = "tproxy", feature = "ebpf"))))]
    fn expire(&mut self, now: Instant) {
        while self
            .sockets
            .peek_lru()
            .is_some_and(|(_, entry)| now.saturating_duration_since(entry.last_used) >= IDLE_TIMEOUT)
        {
            self.sockets.pop_lru();
        }
    }
}

#[cfg(all(target_os = "linux", any(feature = "tproxy", feature = "ebpf")))]
pub(crate) async fn relay(
    mut packets: mpsc::Receiver<UdpPacket>,
    mut create_socket: impl FnMut(SocketAddr) -> io::Result<UdpSocket>,
) {
    let mut sockets = ReplySocketCache::default();
    let mut workspace = SendWorkspace::default();
    let mut batch = Vec::with_capacity(MAX_BATCH_PACKETS);
    let mut sweep = interval_at(Instant::now() + SWEEP_INTERVAL, SWEEP_INTERVAL);
    loop {
        let count = tokio::select! {
            count = packets.recv_many(&mut batch, MAX_BATCH_PACKETS) => count,
            _ = sweep.tick() => { sockets.expire(Instant::now()); continue; },
        };
        if count == 0 {
            break;
        }
        let now = Instant::now();
        send_replies(&batch, &mut workspace, |source| {
            sockets.get_or_create(source, now, || create_socket(source))
        })
        .await;
        batch.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, UdpSocket as StdUdpSocket};

    fn socket() -> io::Result<UdpSocket> {
        let socket = StdUdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket)
    }

    #[tokio::test]
    async fn reply_socket_cache_enforces_capacity_and_reuses_recent_sources() {
        let mut cache = ReplySocketCache {
            sockets: LruCache::new(NonZeroUsize::new(2).unwrap()),
        };
        let a = SocketAddr::from(([192, 0, 2, 1], 1));
        let b = SocketAddr::from(([192, 0, 2, 1], 2));
        let c = SocketAddr::from(([192, 0, 2, 1], 3));
        let first = cache
            .get_or_create(a, Instant::now(), socket)
            .unwrap()
            .local_addr()
            .unwrap();
        cache.get_or_create(b, Instant::now(), socket).unwrap();
        assert_eq!(
            cache
                .get_or_create(a, Instant::now(), || panic!("must reuse socket"))
                .unwrap()
                .local_addr()
                .unwrap(),
            first
        );
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
        assert!(
            cache
                .get_or_create(source, Instant::now(), || {
                    Err(io::Error::other("replacement failed"))
                })
                .is_err()
        );
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
        cache
            .get_or_create(b, Instant::now(), || panic!("must reuse socket"))
            .unwrap();
        tokio::time::advance(IDLE_TIMEOUT / 2).await;
        cache.expire(Instant::now());
        assert!(!cache.sockets.contains(&a));
        assert!(cache.sockets.contains(&b));
    }

    #[tokio::test]
    async fn canonicalizes_ipv4_mapped_ipv6_sources() {
        let mut cache = ReplySocketCache::default();
        let v4 = SocketAddr::from(([192, 0, 2, 1], 1));
        let mapped = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped(), 1));
        let first = cache.get_or_create(mapped, Instant::now(), socket).unwrap();
        let second = cache
            .get_or_create(v4, Instant::now(), || panic!("must reuse canonical socket"))
            .unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(cache.sockets.len(), 1);
    }

    #[tokio::test]
    async fn failed_create_when_full_preserves_existing_entries() {
        let mut cache = ReplySocketCache {
            sockets: LruCache::new(NonZeroUsize::new(2).unwrap()),
        };
        let a = SocketAddr::from(([192, 0, 2, 1], 1));
        let b = SocketAddr::from(([192, 0, 2, 1], 2));
        let c = SocketAddr::from(([192, 0, 2, 1], 3));
        cache.get_or_create(a, Instant::now(), socket).unwrap();
        cache.get_or_create(b, Instant::now(), socket).unwrap();
        assert!(
            cache
                .get_or_create(c, Instant::now(), || Err(io::Error::other("bind failed")))
                .is_err()
        );
        assert_eq!(cache.sockets.len(), 2);
        assert!(cache.sockets.contains(&a));
        assert!(cache.sockets.contains(&b));
    }
}
