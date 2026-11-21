use super::*;
use bytes::Bytes;
use futures::future::poll_fn;
use std::net::{Ipv4Addr, UdpSocket as StdUdpSocket};
use tokio::{sync::oneshot, task::spawn_blocking, time::{advance, timeout}};

fn socket() -> io::Result<UdpSocket> {
    let socket = StdUdpSocket::bind("127.0.0.1:0")?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

fn ready_socket(result: io::Result<ReplySocket>) -> Arc<ReplyFd> {
    let ReplySocket::Ready(socket) = result.unwrap() else { panic!("expected a ready reply socket"); };
    socket
}

#[tokio::test]
async fn association_batches_preserve_source_order_and_send_valid_suffix() {
    let a = socket().unwrap();
    let b = socket().unwrap();
    let first = a.local_addr().unwrap();
    let second = b.local_addr().unwrap();
    let a = Mutex::new(Some(a));
    let b = Mutex::new(Some(b));
    let client = socket().unwrap();
    let destination = client.local_addr().unwrap();
    let mut writer = ReplyWriter::new(Arc::new(ReplySockets::new(move |source| {
        let socket = if source == first { &a } else { &b };
        Ok(socket.lock().take().expect("reuse the bound reply socket"))
    })));

    let mut packets = [
        (first, Bytes::from_static(b"one")),
        (second, Bytes::new()),
        (first, Bytes::from(vec![0; 70_000])),
        (first, Bytes::from_static(b"two")),
    ].into_iter().map(|(source, data)| {
        UdpPacket::new(data, source.into(), destination.into())
    }).collect::<Vec<_>>();
    let receive_buffer = packets.as_ptr();
    writer.submit(&mut packets);
    assert!(packets.is_empty());
    assert_eq!(packets.as_ptr(), receive_buffer);
    assert!(writer.pending.is_none());
    timeout(Duration::from_secs(2), poll_fn(|cx| writer.poll_send(cx))).await.unwrap();
    packets.push(UdpPacket::new(Bytes::from_static(b"three"), first.into(), destination.into()));
    writer.submit(&mut packets);
    assert!(writer.pending.is_none());
    timeout(Duration::from_secs(2), poll_fn(|cx| writer.poll_send(cx))).await.unwrap();

    let mut expected = [
        (first, &b"one"[..]),
        (first, &b"two"[..]),
        (second, &b""[..]),
    ];
    expected.sort_by_key(|(source, _)| *source);
    timeout(Duration::from_secs(2), async {
        let mut buffer = [0; 16];
        for (source, data) in expected.into_iter().chain([(first, &b"three"[..])]) {
            let (len, from) = client.recv_from(&mut buffer).await.unwrap();
            assert_eq!((from, &buffer[..len]), (source, data));
        }
    }).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn blocked_writes_use_one_deadline_per_batch() {
    use std::future::pending;
    let now = Instant::now();
    let deadline = now + WRITE_TIMEOUT;
    assert!(matches!(wait_until_ready(deadline, async { Ok(()) }).await, Some(Ok(()))));
    advance(WRITE_TIMEOUT / 2).await;
    assert!(wait_until_ready(deadline, pending()).await.is_none());
    // Tokio timers are rounded to the next millisecond.
    assert!(Instant::now() <= now + WRITE_TIMEOUT + Duration::from_millis(1));
}

#[tokio::test]
async fn timed_out_source_drops_only_its_unsent_packets() {
    let client = socket().unwrap();
    let destination = client.local_addr().unwrap();
    let shard = ReplySocketShard::new(NonZeroUsize::MIN);
    let first = ready_socket(shard.socket(destination, socket));
    let first_addr = first.local_addr().unwrap();
    let second = socket().unwrap();
    let second_addr = second.local_addr().unwrap();
    let second = Mutex::new(Some(second));
    let sockets = Arc::new(ReplySockets::new(move |source| {
        assert_eq!(source, second_addr, "the expired source must not be retried");
        Ok(second.lock().take().unwrap())
    }));
    let packets = [
        (first_addr, &b"sent"[..]),
        (first_addr, &b"drop-1"[..]),
        (first_addr, &b"drop-2"[..]),
        (second_addr, &b"next-source"[..]),
    ].into_iter().map(|(source, data)| {
        UdpPacket::new(Bytes::from_static(data), source.into(), destination.into())
    }).collect();

    timeout(Duration::from_secs(2), async {
        first.send_to(b"sent", destination).await.unwrap();
        // Start after a successful prefix and force the wait deadline to
        // expire without depending on the kernel reaching UDP backpressure.
        let cursor = ReplyCursor {
            offset: 1,
            group: Some(ReplyGroup { source: first_addr, end: 3, socket: ReplySocket::Ready(first) }),
        };
        send_pending(sockets.clone(), packets, cursor, Instant::now()).await;
        assert_eq!(sockets.timed_out_packets.load(Ordering::Relaxed), 2);

        let mut buffer = [0; 32];
        let (len, from) = client.recv_from(&mut buffer).await.unwrap();
        assert_eq!((from, &buffer[..len]), (first_addr, &b"sent"[..]));
        let (len, from) = client.recv_from(&mut buffer).await.unwrap();
        assert_eq!((from, &buffer[..len]), (second_addr, &b"next-source"[..]));
        assert!(client.try_recv_from(&mut buffer).is_err());
    }).await.unwrap();
}

#[tokio::test]
async fn reply_socket_cache_enforces_capacity_and_reuses_recent_sources() {
    let shard = Arc::new(ReplySocketShard::new(NonZeroUsize::new(2).unwrap()));
    let a = SocketAddr::from(([192, 0, 2, 1], 1));
    let b = SocketAddr::from(([192, 0, 2, 1], 2));
    let c = SocketAddr::from(([192, 0, 2, 1], 3));
    let first = ready_socket(shard.socket(a, socket)).local_addr().unwrap();
    shard.socket(b, socket).unwrap();
    assert_eq!(
        ready_socket(shard.socket(a, || panic!("must reuse socket"))).local_addr().unwrap(),
        first
    );
    shard.socket(c, socket).unwrap();
    let cache = shard.cache.lock();
    assert_eq!(cache.sockets.len(), 2);
    assert!(cache.sockets.contains(&a));
    assert!(!cache.sockets.contains(&b));
}

#[tokio::test(start_paused = true)]
async fn expired_hit_is_removed_even_if_replacement_fails() {
    let shard = Arc::new(ReplySocketShard::new(NonZeroUsize::new(2).unwrap()));
    let source = SocketAddr::from(([192, 0, 2, 1], 1));
    let old = Arc::downgrade(&ready_socket(shard.socket(source, socket)));
    tokio::time::advance(IDLE_TIMEOUT).await;
    assert!(
        shard
            .socket(source, || {
                Err(io::Error::other("replacement failed"))
            })
            .is_err()
    );
    assert!(!shard.cache.lock().sockets.contains(&source));
    let new = ready_socket(shard.socket(source, socket));
    assert!(!old.ptr_eq(&Arc::downgrade(&new)));
}

#[tokio::test(start_paused = true)]
async fn idle_sockets_are_reclaimed_without_new_sources() {
    let shard = Arc::new(ReplySocketShard::new(NonZeroUsize::new(2).unwrap()));
    let a = SocketAddr::from(([192, 0, 2, 1], 1));
    let b = SocketAddr::from(([192, 0, 2, 1], 2));
    shard.socket(a, socket).unwrap();
    shard.socket(b, socket).unwrap();
    tokio::time::advance(IDLE_TIMEOUT / 2).await;
    shard
        .socket(b, || panic!("must reuse socket"))
        .unwrap();
    tokio::time::advance(IDLE_TIMEOUT / 2).await;
    let mut cache = shard.cache.lock();
    cache.expire(Instant::now());
    assert!(!cache.sockets.contains(&a));
    assert!(cache.sockets.contains(&b));
}

#[tokio::test]
async fn canonicalizes_ipv4_mapped_ipv6_sources() {
    let sockets = ReplySockets::new(|source| {
        assert!(source.is_ipv4(), "factory must receive the canonical address");
        socket()
    });
    let ip = Ipv4Addr::new(192, 0, 2, 1);
    for port in 10000..10016 {
        let v4 = SocketAddr::from((ip, port));
        let mapped = SocketAddr::from((ip.to_ipv6_mapped(), port));
        assert!(Arc::ptr_eq(&ready_socket(sockets.socket(v4)), &ready_socket(sockets.socket(mapped))));
    }
}

#[tokio::test]
async fn failed_create_returns_permit_after_reclamation() {
    let shard = ReplySocketShard::new(NonZeroUsize::new(2).unwrap());
    let a = SocketAddr::from(([192, 0, 2, 1], 1));
    let b = SocketAddr::from(([192, 0, 2, 1], 2));
    let c = SocketAddr::from(([192, 0, 2, 1], 3));
    shard.socket(a, socket).unwrap();
    shard.socket(b, socket).unwrap();
    assert!(
        shard
            .socket(c, || Err(io::Error::other("bind failed")))
            .is_err()
    );
    {
        let cache = shard.cache.lock();
        assert_eq!(cache.sockets.len(), 1);
        assert!(cache.sockets.contains(&b));
        assert!(cache.creating.is_empty());
    }
    assert_eq!(shard.slots.available_permits(), 1);
    ready_socket(shard.socket(c, socket));
    assert_eq!(shard.slots.available_permits(), 0);
}

#[tokio::test]
async fn socket_creation_releases_shard_lock_and_reserves_descriptor_budget() {
    let shard = Arc::new(ReplySocketShard::new(NonZeroUsize::new(2).unwrap()));
    let a = "127.0.0.1:10001".parse().unwrap();
    let b = "127.0.0.1:10002".parse().unwrap();
    let c = "127.0.0.1:10003".parse().unwrap();
    ready_socket(shard.socket(b, socket));
    let cached = ready_socket(shard.socket(a, socket));

    let (started, creating) = oneshot::channel();
    let (release, continue_bind) = oneshot::channel();
    let creator = spawn_blocking({
        let shard = shard.clone();
        move || ready_socket(shard.socket(c, || {
            let reply_socket = socket()?;
            started.send(()).unwrap();
            continue_bind.blocking_recv().unwrap();
            Ok(reply_socket)
        }))
    });

    timeout(Duration::from_secs(2), async {
        creating.await.unwrap();
        let (warm, mut same_source) = spawn_blocking({
            let shard = shard.clone();
            move || {
                let warm = ready_socket(shard.socket(a, || panic!("cached lookup must keep working")));
                let ReplySocket::Pending(same_source) =
                    shard.socket(c, || panic!("one bind per source")).unwrap()
                else { panic!("source is still being bound"); };
                (warm, same_source)
            }
        }).await.unwrap();
        assert!(Arc::ptr_eq(&cached, &warm));
        assert_eq!(shard.slots.available_permits(), 0);
        assert!(!shard.cache.lock().sockets.contains(&b));

        release.send(()).unwrap();
        let created = creator.await.unwrap();
        same_source.changed().await.unwrap();
        let reused = ready_socket(shard.socket(c, || panic!("must reuse the completed bind")));
        assert!(Arc::ptr_eq(&created, &reused));

        let cache = shard.cache.lock();
        assert_eq!(cache.sockets.len(), 2);
        assert!(cache.creating.is_empty());
    }).await.unwrap();
}

#[tokio::test]
async fn exhausted_budget_preserves_active_socket_without_notifying_waiters() {
    let shard = ReplySocketShard::new(NonZeroUsize::MIN);
    let a = "127.0.0.1:10001".parse().unwrap();
    let b = "127.0.0.1:10002".parse().unwrap();
    let writer = ready_socket(shard.socket(a, socket));
    let notification = shard.created.subscribe();
    let err = shard.socket(b, || panic!("socket budget in use")).err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    assert!(!notification.has_changed().unwrap());
    assert!(shard.cache.lock().creating.is_empty());
    let reused = ready_socket(shard.socket(a, || panic!("active socket must stay cached")));
    assert!(Arc::ptr_eq(&writer, &reused));
    assert_eq!(shard.slots.available_permits(), 0);
    drop(reused);
    drop(writer);
    ready_socket(shard.socket(b, socket));
    assert!(!shard.cache.lock().sockets.contains(&a));
}

#[tokio::test]
async fn cold_creations_reserve_the_hard_descriptor_budget() {
    let shard = ReplySocketShard::new(NonZeroUsize::new(2).unwrap());
    let a = "127.0.0.1:10001".parse().unwrap();
    let b = "127.0.0.1:10002".parse().unwrap();
    let c = "127.0.0.1:10003".parse().unwrap();
    let first = ready_socket(shard.socket(a, || {
        let _second = ready_socket(shard.socket(b, || {
            let err = shard.socket(c, || panic!("cold creations already own both slots"))
                .err().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
            socket()
        }));
        socket()
    }));

    let cache = shard.cache.lock();
    assert_eq!(cache.sockets.len(), 2);
    assert!(Arc::ptr_eq(&first, &cache.sockets.peek(&a).unwrap().socket));
    assert!(cache.creating.is_empty());
    assert_eq!(shard.slots.available_permits(), 0);
}

#[tokio::test]
async fn reclamation_skips_active_lru_and_evicts_only_the_idle_socket() {
    let shard = ReplySocketShard::new(NonZeroUsize::new(2).unwrap());
    let a = "127.0.0.1:10001".parse().unwrap();
    let b = "127.0.0.1:10002".parse().unwrap();
    let c = "127.0.0.1:10003".parse().unwrap();
    let writer = ready_socket(shard.socket(a, socket));
    ready_socket(shard.socket(b, socket));
    ready_socket(shard.socket(c, socket));
    let cache = shard.cache.lock();
    assert_eq!(cache.sockets.len(), 2);
    assert!(Arc::ptr_eq(&writer, &cache.sockets.peek(&a).unwrap().socket));
    assert!(!cache.sockets.contains(&b));
    assert!(cache.sockets.contains(&c));
    assert_eq!(shard.slots.available_permits(), 0);
}
