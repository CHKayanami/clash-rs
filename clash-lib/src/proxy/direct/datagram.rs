use crate::{
    app::dns::ThreadSafeDNSResolver, common::errors::new_io_error,
    proxy::datagram::UdpPacket, session::SocksAddr,
};
use futures::{Sink, Stream, ready};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;

const UDP_DOMAIN_MAP_TTL: Duration = Duration::from_secs(60);

/// How many consecutive receive failures to tolerate before giving up on the
/// association, so a permanently broken socket cannot spin this loop.
const MAX_CONSECUTIVE_RECV_ERRORS: usize = 32;

/// Only sweep `ip_to_logical` for expiry once it has grown past this. Sweeping
/// on every send made a client talking to N destinations pay O(N) per packet.
const UDP_DOMAIN_MAP_SWEEP_THRESHOLD: usize = 64;

/// Minimum interval between two consecutive `ip_to_logical` sweeps to avoid
/// sweeping repeatedly within high-PPS burst transmissions.
const UDP_DOMAIN_MAP_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Maximum number of datagrams to batch drain on a single ready notification.
const MAX_BATCH_RECV_PACKETS: usize = 16;

#[inline]
fn canonicalize_src(src: SocketAddr) -> SocketAddr {
    match src {
        SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::from((v4, v6.port()))
            } else {
                src
            }
        }
        _ => src,
    }
}

#[must_use = "sinks do nothing unless polled"]
// TODO: maybe we should use abstract datagram IO interface instead of the
// Stream + Sink trait
pub struct OutboundDatagramImpl {
    inner: UdpSocket,
    /// Cached at construction: `local_addr()` is a syscall and the family
    /// cannot change, but it was being queried twice for every packet sent.
    local_is_ipv6: bool,
    resolver: ThreadSafeDNSResolver,
    flushed: bool,
    pkt: Option<UdpPacket>,
    // real upstream IP → dst_addr of the most recent outgoing packet to that
    // IP; used in poll_next to translate src_addr back to dst_addr.
    ip_to_logical: HashMap<SocketAddr, (SocksAddr, Instant)>,
    last_sweep: Instant,
    /// In-flight query polled in the forwarding task; retained across polls
    /// without spawning a task or restarting the lookup.
    pending_dns: Option<super::resolve::PendingResolution>,
    /// Resolved IP for the current queued packet; reused across poll_send_to
    /// retries so we never re-poll an already-completed DNS task.
    resolved_dst: Option<SocketAddr>,
    consecutive_recv_errors: usize,
    /// Prefetch buffer for datagram batching on ready events.
    recv_queue: VecDeque<UdpPacket>,
}

impl OutboundDatagramImpl {
    pub fn new(udp: UdpSocket, resolver: ThreadSafeDNSResolver) -> Self {
        Self {
            local_is_ipv6: udp
                .local_addr()
                .map(|addr| addr.is_ipv6())
                .unwrap_or(false),
            inner: udp,
            resolver,
            flushed: true,
            pkt: None,
            ip_to_logical: HashMap::new(),
            last_sweep: Instant::now(),
            pending_dns: None,
            resolved_dst: None,
            consecutive_recv_errors: 0,
            recv_queue: VecDeque::with_capacity(MAX_BATCH_RECV_PACKETS),
        }
    }
}

impl Sink<UdpPacket> for OutboundDatagramImpl {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.pending_dns = None;
        pin.pkt = Some(item);
        pin.flushed = false;
        pin.resolved_dst = None;
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut inner,
            local_is_ipv6,
            ref mut pkt,
            ref resolver,
            ref mut ip_to_logical,
            ref mut last_sweep,
            ref mut pending_dns,
            ref mut resolved_dst,
            ..
        } = *self;

        let p = pkt
            .as_ref()
            .ok_or_else(|| io::Error::other("no packet to send"))?;

        let dst = match &p.dst_addr {
            SocksAddr::Ip(addr) => {
                // Explicit IP path: clear any stale DNS state from a prior packet.
                *pending_dns = None;
                *resolved_dst = None;
                *addr
            }
            SocksAddr::Domain(domain, port) => {
                if let Some(addr) = *resolved_dst {
                    // Already resolved on a prior poll; skip DNS entirely.
                    addr
                } else {
                    let is_ipv6 = local_is_ipv6;
                    let addr = ready!(super::resolve::poll_resolve_destination(
                        cx,
                        pending_dns,
                        resolver,
                        domain,
                        *port,
                        is_ipv6,
                    ))?;
                    *resolved_dst = Some(addr);
                    addr
                }
            }
        };

        // When sending from a dual-stack AF_INET6 socket, the OS requires IPv4
        // destinations to be expressed as IPv4-mapped IPv6 addresses
        // (::ffff:x.x.x.x). Tokio's poll_send_to does not do this automatically
        // and will return EINVAL otherwise.
        let send_dst = match (local_is_ipv6, dst) {
            (true, SocketAddr::V4(v4)) => {
                SocketAddr::V6(std::net::SocketAddrV6::new(
                    v4.ip().to_ipv6_mapped(),
                    v4.port(),
                    0,
                    0,
                ))
            }
            _ => dst,
        };

        let n = ready!(inner.poll_send_to(cx, p.data.as_ref(), send_dst))?;

        let canon_dst = canonicalize_src(dst);

        // Only register logical domain mappings for Domain destinations.
        // Pure IP destinations do not need logical domain restoration, avoiding
        // unnecessary heap allocations and hash map thrashing on high-PPS IP flows.
        if matches!(p.dst_addr, SocksAddr::Domain(..)) {
            let now = Instant::now();
            if ip_to_logical.len() > UDP_DOMAIN_MAP_SWEEP_THRESHOLD
                && now.duration_since(*last_sweep) >= UDP_DOMAIN_MAP_SWEEP_INTERVAL
            {
                ip_to_logical.retain(|_, (_, ts)| {
                    now.duration_since(*ts) < UDP_DOMAIN_MAP_TTL
                });
                *last_sweep = now;
            }
            ip_to_logical.insert(canon_dst, (p.dst_addr.clone(), now));
        } else {
            ip_to_logical.remove(&canon_dst);
        }

        // Save length before clearing pkt (NLL ends p's borrow after this).
        let data_len = p.data.len();

        *pkt = None;
        self.flushed = true;

        if n == data_len {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(new_io_error(format!(
                "failed to send all data, only sent {n} bytes"
            ))))
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl Stream for OutboundDatagramImpl {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut inner,
            ref ip_to_logical,
            ref mut consecutive_recv_errors,
            ref mut recv_queue,
            ..
        } = *self;

        // 1. Fast Path: return buffered datagram immediately without syscall
        if let Some(packet) = recv_queue.pop_front() {
            return Poll::Ready(Some(packet));
        }

        loop {
            let result = ready!(inner.poll_recv_ready(cx)).and_then(|()| {
                super::recv::recv_batch(
                    inner,
                    MAX_BATCH_RECV_PACKETS,
                    |data, src| {
                        let src = canonicalize_src(src);
                        let src_addr = ip_to_logical
                            .get(&src)
                            .map(|(logical, _)| logical.clone())
                            .unwrap_or_else(|| src.into());
                        recv_queue.push_back(UdpPacket {
                            data,
                            src_addr,
                            dst_addr: SocksAddr::any_ipv4(),
                            ..Default::default()
                        });
                    },
                )
            });
            match result {
                Ok(_) => {
                    *consecutive_recv_errors = 0;
                    if let Some(packet) = recv_queue.pop_front() {
                        return Poll::Ready(Some(packet));
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => {
                    *consecutive_recv_errors += 1;
                    if *consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                        tracing::warn!(
                            "Direct UDP socket reached error limit ({MAX_CONSECUTIVE_RECV_ERRORS}), closing: {err}"
                        );
                        return Poll::Ready(None);
                    }
                    tracing::trace!("Direct UDP transient recv error: {err}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::dns::MockClashResolver,
        proxy::utils::new_dual_stack_udp_socket,
    };
    use futures::{SinkExt, StreamExt};
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
        time::Duration,
    };
    use tokio::net::UdpSocket;

    /// Spawn a loopback UDP echo server; returns its port.
    async fn spawn_echo_server() -> u16 {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let _ = sock.send_to(&buf[..n], peer).await;
            }
        });
        port
    }

    /// Build an `OutboundDatagramImpl` backed by a loopback socket with a mock
    /// resolver that maps every domain to `127.0.0.1`.
    async fn make_datagram() -> OutboundDatagramImpl {
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_resolve_v4()
            .returning(|_, _| Ok(Some(Ipv4Addr::LOCALHOST)));
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        OutboundDatagramImpl::new(udp, Arc::new(resolver))
    }

    #[tokio::test]
    async fn test_ip_send_clears_previous_domain_mapping() {
        let port = spawn_echo_server().await;
        let mut datagram = make_datagram().await;
        let domain = SocksAddr::Domain("echo.test".into(), port);
        let ip = SocksAddr::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        for destination in [domain, ip] {
            datagram
                .send(UdpPacket {
                    data: bytes::Bytes::from_static(b"probe"),
                    dst_addr: destination.clone(),
                    ..Default::default()
                })
                .await
                .unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(2), datagram.next())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply.src_addr, destination);
        }
    }

    #[tokio::test]
    async fn test_mapped_ipv6_domain_mapping_uses_canonical_key() {
        let port = spawn_echo_server().await;
        let mapped_ip = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        let mut resolver = MockClashResolver::new();
        resolver.expect_resolve().returning(move |_, _| {
            Ok(Some(IpAddr::V6(mapped_ip)))
        });
        let udp = new_dual_stack_udp_socket(
            None,
            #[cfg(target_os = "linux")]
            None,
        )
        .unwrap();
        assert!(udp.local_addr().unwrap().is_ipv6());
        let mut datagram = OutboundDatagramImpl::new(udp, Arc::new(resolver));
        let domain = SocksAddr::Domain("echo.test".into(), port);
        let canonical = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let mapped = SocketAddr::from((mapped_ip, port));

        // Both mapped and native IP sends must clear a mapping created from
        // a mapped DNS answer; domain replies must restore the logical source.
        for destination in [
            domain.clone(),
            SocksAddr::Ip(mapped),
            domain,
            SocksAddr::Ip(canonical),
        ] {
            datagram
                .send(UdpPacket {
                    data: bytes::Bytes::from_static(b"probe"),
                    dst_addr: destination.clone(),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert!(!datagram.ip_to_logical.contains_key(&mapped));
            let expected = if matches!(destination, SocksAddr::Domain(..)) {
                assert!(datagram.ip_to_logical.contains_key(&canonical));
                destination
            } else {
                assert!(datagram.ip_to_logical.is_empty());
                SocksAddr::Ip(canonical)
            };
            let reply = tokio::time::timeout(Duration::from_secs(2), datagram.next())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply.src_addr, expected);
        }
    }

    #[tokio::test]
    async fn test_single_dest_domain_src_addr_restored() {
        let echo_port = spawn_echo_server().await;
        let mut datagram = make_datagram().await;

        let dst = SocksAddr::Domain("echo.test".into(), echo_port);
        datagram
            .send(UdpPacket {
                data: bytes::Bytes::from_static(b"hello"),
                dst_addr: dst.clone(),
                ..Default::default()
            })
            .await
            .unwrap();

        let pkt = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("timed out")
            .expect("stream ended");

        assert_eq!(pkt.src_addr, dst, "src_addr must be restored to the domain");
        assert_eq!(pkt.data.as_ref(), b"hello");
    }

    /// A single outbound socket sends to **two** different domain destinations
    /// (1→N); each response must carry the correct logical src_addr.
    #[tokio::test]
    async fn test_multi_dest_1_to_n_src_addr_restored() {
        let port_a = spawn_echo_server().await;
        let port_b = spawn_echo_server().await;
        let mut datagram = make_datagram().await;

        let dst_a = SocksAddr::Domain("echo1.test".into(), port_a);
        let dst_b = SocksAddr::Domain("echo2.test".into(), port_b);

        // One socket, two destinations — 1→N.
        datagram
            .send(UdpPacket {
                data: bytes::Bytes::from_static(b"to-a"),
                dst_addr: dst_a.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        datagram
            .send(UdpPacket {
                data: bytes::Bytes::from_static(b"to-b"),
                dst_addr: dst_b.clone(),
                ..Default::default()
            })
            .await
            .unwrap();

        // Responses may arrive in any order.
        let timeout = Duration::from_secs(2);
        let pkt1 = tokio::time::timeout(timeout, datagram.next())
            .await
            .expect("timed out waiting for first response")
            .expect("stream ended");
        let pkt2 = tokio::time::timeout(timeout, datagram.next())
            .await
            .expect("timed out waiting for second response")
            .expect("stream ended");

        let got: HashSet<SocksAddr> =
            [pkt1.src_addr, pkt2.src_addr].into_iter().collect();
        assert!(got.contains(&dst_a), "missing echo1.test src_addr");
        assert!(got.contains(&dst_b), "missing echo2.test src_addr");
    }

    /// When DNS resolution fails, `poll_flush` must return an error and clear
    /// `pending_dns` so that a subsequent `send` can start a fresh DNS query
    /// without polling a completed query again.
    #[tokio::test]
    async fn test_dns_failure_does_not_panic_on_retry() {
        let mut resolver = MockClashResolver::new();
        // First call: resolution fails.
        // Second call (after retry): resolution succeeds.
        let mut call_count = 0u8;
        resolver.expect_resolve_v4().returning(move |_, _| {
            call_count += 1;
            if call_count == 1 {
                Err(anyhow::anyhow!("simulated DNS failure"))
            } else {
                Ok(Some(Ipv4Addr::LOCALHOST))
            }
        });
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut datagram = OutboundDatagramImpl::new(udp, Arc::new(resolver));

        let echo_port = spawn_echo_server().await;
        let dst = SocksAddr::Domain("fail.test".into(), echo_port);

        // First send: DNS fails — must return Err, not panic.
        let result = datagram
            .send(UdpPacket {
                data: bytes::Bytes::from_static(b"hello"),
                dst_addr: dst.clone(),
                ..Default::default()
            })
            .await;
        assert!(result.is_err(), "expected error on DNS failure");

        // Second send (same destination): DNS succeeds — must NOT panic.
        datagram
            .send(UdpPacket {
                data: bytes::Bytes::from_static(b"hello again"),
                dst_addr: dst.clone(),
                ..Default::default()
            })
            .await
            .expect("second send must succeed after DNS recovers");
    }
    /// inbound packets to the outbound socket and they are forwarded.
    /// The src_addr of an unsolicited packet falls back to the raw IP.
    #[tokio::test]
    async fn test_full_cone_unsolicited_inbound_accepted() {
        let echo_port = spawn_echo_server().await;
        let mut datagram = make_datagram().await;

        // Read the outbound port before moving `datagram` into the stream.
        let outbound_port = {
            let addr = datagram
                .inner
                .local_addr()
                .expect("local_addr must be available");
            addr.port()
        };

        // Establish a session to the echo server so ip_to_logical is populated.
        let dst = SocksAddr::Domain("echo.test".into(), echo_port);
        datagram
            .send(UdpPacket {
                data: bytes::Bytes::from_static(b"establish"),
                dst_addr: dst.clone(),
                ..Default::default()
            })
            .await
            .unwrap();

        let pkt = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("timed out")
            .expect("stream ended");
        assert_eq!(
            pkt.src_addr, dst,
            "echo response must restore domain src_addr"
        );

        // A third-party socket (absent from ip_to_logical) sends unsolicited.
        let third_party = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let third_party_addr = third_party.local_addr().unwrap();
        third_party
            .send_to(b"unsolicited", ("127.0.0.1", outbound_port))
            .await
            .unwrap();

        let pkt = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("timed out waiting for unsolicited packet")
            .expect("stream ended");

        // Full-cone: the packet is delivered (not dropped).
        assert_eq!(pkt.data.as_ref(), b"unsolicited");
        // src_addr is the raw IP because the sender is not in ip_to_logical.
        assert_eq!(pkt.src_addr, SocksAddr::Ip(third_party_addr));
    }

    /// Pure IP destinations should not insert into `ip_to_logical`,
    /// saving allocations and map lookups.
    #[tokio::test]
    async fn test_pure_ip_dest_bypasses_ip_to_logical() {
        let echo_port = spawn_echo_server().await;
        let mut datagram = make_datagram().await;

        let ip_dst =
            SocksAddr::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, echo_port)));
        datagram
            .send(UdpPacket {
                data: bytes::Bytes::from_static(b"pure-ip"),
                dst_addr: ip_dst.clone(),
                ..Default::default()
            })
            .await
            .unwrap();

        // ip_to_logical should remain empty for pure IP destinations
        assert!(datagram.ip_to_logical.is_empty());

        let pkt = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("timed out")
            .expect("stream ended");

        assert_eq!(pkt.src_addr, ip_dst);
        assert_eq!(pkt.data.as_ref(), b"pure-ip");
    }

    /// Verify batch receive drain: multiple packets arriving in burst are queued
    /// and yielded correctly via `Stream::poll_next`.
    #[tokio::test]
    async fn test_batch_recv_burst_packets() {
        let echo_port = spawn_echo_server().await;
        let mut datagram = make_datagram().await;

        let dst = SocksAddr::Domain("echo.test".into(), echo_port);

        // Send 5 packets in a burst
        for i in 0..5 {
            let payload = format!("burst-{i}");
            datagram
                .send(UdpPacket {
                    data: bytes::Bytes::from(payload),
                    dst_addr: dst.clone(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }

        let mut received = Vec::new();
        for _ in 0..5 {
            let pkt = tokio::time::timeout(Duration::from_secs(2), datagram.next())
                .await
                .expect("timed out")
                .expect("stream ended");
            assert_eq!(pkt.src_addr, dst);
            received.push(String::from_utf8(pkt.data.to_vec()).unwrap());
        }

        assert_eq!(received.len(), 5);
        for i in 0..5 {
            assert!(received.contains(&format!("burst-{i}")));
        }
    }
}
