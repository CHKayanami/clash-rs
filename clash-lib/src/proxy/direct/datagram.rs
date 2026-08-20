use crate::{
    app::dns::ThreadSafeDNSResolver, common::errors::new_io_error,
    proxy::datagram::UdpPacket, session::SocksAddr,
};
use bytes::BytesMut;
use futures::{Sink, Stream, ready};
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{io::ReadBuf, net::UdpSocket, task::JoinHandle};

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

const UDP_RECV_CHUNK_SIZE: usize = 64 * 1024;
const MAX_UDP_DATAGRAM_SIZE: usize = 65535;

thread_local! {
    static UDP_CHUNK_BUF: RefCell<BytesMut> = RefCell::new(BytesMut::new());
}

#[inline]
fn ensure_chunk_capacity(chunk_buf: &mut BytesMut) {
    if chunk_buf.capacity() - chunk_buf.len() < MAX_UDP_DATAGRAM_SIZE {
        if chunk_buf.is_empty() {
            let cap = chunk_buf.capacity();
            if cap < UDP_RECV_CHUNK_SIZE {
                chunk_buf.reserve(UDP_RECV_CHUNK_SIZE - cap);
            }
        } else {
            *chunk_buf = BytesMut::with_capacity(UDP_RECV_CHUNK_SIZE);
        }
    }
}

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
    /// In-flight DNS resolution task for the current queued packet.
    /// Using a JoinHandle (Send + Sync) rather than a raw BoxFuture so that
    /// OutboundDatagramImpl satisfies the Sync bound required by
    /// ChainedDatagram. The task is spawned once and awaited across polls —
    /// no query restarts.
    pending_dns: Option<JoinHandle<io::Result<SocketAddr>>>,
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
        if let Some(handle) = pin.pending_dns.take() {
            handle.abort();
        }
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
                    let handle = pending_dns.get_or_insert_with(|| {
                        let resolver = resolver.clone();
                        let domain = domain.clone();
                        let port = *port;
                        tokio::spawn(async move {
                            let ip = if is_ipv6 {
                                resolver.resolve(&domain, false).await.map_err(
                                    |_| io::Error::other("resolve domain failed"),
                                )?
                            } else {
                                resolver
                                    .resolve_v4(&domain, false)
                                    .await
                                    .map_err(|_| {
                                        io::Error::other("resolve domain failed")
                                    })?
                                    .map(IpAddr::V4)
                            };
                            match ip {
                                Some(ip) => Ok(SocketAddr::from((ip, port))),
                                None => Err(io::Error::other(format!(
                                    "resolve domain failed: {domain}"
                                 ))),
                            }
                        })
                    });
                    let join_result = ready!(Pin::new(handle).poll(cx));
                    // Always clear the handle once it has completed (regardless of
                    // success or failure). If we skip this on the error path the
                    // handle stays in `pending_dns` and the next call to
                    // `poll_flush` will try to poll an already-completed
                    // `JoinHandle`, which panics with "JoinHandle polled after
                    // completion".
                    *pending_dns = None;
                    let addr = match join_result {
                        Ok(result) => result?,
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::other(format!(
                                "DNS task panicked: {e}"
                            ))));
                        }
                    };
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

        // Only register logical domain mappings for Domain destinations.
        // Pure IP destinations do not need logical domain restoration, avoiding
        // unnecessary heap allocations and hash map thrashing on high-PPS IP flows.
        if matches!(p.dst_addr, SocksAddr::Domain(..)) {
            let now = Instant::now();
            if ip_to_logical.len() > UDP_DOMAIN_MAP_SWEEP_THRESHOLD
                && now.duration_since(*last_sweep) >= UDP_DOMAIN_MAP_SWEEP_INTERVAL
            {
                ip_to_logical
                    .retain(|_, (_, ts)| now.duration_since(*ts) < UDP_DOMAIN_MAP_TTL);
                *last_sweep = now;
            }
            ip_to_logical.insert(dst, (p.dst_addr.clone(), now));
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

        UDP_CHUNK_BUF.with_borrow_mut(|chunk_buf| {
            ensure_chunk_capacity(chunk_buf);

            loop {
                let unfilled = chunk_buf.spare_capacity_mut();
                let mut buf = ReadBuf::uninit(unfilled);
                match ready!(inner.poll_recv_from(cx, &mut buf)) {
                    Ok(src) => {
                        *consecutive_recv_errors = 0;
                        let filled_len = buf.filled().len();
                        unsafe {
                            let new_len = chunk_buf.len() + filled_len;
                            chunk_buf.set_len(new_len);
                        }
                        let data = chunk_buf.split_to(filled_len).freeze();
                        let src = canonicalize_src(src);
                        let src_addr = ip_to_logical
                            .get(&src)
                            .map(|(logical, _)| logical.clone())
                            .unwrap_or_else(|| src.into());
                        let first_packet = UdpPacket {
                            data,
                            src_addr,
                            // Overwritten by the dispatcher with the originating
                            // client address on the reply path.
                            dst_addr: SocksAddr::any_ipv4(),
                            ..Default::default()
                        };

                        // 2. Batch Drain: opportunistically drain more packets from socket
                        while recv_queue.len() < MAX_BATCH_RECV_PACKETS - 1 {
                            ensure_chunk_capacity(chunk_buf);
                            let spare = chunk_buf.spare_capacity_mut();
                            let spare_slice = unsafe {
                                std::slice::from_raw_parts_mut(
                                    spare.as_mut_ptr() as *mut u8,
                                    spare.len(),
                                )
                            };
                            match inner.try_recv_from(spare_slice) {
                                Ok((n, next_src)) => {
                                    unsafe {
                                        let new_len = chunk_buf.len() + n;
                                        chunk_buf.set_len(new_len);
                                    }
                                    let next_data = chunk_buf.split_to(n).freeze();
                                    let next_src = canonicalize_src(next_src);
                                    let next_src_addr = ip_to_logical
                                        .get(&next_src)
                                        .map(|(logical, _)| logical.clone())
                                        .unwrap_or_else(|| next_src.into());

                                    recv_queue.push_back(UdpPacket {
                                        data: next_data,
                                        src_addr: next_src_addr,
                                        dst_addr: SocksAddr::any_ipv4(),
                                        ..Default::default()
                                    });
                                }
                                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    break;
                                }
                                Err(e) => {
                                    tracing::trace!("Direct UDP transient batch recv error: {e}");
                                    break;
                                }
                            }
                        }

                        return Poll::Ready(Some(first_packet));
                    }
                    // A UDP socket reports plenty of transient failures — an inbound
                    // ICMP port-unreachable for an earlier packet surfaces here as
                    // ECONNREFUSED. Ending the stream on the first one tore down the
                    // whole association, and this is the DIRECT path.
                    Err(e) => {
                        *consecutive_recv_errors += 1;
                        if *consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                            tracing::warn!(
                                "Direct UDP socket reached error limit ({MAX_CONSECUTIVE_RECV_ERRORS}), closing: {e}"
                            );
                            return Poll::Ready(None);
                        }
                        tracing::trace!("Direct UDP transient recv error: {e}");
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::MockClashResolver;
    use futures::{SinkExt, StreamExt};
    use std::{collections::HashSet, net::Ipv4Addr, sync::Arc, time::Duration};
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
    async fn test_single_dest_domain_src_addr_restored() {
        let echo_port = spawn_echo_server().await;
        let mut datagram = make_datagram().await;

        let dst = SocksAddr::Domain("echo.test".to_owned(), echo_port);
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

        let dst_a = SocksAddr::Domain("echo1.test".to_owned(), port_a);
        let dst_b = SocksAddr::Domain("echo2.test".to_owned(), port_b);

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
    /// without panicking with "JoinHandle polled after completion".
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
        let dst = SocksAddr::Domain("fail.test".to_owned(), echo_port);

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
        let dst = SocksAddr::Domain("echo.test".to_owned(), echo_port);
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

        let ip_dst = SocksAddr::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, echo_port)));
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

        let dst = SocksAddr::Domain("echo.test".to_owned(), echo_port);

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

