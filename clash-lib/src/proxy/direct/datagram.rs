use crate::{app::dns::ThreadSafeDNSResolver, proxy::datagram::UdpPacket, session::SocksAddr};
use futures::{Sink, Stream, ready};
use std::{collections::HashMap, io, net::SocketAddr, pin::Pin,
    task::{Context, Poll}, time::{Duration, Instant}};
use tokio::net::UdpSocket;
use super::{native::NativeDatagram, resolve::{PendingResolution, poll_resolve_destination}};

const UDP_DOMAIN_MAP_TTL: Duration = Duration::from_secs(60);
const UDP_DOMAIN_MAP_SWEEP_THRESHOLD: usize = 64;
const UDP_DOMAIN_MAP_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

#[inline]
fn canonicalize_src(mut src: SocketAddr) -> SocketAddr {
    src.set_ip(src.ip().to_canonical());
    src
}

/// Domain resolution and logical peer restoration for dialer UDP sockets.
/// The association path uses NativeDatagram directly.
#[must_use = "sinks do nothing unless polled"]
pub struct OutboundDatagramImpl {
    native: NativeDatagram,
    resolver: ThreadSafeDNSResolver,
    flushed: bool,
    pkt: Option<UdpPacket>,
    ip_to_logical: HashMap<SocketAddr, (SocksAddr, Instant)>,
    last_sweep: Instant,
    pending_dns: Option<PendingResolution>,
    resolved_dst: Option<SocketAddr>,
    logical: Option<SocksAddr>,
}

impl OutboundDatagramImpl {
    pub fn new(socket: UdpSocket, resolver: ThreadSafeDNSResolver) -> io::Result<Self> {
        Ok(Self { native: NativeDatagram::new(socket)?, resolver, flushed: true, pkt: None,
            ip_to_logical: HashMap::new(), last_sweep: Instant::now(), pending_dns: None,
            resolved_dst: None, logical: None })
    }

    // SOCKS relays have a physical IP target and need no logical DNS mapping.
    pub(crate) fn poll_send_to_vectored(
        &self, cx: &mut Context<'_>, header: &[u8], payload: &[u8], destination: SocketAddr,
    ) -> Poll<io::Result<()>> {
        self.native.poll_send_to_vectored(cx, header, payload, destination)
    }

    fn clear_send(&mut self) {
        self.pkt = None;
        self.pending_dns = None;
        self.resolved_dst = None;
        self.logical = None;
        self.flushed = true;
    }

    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(packet) = &self.pkt {
            let destination = match &packet.dst_addr {
                SocksAddr::Ip(address) => *address,
                SocksAddr::Domain(domain, port) => match self.resolved_dst {
                    Some(address) => address,
                    None => ready!(poll_resolve_destination(cx, &mut self.pending_dns, &self.resolver,
                        domain, *port, self.native.local_is_ipv6()))?,
                },
            };
            self.resolved_dst = Some(destination);
            ready!(Pin::new(&mut self.native).poll_ready(cx))?;
            let mut packet = self.pkt.take().unwrap();
            self.logical = packet.dst_addr.is_domain().then(|| packet.dst_addr.clone());
            packet.dst_addr = destination.into();
            Pin::new(&mut self.native).start_send(packet)?;
        }
        ready!(Pin::new(&mut self.native).poll_flush(cx))?;
        let destination = canonicalize_src(self.resolved_dst.unwrap());
        if let Some(logical) = self.logical.take() {
            let now = Instant::now();
            if self.ip_to_logical.len() > UDP_DOMAIN_MAP_SWEEP_THRESHOLD
                && now.duration_since(self.last_sweep) >= UDP_DOMAIN_MAP_SWEEP_INTERVAL {
                self.ip_to_logical.retain(|_, (_, time)| now.duration_since(*time) < UDP_DOMAIN_MAP_TTL);
                self.last_sweep = now;
            }
            self.ip_to_logical.insert(destination, (logical, now));
        } else { self.ip_to_logical.remove(&destination); }
        self.clear_send();
        Poll::Ready(Ok(()))
    }
}

impl Sink<UdpPacket> for OutboundDatagramImpl {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: UdpPacket) -> io::Result<()> {
        self.clear_send();
        self.pkt = Some(item);
        self.flushed = false;
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.flushed { return Poll::Ready(Ok(())); }
        let result = self.poll_send(cx);
        if matches!(&result, Poll::Ready(Err(_))) { self.clear_send(); }
        result
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl Stream for OutboundDatagramImpl {
    type Item = UdpPacket;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>> {
        let Self { native, ip_to_logical, .. } = &mut *self;
        native.poll_recv_with(cx, |peer| ip_to_logical.get(&peer)
            .map(|(logical, _)| logical.clone()).unwrap_or_else(|| peer.into()))
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
        OutboundDatagramImpl::new(udp, Arc::new(resolver)).unwrap()
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
        let mut datagram = OutboundDatagramImpl::new(udp, Arc::new(resolver)).unwrap();
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
        let mut datagram = OutboundDatagramImpl::new(udp, Arc::new(resolver)).unwrap();

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
                .native
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
