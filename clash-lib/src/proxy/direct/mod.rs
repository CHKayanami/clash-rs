use std::fmt::Debug;
use std::sync::Arc;

pub(crate) mod datagram;
pub(crate) mod pool;

use crate::{
    app::dns::ThreadSafeDNSResolver,
    proxy::{
        AnyOutboundDatagram, AnyStream, OutboundHandler,
        direct::datagram::OutboundDatagramImpl,
        direct::pool::{DirectDatagramPool, DirectSocketKey},
        utils::{dial_tcp_with_happy_eyeballs, new_dual_stack_udp_socket},
    },
    session::Session,
};
use erased_serde::Serialize as ErasedSerialize;
use std::collections::HashMap;

use super::{
    ConnectorType, DialWithConnector, OutboundType, PlainProxyAPIResponse,
    utils::RemoteConnector,
};
use async_trait::async_trait;

#[derive(Clone)]
pub struct Handler {
    pub name: String,
    pool: Arc<DirectDatagramPool>,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Direct").field("name", &self.name).finish()
    }
}

impl Handler {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            pool: Arc::new(DirectDatagramPool::new()),
        }
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    /// The configured name, not the literal `DIRECT`.
    ///
    /// Returning the constant meant every `type: direct` proxy in a config
    /// reported the same name, and callers key off this: `ProxyManager`
    /// liveness records, the dispatcher's UDP NAT entries, and the connection
    /// chain all collapsed distinct direct proxies onto one identity.
    fn name(&self) -> &str {
        &self.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Direct
    }

    async fn support_udp(&self) -> bool {
        true
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyStream> {
        let stream = dial_tcp_with_happy_eyeballs(
            sess.destination.host_cow().as_ref(),
            sess.destination.port(),
            &resolver,
            sess.iface.as_ref(),
            false,
            #[cfg(target_os = "linux")]
            sess.so_mark,
        )
        .await?;

        sess.push_chain(self.name());
        Ok(Box::new(stream))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyOutboundDatagram> {
        let iface = if sess.destination.ip().is_some_and(|ip| ip.is_loopback()) {
            None
        } else {
            sess.iface.as_ref()
        };
        sess.push_chain(self.name());

        if sess.source.port() == 0 {
            // Unspecified source fallback (e.g. some isolated tests)
            let udp = new_dual_stack_udp_socket(
                iface,
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )?;
            return Ok(Box::new(OutboundDatagramImpl::new(udp, resolver)));
        }

        let key = DirectSocketKey {
            source: sess.source,
            iface_name: iface.map(|i| i.name.clone()),
            #[cfg(target_os = "linux")]
            so_mark: sess.so_mark,
            #[cfg(not(target_os = "linux"))]
            so_mark: None,
        };

        let datagram = self.pool.connect(key, iface, sess.destination.clone(), resolver)?;
        Ok(Box::new(datagram))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<AnyStream> {
        let s = connector
            .connect_stream(
                resolver,
                sess.destination.host_cow().as_ref(),
                sess.destination.port(),
                false,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        sess.push_chain(self.name());
        Ok(s)
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<AnyOutboundDatagram> {
        let d = connector
            .connect_datagram(
                resolver,
                None,
                sess.destination.clone(),
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        sess.push_chain(self.name());
        Ok(d)
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        HashMap::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::dns::MockClashResolver,
        proxy::datagram::UdpPacket,
        session::{Network, Session, SocksAddr, Type},
    };
    use futures::{SinkExt, StreamExt};
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };
    use tokio::net::UdpSocket;

    async fn spawn_udp_echo(bind: &str) -> SocketAddr {
        let sock = UdpSocket::bind(bind).await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let _ = sock.send_to(&buf[..n], peer).await;
            }
        });
        addr
    }

    fn make_resolver() -> ThreadSafeDNSResolver {
        // IP destinations never touch the resolver; an empty mock is enough.
        Arc::new(MockClashResolver::new())
    }

    /// Full round-trip through Handler::connect_datagram →
    /// new_dual_stack_udp_socket → IPv4 echo server.  This exercises the
    /// real socket-creation path (the source of the Windows WSAEINVAL
    /// regression in #1399).
    #[tokio::test]
    async fn test_connect_datagram_ipv4_roundtrip() {
        let echo = spawn_udp_echo("127.0.0.1:0").await;
        let handler = Handler::new("DIRECT");
        let sess = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            destination: SocksAddr::Ip(echo),
            ..Default::default()
        };

        let mut d = handler
            .connect_datagram(&sess, make_resolver())
            .await
            .expect("connect_datagram failed");

        d.send(UdpPacket {
            data: bytes::Bytes::from_static(b"hello-v4"),
            dst_addr: SocksAddr::Ip(echo),
            ..Default::default()
        })
        .await
        .expect("send failed");

        let pkt = tokio::time::timeout(Duration::from_secs(2), d.next())
            .await
            .expect("timed out")
            .expect("stream ended");
        assert_eq!(pkt.data.as_ref(), b"hello-v4");
    }

    /// Same path but sending to two different IPv4 destinations via the same
    /// socket — validates the 1→N multiplexing that requires a dual-stack
    /// socket in the first place.
    #[tokio::test]
    async fn test_connect_datagram_ipv4_multi_dest() {
        let echo_a = spawn_udp_echo("127.0.0.1:0").await;
        let echo_b = spawn_udp_echo("127.0.0.1:0").await;
        let handler = Handler::new("DIRECT");
        let sess = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            destination: SocksAddr::Ip(echo_a),
            ..Default::default()
        };

        let mut d = handler
            .connect_datagram(&sess, make_resolver())
            .await
            .expect("connect_datagram failed");

        for (dst, payload) in [(echo_a, b"to-a" as &[u8]), (echo_b, b"to-b")] {
            d.send(UdpPacket {
                data: bytes::Bytes::copy_from_slice(payload),
                dst_addr: SocksAddr::Ip(dst),
                ..Default::default()
            })
            .await
            .expect("send failed");
        }

        let mut received = std::collections::HashSet::new();
        for _ in 0..2 {
            let pkt = tokio::time::timeout(Duration::from_secs(2), d.next())
                .await
                .expect("timed out")
                .expect("stream ended");
            received.insert(pkt.data);
        }
        assert!(received.contains(&bytes::Bytes::from_static(b"to-a")));
        assert!(received.contains(&bytes::Bytes::from_static(b"to-b")));
    }

    /// IPv6 round-trip — skipped when the host has no IPv6 loopback.
    #[tokio::test]
    async fn test_connect_datagram_ipv6_roundtrip() {
        // Probe for IPv6 loopback availability.
        if UdpSocket::bind("[::1]:0").await.is_err() {
            eprintln!("skipping: no IPv6 loopback");
            return;
        }
        let echo = spawn_udp_echo("[::1]:0").await;
        let handler = Handler::new("DIRECT");
        let sess = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            destination: SocksAddr::Ip(echo),
            source: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            ..Default::default()
        };

        let mut d = handler
            .connect_datagram(&sess, make_resolver())
            .await
            .expect("connect_datagram failed");

        d.send(UdpPacket {
            data: bytes::Bytes::from_static(b"hello-v6"),
            dst_addr: SocksAddr::Ip(echo),
            ..Default::default()
        })
        .await
        .expect("send failed");

        let pkt = tokio::time::timeout(Duration::from_secs(2), d.next())
            .await
            .expect("timed out")
            .expect("stream ended");
        assert_eq!(pkt.data.as_ref(), b"hello-v6");
    }

    async fn spawn_recording_udp_echo(
        bind: &str,
        peers: Arc<parking_lot::Mutex<Vec<SocketAddr>>>,
    ) -> SocketAddr {
        let sock = UdpSocket::bind(bind).await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                peers.lock().push(peer);
                let _ = sock.send_to(&buf[..n], peer).await;
            }
        });
        addr
    }

    /// Verifies that multiple sessions from the same client source reuse the
    /// exact same underlying OS UDP socket (Full-Cone NAT).
    #[tokio::test]
    async fn test_connect_datagram_pooled_multi_session() {
        let recorded_peers = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let echo_a = spawn_recording_udp_echo("127.0.0.1:0", recorded_peers.clone()).await;
        let echo_b = spawn_recording_udp_echo("127.0.0.1:0", recorded_peers.clone()).await;

        let handler = Handler::new("DIRECT");
        let client_src: SocketAddr = "127.0.0.1:45678".parse().unwrap();

        let sess_a = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            source: client_src,
            destination: SocksAddr::Ip(echo_a),
            ..Default::default()
        };
        let sess_b = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            source: client_src,
            destination: SocksAddr::Ip(echo_b),
            ..Default::default()
        };

        let mut da = handler
            .connect_datagram(&sess_a, make_resolver())
            .await
            .expect("connect_datagram A failed");
        let mut db = handler
            .connect_datagram(&sess_b, make_resolver())
            .await
            .expect("connect_datagram B failed");

        da.send(UdpPacket {
            data: bytes::Bytes::from_static(b"hello-a"),
            dst_addr: SocksAddr::Ip(echo_a),
            ..Default::default()
        })
        .await
        .unwrap();

        db.send(UdpPacket {
            data: bytes::Bytes::from_static(b"hello-b"),
            dst_addr: SocksAddr::Ip(echo_b),
            ..Default::default()
        })
        .await
        .unwrap();

        let pkt_a = tokio::time::timeout(Duration::from_secs(2), da.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pkt_a.data.as_ref(), b"hello-a");

        let pkt_b = tokio::time::timeout(Duration::from_secs(2), db.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pkt_b.data.as_ref(), b"hello-b");

        // Verify that both echo_a and echo_b observed the exact same client socket address!
        let peers = recorded_peers.lock();
        assert_eq!(peers.len(), 2);
        assert_eq!(
            peers[0], peers[1],
            "Both sessions must reuse the same underlying OS socket"
        );
    }

    /// Verifies that multiple sessions from the same client accessing the
    /// EXACT SAME destination do not overwrite each other, and dropping one
    /// does not break the remaining active session.
    #[tokio::test]
    async fn test_connect_datagram_pooled_same_destination_isolation() {
        let echo = spawn_udp_echo("127.0.0.1:0").await;
        let handler = Handler::new("DIRECT");
        let client_src: SocketAddr = "127.0.0.1:45679".parse().unwrap();

        let sess_1 = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            source: client_src,
            destination: SocksAddr::Ip(echo),
            ..Default::default()
        };
        let sess_2 = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            source: client_src,
            destination: SocksAddr::Ip(echo),
            ..Default::default()
        };

        let mut d1 = handler
            .connect_datagram(&sess_1, make_resolver())
            .await
            .expect("connect_datagram 1 failed");
        let mut d2 = handler
            .connect_datagram(&sess_2, make_resolver())
            .await
            .expect("connect_datagram 2 failed");

        // Send from session 1
        d1.send(UdpPacket {
            data: bytes::Bytes::from_static(b"req-1"),
            dst_addr: SocksAddr::Ip(echo),
            ..Default::default()
        })
        .await
        .unwrap();

        let pkt_1 = tokio::time::timeout(Duration::from_secs(2), d1.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pkt_1.data.as_ref(), b"req-1");

        // Send from session 2
        d2.send(UdpPacket {
            data: bytes::Bytes::from_static(b"req-2"),
            dst_addr: SocksAddr::Ip(echo),
            ..Default::default()
        })
        .await
        .unwrap();

        let pkt_2 = tokio::time::timeout(Duration::from_secs(2), d2.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pkt_2.data.as_ref(), b"req-2");

        // Drop session 1
        drop(d1);

        // Session 2 must still receive responses without being orphaned
        d2.send(UdpPacket {
            data: bytes::Bytes::from_static(b"req-3-after-drop"),
            dst_addr: SocksAddr::Ip(echo),
            ..Default::default()
        })
        .await
        .unwrap();

        let pkt_3 = tokio::time::timeout(Duration::from_secs(2), d2.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pkt_3.data.as_ref(), b"req-3-after-drop");
    }

    /// Verifies that packets from un-registered remote addresses (e.g. STUN alternate-port
    /// replies or P2P hole-punching packets) are accepted and delivered under Full-Cone NAT.
    #[tokio::test]
    async fn test_connect_datagram_pooled_unsolicited_inbound_accepted() {
        let recorded_peers = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let echo = spawn_recording_udp_echo("127.0.0.1:0", recorded_peers.clone()).await;

        let handler = Handler::new("DIRECT");
        let client_src: SocketAddr = "127.0.0.1:45680".parse().unwrap();

        let sess = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            source: client_src,
            destination: SocksAddr::Ip(echo),
            ..Default::default()
        };

        let mut d = handler
            .connect_datagram(&sess, make_resolver())
            .await
            .expect("connect_datagram failed");

        // Initial outgoing packet to trigger socket allocation
        d.send(UdpPacket {
            data: bytes::Bytes::from_static(b"ping"),
            dst_addr: SocksAddr::Ip(echo),
            ..Default::default()
        })
        .await
        .unwrap();

        let pkt = tokio::time::timeout(Duration::from_secs(2), d.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pkt.data.as_ref(), b"ping");

        // Determine the outbound port that the pool allocated
        let outbound_client_port = {
            let peers = recorded_peers.lock();
            peers[0]
        };

        // Third-party socket sends an unsolicited packet (never sent to by the client)
        let third_party = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let third_party_addr = third_party.local_addr().unwrap();
        third_party
            .send_to(b"unsolicited-reply", outbound_client_port)
            .await
            .unwrap();

        let unsolicited_pkt = tokio::time::timeout(Duration::from_secs(2), d.next())
            .await
            .expect("timed out waiting for unsolicited packet")
            .expect("stream ended");

        assert_eq!(unsolicited_pkt.data.as_ref(), b"unsolicited-reply");
        assert_eq!(unsolicited_pkt.src_addr, SocksAddr::Ip(third_party_addr));
    }

    /// Verifies that concurrent in-flight requests to the EXACT SAME destination
    /// are never crossed or misrouted even if replies arrive out-of-order.
    #[tokio::test]
    async fn test_connect_datagram_pooled_concurrent_same_destination_reordering() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();

        // Spawn custom server that collects 2 requests, then replies in REVERSE order
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (n1, peer1) = socket.recv_from(&mut buf).await.unwrap();
            let data1 = buf[..n1].to_vec();

            let (n2, peer2) = socket.recv_from(&mut buf).await.unwrap();
            let data2 = buf[..n2].to_vec();

            // Reply to second request FIRST
            socket.send_to(&data2, peer2).await.unwrap();
            // Small delay, then reply to first request
            tokio::time::sleep(Duration::from_millis(50)).await;
            socket.send_to(&data1, peer1).await.unwrap();
        });

        let handler = Handler::new("DIRECT");
        let client_src: SocketAddr = "127.0.0.1:45681".parse().unwrap();

        let sess_1 = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            source: client_src,
            destination: SocksAddr::Ip(server_addr),
            ..Default::default()
        };
        let sess_2 = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            source: client_src,
            destination: SocksAddr::Ip(server_addr),
            ..Default::default()
        };

        let mut d1 = handler
            .connect_datagram(&sess_1, make_resolver())
            .await
            .expect("connect 1 failed");
        let mut d2 = handler
            .connect_datagram(&sess_2, make_resolver())
            .await
            .expect("connect 2 failed");

        // Concurrent in-flight sends
        d1.send(UdpPacket {
            data: bytes::Bytes::from_static(b"req-1"),
            dst_addr: SocksAddr::Ip(server_addr),
            ..Default::default()
        })
        .await
        .unwrap();

        d2.send(UdpPacket {
            data: bytes::Bytes::from_static(b"req-2"),
            dst_addr: SocksAddr::Ip(server_addr),
            ..Default::default()
        })
        .await
        .unwrap();

        // Despite server replying to req-2 first, d1 must strictly receive req-1, and d2 must receive req-2
        let (res1, res2) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(2), d1.next()),
            tokio::time::timeout(Duration::from_secs(2), d2.next())
        );

        let pkt1 = res1.unwrap().unwrap();
        let pkt2 = res2.unwrap().unwrap();

        assert_eq!(pkt1.data.as_ref(), b"req-1");
        assert_eq!(pkt2.data.as_ref(), b"req-2");
    }

    /// Verifies that when multiple sessions share a socket with different destinations,
    /// an unsolicited packet from an external party (e.g. P2P hole punching) is ACCEPTED
    /// under Full-Cone NAT semantics, and its true source address is strictly preserved (not rewritten).
    #[tokio::test]
    async fn test_connect_datagram_pooled_unsolicited_full_cone_multiple_sessions() {
        let recorded_peers = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let echo_1 = spawn_recording_udp_echo("127.0.0.1:0", recorded_peers.clone()).await;
        let echo_2 = spawn_recording_udp_echo("127.0.0.1:0", recorded_peers.clone()).await;

        let handler = Handler::new("DIRECT");
        let client_src: SocketAddr = "127.0.0.1:45682".parse().unwrap();

        let sess_1 = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            source: client_src,
            destination: SocksAddr::Ip(echo_1),
            ..Default::default()
        };
        let sess_2 = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            source: client_src,
            destination: SocksAddr::Ip(echo_2),
            ..Default::default()
        };

        let mut d1 = handler.connect_datagram(&sess_1, make_resolver()).await.unwrap();
        let mut d2 = handler.connect_datagram(&sess_2, make_resolver()).await.unwrap();

        // Send to establish socket and register destinations
        d1.send(UdpPacket {
            data: bytes::Bytes::from_static(b"ping-1"),
            dst_addr: SocksAddr::Ip(echo_1),
            ..Default::default()
        }).await.unwrap();

        d2.send(UdpPacket {
            data: bytes::Bytes::from_static(b"ping-2"),
            dst_addr: SocksAddr::Ip(echo_2),
            ..Default::default()
        }).await.unwrap();

        let _ = tokio::time::timeout(Duration::from_secs(2), d1.next()).await.unwrap().unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), d2.next()).await.unwrap().unwrap();

        let outbound_port = {
            let peers = recorded_peers.lock();
            peers[0]
        };

        // Third party sends unsolicited P2P hole-punching packet to the shared socket
        let third_party = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let third_party_addr = third_party.local_addr().unwrap();
        third_party.send_to(b"p2p-punch", outbound_port).await.unwrap();

        // Under Full-Cone NAT semantics, the active session receives the hole punch packet
        let r = tokio::time::timeout(Duration::from_secs(2), d2.next()).await;
        let pkt = r.expect("timed out waiting for P2P punch packet").expect("stream ended");

        assert_eq!(pkt.data.as_ref(), b"p2p-punch");
        // Verify source address is NOT rewritten to echo_2's address; it must stay as the third party's true IP!
        assert_eq!(pkt.src_addr, SocksAddr::Ip(third_party_addr));
    }

    /// Verifies that if a domain-based session lazily resolves to an IP that collides with an
    /// existing active session on the same socket, it dynamically re-homes to another socket,
    /// ensuring both sessions receive their own replies without crossing.
    #[tokio::test]
    async fn test_connect_datagram_pooled_domain_ip_collision_rehoming() {
        let echo = spawn_udp_echo("127.0.0.1:0").await;
        let handler = Handler::new("DIRECT");
        let client_src: SocketAddr = "127.0.0.1:45683".parse().unwrap();

        // Session 1: directly connects to IP
        let sess_ip = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            source: client_src,
            destination: SocksAddr::Ip(echo),
            ..Default::default()
        };

        // Session 2: connects to Domain (which will resolve to the same IP)
        let sess_domain = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            source: client_src,
            destination: SocksAddr::Domain("localhost".into(), echo.port()),
            ..Default::default()
        };

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver
            .expect_resolve_v4()
            .returning(|_, _| Ok(Some(std::net::Ipv4Addr::LOCALHOST)));
        mock_resolver
            .expect_resolve()
            .returning(|_, _| Ok(Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))));
        let resolver: ThreadSafeDNSResolver = Arc::new(mock_resolver);

        let mut d_ip = handler.connect_datagram(&sess_ip, resolver.clone()).await.unwrap();
        let mut d_domain = handler.connect_datagram(&sess_domain, resolver).await.unwrap();

        // Send from d_ip
        d_ip.send(UdpPacket {
            data: bytes::Bytes::from_static(b"from-ip-session"),
            dst_addr: SocksAddr::Ip(echo),
            ..Default::default()
        }).await.unwrap();

        // Send from d_domain (triggers lazy DNS resolution -> collides with d_ip -> re-homes to new socket)
        d_domain.send(UdpPacket {
            data: bytes::Bytes::from_static(b"from-domain-session"),
            dst_addr: SocksAddr::Domain("localhost".into(), echo.port()),
            ..Default::default()
        }).await.unwrap();

        // Both sessions must receive their own responses correctly!
        let pkt_domain = tokio::time::timeout(Duration::from_secs(2), d_domain.next()).await.unwrap().unwrap();
        let pkt_ip = tokio::time::timeout(Duration::from_secs(2), d_ip.next()).await.unwrap().unwrap();

        assert_eq!(pkt_ip.data.as_ref(), b"from-ip-session");
        assert_eq!(pkt_domain.data.as_ref(), b"from-domain-session");
        // Verify logical address restoration on rehomed domain session
        assert_eq!(pkt_domain.src_addr, SocksAddr::Domain("localhost".into(), echo.port()));
    }

    #[tokio::test]
    async fn test_connect_datagram_pooled_domain_logical_address_restoration() {
        let echo_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_socket.local_addr().unwrap();

        let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_socket.local_addr().unwrap();

        let handler = Handler::new("DIRECT");

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver
            .expect_resolve_v4()
            .returning(|_, _| Ok(Some(std::net::Ipv4Addr::LOCALHOST)));
        mock_resolver
            .expect_resolve()
            .returning(|_, _| Ok(Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))));
        let resolver: ThreadSafeDNSResolver = Arc::new(mock_resolver);

        let domain_name = "my-service.local";
        let sess = Session {
            network: Network::Udp,
            typ: Type::Socks5,
            source: "127.0.0.1:50001".parse().unwrap(),
            destination: SocksAddr::Domain(domain_name.into(), echo_addr.port()),
            ..Default::default()
        };

        let mut d = handler.connect_datagram(&sess, resolver).await.unwrap();

        // 1. Send first packet to domain destination
        d.send(UdpPacket {
            data: bytes::Bytes::from_static(b"packet-1"),
            dst_addr: SocksAddr::Domain(domain_name.into(), echo_addr.port()),
            ..Default::default()
        }).await.unwrap();

        let mut buf = [0u8; 1024];
        let (n, direct_addr) = echo_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"packet-1");

        // Echo server replies
        echo_socket.send_to(b"reply-1", direct_addr).await.unwrap();

        // Direct datagram receives reply
        let reply1 = tokio::time::timeout(Duration::from_secs(2), d.next()).await.unwrap().unwrap();
        assert_eq!(reply1.data.as_ref(), b"reply-1");
        // Verify logical address restoration: source is restored to Domain!
        assert_eq!(reply1.src_addr, SocksAddr::Domain(domain_name.into(), echo_addr.port()));

        // 2. Send second packet to test persistence across flushes
        d.send(UdpPacket {
            data: bytes::Bytes::from_static(b"packet-2"),
            dst_addr: SocksAddr::Domain(domain_name.into(), echo_addr.port()),
            ..Default::default()
        }).await.unwrap();

        let (n2, _) = echo_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"packet-2");

        echo_socket.send_to(b"reply-2", direct_addr).await.unwrap();

        let reply2 = tokio::time::timeout(Duration::from_secs(2), d.next()).await.unwrap().unwrap();
        assert_eq!(reply2.data.as_ref(), b"reply-2");
        // Source must STILL be restored to Domain on consecutive packets!
        assert_eq!(reply2.src_addr, SocksAddr::Domain(domain_name.into(), echo_addr.port()));

        // 3. Unsolicited peer packet sent to the same direct socket
        peer_socket.send_to(b"peer-hole-punch", direct_addr).await.unwrap();

        let peer_pkt = tokio::time::timeout(Duration::from_secs(2), d.next()).await.unwrap().unwrap();
        assert_eq!(peer_pkt.data.as_ref(), b"peer-hole-punch");
        // Must NOT be rewritten to domain: retain genuine peer IP!
        assert_eq!(peer_pkt.src_addr, SocksAddr::Ip(peer_addr));
    }
}
