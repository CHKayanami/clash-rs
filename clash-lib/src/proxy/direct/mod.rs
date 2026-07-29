use std::fmt::Debug;

pub(crate) mod datagram;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::map_io_error,
    proxy::{
        OutboundHandler,
        direct::datagram::OutboundDatagramImpl,
        utils::{new_dual_stack_udp_socket, prepare_tcp_socket},
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
use futures::TryFutureExt;

#[derive(Clone)]
pub struct Handler {
    pub name: String,
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
        }
    }

    /// Open one TCP connection to `endpoint`, honouring the session's interface
    /// and firewall mark.
    async fn dial(
        sess: &Session,
        endpoint: std::net::SocketAddr,
    ) -> std::io::Result<tokio::net::TcpStream> {
        let socket = prepare_tcp_socket(
            endpoint,
            sess.iface.as_ref(),
            #[cfg(target_os = "linux")]
            sess.so_mark,
        )?;

        tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(endpoint))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "tcp connection timed out",
                )
            })?
    }
}

impl DialWithConnector for Handler {}

/// How long a direct TCP connect may take before being abandoned.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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
    ) -> std::io::Result<BoxedChainedStream> {
        let host = sess.destination.host();
        let port = sess.destination.port();

        let remote_ip = resolver
            .resolve(host.as_str(), false)
            .map_err(map_io_error)
            .await?
            .ok_or_else(|| std::io::Error::other("no dns result"))?;

        let first_err = match Self::dial(sess, (remote_ip, port).into()).await {
            Ok(stream) => {
                let s = ChainedStreamWrapper::new(stream);
                s.append_to_chain(self.name()).await;
                return Ok(Box::new(s));
            }
            Err(e) => e,
        };

        // `resolve` hands back a single address, so a host that is reachable
        // over one family but not the other (a broken IPv6 path being the
        // common case) failed outright. Retry once against the other family
        // before giving up. Only meaningful for names — an IP literal resolves
        // to itself.
        let fallback_ip = if sess.destination.is_domain() {
            if remote_ip.is_ipv6() {
                resolver
                    .resolve_v4(host.as_str(), false)
                    .await
                    .ok()
                    .flatten()
                    .map(std::net::IpAddr::from)
            } else {
                resolver
                    .resolve_v6(host.as_str(), false)
                    .await
                    .ok()
                    .flatten()
                    .map(std::net::IpAddr::from)
            }
        } else {
            None
        };

        let Some(fallback_ip) = fallback_ip.filter(|ip| *ip != remote_ip) else {
            return Err(first_err);
        };

        tracing::debug!(
            "direct connect to {remote_ip} failed ({first_err}), retrying \
             {host} via {fallback_ip}"
        );

        let tcp_stream = Self::dial(sess, (fallback_ip, port).into())
            .await
            .map_err(|_| first_err)?;

        let s = ChainedStreamWrapper::new(tcp_stream);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        // The outbound socket is shared across ALL destinations from the same
        // client (keyed by src_addr only in the dispatcher). Use a dual-stack
        // socket so one socket can send to both IPv4 and IPv6 destinations
        // without EAFNOSUPPORT.
        let udp = new_dual_stack_udp_socket(
            sess.iface.as_ref(),
            #[cfg(target_os = "linux")]
            sess.so_mark,
        )?;
        let d =
            ChainedDatagramWrapper::new(OutboundDatagramImpl::new(udp, resolver));
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<BoxedChainedStream> {
        let s = connector
            .connect_stream(
                resolver,
                sess.destination.host().as_str(),
                sess.destination.port(),
                false,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        let s = ChainedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<BoxedChainedDatagram> {
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
        let d = ChainedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
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
}
