use super::platform::must_bind_socket_on_interface;
use crate::{
    app::{dns::ThreadSafeDNSResolver, net::OutboundInterface},
    proxy::AnyStream,
};

use futures::io;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    time::timeout,
};
use tokio_tfo::TfoStream;
use tracing::{debug, error, instrument, trace};

/// Connection Attempt Delay for Happy Eyeballs.
/// Set to 1s to comfortably accommodate global cross-border proxy server RTTs
/// while still eliminating the 10s blackhole timeout.
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_secs(1);

pub fn apply_tcp_options(s: &TcpStream) -> std::io::Result<()> {
    #[cfg(not(target_os = "windows"))]
    {
        let sock_ref = socket2::SockRef::from(s);
        sock_ref.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1))
                .with_retries(3),
        )?;
    }
    #[cfg(target_os = "windows")]
    {
        let sock_ref = socket2::SockRef::from(s);
        sock_ref.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1)),
        )?;
    }
    // Disable Nagle's algorithm so that small writes (e.g. HTTP response
    // headers arriving from the proxy side) are forwarded to the client
    // immediately without waiting for a full TCP segment.
    s.set_nodelay(true)
}

/// Create and configure a `TcpSocket` with interface binding, keepalive, and
/// nodelay. The returned socket is ready to call `.connect()` on.
pub fn prepare_tcp_socket(
    endpoint: SocketAddr,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<TcpSocket> {
    let (domain, protocol) = match endpoint {
        SocketAddr::V4(_) => (Domain::IPV4, Protocol::TCP),
        SocketAddr::V6(_) => (Domain::IPV6, Protocol::TCP),
    };

    let socket = Socket::new(domain, Type::STREAM, Some(protocol))?;
    debug!("created tcp socket for {}", endpoint);

    // 接口绑定与策略路由
    if !cfg!(target_os = "android")
        && let Some(iface) = iface
        && !endpoint.ip().is_loopback()
    {
        must_bind_socket_on_interface(&socket, iface, domain)?;
    }

    #[cfg(not(target_os = "android"))]
    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    // 高性能保活参数
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(5))
        .with_retries(3);

    socket.set_tcp_keepalive(&keepalive)?;
    socket.set_tcp_nodelay(true)?;
    socket.set_nonblocking(true)?;

    Ok(TcpSocket::from_std_stream(socket.into()))
}

#[instrument(skip(so_mark))]
pub async fn new_tcp_stream(
    endpoint: SocketAddr,
    iface: Option<&OutboundInterface>,
    tfo: bool,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<AnyStream> {
    let tokio_socket = prepare_tcp_socket(
        endpoint,
        iface,
        #[cfg(target_os = "linux")]
        so_mark,
    )?;

    if tfo {
        trace!(
            "[TCP Outbound] Initiating TCP Fast Open (TFO) to {}",
            endpoint
        );

        match timeout(
            Duration::from_secs(10),
            TfoStream::connect_with_socket(tokio_socket, endpoint),
        )
        .await
        {
            Ok(Ok(tfo_stream)) => Ok(Box::new(tfo_stream)),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TFO connection timed out",
            )),
        }
    } else {
        trace!(
            "[TCP Outbound] Initiating standard TCP connection to {}",
            endpoint
        );

        match timeout(Duration::from_secs(10), tokio_socket.connect(endpoint)).await
        {
            Ok(Ok(tcp_stream)) => Ok(Box::new(tcp_stream)),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "standard tcp connection timed out",
            )),
        }
    }
}

/// Dial TCP with Happy Eyeballs (RFC 8305) dual-stack fast fallback.
///
/// If `host` is an IP literal, dials directly.
/// If `host` is a domain name, resolves both IPv6 and IPv4 in parallel.
/// If both families are available, attempts IPv6 first with a 250ms Connection
/// Attempt Delay, then races IPv4 concurrently, eliminating the 10s timeout
/// stall when IPv6 has a routing black hole.
pub async fn dial_tcp_with_happy_eyeballs(
    host: &str,
    port: u16,
    resolver: &ThreadSafeDNSResolver,
    iface: Option<&OutboundInterface>,
    tfo: bool,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<AnyStream> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return new_tcp_stream(
            SocketAddr::new(ip, port),
            iface,
            tfo,
            #[cfg(target_os = "linux")]
            so_mark,
        )
        .await;
    }

    let (v6_res, v4_res) = tokio::join!(
        resolver.resolve_v6(host, false),
        resolver.resolve_v4(host, false),
    );

    let v6_ip = v6_res.ok().flatten().map(IpAddr::V6);
    let v4_ip = v4_res.ok().flatten().map(IpAddr::V4);

    match (v6_ip, v4_ip) {
        (Some(v6), Some(v4)) => {
            let v6_addr = SocketAddr::new(v6, port);
            let v4_addr = SocketAddr::new(v4, port);

            let v6_dial = new_tcp_stream(
                v6_addr,
                iface,
                tfo,
                #[cfg(target_os = "linux")]
                so_mark,
            );
            tokio::pin!(v6_dial);

            tokio::select! {
                res = &mut v6_dial => {
                    match res {
                        Ok(stream) => return Ok(stream),
                        Err(e) => {
                            debug!("IPv6 connect to {v6_addr} failed ({e}), falling back to IPv4 {v4_addr}");
                            return new_tcp_stream(
                                v4_addr,
                                iface,
                                tfo,
                                #[cfg(target_os = "linux")]
                                so_mark,
                            ).await;
                        }
                    }
                }
                _ = tokio::time::sleep(HAPPY_EYEBALLS_DELAY) => {
                    debug!("IPv6 connect to {v6_addr} delayed past {HAPPY_EYEBALLS_DELAY:?}, racing IPv4 {v4_addr}");
                }
            }

            let v4_dial = new_tcp_stream(
                v4_addr,
                iface,
                tfo,
                #[cfg(target_os = "linux")]
                so_mark,
            );
            tokio::pin!(v4_dial);

            tokio::select! {
                res_v6 = &mut v6_dial => {
                    match res_v6 {
                        Ok(stream) => Ok(stream),
                        Err(err_v6) => {
                            debug!("IPv6 connect to {v6_addr} failed ({err_v6}), waiting for IPv4");
                            v4_dial.await
                        }
                    }
                }
                res_v4 = &mut v4_dial => {
                    match res_v4 {
                        Ok(stream) => Ok(stream),
                        Err(err_v4) => {
                            debug!("IPv4 connect to {v4_addr} failed ({err_v4}), waiting for IPv6");
                            v6_dial.await
                        }
                    }
                }
            }
        }
        (Some(v6), None) => {
            new_tcp_stream(
                SocketAddr::new(v6, port),
                iface,
                tfo,
                #[cfg(target_os = "linux")]
                so_mark,
            )
            .await
        }
        (None, Some(v4)) => {
            new_tcp_stream(
                SocketAddr::new(v4, port),
                iface,
                tfo,
                #[cfg(target_os = "linux")]
                so_mark,
            )
            .await
        }
        (None, None) => {
            Err(std::io::Error::other(format!("no dns result for {host}")))
        }
    }
}

#[instrument(skip(so_mark))]
pub async fn new_udp_socket(
    src: Option<SocketAddr>,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
    // Optional family hint for the socket.
    // If not provided, the family will be determined based on the source
    // address or interface.
    family_hint: Option<std::net::SocketAddr>,
) -> std::io::Result<UdpSocket> {
    // Determine the socket family based on the source address or interface
    // logic:
    // - If family_hint is provided, use it.
    // - If src is provided and is IPv6, use IPv6.
    // - If iface is provided and is IPv6, use IPv6.
    // - Otherwise, default to IPv4.
    let (socket, family) = match (family_hint, src, iface) {
        (Some(family_hint), ..) => {
            let domain = socket2::Domain::for_address(family_hint);
            (
                socket2::Socket::new(domain, socket2::Type::DGRAM, None)?,
                domain,
            )
        }
        (None, Some(src), _) if src.is_ipv6() => (
            try_create_dualstack_socket(src, socket2::Type::DGRAM)?.0,
            socket2::Domain::IPV6,
        ),
        (None, _, Some(iface)) if iface.addr_v6.is_some() => (
            socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?,
            socket2::Domain::IPV6,
        ),
        _ => (
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?,
            socket2::Domain::IPV4,
        ),
    };
    debug!("created udp socket");

    if !cfg!(target_os = "android") {
        // Skip interface binding for loopback destinations — binding a socket
        // to an outbound interface prevents reaching localhost addresses.
        let dst_is_loopback =
            family_hint.map(|a| a.ip().is_loopback()).unwrap_or(false);
        match (src, iface) {
            (_, Some(iface)) if !dst_is_loopback => {
                must_bind_socket_on_interface(&socket, iface, family).inspect_err(
                    |x| {
                        error!("failed to bind socket to interface: {}", x);
                    },
                )?;
                // binding is not necessary for linux but is required on windows
                // Without binding local_addr can't be obtained by system call
                // which is required on quinn.
                #[cfg(target_os = "windows")]
                if let Some(addr) = src {
                    socket.bind(&socket2::SockAddr::from(addr))?;
                }

                trace!(iface = ?iface, "udp socket bound: {socket:?}");
            }
            (Some(src), _) => {
                // Either no interface, or destination is loopback (skip iface
                // binding so localhost is reachable).
                socket.bind(&src.into())?;
                trace!(src = ?src, "udp socket bound: {socket:?}");
            }
            (None, _) => {
                // On Windows, UDP sockets must be bound to get a valid local_addr
                // which is required for some operations (e.g., quinn/QUIC)
                #[cfg(target_os = "windows")]
                {
                    let bind_addr = match family {
                        socket2::Domain::IPV4 => {
                            "0.0.0.0:0".parse::<SocketAddr>().unwrap()
                        }
                        socket2::Domain::IPV6 => {
                            "[::]:0".parse::<SocketAddr>().unwrap()
                        }
                        _ => "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
                    };
                    socket.bind(&socket2::SockAddr::from(bind_addr))?;
                    trace!(addr = ?bind_addr, "udp socket bound to default address on Windows: {socket:?}");
                }
                #[cfg(not(target_os = "windows"))]
                trace!("udp socket not bound to any specific address: {socket:?}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;

    UdpSocket::from_std(socket.into())
}

/// Convert ipv6 mapped ipv4 address back to ipv4. Other address remain
/// unchanged. e.g. ::ffff:127.0.0.1 -> 127.0.0.1
pub trait ToCanonical {
    fn to_canonical(self) -> SocketAddr;
}

impl ToCanonical for SocketAddr {
    fn to_canonical(mut self) -> SocketAddr {
        self.set_ip(self.ip().to_canonical());
        self
    }
}

/// Create dualstack socket if it can
/// If failed, fallback to single stack silently
pub fn try_create_dualstack_socket(
    addr: SocketAddr,
    tcp_or_udp: socket2::Type,
) -> std::io::Result<(socket2::Socket, bool)> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let mut dualstack = false;
    let socket = socket2::Socket::new(domain, tcp_or_udp, None)?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        if let Err(e) = socket.set_only_v6(false) {
            // If setting dualstack fails, fallback to single stack
            tracing::warn!(
                "dualstack not supported, falling back to ipv6 only: {e}"
            );
        } else {
            dualstack = true;
        }
    };
    Ok((socket, dualstack))
}

/// Create a dual-stack UDP socket bound to `[::]`, falling back to an IPv4
/// socket bound to `0.0.0.0` if IPv6 is unavailable.  The resulting socket
/// can send to both IPv4 and IPv6 destinations without EAFNOSUPPORT, which
/// is required when one outbound socket is reused across destinations with
/// different address families (e.g. in the DIRECT handler).
pub fn new_dual_stack_udp_socket(
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<UdpSocket> {
    let dual_stack = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
    let ipv4_only = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

    let (socket, bind_addr) =
        match try_create_dualstack_socket(dual_stack, socket2::Type::DGRAM) {
            Ok((s, true)) => (s, dual_stack),
            Ok((_, false)) | Err(_) => (
                socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    None,
                )?,
                ipv4_only,
            ),
        };

    if let Some(iface) = iface {
        let family = socket2::Domain::for_address(bind_addr);
        must_bind_socket_on_interface(&socket, iface, family).inspect_err(|x| {
            error!("failed to bind socket to interface: {}", x);
        })?;
    }
    // must_bind_socket_on_interface only sets a socket option (SO_BINDTODEVICE
    // / IP_BOUND_IF / IPV6_UNICAST_IF); it does not assign a local port.
    // Always bind explicitly so the socket has a valid local address on all
    // platforms — required on Windows to avoid WSAEINVAL (10022) from sendto.
    socket.bind(&bind_addr.into())?;

    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

pub fn try_create_dualstack_tcplistener(
    addr: SocketAddr,
) -> io::Result<TcpListener> {
    let (socket, _dualstack) =
        try_create_dualstack_socket(addr, socket2::Type::STREAM)?;

    socket.set_nonblocking(true)?;
    // For fast restart avoid Address In Use Error
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let listener = TcpListener::from_std(socket.into())?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::SocketAddrV6, time::Duration};

    /// Locate the loopback network interface on the current host.
    /// Returns `None` if the interface cannot be found or enumeration fails.
    fn find_loopback_iface() -> Option<OutboundInterface> {
        use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
        let ifaces = NetworkInterface::show().ok()?;
        let lo = ifaces.into_iter().find(|iface| {
            iface.addr.iter().any(|a| match a {
                Addr::V4(v4) => v4.ip.is_loopback(),
                _ => false,
            })
        })?;
        Some(OutboundInterface {
            name: lo.name,
            addr_v4: Some(Ipv4Addr::LOCALHOST),
            addr_v6: Some(Ipv6Addr::LOCALHOST),
            index: lo.index,
            netmask_v4: None,
            broadcast_v4: None,
            netmask_v6: None,
            broadcast_v6: None,
            mac_addr: None,
        })
    }

    // Regression test for https://github.com/Watfaq/clash-rs/issues/1399.
    //
    // new_dual_stack_udp_socket must call bind() even when `iface` is provided.
    // Before the fix, the iface branch skipped bind() so the socket was
    // "unbound"; sendto with an IPv4-mapped destination then returned
    // WSAEINVAL (os error 10022) on Windows.

    /// Without an iface: socket is bound and IPv4-mapped round-trip works.
    #[tokio::test]
    async fn test_dual_stack_no_iface_is_bound_and_sends_ipv4_mapped() {
        let sock = new_dual_stack_udp_socket(
            None,
            #[cfg(target_os = "linux")]
            None,
        )
        .expect("failed to create dual-stack socket");

        let local = sock.local_addr().expect("local_addr failed");
        assert_ne!(local.port(), 0, "socket must have a non-zero local port");

        // Only exercise IPv4-mapped sendto when we actually got a dual-stack
        // (IPv6) socket; on hosts without IPv6 the fallback is an IPv4 socket.
        if !local.is_ipv6() {
            return;
        }

        let echo = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind echo server");
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64];
            if let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        });

        let dst = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            echo_port,
            0,
            0,
        ));
        sock.send_to(b"ping", dst).await.expect("send_to failed");

        let mut buf = vec![0u8; 64];
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
                .await
                .expect("timed out")
                .expect("recv_from failed");
        assert_eq!(&buf[..n], b"ping");
    }

    /// With an iface (loopback): socket must still be bound after
    /// must_bind_socket_on_interface so that sendto does not return WSAEINVAL.
    ///
    /// Skipped on Linux when SO_BINDTODEVICE requires elevated privileges.
    #[tokio::test]
    async fn test_dual_stack_with_iface_is_bound() {
        let Some(iface) = find_loopback_iface() else {
            eprintln!("skipping: loopback interface not found");
            return;
        };

        let result = new_dual_stack_udp_socket(
            Some(&iface),
            #[cfg(target_os = "linux")]
            None,
        );

        // On Linux, SO_BINDTODEVICE requires CAP_NET_RAW; skip gracefully.
        #[cfg(target_os = "linux")]
        if result.is_err() {
            eprintln!("skipping: SO_BINDTODEVICE requires elevated privileges");
            return;
        }

        let sock = result.expect("failed to create dual-stack socket with iface");
        let local = sock.local_addr().expect("local_addr failed");
        assert_ne!(
            local.port(),
            0,
            "socket must have a non-zero local port even when iface is set"
        );
    }

    #[tokio::test]
    async fn test_dial_happy_eyeballs_ip_literal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let mock_resolver = crate::app::dns::MockClashResolver::new();
        // Resolver should not be invoked for IP literal
        let resolver: ThreadSafeDNSResolver = std::sync::Arc::new(mock_resolver);

        let stream = dial_tcp_with_happy_eyeballs(
            "127.0.0.1",
            port,
            &resolver,
            None,
            false,
            #[cfg(target_os = "linux")]
            None,
        )
        .await;

        assert!(stream.is_ok(), "IP literal dial should succeed");
    }

    #[tokio::test]
    async fn test_dial_happy_eyeballs_fast_fallback_on_v6_blackhole() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let mut mock_resolver = crate::app::dns::MockClashResolver::new();
        // Return an unreachable documentation IPv6 address (2001:db8::1) that blackholes
        mock_resolver
            .expect_resolve_v6()
            .returning(|_, _| Ok(Some("2001:db8::1".parse::<Ipv6Addr>().unwrap())));
        // Return working localhost IPv4
        mock_resolver
            .expect_resolve_v4()
            .returning(|_, _| Ok(Some(Ipv4Addr::LOCALHOST)));

        let resolver: ThreadSafeDNSResolver = std::sync::Arc::new(mock_resolver);

        let start = std::time::Instant::now();
        let stream = dial_tcp_with_happy_eyeballs(
            "dualstack.test",
            port,
            &resolver,
            None,
            false,
            #[cfg(target_os = "linux")]
            None,
        )
        .await;

        let elapsed = start.elapsed();
        assert!(stream.is_ok(), "Should successfully connect via IPv4");
        // Happy Eyeballs should connect within ~500ms instead of 10s timeout
        assert!(
            elapsed < Duration::from_secs(2),
            "Happy Eyeballs should fallback quickly, elapsed: {elapsed:?}"
        );
    }
}

