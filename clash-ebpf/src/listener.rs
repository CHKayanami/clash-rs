use crate::config::EbpfConfig;
use crate::netns::DaeNs;
use crate::session::{EbpfSession, TransportProtocol, get_original_dst};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::debug;

#[derive(Error, Debug)]
pub enum ListenerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("NetNS error: {0}")]
    NetNs(#[from] crate::netns::NetNsError),
}

pub struct EbpfListener {
    tcp_listener_v4: TcpListener,
    tcp_listener_v6: Option<TcpListener>,
    udp_socket_v4: Arc<UdpSocket>,
    udp_socket_v6: Option<Arc<UdpSocket>>,
    #[cfg(target_os = "linux")]
    dns_reply_socket_v4: std::sync::Mutex<Option<Arc<UdpSocket>>>,
    #[cfg(target_os = "linux")]
    dns_reply_socket_v6: std::sync::Mutex<Option<Arc<UdpSocket>>>,
    #[allow(dead_code)]
    config: EbpfConfig,
    #[allow(dead_code)]
    ns: Arc<DaeNs>,
}

impl EbpfListener {
    /// Binds the transparent proxy TCP/UDP sockets inside the daens network namespace for IPv4 and IPv6.
    pub fn bind(ns: &DaeNs, config: EbpfConfig) -> Result<Self, ListenerError> {
        let ns_clone = Arc::new(ns.try_clone()?);
        ns.with_daens(|| -> std::io::Result<Self> {
            use socket2::{Domain, Protocol, Socket, Type};

            // 1. TCP IPv4 Transparent Listener
            let tcp_sock_v4 =
                Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            tcp_sock_v4.set_nonblocking(true)?;
            tcp_sock_v4.set_cloexec(true)?;
            tcp_sock_v4.set_reuse_address(true)?;
            #[cfg(target_os = "linux")]
            {
                tcp_sock_v4.set_ip_transparent_v4(true)?;
                let _ = nix::sys::socket::setsockopt(
                    &tcp_sock_v4,
                    nix::sys::socket::sockopt::Mark,
                    &(clash_ebpf_common::DAE_BYPASS_MARK as u32),
                );
            }
            let addr_v4 = SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                config.tproxy_port,
            ));
            tcp_sock_v4.bind(&addr_v4.into())?;
            tcp_sock_v4.listen(1024)?;
            let tcp_listener_v4 = TcpListener::from_std(tcp_sock_v4.into())?;

            // 2. TCP IPv6 Transparent Listener (Optional)
            let tcp_listener_v6 = match (|| -> std::io::Result<TcpListener> {
                let tcp_sock_v6 =
                    Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
                tcp_sock_v6.set_nonblocking(true)?;
                tcp_sock_v6.set_cloexec(true)?;
                tcp_sock_v6.set_reuse_address(true)?;
                tcp_sock_v6.set_only_v6(true)?;
                #[cfg(target_os = "linux")]
                {
                    tcp_sock_v6.set_ip_transparent_v6(true)?;
                    let _ = nix::sys::socket::setsockopt(
                        &tcp_sock_v6,
                        nix::sys::socket::sockopt::Mark,
                        &(clash_ebpf_common::DAE_BYPASS_MARK as u32),
                    );
                }
                let addr_v6 = SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    config.tproxy_port,
                    0,
                    0,
                ));
                tcp_sock_v6.bind(&addr_v6.into())?;
                tcp_sock_v6.listen(1024)?;
                TcpListener::from_std(tcp_sock_v6.into())
            })() {
                Ok(l) => {
                    tracing::info!(
                        "Bound TCP IPv6 transparent listener on port {}",
                        config.tproxy_port
                    );
                    Some(l)
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to bind TCP IPv6 transparent listener: {e}"
                    );
                    None
                }
            };

            // 3. UDP IPv4 Transparent Listener
            let udp_sock_v4 =
                Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            udp_sock_v4.set_nonblocking(true)?;
            udp_sock_v4.set_cloexec(true)?;
            udp_sock_v4.set_reuse_address(true)?;
            let _ = udp_sock_v4.set_recv_buffer_size(8 << 20);
            #[cfg(target_os = "linux")]
            {
                let _ = udp_sock_v4.set_reuse_port(true);
                udp_sock_v4.set_ip_transparent_v4(true)?;
                let _ = nix::sys::socket::setsockopt(
                    &udp_sock_v4,
                    nix::sys::socket::sockopt::Ipv4OrigDstAddr,
                    &true,
                );
                let _ = nix::sys::socket::setsockopt(
                    &udp_sock_v4,
                    nix::sys::socket::sockopt::Ipv4PacketInfo,
                    &true,
                );
                let _ = nix::sys::socket::setsockopt(
                    &udp_sock_v4,
                    nix::sys::socket::sockopt::Mark,
                    &(clash_ebpf_common::DAE_BYPASS_MARK as u32),
                );
            }
            let udp_addr_v4 = SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                config.tproxy_port,
            ));
            udp_sock_v4.bind(&udp_addr_v4.into())?;
            let udp_socket_v4 = UdpSocket::from_std(udp_sock_v4.into())?;

            // 4. UDP IPv6 Transparent Listener (Optional)
            let udp_socket_v6 = match (|| -> std::io::Result<UdpSocket> {
                let udp_sock_v6 =
                    Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
                udp_sock_v6.set_nonblocking(true)?;
                udp_sock_v6.set_cloexec(true)?;
                udp_sock_v6.set_reuse_address(true)?;
                udp_sock_v6.set_only_v6(true)?;
                let _ = udp_sock_v6.set_recv_buffer_size(8 << 20);
                #[cfg(target_os = "linux")]
                {
                    let _ = udp_sock_v6.set_reuse_port(true);
                    udp_sock_v6.set_ip_transparent_v6(true)?;
                    let _ = nix::sys::socket::setsockopt(
                        &udp_sock_v6,
                        nix::sys::socket::sockopt::Ipv6OrigDstAddr,
                        &true,
                    );
                    let _ = nix::sys::socket::setsockopt(
                        &udp_sock_v6,
                        nix::sys::socket::sockopt::Ipv6RecvPacketInfo,
                        &true,
                    );
                    let _ = nix::sys::socket::setsockopt(
                        &udp_sock_v6,
                        nix::sys::socket::sockopt::Mark,
                        &(clash_ebpf_common::DAE_BYPASS_MARK as u32),
                    );
                }
                let udp_addr_v6 = SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    config.tproxy_port,
                    0,
                    0,
                ));
                udp_sock_v6.bind(&udp_addr_v6.into())?;
                UdpSocket::from_std(udp_sock_v6.into())
            })() {
                Ok(s) => {
                    tracing::info!(
                        "Bound UDP IPv6 transparent listener on port {}",
                        config.tproxy_port
                    );
                    Some(s)
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to bind UDP IPv6 transparent listener: {e}"
                    );
                    None
                }
            };

            Ok(Self {
                tcp_listener_v4,
                tcp_listener_v6,
                udp_socket_v4: Arc::new(udp_socket_v4),
                udp_socket_v6: udp_socket_v6.map(Arc::new),
                #[cfg(target_os = "linux")]
                dns_reply_socket_v4: std::sync::Mutex::new(None),
                #[cfg(target_os = "linux")]
                dns_reply_socket_v6: std::sync::Mutex::new(None),
                config,
                ns: ns_clone,
            })
        })?
        .map_err(ListenerError::Io)
    }

    #[cfg(target_os = "linux")]
    fn build_dns_reply_socket(&self, is_v6: bool) -> std::io::Result<UdpSocket> {
        self.ns
            .with_daens(|| -> std::io::Result<UdpSocket> {
                use socket2::{Domain, Protocol, Socket, Type};
                let domain = if is_v6 { Domain::IPV6 } else { Domain::IPV4 };
                let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
                socket.set_nonblocking(true)?;
                socket.set_cloexec(true)?;
                socket.set_reuse_address(true)?;
                let _ = socket.set_reuse_port(true);
                if is_v6 {
                    socket.set_only_v6(true)?;
                    socket.set_ip_transparent_v6(true)?;
                } else {
                    socket.set_ip_transparent_v4(true)?;
                }
                let bind_addr = if is_v6 {
                    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 53, 0, 0))
                } else {
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 53))
                };
                socket.bind(&bind_addr.into())?;
                UdpSocket::from_std(socket.into())
            })
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
    }

    #[cfg(target_os = "linux")]
    fn get_or_create_dns_reply_socket(&self, is_v6: bool) -> std::io::Result<Arc<UdpSocket>> {
        let cache = if is_v6 {
            &self.dns_reply_socket_v6
        } else {
            &self.dns_reply_socket_v4
        };
        if let Some(sock) = cache.lock().unwrap().as_ref() {
            return Ok(Arc::clone(sock));
        }
        let new_sock = Arc::new(self.build_dns_reply_socket(is_v6)?);
        let mut guard = cache.lock().unwrap();
        if let Some(sock) = guard.as_ref() {
            return Ok(Arc::clone(sock));
        }
        *guard = Some(Arc::clone(&new_sock));
        Ok(new_sock)
    }

    #[cfg(target_os = "linux")]
    fn replace_dns_reply_socket(
        &self,
        is_v6: bool,
        old: &Arc<UdpSocket>,
    ) -> std::io::Result<Arc<UdpSocket>> {
        let cache = if is_v6 {
            &self.dns_reply_socket_v6
        } else {
            &self.dns_reply_socket_v4
        };
        let mut guard = cache.lock().unwrap();
        if let Some(cur) = guard.as_ref() {
            if !Arc::ptr_eq(cur, old) {
                return Ok(Arc::clone(cur));
            }
        }
        let new_sock = Arc::new(self.build_dns_reply_socket(is_v6)?);
        *guard = Some(Arc::clone(&new_sock));
        Ok(new_sock)
    }

    /// Sends a DNS reply datagram to `dst` with `src` (the original destination DNS server) as the source address
    /// via pktinfo ancillary data on the cached transparent socket bound to port 53.
    #[allow(unused_variables)]
    pub async fn send_dns_reply(
        &self,
        data: &[u8],
        src: SocketAddr,
        dst: SocketAddr,
    ) -> std::io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            use tokio::io::Interest;

            let is_v6 = src.is_ipv6();

            // 1. Try cached DNS reply socket (bound to port 53 in daens)
            if let Ok(socket) = self.get_or_create_dns_reply_socket(is_v6) {
                let first = socket
                    .async_io(Interest::WRITABLE, || {
                        sendmsg_with_src(socket.as_raw_fd(), data, src.ip(), 0, dst)
                    })
                    .await;
                match first {
                    Ok(n) => return Ok(n),
                    Err(e) => {
                        tracing::debug!(
                            "cached DNS reply socket send failed ({e}); rebuilding once"
                        );
                    }
                }
                if let Ok(socket) = self.replace_dns_reply_socket(is_v6, &socket) {
                    if let Ok(n) = socket
                        .async_io(Interest::WRITABLE, || {
                            sendmsg_with_src(socket.as_raw_fd(), data, src.ip(), 0, dst)
                        })
                        .await
                    {
                        return Ok(n);
                    }
                }
            }

            // 2. Fallback to one-shot dynamic transparent reply socket if cached path fails
            let fallback_sock = self.create_reply_socket(src)?;
            fallback_sock.send_to(data, dst).await
        }

        #[cfg(not(target_os = "linux"))]
        {
            self.udp_socket_v4.send_to(data, dst).await
        }
    }

    /// Creates a transparent UDP socket inside daens bound to `original_dst` for replying to clients.
    /// This ensures DNS (port 53) and proxied UDP replies preserve the source address the client queried.
    pub fn create_reply_socket(
        &self,
        original_dst: SocketAddr,
    ) -> std::io::Result<UdpSocket> {
        self.ns
            .with_daens(|| -> std::io::Result<UdpSocket> {
                use socket2::{Domain, Protocol, Socket, Type};
                let domain = if original_dst.is_ipv4() {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                };
                let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
                socket.set_nonblocking(true)?;
                socket.set_cloexec(true)?;
                socket.set_reuse_address(true)?;
                #[cfg(target_os = "linux")]
                {
                    let _ = socket.set_reuse_port(true);
                    if original_dst.is_ipv4() {
                        socket.set_ip_transparent_v4(true)?;
                    } else {
                        socket.set_ip_transparent_v6(true)?;
                    }
                }

                socket.bind(&original_dst.into())?;

                let udp_std: std::net::UdpSocket = socket.into();
                UdpSocket::from_std(udp_std)
            })
            .map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
            })?
    }

    /// Returns the raw file descriptor of the TCP IPv4 listener socket.
    #[cfg(target_os = "linux")]
    pub fn tcp_v4_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.tcp_listener_v4.as_raw_fd()
    }

    /// Returns the raw file descriptor of the TCP IPv6 listener socket.
    #[cfg(target_os = "linux")]
    pub fn tcp_v6_raw_fd(&self) -> Option<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        self.tcp_listener_v6.as_ref().map(|l| l.as_raw_fd())
    }

    /// Returns the raw file descriptor of the UDP IPv4 socket.
    #[cfg(target_os = "linux")]
    pub fn udp_v4_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.udp_socket_v4.as_raw_fd()
    }

    /// Returns the raw file descriptor of the UDP IPv6 socket.
    #[cfg(target_os = "linux")]
    pub fn udp_v6_raw_fd(&self) -> Option<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        self.udp_socket_v6.as_ref().map(|s| s.as_raw_fd())
    }

    /// Accepts the next incoming transparent TCP connection (IPv4 or IPv6) and extracts its session info.
    pub async fn accept_tcp(&self) -> std::io::Result<(TcpStream, EbpfSession)> {
        let (stream, src_addr) = if let Some(v6) = &self.tcp_listener_v6 {
            tokio::select! {
                res = self.tcp_listener_v4.accept() => res?,
                res = v6.accept() => res?,
            }
        } else {
            self.tcp_listener_v4.accept().await?
        };

        #[cfg(target_os = "linux")]
        {
            // Clear inherited SO_MARK on accepted socket (honk parity)
            let _ = nix::sys::socket::setsockopt(
                &stream,
                nix::sys::socket::sockopt::Mark,
                &0u32,
            );
        }

        let dst_addr = get_original_dst(&stream)?;

        let session = EbpfSession {
            source: src_addr,
            destination: dst_addr,
            protocol: TransportProtocol::Tcp,
        };

        debug!(
            "eBPF TCP transparent connection: {} -> {}",
            src_addr, dst_addr
        );
        Ok((stream, session))
    }

    /// Receives a transparent UDP packet from a specific `sock` into `buf` using Tokio `async_io`.
    #[cfg(target_os = "linux")]
    pub async fn recv_from_socket(
        sock: &UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddr, SocketAddr)> {
        use std::os::fd::AsRawFd;
        let fd = sock.as_raw_fd();
        let local_addr = sock.local_addr().ok();

        sock.async_io(tokio::io::Interest::READABLE, || {
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut src_storage: libc::sockaddr_storage =
                unsafe { std::mem::zeroed() };
            let mut control_buf = [0u8; 512];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut src_storage as *mut _ as *mut libc::c_void;
            msg.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control_buf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = control_buf.len() as _;

            let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }

            let src_addr = match src_storage.ss_family as libc::c_int {
                libc::AF_INET => {
                    let sin = unsafe {
                        &*(&src_storage as *const _ as *const libc::sockaddr_in)
                    };
                    let ip =
                        std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                    let port = u16::from_be(sin.sin_port);
                    SocketAddr::V4(SocketAddrV4::new(ip, port))
                }
                libc::AF_INET6 => {
                    let sin6 = unsafe {
                        &*(&src_storage as *const _ as *const libc::sockaddr_in6)
                    };
                    let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    let port = u16::from_be(sin6.sin6_port);
                    SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0))
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unknown address family",
                    ));
                }
            };

            let mut dst_addr = None;
            let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
            while !cmsg.is_null() {
                let level = unsafe { (*cmsg).cmsg_level };
                let type_ = unsafe { (*cmsg).cmsg_type };
                if level == libc::SOL_IP
                    && (type_ == libc::IP_ORIGDSTADDR
                        || type_ == libc::IP_RECVORIGDSTADDR)
                {
                    let sin = unsafe {
                        &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in)
                    };
                    let ip =
                        std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                    let port = u16::from_be(sin.sin_port);
                    dst_addr = Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
                    break;
                } else if level == libc::SOL_IPV6
                    && (type_ == libc::IPV6_ORIGDSTADDR
                        || type_ == libc::IPV6_RECVORIGDSTADDR)
                {
                    let sin6 = unsafe {
                        &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6)
                    };
                    let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    let port = u16::from_be(sin6.sin6_port);
                    dst_addr = Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                        ip, port, 0, 0,
                    )));
                    break;
                }
                cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
            }

            let dst_addr = dst_addr.or(local_addr).unwrap_or(src_addr);
            Ok((n as usize, src_addr, dst_addr))
        })
        .await
    }

    /// Receives multiple transparent UDP packets in a batch using Tokio `async_io`.
    #[cfg(target_os = "linux")]
    pub async fn recv_many_from_socket(
        sock: &UdpSocket,
        packets: &mut Vec<(bytes::Bytes, SocketAddr, SocketAddr)>,
        max_count: usize,
    ) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd;
        let fd = sock.as_raw_fd();
        let local_addr = sock.local_addr().ok();

        sock.async_io(tokio::io::Interest::READABLE, || {
            let mut read_count = 0;
            let mut buf = [0u8; 65535];
            while read_count < max_count {
                let mut iov = libc::iovec {
                    iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                    iov_len: buf.len(),
                };
                let mut src_storage: libc::sockaddr_storage =
                    unsafe { std::mem::zeroed() };
                let mut control_buf = [0u8; 512];
                let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
                msg.msg_name = &mut src_storage as *mut _ as *mut libc::c_void;
                msg.msg_namelen =
                    std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = control_buf.as_mut_ptr() as *mut libc::c_void;
                msg.msg_controllen = control_buf.len() as _;

                let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        if read_count > 0 {
                            break;
                        }
                    }
                    return Err(err);
                }

                let src_addr = match src_storage.ss_family as libc::c_int {
                    libc::AF_INET => {
                        let sin = unsafe {
                            &*(&src_storage as *const _ as *const libc::sockaddr_in)
                        };
                        let ip =
                            std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                        let port = u16::from_be(sin.sin_port);
                        SocketAddr::V4(SocketAddrV4::new(ip, port))
                    }
                    libc::AF_INET6 => {
                        let sin6 = unsafe {
                            &*(&src_storage as *const _ as *const libc::sockaddr_in6)
                        };
                        let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                        let port = u16::from_be(sin6.sin6_port);
                        SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0))
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "unknown address family",
                        ));
                    }
                };

                let mut dst_addr = None;
                let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
                while !cmsg.is_null() {
                    let level = unsafe { (*cmsg).cmsg_level };
                    let type_ = unsafe { (*cmsg).cmsg_type };
                    if level == libc::SOL_IP
                        && (type_ == libc::IP_ORIGDSTADDR
                            || type_ == libc::IP_RECVORIGDSTADDR)
                    {
                        let sin = unsafe {
                            &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in)
                        };
                        let ip =
                            std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                        let port = u16::from_be(sin.sin_port);
                        dst_addr = Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
                        break;
                    } else if level == libc::SOL_IPV6
                        && (type_ == libc::IPV6_ORIGDSTADDR
                            || type_ == libc::IPV6_RECVORIGDSTADDR)
                    {
                        let sin6 = unsafe {
                            &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6)
                        };
                        let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                        let port = u16::from_be(sin6.sin6_port);
                        dst_addr = Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                            ip, port, 0, 0,
                        )));
                        break;
                    }
                    cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
                }

                let dst_addr = dst_addr.or(local_addr).unwrap_or(src_addr);
                packets.push((bytes::Bytes::copy_from_slice(&buf[..n as usize]), src_addr, dst_addr));
                read_count += 1;
            }

            Ok(read_count)
        })
        .await
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn recv_from_socket(
        sock: &UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddr, SocketAddr)> {
        let (len, src_addr) = sock.recv_from(buf).await?;
        let dst_addr = sock.local_addr().unwrap_or(src_addr);
        Ok((len, src_addr, dst_addr))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn recv_many_from_socket(
        sock: &UdpSocket,
        packets: &mut Vec<(bytes::Bytes, SocketAddr, SocketAddr)>,
        _max_count: usize,
    ) -> std::io::Result<usize> {
        let mut buf = [0u8; 65535];
        let (len, src_addr) = sock.recv_from(&mut buf).await?;
        let dst_addr = sock.local_addr().unwrap_or(src_addr);
        packets.push((bytes::Bytes::copy_from_slice(&buf[..len]), src_addr, dst_addr));
        Ok(1)
    }

    /// Receives the next transparent UDP packet into `buf`, returning bytes read, source address and original destination.
    pub async fn recv_udp(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddr, SocketAddr)> {
        Self::recv_from_socket(&self.udp_socket_v4, buf).await
    }

    pub fn udp_socket(&self) -> Arc<UdpSocket> {
        self.udp_socket_v4.clone()
    }

    pub fn udp_socket_v4(&self) -> Arc<UdpSocket> {
        self.udp_socket_v4.clone()
    }

    pub fn udp_socket_v6(&self) -> Option<Arc<UdpSocket>> {
        self.udp_socket_v6.clone()
    }
}

#[cfg(target_os = "linux")]
fn sendmsg_with_src(
    fd: std::os::fd::RawFd,
    data: &[u8],
    src_ip: std::net::IpAddr,
    src_ifindex: u32,
    dst: SocketAddr,
) -> std::io::Result<usize> {
    let dst_addr = socket2::SockAddr::from(dst);
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };

    #[repr(C)]
    struct CmsgStorage {
        _alignment: [libc::cmsghdr; 0],
        bytes: [u8; 128],
    }

    let mut cmsg_buf = CmsgStorage {
        _alignment: [],
        bytes: [0u8; 128],
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = dst_addr.as_ptr() as *mut libc::c_void;
    msg.msg_namelen = dst_addr.len();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.bytes.as_mut_ptr() as *mut libc::c_void;

    let payload_len = match src_ip {
        std::net::IpAddr::V4(_) => std::mem::size_of::<libc::in_pktinfo>(),
        std::net::IpAddr::V6(_) => std::mem::size_of::<libc::in6_pktinfo>(),
    };
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(payload_len as _) } as _;

    unsafe {
        let hdr = libc::CMSG_FIRSTHDR(&msg);
        if hdr.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "pktinfo cmsg buffer too small",
            ));
        }
        match src_ip {
            std::net::IpAddr::V4(ip) => {
                (*hdr).cmsg_level = libc::IPPROTO_IP;
                (*hdr).cmsg_type = libc::IP_PKTINFO;
                (*hdr).cmsg_len = libc::CMSG_LEN(payload_len as _) as _;
                let pktinfo = libc::CMSG_DATA(hdr) as *mut libc::in_pktinfo;
                (*pktinfo).ipi_ifindex = src_ifindex as libc::c_int;
                (*pktinfo).ipi_spec_dst = libc::in_addr {
                    s_addr: u32::from(ip).to_be(),
                };
                (*pktinfo).ipi_addr = libc::in_addr { s_addr: 0 };
            }
            std::net::IpAddr::V6(ip) => {
                (*hdr).cmsg_level = libc::IPPROTO_IPV6;
                (*hdr).cmsg_type = libc::IPV6_PKTINFO;
                (*hdr).cmsg_len = libc::CMSG_LEN(payload_len as _) as _;
                let pktinfo = libc::CMSG_DATA(hdr) as *mut libc::in6_pktinfo;
                (*pktinfo).ipi6_addr = libc::in6_addr {
                    s6_addr: ip.octets(),
                };
                (*pktinfo).ipi6_ifindex = src_ifindex;
            }
        }
        let n = libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT);
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}
