use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Information about an incoming transparently proxied connection.
#[derive(Debug)]
pub struct EbpfSession {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub protocol: TransportProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

/// Helper to get the original destination address from a TCP stream with SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST.
#[cfg(target_os = "linux")]
pub fn get_original_dst(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();

    // Try IPv4 original dst first
    let mut addr_v4: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len_v4 = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let res_v4 = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr_v4 as *mut _ as *mut libc::c_void,
            &mut len_v4,
        )
    };

    if res_v4 == 0 {
        let ip = std::net::Ipv4Addr::from(addr_v4.sin_addr.s_addr.to_ne_bytes());
        let port = u16::from_be(addr_v4.sin_port);
        return Ok(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)));
    }


    // Try IPv6 original dst
    let mut addr_v6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len_v6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    let res_v6 = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            libc::IP6T_SO_ORIGINAL_DST,
            &mut addr_v6 as *mut _ as *mut libc::c_void,
            &mut len_v6,
        )
    };

    if res_v6 == 0 {
        let ip = std::net::Ipv6Addr::from(addr_v6.sin6_addr.s6_addr);
        let port = u16::from_be(addr_v6.sin6_port);
        return Ok(SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0)));
    }

    // In pure eBPF / IP_TRANSPARENT mode, the accepted child socket's local_addr
    // is the flow's true original destination address (e.g. Fake-IP / target host).
    stream.local_addr()
}

#[cfg(not(target_os = "linux"))]
pub fn get_original_dst(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    stream.local_addr()
}

