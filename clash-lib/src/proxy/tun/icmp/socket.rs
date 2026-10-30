use std::{io, mem::{size_of, size_of_val, zeroed},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
    os::fd::AsRawFd, ptr};
use libc::{c_int, iovec, msghdr, socklen_t, setsockopt, recvmsg,
    CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_NXTHDR};
use socket2::{Domain, Protocol, Socket, Type, SockRef};
use tokio::{io::Interest, net::UdpSocket};
#[cfg(target_os = "android")]
use crate::android::protect_socket;
#[cfg(target_os = "linux")]
use crate::{app::net::get_outbound_interface, proxy::utils::{
    must_bind_socket_on_interface, resolve_so_mark}};

pub(super) fn open(destination: IpAddr, so_mark: Option<u32>) -> io::Result<UdpSocket> {
    let (domain, protocol, bind) = if destination.is_ipv4() {
        (Domain::IPV4, Protocol::ICMPV4, SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))
    } else {
        (Domain::IPV6, Protocol::ICMPV6, SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0))
    };
    // SOCK_DGRAM ICMP uses the kernel ping socket API, not a privileged raw
    // socket. Android permits it to application network groups.
    let socket = Socket::new(domain, Type::DGRAM, Some(protocol))?;
    #[cfg(target_os = "android")]
    protect_socket(socket.as_raw_fd())?;
    #[cfg(target_os = "linux")]
    {
        if !destination.is_loopback() && let Some(iface) = get_outbound_interface() {
            must_bind_socket_on_interface(&socket, &iface, domain)?;
        }
        if let Some(mark) = resolve_so_mark(so_mark) { socket.set_mark(mark)?; }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = so_mark;
    socket.set_nonblocking(true)?;
    socket.bind(&bind.into())?;
    socket.connect(&SocketAddr::new(destination, 0).into())?;
    // Tokio's datagram I/O works on this SOCK_DGRAM descriptor; all ICMP
    // framing/checksum handling stays in our caller and the kernel ping API.
    let socket: StdUdpSocket = socket.into();
    let socket = UdpSocket::from_std(socket)?;
    enable_receive_hop_limit(&socket, destination.is_ipv6())?;
    Ok(socket)
}

pub(super) fn set_hop_limit(socket: &UdpSocket, ipv6: bool, limit: u8) -> io::Result<()> {
    let socket = SockRef::from(socket);
    if ipv6 { socket.set_unicast_hops_v6(u32::from(limit)) }
    else { socket.set_ttl_v4(u32::from(limit)) }
}


pub(super) fn enable_receive_hop_limit(socket: &UdpSocket, ipv6: bool) -> io::Result<()> {
    let (level, option) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT)
    } else {
        (libc::IPPROTO_IP, libc::IP_RECVTTL)
    };
    let enabled: c_int = 1;
    // SAFETY: the descriptor is borrowed for the call and enabled is a live
    // integer with exactly the length passed to setsockopt.
    let result = unsafe { setsockopt(socket.as_raw_fd(), level, option,
        ptr::from_ref(&enabled).cast(), size_of::<c_int>() as socklen_t) };
    if result < 0 { return Err(io::Error::last_os_error()); }
    Ok(())
}

pub(super) async fn receive(socket: &UdpSocket, buffer: &mut [u8], ipv6: bool)
    -> io::Result<(usize, u8)> {
    socket.async_io(Interest::READABLE, || receive_once(socket, buffer, ipv6)).await
}

fn receive_once(socket: &UdpSocket, buffer: &mut [u8], ipv6: bool) -> io::Result<(usize, u8)> {
    // usize storage provides cmsghdr alignment; control bytes and all pointers
    // remain local to this synchronous syscall and never cross an await.
    let mut control = [0usize; 16];
    let mut vector = iovec { iov_base: buffer.as_mut_ptr().cast(), iov_len: buffer.len() };
    // SAFETY: zero is valid for msghdr; unused address fields remain null.
    let mut message: msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&control) as _;
    // SAFETY: iovec and ancillary storage are writable for their declared
    // lengths and outlive recvmsg. The socket is nonblocking and borrowed.
    let length = unsafe { recvmsg(socket.as_raw_fd(), &mut message, 0) };
    if length < 0 { return Err(io::Error::last_os_error()); }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated ICMP reply or control data"));
    }
    // SAFETY: recvmsg initialized the control headers; CMSG helpers walk only
    // the returned region. Check payload length before reading ancillary data.
    unsafe {
        let mut header = CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            let is_v6 = (*header).cmsg_level == libc::IPPROTO_IPV6
                && (*header).cmsg_type == libc::IPV6_HOPLIMIT;
            let is_v4 = (*header).cmsg_level == libc::IPPROTO_IP
                && (*header).cmsg_type == ipv4_ttl_control_type();
            if (ipv6 && is_v6) || (!ipv6 && is_v4) {
                let data_len = ((*header).cmsg_len as usize)
                    .saturating_sub(CMSG_LEN(0) as usize);
                let data = CMSG_DATA(header);
                // BSD returns IPv4 TTL as a byte; Linux and IPv6 use int.
                let value = if !ipv6 && data_len == 1 {
                    i32::from(*data)
                } else if data_len >= size_of::<c_int>() {
                    ptr::read_unaligned(data.cast::<c_int>())
                } else {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid ICMP hop limit"));
                };
                let hop_limit = u8::try_from(value).map_err(|_| io::Error::new(
                    io::ErrorKind::InvalidData, "ICMP hop limit out of range"))?;
                return Ok((length as usize, hop_limit));
            }
            header = CMSG_NXTHDR(&message, header);
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "missing ICMP reply hop limit"))
}

fn ipv4_ttl_control_type() -> c_int {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    { libc::IP_TTL }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    { libc::IP_RECVTTL }
}
