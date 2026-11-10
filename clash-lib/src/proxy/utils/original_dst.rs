use std::{io, net::SocketAddr, os::fd::AsRawFd};

use socket2::SockAddr;
use tokio::net::TcpStream;

// get original destination
// https://github.com/shadowsocks/shadowsocks-rust/blob/master/crates/shadowsocks-service/src/local/redir/tcprelay/sys/unix/linux.rs#L111
pub(crate) fn get_original_destination_addr(s: &TcpStream) -> io::Result<SocketAddr> {
    let fd = s.as_raw_fd();

    // SockAddr owns sufficiently aligned sockaddr_storage; try_init supplies its
    // capacity and only exposes the address after getsockopt initializes it.
    // The stream keeps fd alive for both calls.
    unsafe {
        let (_, target_addr) =
            SockAddr::try_init(|target_addr, target_addr_len| {
                // No sufficient method to know whether the destination IPv4 or IPv6.
                // Follow the method in shadowsocks-libev.

                let ret = libc::getsockopt(
                    fd,
                    libc::SOL_IPV6,
                    libc::IP6T_SO_ORIGINAL_DST,
                    target_addr as *mut _,
                    target_addr_len, // libc::socklen_t
                );

                if ret == 0 {
                    return Ok(());
                } else {
                    let err = io::Error::last_os_error();
                    match err.raw_os_error() {
                        None => return Err(err),
                        // ENOPROTOOPT, EOPNOTSUPP (ENOTSUP): IP6T_SO_ORIGINAL_DST
                        // doesn't exist ENOENT: Destination
                        // address is not IPv6
                        #[allow(unreachable_patterns)]
                        Some(libc::ENOPROTOOPT)
                        | Some(libc::ENOENT)
                        | Some(libc::EOPNOTSUPP)
                        | Some(libc::ENOTSUP) => {}
                        Some(..) => return Err(err),
                    }
                }

                let ret = libc::getsockopt(
                    fd,
                    libc::SOL_IP,
                    libc::SO_ORIGINAL_DST,
                    target_addr as *mut _,
                    target_addr_len, // libc::socklen_t
                );

                if ret != 0 {
                    let err = io::Error::last_os_error();
                    return Err(err);
                }

                Ok(())
            })?;

        // Convert sockaddr_storage to SocketAddr
        target_addr.as_socket().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData, "unexpected original destination address family",
        ))
    }
}
