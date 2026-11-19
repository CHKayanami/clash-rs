use std::io;
use std::net::{SocketAddr, UdpSocket};

use socket2::{Domain, Socket, Type};
use tokio::net::TcpListener;
use tracing::warn;

pub(crate) async fn bind_tcp(address: SocketAddr, dual_stack: bool) -> io::Result<TcpListener> {
    if !dual_stack || !is_ipv6_wildcard(address) {
        return TcpListener::bind(address).await;
    }
    let socket = dual_stack_socket(address, Type::STREAM)?;
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

pub(crate) fn bind_udp(address: SocketAddr, dual_stack: bool) -> io::Result<UdpSocket> {
    if dual_stack && is_ipv6_wildcard(address) {
        let socket = dual_stack_socket(address, Type::DGRAM)?;
        socket.bind(&address.into())?;
        return Ok(socket.into());
    }
    let socket = UdpSocket::bind(address)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn is_ipv6_wildcard(address: SocketAddr) -> bool {
    matches!(address, SocketAddr::V6(address) if address.ip().is_unspecified())
}

fn dual_stack_socket(address: SocketAddr, kind: Type) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV6, kind, None)?;
    if let Err(error) = socket.set_only_v6(false) {
        warn!(%address, %error, "Could not enable dual-stack DNS socket, using system default");
    }
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::SockRef;
    use std::net::Ipv6Addr;

    #[tokio::test]
    async fn explicit_ipv6_wildcard_uses_system_socket_defaults() -> io::Result<()> {
        let address = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
        let tcp_default = Socket::new(Domain::IPV6, Type::STREAM, None)?.only_v6()?;
        let udp_default = Socket::new(Domain::IPV6, Type::DGRAM, None)?.only_v6()?;
        let tcp = bind_tcp(address, false).await?;
        let udp = bind_udp(address, false)?;
        assert_eq!(SockRef::from(&tcp).only_v6()?, tcp_default);
        assert_eq!(SockRef::from(&udp).only_v6()?, udp_default);
        Ok(())
    }
}
