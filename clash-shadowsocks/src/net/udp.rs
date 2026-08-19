//! UDP socket wrappers

use std::{
    io,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    task::{Context as TaskContext, Poll},
};

use futures::ready;
use tokio::{io::ReadBuf, net::ToSocketAddrs};

#[inline]
fn make_mtu_error(packet_size: usize, mtu: usize) -> io::Error {
    io::Error::other(format!("UDP packet {packet_size} > MTU {mtu}"))
}

/// Wrappers for outbound `UdpSocket`
#[derive(Debug)]
pub struct UdpSocket {
    socket: tokio::net::UdpSocket,
    mtu: Option<usize>,
}

impl UdpSocket {
    /// Create a new `UdpSocket` from a `tokio::net::UdpSocket`
    pub fn new(socket: tokio::net::UdpSocket, mtu: Option<usize>) -> Self {
        Self { socket, mtu }
    }

    /// Set MTU
    pub fn set_mtu(&mut self, mtu: Option<usize>) {
        self.mtu = mtu;
    }

    /// Get MTU
    pub fn mtu(&self) -> Option<usize> {
        self.mtu
    }

    /// Wrapper of `UdpSocket::poll_send`
    pub fn poll_send(&self, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        // Check MTU
        if let Some(mtu) = self.mtu
            && buf.len() > mtu
        {
            return Err(make_mtu_error(buf.len(), mtu)).into();
        }

        self.socket.poll_send(cx, buf)
    }

    /// Wrapper of `UdpSocket::send`
    #[inline]
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        // Check MTU
        if let Some(mtu) = self.mtu
            && buf.len() > mtu
        {
            return Err(make_mtu_error(buf.len(), mtu));
        }

        self.socket.send(buf).await
    }

    /// Wrapper of `UdpSocket::poll_send_to`
    pub fn poll_send_to(&self, cx: &mut TaskContext<'_>, buf: &[u8], target: SocketAddr) -> Poll<io::Result<usize>> {
        // Check MTU
        if let Some(mtu) = self.mtu
            && buf.len() > mtu
        {
            return Err(make_mtu_error(buf.len(), mtu)).into();
        }

        self.socket.poll_send_to(cx, buf, target)
    }

    /// Wrapper of `UdpSocket::send_to`
    #[inline]
    pub async fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], target: A) -> io::Result<usize> {
        // Check MTU
        if let Some(mtu) = self.mtu
            && buf.len() > mtu
        {
            return Err(make_mtu_error(buf.len(), mtu));
        }

        self.socket.send_to(buf, target).await
    }

    /// Wrapper of `UdpSocket::poll_recv`
    #[inline]
    pub fn poll_recv(&self, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        ready!(self.socket.poll_recv(cx, buf))?;

        if let Some(mtu) = self.mtu
            && buf.filled().len() > mtu
        {
            return Err(make_mtu_error(buf.filled().len(), mtu)).into();
        }

        Ok(()).into()
    }

    /// Wrapper of `UdpSocket::recv`
    #[inline]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.socket.recv(buf).await?;

        if let Some(mtu) = self.mtu
            && n > mtu
        {
            return Err(make_mtu_error(n, mtu));
        }

        Ok(n)
    }

    /// Wrapper of `UdpSocket::poll_recv_from`
    #[inline]
    pub fn poll_recv_from(&self, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<SocketAddr>> {
        let addr = ready!(self.socket.poll_recv_from(cx, buf))?;

        if let Some(mtu) = self.mtu
            && buf.filled().len() > mtu
        {
            return Err(make_mtu_error(buf.filled().len(), mtu)).into();
        }

        Ok(addr).into()
    }

    /// Wrapper of `UdpSocket::recv_from`
    #[inline]
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, addr) = self.socket.recv_from(buf).await?;

        if let Some(mtu) = self.mtu
            && n > mtu
        {
            return Err(make_mtu_error(n, mtu));
        }

        Ok((n, addr))
    }
}

impl Deref for UdpSocket {
    type Target = tokio::net::UdpSocket;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl DerefMut for UdpSocket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

impl From<tokio::net::UdpSocket> for UdpSocket {
    fn from(socket: tokio::net::UdpSocket) -> Self {
        Self { socket, mtu: None }
    }
}

impl From<UdpSocket> for tokio::net::UdpSocket {
    fn from(s: UdpSocket) -> Self {
        s.socket
    }
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for UdpSocket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.socket.as_raw_fd()
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for UdpSocket {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsRawSocket for UdpSocket {
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        self.socket.as_raw_socket()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsSocket for UdpSocket {
    fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
        self.socket.as_socket()
    }
}
