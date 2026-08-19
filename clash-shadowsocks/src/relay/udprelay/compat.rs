use std::{
    io,
    net::SocketAddr,
    ops::Deref,
    task::{Context, Poll},
};

use tokio::io::ReadBuf;

use crate::net::UdpSocket;

/// A socket I/O object that can transport datagram
pub trait DatagramSocket {
    /// Local binded address
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// A socket I/O object that can receive datagram
pub trait DatagramReceive {
    /// `recv` data into `buf`
    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>>;
    /// `recv` data into `buf` with source address
    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<SocketAddr>>;
}

/// A socket I/O object that can send datagram
pub trait DatagramSend {
    /// `send` data with `buf` to `target`, returning the sent bytes
    fn poll_send_to(&self, cx: &mut Context<'_>, buf: &[u8], target: SocketAddr) -> Poll<io::Result<usize>>;
}

impl DatagramSocket for UdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.deref().local_addr()
    }
}

impl DatagramReceive for UdpSocket {
    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Self::poll_recv(self, cx, buf)
    }

    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<SocketAddr>> {
        Self::poll_recv_from(self, cx, buf)
    }
}

impl DatagramSend for UdpSocket {
    fn poll_send_to(&self, cx: &mut Context<'_>, buf: &[u8], target: SocketAddr) -> Poll<io::Result<usize>> {
        Self::poll_send_to(self, cx, buf, target)
    }
}
