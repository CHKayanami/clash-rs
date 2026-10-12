use std::{collections::VecDeque, io, net::{SocketAddr, SocketAddrV6}, pin::Pin,
    task::{Context, Poll}};
use futures::{Sink, Stream, ready};
use tokio::net::UdpSocket;
use tracing::{trace, warn};
use crate::{proxy::datagram::UdpPacket, session::SocksAddr};

const MAX_CONSECUTIVE_RECV_ERRORS: usize = 32;
const MAX_BATCH_RECV_PACKETS: usize = 16;

/// Physical UDP I/O. No resolver or logical-address state is retained here.
pub struct NativeDatagram {
    inner: UdpSocket,
    local_is_ipv6: bool,
    packet: Option<UdpPacket>,
    consecutive_recv_errors: usize,
    recv_queue: VecDeque<UdpPacket>,
}

impl NativeDatagram {
    pub fn new(inner: UdpSocket) -> io::Result<Self> {
        let local_is_ipv6 = inner.local_addr()?.is_ipv6();
        Ok(Self { inner, local_is_ipv6, packet: None, consecutive_recv_errors: 0,
            recv_queue: VecDeque::with_capacity(MAX_BATCH_RECV_PACKETS) })
    }

    pub(super) fn local_is_ipv6(&self) -> bool { self.local_is_ipv6 }

    #[cfg(test)]
    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> { self.inner.local_addr() }

    // The domain wrapper applies its mapping when the batch is received,
    // preserving the source of already-buffered packets across later sends.
    pub(super) fn poll_recv_with(&mut self, cx: &mut Context<'_>,
        mut source: impl FnMut(SocketAddr) -> SocksAddr,
    ) -> Poll<Option<UdpPacket>> {
        if let Some(packet) = self.recv_queue.pop_front() { return Poll::Ready(Some(packet)); }
        loop {
            let result = ready!(self.inner.poll_recv_ready(cx)).and_then(|()| {
                super::recv::recv_batch(&self.inner, MAX_BATCH_RECV_PACKETS, |data, peer| {
                    let mut peer = peer;
                    peer.set_ip(peer.ip().to_canonical());
                    self.recv_queue.push_back(UdpPacket { data, src_addr: source(peer),
                        dst_addr: SocksAddr::any_ipv4(), ..Default::default() });
                })
            });
            match result {
                Ok(_) => {
                    self.consecutive_recv_errors = 0;
                    if let Some(packet) = self.recv_queue.pop_front() { return Poll::Ready(Some(packet)); }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => {
                    self.consecutive_recv_errors += 1;
                    if self.consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                        warn!("Direct UDP socket reached receive error limit: {err}");
                        return Poll::Ready(None);
                    }
                    trace!("Direct UDP transient receive error: {err}");
                }
            }
        }
    }
}

impl Sink<UdpPacket> for NativeDatagram {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, packet: UdpPacket) -> io::Result<()> {
        if !matches!(packet.dst_addr, SocksAddr::Ip(_)) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "physical UDP target must be an IP address"));
        }
        self.packet = Some(packet);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(packet) = self.packet.as_ref() else { return Poll::Ready(Ok(())); };
        let SocksAddr::Ip(mut destination) = packet.dst_addr else { unreachable!("validated by start_send"); };
        if self.local_is_ipv6 && let SocketAddr::V4(address) = destination {
            destination = SocketAddr::V6(SocketAddrV6::new(address.ip().to_ipv6_mapped(), address.port(), 0, 0));
        }
        let length = packet.data.len();
        let result = ready!(self.inner.poll_send_to(cx, &packet.data, destination));
        self.packet = None;
        Poll::Ready(result.and_then(|sent| {
            if sent == length { Ok(()) }
            else { Err(io::Error::new(io::ErrorKind::WriteZero, "partial UDP datagram send")) }
        }))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl Stream for NativeDatagram {
    type Item = UdpPacket;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>> {
        self.poll_recv_with(cx, SocksAddr::Ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures::{SinkExt, StreamExt};
    use crate::proxy::utils::new_dual_stack_udp_socket;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn native_udp_rejects_domains_and_recovers_after_send_errors() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut datagram = NativeDatagram::new(new_dual_stack_udp_socket(None,
            #[cfg(target_os = "linux")] None).unwrap()).unwrap();
        let domain = SocksAddr::try_from(("example.test".to_owned(), 80)).unwrap();
        let err = datagram.send(UdpPacket::new(Bytes::from_static(b"a"), SocksAddr::any_ipv4(), domain)).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let target: SocksAddr = server.local_addr().unwrap().into();
        assert!(datagram.send(UdpPacket::new(Bytes::from(vec![0; 70000]), SocksAddr::any_ipv4(), target.clone())).await.is_err());
        datagram.send(UdpPacket::new(Bytes::from_static(b"valid"), SocksAddr::any_ipv4(), target)).await.unwrap();
        let mut buf = [0; 32];
        let (length, source) = timeout(Duration::from_secs(2), server.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..length], b"valid");
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(b"unknown", source).await.unwrap();
        let reply = timeout(Duration::from_secs(2), datagram.next()).await.unwrap().unwrap();
        assert_eq!(reply.src_addr, SocksAddr::Ip(peer.local_addr().unwrap()));
        assert_eq!(reply.data.as_ref(), b"unknown");
    }

    #[tokio::test]
    async fn native_udp_preserves_ipv6_peers_and_empty_packets() {
        let server = UdpSocket::bind("[::1]:0").await.unwrap();
        let socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let mut datagram = NativeDatagram::new(socket).unwrap();
        let target: SocksAddr = server.local_addr().unwrap().into();
        datagram.send(UdpPacket::new(Bytes::new(), SocksAddr::any_ipv4(), target.clone())).await.unwrap();
        let mut buf = [0; 32];
        let (length, source) = timeout(Duration::from_secs(2), server.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(length, 0);
        server.send_to(b"", source).await.unwrap();
        let reply = timeout(Duration::from_secs(2), datagram.next()).await.unwrap().unwrap();
        assert_eq!(reply.src_addr, target);
        assert!(reply.data.is_empty());
    }
}
