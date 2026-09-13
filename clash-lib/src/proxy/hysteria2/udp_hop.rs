use std::{
    fmt::Debug,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU16, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller, udp::Transmit};

use crate::proxy::converters::hysteria2::PortGenerator;

/// A lock-free UDP socket wrapper that performs client-side port hopping.
///
/// Hysteria2 port hopping rotates the outbound destination port among the configured
/// hopping port range, while the server redirects that entire range onto its listen
/// port (via iptables DNAT).
///
/// Received packets will have their source port rewritten to the nominal `init_port`
/// so that Quinn sees a stable peer address across hops.
pub struct UdpHop {
    inner: Arc<dyn AsyncUdpSocket>,
    current_port: AtomicU16,
    last_hop_millis: AtomicU64,
    start_time: Instant,
    init_port: u16,
    port_range: PortGenerator,
    interval_millis: u64,
}

impl UdpHop {
    pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

    pub fn new_with_inner(
        inner: Arc<dyn AsyncUdpSocket>,
        port: u16,
        port_range: PortGenerator,
        interval: Option<Duration>,
    ) -> Self {
        let interval = interval.unwrap_or(Self::DEFAULT_INTERVAL);
        Self {
            inner,
            current_port: AtomicU16::new(0),
            last_hop_millis: AtomicU64::new(0),
            start_time: Instant::now(),
            init_port: port,
            port_range,
            interval_millis: interval.as_millis().max(1) as u64,
        }
    }

    #[allow(dead_code)]
    pub fn new(
        socket: std::net::UdpSocket,
        port: u16,
        port_range: PortGenerator,
        interval: Option<Duration>,
    ) -> io::Result<Self> {
        let inner = TokioRuntime.wrap_udp_socket(socket)?;
        Ok(Self::new_with_inner(inner, port, port_range, interval))
    }

    /// Obtains the current hopping port in a lock-free manner.
    ///
    /// If the interval has elapsed (or this is the initial hop), the calling thread
    /// attempts to atomically claim the hop via CAS on `last_hop_millis` and selects
    /// a new port.
    fn get_or_hop_port(&self) -> u16 {
        let now = self.start_time.elapsed().as_millis() as u64;
        let last = self.last_hop_millis.load(Ordering::Acquire);
        let cur = self.current_port.load(Ordering::Acquire);

        // Fast path: port initialized and within hop interval
        if cur != 0 && now.saturating_sub(last) < self.interval_millis {
            return cur;
        }

        // Slow path: try to claim hop update
        if self
            .last_hop_millis
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let current_opt = if cur != 0 { Some(cur) } else { None };
            let next = self.port_range.get_next_avoiding(current_opt);
            self.current_port.store(next, Ordering::Release);
            next
        } else {
            // Another thread already updated the timestamp or is updating
            let updated = self.current_port.load(Ordering::Acquire);
            if updated != 0 {
                updated
            } else {
                self.port_range.get()
            }
        }
    }
}

impl Debug for UdpHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpHop")
            .field("init_port", &self.init_port)
            .field("interval_millis", &self.interval_millis)
            .field("current_port", &self.current_port.load(Ordering::Relaxed))
            .finish()
    }
}

impl AsyncUdpSocket for UdpHop {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let port = self.get_or_hop_port();

        let mut transmit = transmit.clone();
        transmit.destination.set_port(port);

        self.inner.try_send(&transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(count)) => {
                for m in &mut meta[..count] {
                    m.addr.set_port(self.init_port);
                }
                Poll::Ready(Ok(count))
            }
            res => res,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lock_free_hop_first_hop_and_interval() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut port_gen = PortGenerator::new(443);
        port_gen = port_gen.parse_ports_str("20000-20003").unwrap();

        let hop = UdpHop::new(socket, 443, port_gen, Some(Duration::from_millis(50))).unwrap();

        // 1. First call hops immediately to the hopping range
        let port1 = hop.get_or_hop_port();
        assert!(port1 >= 20000 && port1 <= 20003);

        // 2. Before interval expires, destination port remains identical
        let port2 = hop.get_or_hop_port();
        assert_eq!(port1, port2);

        // 3. After interval expires, hops to a different port
        tokio::time::sleep(Duration::from_millis(60)).await;
        let port3 = hop.get_or_hop_port();
        assert!(port3 >= 20000 && port3 <= 20003);
        assert_ne!(port1, port3);
    }

    #[tokio::test]
    async fn test_udp_hop_socket_send_and_recv() {
        let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

        let mut port_gen = PortGenerator::new(server_addr.port());
        // Configure hopping port matching server port
        port_gen = port_gen.parse_ports_str(&server_addr.port().to_string()).unwrap();

        let hop = Arc::new(UdpHop::new(client_socket, server_addr.port(), port_gen, None).unwrap());

        let data = b"hello hy2 hopping";
        let transmit = Transmit {
            destination: server_addr,
            ecn: None,
            contents: data,
            segment_size: None,
            src_ip: None,
        };

        let mut poller = hop.clone().create_io_poller();
        std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();

        hop.try_send(&transmit).unwrap();

        let mut recv_buf = [0u8; 64];
        let (len, client_addr) = server_socket.recv_from(&mut recv_buf).await.unwrap();
        assert_eq!(&recv_buf[..len], data);

        // Echo response back
        let reply = b"pong";
        server_socket.send_to(reply, client_addr).await.unwrap();

        // Recv on hop
        let mut buf = [0u8; 64];
        let mut meta = [quinn::udp::RecvMeta {
            addr: SocketAddr::new([127, 0, 0, 1].into(), 0),
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }];

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            std::future::poll_fn(|cx| {
                let mut io_slice = [io::IoSliceMut::new(&mut buf)];
                match hop.poll_recv(cx, &mut io_slice, &mut meta) {
                    Poll::Ready(Ok(count)) => Poll::Ready(Ok(count)),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await
        })
        .await;

        assert!(result.is_ok(), "timed out waiting for packet");
        let count = result.unwrap().unwrap();
        assert_eq!(count, 1);
        assert_eq!(meta[0].addr.port(), server_addr.port());
        assert_eq!(&buf[..meta[0].len], reply);
    }

    #[tokio::test]
    async fn test_udp_hop_with_salamander_obfs() {
        use crate::proxy::hysteria2::salamander::Salamander;

        let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

        let mut port_gen = PortGenerator::new(server_addr.port());
        port_gen = port_gen.parse_ports_str(&server_addr.port().to_string()).unwrap();

        let key = b"my-secret-password".to_vec();

        // Layering: client_socket -> UdpHop -> Salamander
        let hop = Arc::new(UdpHop::new(client_socket, server_addr.port(), port_gen, None).unwrap());
        let obfs = Arc::new(Salamander::new_with_inner(hop, key.clone()));

        // Also wrap server side with Salamander to receive & decrypt
        let server_std = server_socket.into_std().unwrap();
        let server_obfs = Arc::new(Salamander::new(server_std, key).unwrap());

        let data = b"hello layered hop and obfs";
        let transmit = Transmit {
            destination: server_addr,
            ecn: None,
            contents: data,
            segment_size: None,
            src_ip: None,
        };

        let mut poller = obfs.clone().create_io_poller();
        std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();

        obfs.try_send(&transmit).unwrap();

        // Recv on server obfs
        let mut server_buf = [0u8; 128];
        let mut server_meta = [quinn::udp::RecvMeta {
            addr: SocketAddr::new([127, 0, 0, 1].into(), 0),
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }];

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            std::future::poll_fn(|cx| {
                let mut io_slice = [io::IoSliceMut::new(&mut server_buf)];
                match server_obfs.poll_recv(cx, &mut io_slice, &mut server_meta) {
                    Poll::Ready(Ok(count)) => Poll::Ready(Ok(count)),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await
        })
        .await;

        assert!(result.is_ok(), "server timed out waiting for packet");
        let count = result.unwrap().unwrap();
        assert_eq!(count, 1);
        assert_eq!(&server_buf[..server_meta[0].len], data);
    }
}
