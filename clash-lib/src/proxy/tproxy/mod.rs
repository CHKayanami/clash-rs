use crate::runner::ListenerReady;
use crate::proxy::AnyStream;
use super::{
    datagram::UdpPacket,
    inbound::InboundHandlerTrait,
};
use crate::{
    app::dispatcher::Dispatcher,
    proxy::utils::{
        ToCanonical, apply_tcp_socket_options, try_create_dualstack_socket,
    },
    session::{Network, Session, Type},
};

use async_trait::async_trait;
use clash_common::udp::{BatchReceiver, MAX_BATCH, enable_gro};
use socket2::{Domain, Protocol, Socket, Type as SocketType};
use std::{
    io,
    mem::size_of_val,
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
    sync::Arc,
};
use tokio::{net::{TcpListener, UdpSocket}, task::consume_budget};
use tracing::{debug, trace, warn};

pub struct TproxyInbound {
    addr: SocketAddr,
    udp: bool,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
}

impl Drop for TproxyInbound {
    fn drop(&mut self) {
        debug!("Tproxy inbound listener on {} stopped", self.addr);
    }
}

/// TPROXY receives traffic that was redirected in the mangle PREROUTING chain,
/// which is by definition traffic from *other* hosts — a locally originated
/// connection never reaches it. Filtering by source the way the http/socks
/// inbounds do would therefore reject essentially everything, and the
/// `IP_TRANSPARENT` socket's local address is the pre-redirect destination
/// rather than our own, so that comparison would not even be meaningful here.
///
/// `allow-lan` is consequently not enforced for tproxy. Say so out loud rather
/// than silently discarding the setting.
fn warn_allow_lan_unenforced(addr: SocketAddr, allow_lan: bool) {
    if !allow_lan {
        warn!(
            "tproxy inbound {} does not enforce allow-lan: TPROXY only receives \
             traffic from other hosts, so filtering by source would reject \
             everything. Restrict access with firewall rules instead.",
            addr
        );
    }
}

impl TproxyInbound {
    pub fn new(
        addr: SocketAddr,
        allow_lan: bool,
        udp: bool,
        dispatcher: Arc<Dispatcher>,
        fw_mark: Option<u32>,
    ) -> Self {
        warn_allow_lan_unenforced(addr, allow_lan);
        Self {
            addr,
            udp,
            dispatcher,
            fw_mark,
        }
    }
}

#[async_trait]
impl InboundHandlerTrait for TproxyInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        self.udp
    }

    async fn listen_tcp(&self, ready: ListenerReady) -> io::Result<()> {
        let (socket, dualstack) =
            try_create_dualstack_socket(self.addr, SocketType::STREAM)?;
        if dualstack || self.addr.is_ipv4() {
            // set ipv4 transparent
            socket.set_ip_transparent_v4(true)?;
        }
        if self.addr.is_ipv6() {
            socket.set_ip_transparent_v6(true)?;
        }
        socket.set_nonblocking(true)?;
        // For fast restart, avoid Address In Use while old sockets linger in
        // TIME_WAIT — the shared `try_create_dualstack_tcplistener` does this
        // too, but tproxy builds its listener by hand.
        socket.set_reuse_address(true)?;
        // Set keepalive & TCP_NODELAY on the listener so accepted sockets inherit them.
        apply_tcp_socket_options(&socket)?;
        socket.bind(&self.addr.into())?;
        socket.listen(1024)?;

        let listener = TcpListener::from_std(socket.into())?;

        ready.notify();

        loop {
            let (socket, peer_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("tproxy inbound accept error: {e}");
                    continue;
                }
            };
            let src_addr = peer_addr.to_canonical();

            // local_addr is getsockname
            let orig_dst = match socket.local_addr() {
                Ok(addr) => addr.to_canonical(),
                Err(e) => {
                    warn!("tproxy failed to get local address for {src_addr}: {e}");
                    continue;
                }
            };

            let sess = Session {
                network: Network::Tcp,
                typ: Type::Tproxy,
                source: src_addr,
                destination: orig_dst.into(),
                so_mark: self.fw_mark,
                ..Default::default()
            };

            trace!("tproxy new tcp conn {}", sess);

            let dispatcher = self.dispatcher.clone();
            tokio::spawn(async move {
                dispatcher
                    .dispatch_stream(sess, AnyStream::Tcp(socket))
                    .await;
            });
        }
    }

    async fn listen_udp(&self, ready: ListenerReady) -> io::Result<()> {
        let (socket, dual_stack) =
            try_create_dualstack_socket(self.addr, SocketType::DGRAM)?;
        if dual_stack || self.addr.is_ipv4() {
            // set ipv4 transparent
            // IPv6 doesn't require this
            socket.set_ip_transparent_v4(true)?;
        }
        if self.addr.is_ipv6() {
            // This might not be necessary
            socket.set_ip_transparent_v6(true)?;
        }
        socket.set_reuse_port(true)?;
        socket.set_nonblocking(true)?;
        socket.set_broadcast(true)?;
        if let Err(error) = socket.set_recv_buffer_size(UDP_RECV_BUFFER_SIZE) {
            debug!(
                "TProxy UDP failed to set SO_RCVBUF to {UDP_RECV_BUFFER_SIZE}: {error}"
            );
        }
        set_ip_recv_orig_dstaddr(
            if self.addr.is_ipv4() {
                libc::IPPROTO_IP
            } else {
                libc::IPPROTO_IPV6
            },
            &socket,
        )?;
        if dual_stack {
            set_ip_recv_orig_dstaddr(libc::IPPROTO_IP, &socket)?;
        }
        socket.bind(&self.addr.into())?;

        let listener = UdpSocket::from_std(socket.into())?;
        if let Err(error) = enable_gro(&listener) {
            debug!("TProxy UDP GRO unavailable; using ordinary datagrams: {error}");
        }

        ready.notify();

        handle_inbound_datagram(
            self.fw_mark,
            listener,
            self.dispatcher.clone(),
        )
        .await
    }
}

/// Target receive socket buffer size for high-throughput UDP/QUIC traffic.
const UDP_RECV_BUFFER_SIZE: usize = 8 << 20;

/// Pre-allocated batch vector capacity accommodating GRO-expanded datagrams.
const UDP_RECV_VEC_CAPACITY: usize = MAX_BATCH * 4;

/// Create an `IP_TRANSPARENT` UDP socket bound to `src` so the kernel builds
/// headers, computes checksums, and handles Path-MTU / fragmentation.
fn create_transparent_reply_socket(
    src: SocketAddr,
    fw_mark: Option<u32>,
) -> io::Result<UdpSocket> {
    let src = src.to_canonical();
    let domain = if src.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, SocketType::DGRAM, Some(Protocol::UDP))?;

    // Allow binding to a non-local address.
    if src.is_ipv4() {
        socket.set_ip_transparent_v4(true)?;
    } else {
        socket.set_ip_transparent_v6(true)?;
    }

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;

    if let Some(mark) = fw_mark {
        socket.set_mark(mark)?;
    }

    socket.bind(&src.into())?;

    UdpSocket::from_std(socket.into())
}

/// How many consecutive receive failures to tolerate before concluding the
/// socket is unusable. Guards against a hot loop on a permanent error while
/// still riding out the transient ones (`ECONNREFUSED` from an inbound ICMP
/// port-unreachable, `EINTR`, and friends) that used to kill the listener.
const MAX_CONSECUTIVE_RECV_ERRORS: usize = 32;

async fn handle_inbound_datagram(
    fw_mark: Option<u32>,
    socket: UdpSocket,
    dispatcher: Arc<Dispatcher>,
) -> io::Result<()> {
    let sess = Session {
        network: Network::Udp,
        typ: Type::Tproxy,
        so_mark: fw_mark,
        ..Default::default()
    };

    dispatcher.dispatch_transparent_udp(sess, move |ingress| async move {
        let mut receiver = BatchReceiver::default();
        let mut packets = Vec::with_capacity(UDP_RECV_VEC_CAPACITY);
        let mut consecutive_errors = 0usize;

        loop {
            match receiver.recv_batch(&socket, &mut packets, MAX_BATCH).await {
                Ok(_) => consecutive_errors = 0,
                Err(e) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                        warn!(
                            "tproxy udp recv failed {} times in a row: {}",
                            consecutive_errors, e
                        );
                        break;
                    }
                    debug!("tproxy udp recv error (continuing): {}", e);
                    continue;
                }
            }
            let incoming = packets.drain(..)
                .filter(|(_, _, destination)| {
                    !destination.ip().is_multicast()
                        && !matches!(destination.ip(), IpAddr::V4(ip) if ip.is_broadcast())
                })
                .map(|(data, source, destination)| {
                    UdpPacket::new(data, source.into(), destination.into())
                });
            if !ingress.send_batch(incoming) {
                warn!("tproxy udp route queue closed");
                break;
            }
            consume_budget().await;
        }
    }, move |source| create_transparent_reply_socket(source, fw_mark)).await;

    // Inbound TCP and UDP listeners share a single `try_join_all` inside a
    // critical task; return `Ok(())` so a UDP-only failure stops only UDP
    // without cancelling TCP or triggering global shutdown.
    Ok(())
}

fn set_ip_recv_orig_dstaddr(
    level: libc::c_int,
    socket: &Socket,
) -> io::Result<()> {
    let opt = match level {
        libc::IPPROTO_IP => libc::IP_RECVORIGDSTADDR,
        libc::IPPROTO_IPV6 => libc::IPV6_RECVORIGDSTADDR,
        _ => unreachable!("invalid sockopt level {}", level),
    };

    let enable: libc::c_int = 1;
    set_socket_option(socket, level, opt, enable)
}

fn set_socket_option(
    socket: &Socket,
    level: i32,
    opt: i32,
    val: i32,
) -> io::Result<()> {
    let fd = socket.as_raw_fd();

    let enable: libc::c_int = val;

    // SAFETY: `fd` belongs to a live `Socket`, and `enable` is a valid
    // initialized `libc::c_int` matching the passed option length.
    unsafe {
        let ret = libc::setsockopt(
            fd,
            level,
            opt,
            &enable as *const _ as *const _,
            size_of_val(&enable) as libc::socklen_t,
        );

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}
