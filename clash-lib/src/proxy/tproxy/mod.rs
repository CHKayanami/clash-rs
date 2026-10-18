use crate::runner::ListenerReady;
use crate::proxy::AnyStream;
use super::{
    datagram::{ChannelDatagram, UdpPacket},
    inbound::InboundHandlerTrait,
};
use crate::{
    app::dispatcher::Dispatcher,
    proxy::utils::{ToCanonical, apply_tcp_options, try_create_dualstack_socket},
    session::{Network, Session, Type},
};

use async_trait::async_trait;
use clash_common::udp::{BatchReceiver, enable_gro, MAX_BATCH};
use crate::proxy::utils::udp_batch::send_replies;
use std::{
    io,
    net::SocketAddr,
    os::fd::AsRawFd,
    sync::Arc,
    time::Duration,
};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, trace, warn};

pub struct TproxyInbound {
    addr: SocketAddr,
    allow_lan: bool,
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
        Self {
            addr,
            allow_lan,
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

    async fn listen_tcp(&self, ready: ListenerReady) -> std::io::Result<()> {
        warn_allow_lan_unenforced(self.addr, self.allow_lan);

        let (socket, dualstack) =
            try_create_dualstack_socket(self.addr, socket2::Type::STREAM)?;
        if dualstack || self.addr.is_ipv4() {
            // set ipv4 transparent
            socket.set_ip_transparent_v4(true)?;
        }
        if self.addr.is_ipv6() {
            set_ip_transparent_v6(&socket)?;
        }
        socket.set_nonblocking(true)?;
        // For fast restart, avoid Address In Use while old sockets linger in
        // TIME_WAIT — the shared `try_create_dualstack_tcplistener` does this
        // too, but tproxy builds its listener by hand.
        socket.set_reuse_address(true)?;
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

            if let Err(e) = apply_tcp_options(&socket) {
                warn!("tproxy failed to apply tcp options for {src_addr}: {e}");
                continue;
            }

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

    async fn listen_udp(&self, ready: ListenerReady) -> std::io::Result<()> {
        warn_allow_lan_unenforced(self.addr, self.allow_lan);

        let (socket, dual_stack) =
            try_create_dualstack_socket(self.addr, socket2::Type::DGRAM)?;
        if dual_stack || self.addr.is_ipv4() {
            // set ipv4 transparent
            // IPv6 doesn't require this
            socket.set_ip_transparent_v4(true)?;
        }
        if self.addr.is_ipv6() {
            // This might not be necessary
            set_ip_transparent_v6(&socket)?;
        }
        socket.set_reuse_port(true)?;
        socket.set_nonblocking(true)?;
        socket.set_broadcast(true)?;
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
            Arc::new(listener),
            self.dispatcher.clone(),
        )
        .await
    }
}

/// Maximum number of cached `IP_TRANSPARENT` UDP sockets.
///
/// TPROXY source addresses are typically LAN device IPs with varying ports;
/// 1024 entries comfortably cover active sessions without excessive fd consumption.
const TRANSPARENT_SOCKET_CACHE_CAPACITY: u64 = 1024;

/// Capacity for UDP packet dispatch channel between TPROXY listener and dispatcher.
const UDP_CHANNEL_CAPACITY: usize = 1024;

/// How long an idle cached socket stays alive before eviction.
const TRANSPARENT_SOCKET_TTL: Duration = Duration::from_secs(60);

/// Creates and returns a `moka` cache of `IP_TRANSPARENT` UDP sockets keyed by
/// the spoofed source address.  Each socket is a regular `SOCK_DGRAM` socket
/// that has been `bind()`-ed to the source address with `IP_TRANSPARENT` set,
/// so that the kernel builds all headers, computes checksums, and handles
/// Path-MTU / fragmentation for us.
fn new_transparent_socket_cache() -> moka::sync::Cache<SocketAddr, Arc<tokio::net::UdpSocket>> {
    moka::sync::Cache::builder()
        .max_capacity(TRANSPARENT_SOCKET_CACHE_CAPACITY)
        .time_to_idle(TRANSPARENT_SOCKET_TTL)
        .build()
}

/// Obtain (or create) a cached `IP_TRANSPARENT` UDP socket bound to `src`.
fn get_or_create_transparent_socket(
    cache: &moka::sync::Cache<SocketAddr, Arc<tokio::net::UdpSocket>>,
    src: SocketAddr,
    fw_mark: Option<u32>,
) -> io::Result<Arc<tokio::net::UdpSocket>> {
    if let Some(sock) = cache.get(&src) {
        return Ok(sock);
    }

    let domain = if src.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket =
        socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;

    // Allow binding to a non-local address.
    if src.is_ipv4() {
        socket.set_ip_transparent_v4(true)?;
    } else {
        set_ip_transparent_v6(&socket)?;
    }

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;

    if let Some(mark) = fw_mark {
        socket.set_mark(mark)?;
    }

    socket.bind(&src.into())?;

    let udp_socket = Arc::new(tokio::net::UdpSocket::from_std(socket.into())?);
    cache.insert(src, udp_socket.clone());
    Ok(udp_socket)
}

/// How many consecutive receive failures to tolerate before concluding the
/// socket is unusable. Guards against a hot loop on a permanent error while
/// still riding out the transient ones (`ECONNREFUSED` from an inbound ICMP
/// port-unreachable, `EINTR`, and friends) that used to kill the listener.
const MAX_CONSECUTIVE_RECV_ERRORS: usize = 32;

async fn handle_inbound_datagram(
    fw_mark: Option<u32>,
    socket: Arc<UdpSocket>,
    dispatcher: Arc<Dispatcher>,
) -> std::io::Result<()> {
    // dispatcher <-> tproxy communications
    let (l_tx, l_rx) = tokio::sync::mpsc::channel(UDP_CHANNEL_CAPACITY);

    // forward packets from tproxy to dispatcher
    let (d_tx, d_rx) = tokio::sync::mpsc::channel(UDP_CHANNEL_CAPACITY);

    // for dispatcher - the dispatcher would receive packets from this channel,
    // which is from the stack and send back packets to this channel, which is
    // to the tproxy
    let udp_stream = ChannelDatagram::new(l_tx, d_rx);

    let sess = Session {
        network: Network::Udp,
        typ: Type::Tproxy,
        so_mark: fw_mark,
        ..Default::default()
    };

    let closer: tokio::sync::oneshot::Sender<u8> = dispatcher
        .dispatch_datagram(sess, Box::new(udp_stream))
        .await;

    // dispatcher -> tproxy
    let fut1 = handle_packet_from_dispatcher(l_rx, fw_mark);

    // tproxy -> dispatcher
    let fut2 = async move {
        let mut receiver = BatchReceiver::default();
        let mut packets = Vec::with_capacity(MAX_BATCH);
        let mut consecutive_errors = 0usize;
        let mut dropped = 0u64;

        loop {
            packets.clear();
            match receiver.recv_batch(&socket, &mut packets, MAX_BATCH).await {
                Ok(_) => consecutive_errors = 0,
                Err(e) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                        warn!("tproxy udp recv failed {} times in a row: {}", consecutive_errors, e);
                        break;
                    }
                    debug!("tproxy udp recv error (continuing): {}", e);
                    continue;
                }
            }
            for (data, source, destination) in packets.drain(..) {
                if destination.ip().is_multicast()
                    || matches!(destination.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast()) {
                    continue;
                }
                let pkt = UdpPacket {
                    data, src_addr: source.into(), dst_addr: destination.into(), inbound_user: None,
                };

                // Every client shares this channel, so awaiting a full one
                // would stall reads for all of them and overflow the kernel
                // buffer anyway. Drop instead — UDP callers already tolerate
                // loss — and keep serving the other flows.
                match d_tx.try_send(pkt) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        dropped += 1;
                        if dropped.is_power_of_two() {
                            warn!(
                                "tproxy udp dispatch queue full, dropped {} \
                                 packet(s) so far",
                                dropped
                            );
                        }
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        warn!("tproxy udp dispatch channel closed");
                        return;
                    }
                }
            }
        }
        warn!("tproxy udp listening ended");
    };

    tokio::select! {
    _ = fut1 => {
        warn!("tproxy outbound (dispatcher -> tproxy) stream ended first");
    }
    _ = fut2 => {
        warn!("tproxy inbound (tproxy -> dispatcher) stream ended first");
    }
    }

    closer.send(0).ok();

    Ok(())
}

fn set_ip_recv_orig_dstaddr(
    level: libc::c_int,
    socket: &socket2::Socket,
) -> io::Result<()> {
    let opt = match level {
        libc::IPPROTO_IP => libc::IP_RECVORIGDSTADDR,
        libc::IPPROTO_IPV6 => libc::IPV6_RECVORIGDSTADDR,
        _ => unreachable!("invalid sockopt level {}", level),
    };

    let enable: libc::c_int = 1;
    set_socket_option(socket, level, opt, enable)
}

async fn handle_packet_from_dispatcher(
    mut l_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    fw_mark: Option<u32>,
) {
    let cache = new_transparent_socket_cache();
    let mut reply_batch = Vec::with_capacity(MAX_BATCH);
    while l_rx.recv_many(&mut reply_batch, MAX_BATCH).await > 0 {
        send_replies(&reply_batch, |source| {
            get_or_create_transparent_socket(&cache, source, fw_mark)
        }).await;
        reply_batch.clear();
    }

    // reaching here means the dispatcher hung up; the outer `select!` tears the
    // rest of the tproxy session down
    tracing::info!(
        "dispatcher channel to tproxy is closed, exiting outbound loop gracefully"
    );
}

// socket2 doesn't provide set_ip_transparent_v6
// So we must implement it ourselves
fn set_ip_transparent_v6(socket: &socket2::Socket) -> io::Result<()> {
    let (opt, level) = (libc::IPV6_TRANSPARENT, libc::IPPROTO_IPV6);

    let enable: libc::c_int = 1;
    set_socket_option(socket, level, opt, enable)
}

fn set_socket_option(
    socket: &socket2::Socket,
    level: i32,
    opt: i32,
    val: i32,
) -> io::Result<()> {
    let fd = socket.as_raw_fd();

    let enable: libc::c_int = val;

    unsafe {
        let ret = libc::setsockopt(
            fd,
            level,
            opt,
            &enable as *const _ as *const _,
            std::mem::size_of_val(&enable) as libc::socklen_t,
        );

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}
