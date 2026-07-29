use super::{
    datagram::{ChannelDatagram, UdpPacket},
    inbound::InboundHandlerTrait,
};
use crate::{
    app::dispatcher::Dispatcher,
    common::errors::new_io_error,
    proxy::utils::{ToCanonical, apply_tcp_options, try_create_dualstack_socket},
    session::{Network, Session, Type},
};

use async_trait::async_trait;
use etherparse::PacketBuilder;
use futures::future;
use std::{
    io,
    net::{SocketAddr, SocketAddrV6},
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    task::Poll,
};
use tokio::net::TcpListener;
use tracing::{debug, trace, warn};

pub struct TproxyInbound {
    addr: SocketAddr,
    allow_lan: bool,
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
        dispatcher: Arc<Dispatcher>,
        fw_mark: Option<u32>,
    ) -> Self {
        Self {
            addr,
            allow_lan,
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
        true
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
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
                dispatcher.dispatch_stream(sess, Box::new(socket)).await;
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
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

        let listener = unix_udp_sock::UdpSocket::from_std(socket.into())?;

        handle_inbound_datagram(
            self.fw_mark,
            Arc::new(listener),
            self.dispatcher.clone(),
        )
        .await
    }
}

fn new_unbound_socket(
    family_hint: SocketAddr,
    fw_mark: Option<u32>,
) -> io::Result<socket2::Socket> {
    let socket = if family_hint.is_ipv4() {
        socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(libc::IPPROTO_RAW.into()),
        )?
    } else {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::RAW,
            Some(libc::IPPROTO_RAW.into()),
        )?;
        // Linux enables IP_HDRINCL implicitly for AF_INET/IPPROTO_RAW, but the
        // v6 equivalent must be asked for. Without it the kernel builds its own
        // IPv6 header and treats the one we hand-build in `sendto_with_src` /
        // `build_v6_fragments` as payload, producing packets no client accepts
        // — and the spoofed source address would be ignored, which is the whole
        // point of this socket.
        socket.set_header_included_v6(true)?;
        socket
    };
    socket.set_nonblocking(true)?;
    if let Some(so_mark) = fw_mark {
        socket.set_mark(so_mark)?;
    }
    Ok(socket)
}
static IPV6_FRAG_ID: AtomicU32 = AtomicU32::new(1);

/// Every IPv6 path is guaranteed to carry at least this much without
/// fragmentation (RFC 8200 §5). We have no PMTU information for the spoofed
/// source we are sending as, so this is the only size that is always safe.
const IPV6_MIN_MTU: usize = 1280;

async fn raw_sendto(
    afd: &tokio::io::unix::AsyncFd<socket2::Socket>,
    packet: &[u8],
    dst: SocketAddr,
) -> io::Result<()> {
    future::poll_fn(|cx: &mut futures::task::Context<'_>| {
        let mut guard = futures::ready!(afd.poll_write_ready(cx))?;
        let addr = if dst.is_ipv6() {
            // Must set port to 0 for ipv6 raw socket to avoid EINVAL error
            // see https://stackoverflow.com/questions/31419727/how-to-send-modified-ipv6-packet-through-raw-socket
            // and https://nick-black.com/dankwiki/index.php/Packet_sockets
            let dst = SocketAddr::new(dst.ip(), 0);
            socket2::SockAddr::from(dst)
        } else {
            socket2::SockAddr::from(dst)
        };

        // `sendto` returns the number of bytes written, or -1 on error
        let sent = unsafe {
            libc::sendto(
                afd.as_raw_fd(),
                packet.as_ptr() as *const _,
                packet.len(),
                0,
                &addr as *const _ as *const _,
                addr.len(),
            )
        };
        if sent < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                guard.clear_ready();
                return Poll::Pending;
            }
            return Poll::Ready(Err(err));
        }
        if sent as usize != packet.len() {
            // A datagram socket should never write partially; if it does the
            // packet on the wire is truncated and silently corrupt.
            return Poll::Ready(Err(io::Error::other(format!(
                "raw sendto wrote {} of {} bytes",
                sent,
                packet.len()
            ))));
        }
        Poll::Ready(Ok(()))
    })
    .await
}

fn build_v6_fragments(
    fragmentable_part: &[u8],
    src: SocketAddrV6,
    dst: SocketAddrV6,
    id: u32,
) -> Vec<Vec<u8>> {
    // IPv6 Header = 40B, Fragment Header = 8B. Max payload per fragment =
    // 1280 - 48 = 1232B, which is divisible by 8 (1232 / 8 = 154) as the
    // fragment offset field requires.
    const MAX_FRAG_DATA_LEN: usize = IPV6_MIN_MTU - 48;

    let total_len = fragmentable_part.len();
    let mut offset_bytes = 0;
    let mut fragments = Vec::new();

    while offset_bytes < total_len {
        let chunk_len = std::cmp::min(MAX_FRAG_DATA_LEN, total_len - offset_bytes);
        let chunk = &fragmentable_part[offset_bytes..offset_bytes + chunk_len];

        let offset_units = (offset_bytes / 8) as u16;
        let is_last = offset_bytes + chunk_len == total_len;
        let m_flag = !is_last;

        let mut frag_packet = Vec::with_capacity(40 + 8 + chunk_len);

        // --- IPv6 Header (40 bytes) ---
        // Version 6, Traffic Class 0, Flow Label 0
        frag_packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        // Payload Length (Fragment Header 8B + chunk_len)
        let payload_len = (8 + chunk_len) as u16;
        frag_packet.extend_from_slice(&payload_len.to_be_bytes());
        // Next Header = 44 (IPv6 Fragment Header)
        frag_packet.push(libc::IPPROTO_FRAGMENT as u8);
        // Hop Limit = 64
        frag_packet.push(64);
        // Source IP
        frag_packet.extend_from_slice(&src.ip().octets());
        // Destination IP
        frag_packet.extend_from_slice(&dst.ip().octets());

        // --- IPv6 Fragment Header (8 bytes) ---
        // Next Header = 17 (UDP)
        frag_packet.push(libc::IPPROTO_UDP as u8);
        // Reserved
        frag_packet.push(0);
        // Fragment Offset (13 bits) | Res (2 bits) | M flag (1 bit)
        let frag_offset_and_m = (offset_units << 3) | (if m_flag { 1 } else { 0 });
        frag_packet.extend_from_slice(&frag_offset_and_m.to_be_bytes());
        // Identification (32 bits)
        frag_packet.extend_from_slice(&id.to_be_bytes());

        // --- Fragment Payload ---
        frag_packet.extend_from_slice(chunk);

        fragments.push(frag_packet);
        offset_bytes += chunk_len;
    }

    fragments
}

async fn send_v6_fragmented(
    afd: &tokio::io::unix::AsyncFd<socket2::Socket>,
    fragmentable_part: &[u8],
    src: SocketAddrV6,
    dst: SocketAddrV6,
) -> io::Result<()> {
    let id = IPV6_FRAG_ID.fetch_add(1, Ordering::Relaxed);
    let fragments = build_v6_fragments(fragmentable_part, src, dst, id);
    for frag in fragments {
        raw_sendto(afd, &frag, SocketAddr::V6(dst)).await?;
    }
    Ok(())
}

async fn sendto_with_src(
    afd: &tokio::io::unix::AsyncFd<socket2::Socket>,
    buf: &[u8],
    dst: SocketAddr,
    src: SocketAddr,
) -> io::Result<()> {
    let mut packet: Vec<u8>;
    let builder;
    match (src, dst) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            builder = PacketBuilder::ipv4(src.ip().octets(), dst.ip().octets(), 64)
                .udp(src.port(), dst.port());
            packet = Vec::<u8>::with_capacity(builder.size(buf.len()));
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            builder = PacketBuilder::ipv6(src.ip().octets(), dst.ip().octets(), 64)
                .udp(src.port(), dst.port());
            packet = Vec::<u8>::with_capacity(builder.size(buf.len()));
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source and destination address families do not match",
            ));
        }
    }
    builder
        .write(&mut packet, buf)
        .map_err(|x| new_io_error(format!("failed to build udp packet:{}", x)))?;

    // Fragment at the guaranteed-deliverable size rather than a guessed 1500:
    // anything above `IPV6_MIN_MTU` may be dropped by a router on the path, and
    // the fragments we build are sized for exactly this bound.
    if let (SocketAddr::V6(src_v6), SocketAddr::V6(dst_v6)) = (src, dst)
        && packet.len() > IPV6_MIN_MTU
    {
        // strip our IPv6 header — `build_v6_fragments` writes a fresh one per
        // fragment, and what follows is the fragmentable part
        return send_v6_fragmented(afd, &packet[40..], src_v6, dst_v6).await;
    }

    match raw_sendto(afd, &packet, dst).await {
        Ok(()) => Ok(()),
        Err(err) => {
            let is_emsgsize = err.raw_os_error() == Some(libc::EMSGSIZE);
            if dst.is_ipv6() && is_emsgsize {
                if let (SocketAddr::V6(src_v6), SocketAddr::V6(dst_v6)) = (src, dst)
                {
                    tracing::warn!(
                        "tproxy v6 sendto EMSGSIZE (len={}), falling back to IPv6 fragmentation",
                        packet.len()
                    );
                    send_v6_fragmented(afd, &packet[40..], src_v6, dst_v6).await
                } else {
                    Err(err)
                }
            } else {
                Err(err)
            }
        }
    }
}

/// How many consecutive receive failures to tolerate before concluding the
/// socket is unusable. Guards against a hot loop on a permanent error while
/// still riding out the transient ones (`ECONNREFUSED` from an inbound ICMP
/// port-unreachable, `EINTR`, and friends) that used to kill the listener.
const MAX_CONSECUTIVE_RECV_ERRORS: usize = 32;

async fn handle_inbound_datagram(
    fw_mark: Option<u32>,
    socket: Arc<unix_udp_sock::UdpSocket>,
    dispatcher: Arc<Dispatcher>,
) -> std::io::Result<()> {
    // dispatcher <-> tproxy communications
    let (l_tx, l_rx) = tokio::sync::mpsc::channel(256);

    // forward packets from tproxy to dispatcher
    let (d_tx, d_rx) = tokio::sync::mpsc::channel(256);

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
        let mut buf = vec![0_u8; 1024 * 64];
        let mut consecutive_errors = 0usize;
        let mut dropped = 0u64;

        loop {
            let meta = match socket.recv_msg(&mut buf).await {
                Ok(meta) => {
                    consecutive_errors = 0;
                    meta
                }
                Err(e) => {
                    // A UDP socket surfaces plenty of transient errors — an
                    // ICMP port-unreachable for an earlier packet arrives here
                    // as ECONNREFUSED. Treating any of them as fatal used to
                    // take down transparent UDP proxying until restart.
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                        warn!(
                            "tproxy udp recv failed {} times in a row, giving \
                             up: {}",
                            consecutive_errors, e
                        );
                        break;
                    }
                    debug!("tproxy udp recv error (continuing): {}", e);
                    continue;
                }
            };

            let Some(orig_dst) = meta.orig_dst else {
                trace!("recv msg:{:?} local_addr:{:?}", meta, socket.local_addr());
                warn!("failed to get orig_dst");
                continue;
            };

            // drop multicast and broadcast destinations
            if orig_dst.ip().is_multicast()
                || match orig_dst.ip() {
                    std::net::IpAddr::V4(ip) => ip.is_broadcast(),
                    std::net::IpAddr::V6(_) => false,
                }
            {
                continue;
            }

            trace!(
                "recv msg:{:?} orig_dst:{:?}, local_addr:{:?}",
                meta,
                orig_dst,
                socket.local_addr()
            );

            // never trust a length from outside to index our buffer
            let len = meta.len.min(buf.len());
            if len != meta.len {
                warn!(
                    "tproxy udp recv reported {} bytes into a {}-byte buffer, \
                     truncating",
                    meta.len,
                    buf.len()
                );
            }

            let chunk_size = gro_chunk_size(len, meta.stride);
            if chunk_size == 0 {
                continue;
            }

            for chunk in buf[0..len].chunks(chunk_size) {
                let pkt = UdpPacket {
                    data: bytes::Bytes::copy_from_slice(chunk),
                    src_addr: meta.addr.to_canonical().into(),
                    dst_addr: orig_dst.to_canonical().into(),
                    inbound_user: None,
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

fn gro_chunk_size(len: usize, stride: usize) -> usize {
    if stride == 0 { len } else { stride }
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
    let socket_v4 = new_unbound_socket(SocketAddr::from(([0, 0, 0, 0], 0)), fw_mark)
        .and_then(|s| tokio::io::unix::AsyncFd::new(s));
    let socket_v6 =
        new_unbound_socket(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)), fw_mark)
            .and_then(|s| tokio::io::unix::AsyncFd::new(s));

    // If neither family could be opened there is nothing this loop can ever
    // send — bail out instead of spinning.
    if socket_v4.is_err() && socket_v6.is_err() {
        tracing::error!(
            "Both TPROXY v4 and v6 sockets failed to initialize. V4: {:?}, V6: {:?}",
            socket_v4.err(),
            socket_v6.err()
        );
        return;
    }

    // `while let` on recv() exits cleanly once the dispatcher drops its sender,
    // with no busy-wait.
    while let Some(pkt) = l_rx.recv().await {
        trace!("tproxy <- dispatcher: {:?}", pkt);

        // an inbound that hands us a domain would otherwise panic here
        let Some(src_addr) = pkt.src_addr.try_into_socket_addr() else {
            tracing::warn!(
                "tproxy drop packet: src_addr is not a valid socket addr"
            );
            continue;
        };

        let Some(dst_addr) = pkt.dst_addr.try_into_socket_addr() else {
            tracing::warn!(
                "tproxy drop packet: dst_addr is not a valid socket addr"
            );
            continue;
        };

        // send the reply with the original destination as its source address
        match (src_addr, &socket_v4, &socket_v6) {
            (SocketAddr::V4(_), Ok(socket), _) => {
                if let Err(e) =
                    sendto_with_src(socket, &pkt.data, dst_addr, src_addr).await
                {
                    tracing::error!(
                        "failed to send v4 packet to local through tproxy: {}",
                        e
                    );
                }
            }
            (SocketAddr::V6(_), _, Ok(socket)) => {
                if let Err(e) =
                    sendto_with_src(socket, &pkt.data, dst_addr, src_addr).await
                {
                    tracing::error!(
                        "failed to send v6 packet to local through tproxy: {}",
                        e
                    );
                }
            }
            (SocketAddr::V4(_), Err(e), _) => {
                tracing::error!(
                    "No v4 socket available for sending tproxy udp packet to local: {}",
                    e
                );
            }
            (SocketAddr::V6(_), _, Err(e)) => {
                tracing::error!(
                    "No v6 socket available for sending tproxy udp packet to local: {}",
                    e
                );
            }
        }
    }

    // reaching here means the dispatcher hung up; the outer `select!` tears the
    // rest of the tproxy session down
    tracing::info!(
        "dispatcher channel to tproxy is closed, exiting outbound loop gracefully"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gro_chunk_size_uses_len_when_stride_is_zero() {
        assert_eq!(gro_chunk_size(1024, 0), 1024);
    }

    #[test]
    fn gro_chunk_size_uses_stride_when_non_zero() {
        assert_eq!(gro_chunk_size(1024, 128), 128);
    }

    #[test]
    fn test_build_v6_fragments_splitting() {
        let src: SocketAddrV6 = "[2001:db8::1]:12345".parse().unwrap();
        let dst: SocketAddrV6 = "[2001:db8::2]:53".parse().unwrap();

        // Simulated UDP Header (8B) + 1460B payload = 1468B fragmentable part
        let mut fragmentable = vec![0u8; 1468];
        // UDP Header dummy bytes
        fragmentable[0..2].copy_from_slice(&12345u16.to_be_bytes());
        fragmentable[2..4].copy_from_slice(&53u16.to_be_bytes());
        fragmentable[4..6].copy_from_slice(&1468u16.to_be_bytes());
        fragmentable[6..8].copy_from_slice(&0x1234u16.to_be_bytes()); // checksum

        let id = 0xDEADBEEF;
        let frags = build_v6_fragments(&fragmentable, src, dst, id);

        // Max payload per frag = 1232. 1468 bytes split into 1232 + 236 -> 2 fragments.
        assert_eq!(frags.len(), 2);

        // --- Verify Fragment 0 ---
        let f0 = &frags[0];
        assert_eq!(f0.len(), 40 + 8 + 1232); // 1280 bytes Total
        assert_eq!(f0[0..4], [0x60, 0x00, 0x00, 0x00]); // IPv6 version 6
        assert_eq!(u16::from_be_bytes([f0[4], f0[5]]), 8 + 1232); // Payload length: 1240
        assert_eq!(f0[6], libc::IPPROTO_FRAGMENT as u8); // Next Header = 44 (Fragment)
        assert_eq!(&f0[8..24], src.ip().octets().as_slice());
        assert_eq!(&f0[24..40], dst.ip().octets().as_slice());

        // Fragment Header
        assert_eq!(f0[40], libc::IPPROTO_UDP as u8); // Next Header = 17 (UDP)
        assert_eq!(f0[41], 0); // Reserved
        let frag0_offset_and_m = u16::from_be_bytes([f0[42], f0[43]]);
        assert_eq!(frag0_offset_and_m & 0x0001, 1); // M flag = 1
        assert_eq!(frag0_offset_and_m >> 3, 0); // Offset = 0
        assert_eq!(u32::from_be_bytes([f0[44], f0[45], f0[46], f0[47]]), id);
        assert_eq!(&f0[48..48 + 8], &fragmentable[0..8]); // UDP header present at start of frag 0

        // --- Verify Fragment 1 ---
        let f1 = &frags[1];
        assert_eq!(f1.len(), 40 + 8 + 236); // 284 bytes Total
        assert_eq!(u16::from_be_bytes([f1[4], f1[5]]), 8 + 236); // Payload length: 244
        assert_eq!(f1[6], libc::IPPROTO_FRAGMENT as u8);

        // Fragment Header
        assert_eq!(f1[40], libc::IPPROTO_UDP as u8);
        let frag1_offset_and_m = u16::from_be_bytes([f1[42], f1[43]]);
        assert_eq!(frag1_offset_and_m & 0x0001, 0); // M flag = 0 (last fragment)
        assert_eq!(frag1_offset_and_m >> 3, 1232 / 8); // Offset = 154
        assert_eq!(u32::from_be_bytes([f1[44], f1[45], f1[46], f1[47]]), id);
        assert_eq!(&f1[48..], &fragmentable[1232..]);
    }
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
