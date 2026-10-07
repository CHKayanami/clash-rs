use crate::{
    common::errors::new_io_error,
    proxy::{datagram::UdpPacket, utils::ToCanonical},
    session::SocksAddr,
};
use futures::ready;
use shadowsocks::{
    ProxySocket, net::UdpSocket as SsUdpSocket,
    relay::{Address, udprelay::options::UdpSocketControlData},
    security::replay::PacketWindow,
};
use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::ReadBuf;
use tokio_util::time::{DelayQueue, delay_queue::Key};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use tracing::{debug, error};

pub(crate) struct InboundShadowsocksDatagram {
    // Per-client control data keyed by the authenticated SS2022 session.
    //
    // SS2022 multi-user UDP: the server must encrypt each response with the
    // same uPSK (user key) that was used to authenticate the corresponding
    // request, and must echo the client's session ID.  Because this single
    // socket receives packets from *all* clients, a single shared
    // `UdpSocketControlData` field is insufficient: in a concurrent setting
    // the field would be overwritten by the most-recently-received packet,
    // causing responses for earlier clients to be encrypted with the wrong
    // key (MAC failure on the client side).
    //
    client_controls: HashMap<ClientSessionKey, ClientControl>,
    address_sessions: HashMap<SocketAddr, ClientSessionKey>,
    server_session_ids: HashSet<u64>,
    expirations: DelayQueue<ClientSessionKey>,
    allowed_sources: Option<HashSet<IpAddr>>,

    socket: ProxySocket<SsUdpSocket>,

    // for Sink
    flushed: bool,
    pkt: Option<UdpPacket>,

    // for Stream
    buf: bytes::BytesMut,
    consecutive_recv_errors: usize,
}

/// A client's control block and its idle expiration timer.
struct ClientControl {
    // Allocated once for this authenticated client session, shared by its packets.
    inbound_user: Option<Arc<str>>,
    ctrl: UdpSocketControlData,
    logical_addr: SocketAddr,
    client_addr: SocketAddr,
    expiry: Key,
    window: PacketWindow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ClientSessionKey {
    Aead2022 {
        client_session_id: u64,
        user_hash: Option<[u8; 16]>,
    },
    Legacy(SocketAddr),
}

/// Cap on tracked sessions. SS2022 entries are only added after authentication.
const MAX_TRACKED_CLIENTS: usize = 65_536;

/// Idle time after which a client's control block may be reclaimed. Well beyond
/// any reasonable UDP session, so an active client is never evicted.
const CLIENT_CONTROL_TTL: Duration = Duration::from_secs(600);

/// How many consecutive receive failures to tolerate before ending the stream,
/// so a permanently failing socket cannot spin this loop forever.
const MAX_CONSECUTIVE_RECV_ERRORS: usize = 32;

impl std::fmt::Debug for InboundShadowsocksDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundShadowsocksDatagram")
            .field("socket", &self.socket)
            .finish()
    }
}

impl InboundShadowsocksDatagram {
    pub fn new(
        socket: ProxySocket<SsUdpSocket>,
        allow_lan: bool,
    ) -> io::Result<Self> {
        let local_ip = socket.local_addr()?.ip().to_canonical();
        let allowed_sources = if allow_lan {
            None
        } else if local_ip.is_unspecified() {
            // Wildcard UDP sockets have no per-packet local endpoint. Resolve
            // local interface addresses once instead of allowing remote hosts.
            let interfaces = NetworkInterface::show().map_err(new_io_error)?;
            Some(interfaces.into_iter()
                .flat_map(|iface| iface.addr)
                .map(|addr| addr.ip().to_canonical())
                .collect())
        } else {
            Some(HashSet::from([local_ip]))
        };
        Ok(Self {
            buf: bytes::BytesMut::with_capacity(65535),
            socket,
            client_controls: HashMap::new(),
            address_sessions: HashMap::new(),
            server_session_ids: HashSet::new(),
            expirations: DelayQueue::new(),
            allowed_sources,
            consecutive_recv_errors: 0,

            flushed: true,
            pkt: None,
        })
    }

    fn new_server_session_id(server_session_ids: &HashSet<u64>) -> u64 {
        loop {
            let id = rand::random::<u64>();
            if !server_session_ids.contains(&id) {
                return id;
            }
        }
    }

    fn new_logical_addr(
        client_addr: SocketAddr,
        address_sessions: &HashMap<SocketAddr, ClientSessionKey>,
    ) -> SocketAddr {
        if !address_sessions.contains_key(&client_addr) {
            return client_addr;
        }
        loop {
            let port = rand::random::<u16>();
            let addr = SocketAddr::new(client_addr.ip(), port);
            if port != 0 && !address_sessions.contains_key(&addr) {
                return addr;
            }
        }
    }
}

impl futures::Stream for InboundShadowsocksDatagram {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut buf,
            ref socket,
            ref mut client_controls,
            ref mut address_sessions,
            ref mut server_session_ids,
            ref mut consecutive_recv_errors,
            ref mut expirations,
            ref allowed_sources,
            ..
        } = *self.get_mut();

        // Bound work per poll when many sessions expire together. Each removal
        // touches only that session's indexes; no full-map scans or rebuilds.
        let mut exhausted = true;
        for _ in 0..128 {
            match expirations.poll_expired(cx) {
                Poll::Ready(Some(expired)) => {
                    if let Some(client) = client_controls.remove(expired.get_ref()) {
                        address_sessions.remove(&client.logical_addr);
                        server_session_ids.remove(&client.ctrl.server_session_id);
                    }
                }
                _ => {
                    exhausted = false;
                    break;
                }
            }
        }
        if exhausted {
            // A remaining ready timer must be polled again even if UDP is idle.
            cx.waker().wake_by_ref();
        }

        loop {
            buf.resize(buf.capacity(), 0);
            let mut read_buf = ReadBuf::new(buf);

            let rv = ready!(socket.poll_recv_from_with_ctrl(cx, &mut read_buf));
            debug!("recv udp packet from inbound: {:?}", rv);

            match rv {
                Ok((n, src, target, _, ctrl)) => {
                    *consecutive_recv_errors = 0;
                    // Canonicalize IPv4-mapped IPv6 source addresses (e.g.
                    // ::ffff:x.x.x.x → x.x.x.x) so the key stored here
                    // matches the canonical sess.source the dispatcher assigns
                    // after commit 6783909.  Without this, the Sink's
                    // client_controls lookup uses the canonical address
                    // (from pkt.dst_addr = sess.source) but finds no entry
                    // because it was stored under the raw IPv4-mapped form,
                    // producing "no control entry" and dropping all IPv4 UDP
                    // replies.
                    let src = src.to_canonical();
                    if allowed_sources.as_ref()
                        .is_some_and(|ips| !ips.contains(&src.ip()))
                    {
                        debug!("dropping non-local shadowsocks UDP source {}", src);
                        continue;
                    }

                    // Upsert the per-client control entry so responses to this
                    // client are encrypted with the correct uPSK and echo the
                    // correct client_session_id.  packet_id is kept per-client
                    // for monotonic replay protection at each individual client.

                    let session_key = match ctrl.as_ref() {
                        Some(control) => ClientSessionKey::Aead2022 {
                            client_session_id: control.client_session_id,
                            user_hash: control.user.as_ref().map(|user| {
                                user.identity_hash().try_into()
                                    .expect("16-byte user identity")
                            }),
                        },
                        None => ClientSessionKey::Legacy(src),
                    };
                    if !client_controls.contains_key(&session_key)
                        && client_controls.len() >= MAX_TRACKED_CLIENTS
                    {
                        error!(
                            "shadowsocks udp session limit reached; dropping new session"
                        );
                        continue;
                    }
                    let entry = match client_controls.entry(session_key) {
                        Entry::Occupied(entry) => entry.into_mut(),
                        Entry::Vacant(entry) => {
                            let new_logical_addr =
                                Self::new_logical_addr(src, address_sessions);
                            address_sessions
                                .insert(new_logical_addr, *entry.key());
                            let server_session_id =
                                Self::new_server_session_id(server_session_ids);
                            server_session_ids.insert(server_session_id);
                            let mut d = UdpSocketControlData::default();
                            d.server_session_id = server_session_id;
                            entry.insert(ClientControl {
                                inbound_user: ctrl
                                    .as_ref()
                                    .and_then(|c| c.user.as_ref())
                                    .map(|u| Arc::from(u.name())),
                                ctrl: d,
                                logical_addr: new_logical_addr,
                                client_addr: src,
                                expiry: expirations.insert(
                                    session_key, CLIENT_CONTROL_TTL,
                                ),
                                window: PacketWindow::new(),
                            })
                        }
                    };
                    if let Some(ref c) = ctrl {
                        if entry.window.check_and_set(c.packet_id) {
                            debug!(
                                "shadowsocks inbound udp replay detected: client_session_id={}, packet_id={}",
                                c.client_session_id, c.packet_id
                            );
                            continue;
                        }
                        entry.ctrl.client_session_id = c.client_session_id;
                        entry.ctrl.user = c.user.clone();
                    }
                    entry.client_addr = src;
                    expirations.reset(&entry.expiry, CLIENT_CONTROL_TTL);
                    let logical_addr = entry.logical_addr;

                    return Poll::Ready(Some(UdpPacket {
                        data: bytes::Bytes::copy_from_slice(&read_buf.filled()[..n]),
                        src_addr: logical_addr.into(),
                        dst_addr: match target {
                            shadowsocks::relay::Address::SocketAddress(a) => {
                                a.into()
                            }
                            shadowsocks::relay::Address::DomainNameAddress(
                                domain,
                                port,
                            ) => SocksAddr::Domain(domain.into(), port),
                        },
                        inbound_user: entry.inbound_user.clone(),
                    }));
                }
                Err(e) => {
                    if e.is_packet_error() {
                        // Authentication, replay and malformed-packet errors
                        // consume exactly one datagram. They are untrusted
                        // network input, not evidence that the socket is bad.
                        *consecutive_recv_errors = 0;
                        debug!("dropping invalid shadowsocks udp packet: {}", e);
                        continue;
                    }
                    // Log the error but keep the stream alive. Without looping
                    // here, returning Poll::Pending would leave the task without
                    // a registered waker (the waker was consumed when data
                    // arrived), permanently suspending the UDP dispatch loop.
                    //
                    // Bounded, though: an error that does not consume a
                    // datagram would otherwise spin this loop at 100% CPU.
                    *consecutive_recv_errors += 1;
                    if *consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                        error!(
                            "shadowsocks inbound udp recv failed {} times in a \
                             row, ending stream: {}",
                            consecutive_recv_errors, e
                        );
                        return Poll::Ready(None);
                    }
                    error!("failed to receive udp packet from socket: {}", e);
                    // Fall through to the next loop iteration: if the socket
                    // is empty, poll_recv_from_with_ctrl will re-register the
                    // waker and return Poll::Pending via ready!().
                }
            }
        }
    }
}

impl futures::Sink<UdpPacket> for InboundShadowsocksDatagram {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.pkt = Some(item);
        pin.flushed = false;
        debug!("start sending udp packet: {:?}", pin.pkt);
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut socket,
            ref mut pkt,
            ref mut flushed,
            ref mut client_controls,
            ref address_sessions,
            ..
        } = *self;

        let pkt_container = pkt;

        if let Some(pkt) = pkt_container {
            let addr = Address::from(&pkt.src_addr);

            // Look up the per-client control for this response's destination.
            // This entry must already exist: a response can only arrive after
            // poll_next() has received and dispatched the corresponding request
            // from this client, which is what populates client_controls.
            // A missing entry would mean we have no user key, so we'd silently
            // encrypt with iPSK and the client would get a MAC failure --
            // exactly the bug we are fixing. Error out loudly instead.
            // Responses are always addressed to a concrete client socket, but
            // drop rather than panic if that ever stops holding.
            let Some(client_addr) = pkt.dst_addr.clone().try_into_socket_addr()
            else {
                error!(
                    "shadowsocks udp response to non-ip destination {} - \
                     dropping",
                    pkt.dst_addr
                );
                *pkt_container = None;
                *flushed = true;
                return Poll::Ready(Ok(()));
            };
            let control_key = address_sessions.get(&client_addr).copied();
            let client = match control_key
                .as_ref()
                .and_then(|key| client_controls.get_mut(key))
            {
                Some(c) => c,
                None => {
                    error!(
                        "no control entry for client {client_addr} - dropping \
                         response to avoid iPSK fallback"
                    );
                    *pkt_container = None;
                    *flushed = true;
                    return Poll::Ready(Ok(()));
                }
            };
            let target_addr = client.client_addr;
            let control = &mut client.ctrl;

            let n = ready!(socket.poll_send_to_with_ctrl(
                target_addr,
                &addr,
                control,
                pkt.data.as_ref(),
                cx
            ))?;

            debug!("send udp packet to client {}", pkt);

            control.packet_id = match control.packet_id.checked_add(1) {
                Some(id) => id,
                None => {
                    error!("packet_id overflow, closing socket");
                    return Poll::Ready(Err(std::io::Error::other(
                        "packet_id overflow",
                    )));
                }
            };

            let wrote_all = n == pkt.data.len();
            *pkt_container = None;
            *flushed = true;

            let res = if wrote_all {
                Ok(())
            } else {
                Err(new_io_error(format!(
                    "failed to write entire datagram, written: {n}"
                )))
            };
            Poll::Ready(res)
        } else {
            debug!("no udp packet to send");
            Poll::Ready(Err(std::io::Error::other("no packet to send")))
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
#[path = "datagram_tests.rs"]
mod tests;
