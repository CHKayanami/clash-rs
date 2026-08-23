use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{
    Sink, SinkExt, Stream, StreamExt, ready,
    stream::{SplitSink, SplitStream},
};
use parking_lot::Mutex;
use shadowsocks::{
    ProxySocket,
    relay::udprelay::{
        DatagramReceive, DatagramSend, options::UdpSocketControlData,
    },
};
use tokio::io::ReadBuf;
use tracing::{debug, error, instrument};

use crate::{
    common::errors::new_io_error,
    proxy::{AnyOutboundDatagram, datagram::UdpPacket},
    session::SocksAddr,
};

/// OutboundDatagram wrapper for shadowsocks socket, that takes ShadowsocksUdpIo
/// as underlying I/O
/// How many consecutive receive failures to tolerate before giving up on the
/// association. A decrypt failure means one bad datagram — from a replay, a
/// stale key, or anything else that can reach the socket — and must not end the
/// session, but a permanently broken socket still has to terminate.
const MAX_CONSECUTIVE_RECV_ERRORS: usize = 32;
const MAX_UDP_DATAGRAM_SIZE: usize = 65535;

use std::cell::RefCell;

thread_local! {
    static UDP_RECV_BUF: RefCell<Box<[u8]>> = RefCell::new(vec![0u8; MAX_UDP_DATAGRAM_SIZE].into_boxed_slice());
}

pub struct OutboundDatagramShadowsocks<S> {
    inner: ProxySocket<S>,
    /// The SS server addr
    remote_addr: SocketAddr,

    // for Sink
    flushed: bool,
    pkt: Option<UdpPacket>,

    // for Stream
    consecutive_recv_errors: usize,

    ss_control: UdpSocketControlData,
}

impl<S> OutboundDatagramShadowsocks<S> {
    pub fn new(inner: ProxySocket<S>, remote_addr: SocketAddr) -> Self {
        let mut ss_control = UdpSocketControlData::default();
        ss_control.client_session_id = rand::random::<u64>();

        Self {
            inner,
            flushed: true,
            pkt: None,
            remote_addr,
            consecutive_recv_errors: 0,

            ss_control,
        }
    }
}

impl<S> Sink<UdpPacket> for OutboundDatagramShadowsocks<S>
where
    S: DatagramSend + Unpin,
{
    type Error = io::Error;

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
        Ok(())
    }

    #[instrument(skip(self, cx))]
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut inner,
            ref mut pkt,
            ref remote_addr,
            ref mut flushed,

            ref mut ss_control,
            ..
        } = *self;

        let pkt_container = pkt;

        if let Some(pkt) = pkt_container {
            let data = pkt.data.as_ref();
            let addr: shadowsocks::relay::Address =
                (pkt.dst_addr.host(), pkt.dst_addr.port()).into();

            let n = ready!(inner.poll_send_to_with_ctrl(
                *remote_addr,
                &addr,
                ss_control,
                data,
                cx
            ))?;

            debug!(
                "send udp packet to remote ss server, len: {}, remote_addr: {}, \
                 dst_addr: {}",
                n, remote_addr, addr
            );

            ss_control.packet_id = match ss_control.packet_id.checked_add(1) {
                Some(id) => id,
                None => {
                    error!("packet_id overflow, closing socket");
                    return Poll::Ready(Err(io::Error::other("packet_id overflow")));
                }
            };

            let wrote_all = n == data.len();
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
            Poll::Ready(Err(io::Error::other("no packet to send")))
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

impl<S> Stream for OutboundDatagramShadowsocks<S>
where
    S: DatagramReceive + Unpin,
{
    type Item = UdpPacket;

    #[instrument(skip(self, cx))]
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let me = self.get_mut();

        UDP_RECV_BUF.with_borrow_mut(|recv_buf| {
            loop {
                let mut read_buf = ReadBuf::new(recv_buf.as_mut());

                let rv = ready!(me.inner.poll_recv(cx, &mut read_buf));
                debug!("recv udp packet from remote ss server: {:?}", rv);

                match rv {
                    Ok((n, src, ..)) => {
                        me.consecutive_recv_errors = 0;
                        let data = Bytes::copy_from_slice(&recv_buf[..n]);
                        return Poll::Ready(Some(UdpPacket {
                            data,
                            src_addr: match src {
                                shadowsocks::relay::Address::SocketAddress(a) => {
                                    a.into()
                                }
                                shadowsocks::relay::Address::DomainNameAddress(
                                    domain,
                                    port,
                                ) => SocksAddr::Domain(domain, port),
                            },
                            // overwritten by the dispatcher with the original client
                            // address on the reply path
                            dst_addr: SocksAddr::any_ipv4(),
                            inbound_user: None,
                        }));
                    }
                    // A single undecryptable datagram used to end the whole
                    // association: the dispatcher drives this stream with
                    // `while let Some(..)`, so `None` tears down the relay task.
                    // Drop the packet and keep the session alive instead.
                    Err(e) => {
                        me.consecutive_recv_errors += 1;
                        if me.consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                            error!(
                                "shadowsocks udp recv failed {} times in a row, \
                                 ending association: {}",
                                me.consecutive_recv_errors, e
                            );
                            return Poll::Ready(None);
                        }
                        debug!("dropping undecryptable shadowsocks udp packet: {}", e);
                    }
                }
            }
        })
    }
}

/// Sentinel for `queued_len`: nothing is currently held by the sink.
const NOTHING_QUEUED: usize = usize::MAX;

/// Shadowsocks UDP I/O that ProxySocket required
pub(crate) struct ShadowsocksUdpIo {
    w: Mutex<SplitSink<AnyOutboundDatagram, UdpPacket>>,
    r: Mutex<SplitStream<AnyOutboundDatagram>>,
    /// Length of the datagram handed to the sink but not yet flushed, or
    /// [`NOTHING_QUEUED`]. Used to tell a legitimate re-poll of the same packet
    /// apart from a caller that moved on to a different one.
    queued_len: AtomicUsize,
}

impl ShadowsocksUdpIo {
    pub fn new(inner: AnyOutboundDatagram) -> Self {
        let (w, r) = inner.split();
        Self {
            w: Mutex::new(w),
            r: Mutex::new(r),
            queued_len: AtomicUsize::new(NOTHING_QUEUED),
        }
    }
}

impl DatagramSend for ShadowsocksUdpIo {
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: std::net::SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let mut w = self.w.lock();

        // A `Pending` flush leaves the packet with the sink, and the caller is
        // expected to re-poll with the same data. If it comes back with a
        // *different* datagram instead, flush what we already hold rather than
        // skipping `start_send` and reporting success for a packet we never
        // queued.
        let queued = self.queued_len.load(Ordering::Relaxed);
        if queued != NOTHING_QUEUED && queued != buf.len() {
            ready!(w.poll_flush_unpin(cx))
                .map_err(|e| new_io_error(e.to_string()))?;
            self.queued_len.store(NOTHING_QUEUED, Ordering::Relaxed);
        }

        if self.queued_len.load(Ordering::Relaxed) == NOTHING_QUEUED {
            match w.start_send_unpin(UdpPacket {
                data: bytes::Bytes::copy_from_slice(buf),
                src_addr: SocksAddr::any_ipv4(),
                dst_addr: target.into(),
                inbound_user: None,
            }) {
                Ok(_) => {
                    self.queued_len.store(buf.len(), Ordering::Relaxed);
                }
                Err(e) => return Poll::Ready(Err(new_io_error(e.to_string()))),
            }
        }

        match w.poll_flush_unpin(cx) {
            Poll::Ready(Ok(())) => {
                self.queued_len.store(NOTHING_QUEUED, Ordering::Relaxed);
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => {
                self.queued_len.store(NOTHING_QUEUED, Ordering::Relaxed);
                Poll::Ready(Err(new_io_error(e.to_string())))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl DatagramReceive for ShadowsocksUdpIo {
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut r = self.r.lock();

        match r.poll_next_unpin(cx) {
            Poll::Ready(Some(pkt)) => {
                // Datagram boundaries are significant: the remainder of an
                // oversized packet is not a new packet. Carrying it over to the
                // next call made the tail get decrypted as its own AEAD frame,
                // so truncate and drop it the way a real UDP socket would.
                let to_consume = buf.remaining().min(pkt.data.len());
                if to_consume < pkt.data.len() {
                    error!(
                        "shadowsocks udp datagram of {} bytes truncated to {}",
                        pkt.data.len(),
                        to_consume
                    );
                }
                buf.put_slice(&pkt.data[..to_consume]);
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
            // Reporting a zero-length read here looks like an empty datagram,
            // which fails to decrypt and takes the association down anyway —
            // and leaves the caller free to re-poll an ended stream forever.
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "shadowsocks udp transport closed",
            ))),
        }
    }

    fn poll_recv_from(
        &self,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<std::net::SocketAddr>> {
        Poll::Ready(Err(new_io_error("not supported for shadowsocks udp io")))
    }
}
