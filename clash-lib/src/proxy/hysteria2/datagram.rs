use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    io::{self, ErrorKind},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{Sink, Stream};

use crate::{
    proxy::datagram::{
        UdpPacket,
        batch::{BatchResult, DatagramBatch, PacketBatch, poll_send_ready},
    },
    session::SocksAddr,
};

use super::{
    HysteriaConnection,
    codec::{Defragger, HysUdpPacket},
};

pub struct UdpSession {
    pub incoming: tokio::sync::mpsc::Sender<UdpPacket>,
    pub local_addr: SocksAddr,
    pub defragger: Defragger,
}

impl UdpSession {
    pub fn feed(&mut self, pkt: HysUdpPacket) -> Option<HysUdpPacket> {
        self.defragger.feed(pkt)
    }
}

pub struct HysteriaDatagramOutbound {
    conn: Arc<HysteriaConnection>,
    session_id: u32,
    next_pkt_id: u16,
    closed: bool,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
}

impl HysteriaDatagramOutbound {
    pub fn new(
        session_id: u32,
        conn: Arc<HysteriaConnection>,
        local_addr: SocksAddr,
    ) -> Self {
        tracing::trace!(
            "HysteriaDatagramOutbound::new: session_id={}, local_addr={:?}",
            session_id,
            local_addr
        );

        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        conn.udp_sessions.lock().insert(
            session_id,
            UdpSession {
                incoming: recv_tx,
                local_addr,
                defragger: Defragger::default(),
            },
        );
        tracing::trace!(
            "HysteriaDatagramOutbound: UDP session {} registered",
            session_id
        );

        Self { conn, session_id, next_pkt_id: 0, closed: false, recv_rx }
    }
}

impl Debug for HysteriaDatagramOutbound {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("HysteriaDatagramOutbound")
            .field("session_id", &self.session_id).finish()
    }
}

impl HysteriaDatagramOutbound {
    fn close_session(&mut self) {
        if !self.closed {
            self.closed = true;
            self.conn.udp_sessions.lock().remove(&self.session_id);
            self.recv_rx.close();
        }
    }

    fn max_fragment_size(&self) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(ErrorKind::BrokenPipe, "UDP session closed"));
        }
        self.conn.max_fragment_size()
    }

    fn send(&mut self, item: &UdpPacket, max_frag_size: usize) -> io::Result<()> {
        let pkt_id = self.next_pkt_id;
        self.next_pkt_id = pkt_id.wrapping_add(1);
        self.conn.send_packet(
            &item.data, &item.dst_addr, self.session_id, pkt_id, max_frag_size,
        )
    }
}

impl Drop for HysteriaDatagramOutbound {
    fn drop(&mut self) { self.close_session(); }
}

impl DatagramBatch for HysteriaDatagramOutbound {
    fn poll_send_batch(
        &mut self, _cx: &mut Context<'_>, batch: &mut PacketBatch,
    ) -> Poll<BatchResult> {
        let result = match self.max_fragment_size() {
            Ok(limit) => poll_send_ready(batch, |packet| self.send(packet, limit)),
            Err(error) => BatchResult::terminated(error),
        };
        if result.error.is_some() { self.close_session(); }
        Poll::Ready(result)
    }
}

impl Sink<UdpPacket> for HysteriaDatagramOutbound {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(if self.closed {
            Err(io::Error::new(ErrorKind::BrokenPipe, "UDP session closed"))
        } else { Ok(()) })
    }

    fn start_send(mut self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let result = self.max_fragment_size().and_then(|limit| self.send(&item, limit));
        if result.is_err() { self.close_session(); }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.close_session();
        Poll::Ready(Ok(()))
    }
}

impl Stream for HysteriaDatagramOutbound {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.recv_rx.poll_recv(cx)
    }
}
