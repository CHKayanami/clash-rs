use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, SinkExt, Stream};

use crate::{
    common::errors::new_io_error,
    proxy::datagram::{
        UdpPacket,
        batch::{BatchResult, DatagramBatch, PacketBatch, poll_send_ready, poll_send_stream},
    },
};
use super::{TuicDatagramOutbound, types::SocketAdderTrans};

impl Sink<UdpPacket> for TuicDatagramOutbound {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.closed { return Poll::Ready(Err(new_io_error("UDP session closed"))); }
        match self.send_tx.as_mut() {
            Some(tx) => tx.poll_ready_unpin(cx).map_err(new_io_error),
            None => Poll::Ready(self.conn.check_open().map_err(new_io_error)),
        }
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        if self.closed { return Err(new_io_error("UDP session closed")); }
        match self.send_tx.as_mut() {
            Some(tx) => tx.start_send_unpin(item).map_err(new_io_error),
            None => {
                let result = self.max_datagram_size()
                    .and_then(|limit| self.send_native(&item, limit));
                if result.is_err() { self.close_native(); }
                result
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        match self.send_tx.as_mut() {
            Some(tx) => tx.poll_flush_unpin(cx).map_err(new_io_error),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if let Some(tx) = self.send_tx.as_mut() {
            match tx.poll_close_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => { self.closed = true; return Poll::Ready(result.map_err(new_io_error)); }
            }
        }
        self.close_native();
        Poll::Ready(Ok(()))
    }
}

impl Stream for TuicDatagramOutbound {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.recv_rx.poll_recv(cx)
    }
}

impl Debug for TuicDatagramOutbound {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("TuicDatagramOutbound")
            .field("assoc_id", &self.assoc_id).finish()
    }
}

impl TuicDatagramOutbound {
    fn max_datagram_size(&self) -> io::Result<usize> {
        if self.closed { return Err(new_io_error("UDP session closed")); }
        self.conn.conn.max_datagram_size()
            .ok_or_else(|| new_io_error("QUIC datagrams unavailable"))
    }

    fn send_native(&self, item: &UdpPacket, max_size: usize) -> io::Result<()> {
        self.conn.send_native_packet(
            &item.data, item.dst_addr.clone().into_tuic(), self.assoc_id, max_size,
        ).map_err(new_io_error)
    }

    fn close_native(&mut self) {
        if self.closed || self.send_tx.is_some() { return; }
        self.closed = true;
        self.recv_rx.close();
        self.conn.remove_udp_session(self.assoc_id);
        if self.conn.conn.close_reason().is_some() { return; }
        // Dissociation opens a QUIC stream and must complete asynchronously.
        // Only teardown needs a task; native packet sends stay on the relay.
        let conn = self.conn.clone();
        let assoc_id = self.assoc_id;
        self.runtime.spawn(async move { let _ = conn.send_dissociate(assoc_id).await; });
    }
}

impl Drop for TuicDatagramOutbound {
    fn drop(&mut self) { self.close_native(); }
}

impl DatagramBatch for TuicDatagramOutbound {
    fn poll_send_batch(
        &mut self, cx: &mut Context<'_>, batch: &mut PacketBatch,
    ) -> Poll<BatchResult> {
        if self.send_tx.is_some() { return poll_send_stream(self, cx, batch); }
        let result = match self.max_datagram_size() {
            Ok(limit) => poll_send_ready(batch, |packet| self.send_native(packet, limit)),
            Err(error) => BatchResult::terminated(error),
        };
        if result.error.is_some() { self.close_native(); }
        Poll::Ready(result)
    }
}
