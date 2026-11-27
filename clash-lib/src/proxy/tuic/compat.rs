use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, SinkExt, Stream};
use tokio::time::{Instant, sleep};

use crate::{
    common::errors::new_io_error,
    proxy::datagram::{
        UdpPacket,
        batch::{BatchResult, DatagramBatch, PacketBatch, poll_send_ready, poll_send_stream},
    },
    session::SocksAddr as ClashSocksAddr,
};
use super::{
    TuicDatagramOutbound,
    proto::Address,
    types::{SocketAdderTrans, TUIC_HALF_CLOSED_DRAIN_GRACE},
};

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
                if result.as_ref().is_err_and(|error| error.kind() != io::ErrorKind::InvalidInput) {
                    self.close_native();
                }
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
                Poll::Ready(result) => {
                    self.closed = true;
                    if let Some(cancel) = &self.cancel {
                        cancel.cancel();
                    }
                    return Poll::Ready(result.map_err(new_io_error));
                }
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
        let this = self.as_mut().get_mut();
        this.poll_gc_timer(cx);
        loop {
            match this.recv_rx.poll_recv(cx) {
                Poll::Ready(Some(parsed)) => {
                    let complete = if parsed.frag_total == 1 {
                        (parsed.frag_id == 0 && parsed.addr != Address::None)
                            .then_some((parsed.addr, parsed.payload))
                    } else {
                        this.fragments.accept(parsed)
                    };
                    let Some((address, payload)) = complete else {
                        continue;
                    };
                    match ClashSocksAddr::try_from(address) {
                        Ok(remote_addr) => {
                            this.sync_gc_timer(cx, false);
                            return Poll::Ready(Some(UdpPacket::new(
                                payload,
                                remote_addr,
                                this.local_addr.clone(),
                            )));
                        }
                        Err(e) => {
                            tracing::warn!("[udp] failed converting address: {e}");
                        }
                    }
                }
                Poll::Ready(None) => {
                    this.gc_timer = None;
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    this.sync_gc_timer(cx, true);
                    return Poll::Pending;
                }
            }
        }
    }
}

impl Debug for TuicDatagramOutbound {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("TuicDatagramOutbound")
            .field("assoc_id", &self.assoc_id).finish()
    }
}

impl TuicDatagramOutbound {
    fn sync_gc_timer(&mut self, cx: &mut Context<'_>, register_waker: bool) {
        if self.fragments.is_empty() || self.gc_interval.is_zero() {
            self.gc_timer = None;
        } else if self.gc_timer.is_none() {
            #[cfg(test)]
            {
                self.gc_timer_allocs += 1;
            }
            self.gc_timer = Some(Box::pin(sleep(self.gc_interval)));
            if register_waker {
                self.poll_gc_timer(cx);
            }
        }
    }

    fn poll_gc_timer(&mut self, cx: &mut Context<'_>) {
        if let Some(timer) = self.gc_timer.as_mut()
            && timer.as_mut().poll(cx).is_ready()
        {
            self.fragments.expire_stale();
            if self.fragments.is_empty() {
                self.gc_timer = None;
            } else {
                timer.as_mut().reset(Instant::now() + self.gc_interval);
                let _ = timer.as_mut().poll(cx);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn has_pending_fragments_for_test(&self) -> bool {
        !self.fragments.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn has_gc_timer_for_test(&self) -> bool {
        self.gc_timer.is_some()
    }

    #[cfg(test)]
    pub(crate) fn gc_timer_allocs_for_test(&self) -> usize {
        self.gc_timer_allocs
    }

    fn max_datagram_size(&self) -> io::Result<usize> {
        if self.closed { return Err(new_io_error("UDP session closed")); }
        self.conn.conn.max_datagram_size()
            .ok_or_else(|| new_io_error("QUIC datagrams unavailable"))
    }

    fn send_native(&self, item: &UdpPacket, max_size: usize) -> io::Result<()> {
        self.conn.send_native_packet(
            &item.data, item.dst_addr.clone().into_tuic(), self.assoc_id, max_size,
        )
    }

    fn close_native(&mut self) {
        if self.closed || self.send_tx.is_some() { return; }
        self.closed = true;
        self.recv_rx.close();
        self.conn.remove_udp_session(self.assoc_id);
        let lease = self._lease.take();
        if self.conn.conn.close_reason().is_some() { return; }
        // Dissociation opens a QUIC stream and must complete asynchronously.
        // Only teardown needs a task; native packet sends stay on the relay.
        let conn = self.conn.clone();
        let assoc_id = self.assoc_id;
        self.runtime.spawn(async move {
            let _lease = lease;
            let _ = tokio::time::timeout(conn.drain_timeout(), async {
                if let Ok(send) = conn.send_dissociate(assoc_id).await {
                    let _ = send.stopped().await;
                    if conn.conn.close_reason().is_none() {
                        tokio::select! {
                            _ = tokio::time::sleep(TUIC_HALF_CLOSED_DRAIN_GRACE) => {}
                            _ = conn.conn.closed() => {}
                        }
                    }
                }
            })
            .await;
        });
    }
}

impl Drop for TuicDatagramOutbound {
    fn drop(&mut self) {
        if self.send_tx.take().is_some() {
            if let Some(cancel) = &self.cancel {
                cancel.cancel();
            }
        } else {
            self.close_native();
        }
        self._lease.take();
    }
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
        if result.fatal { self.close_native(); }
        Poll::Ready(result)
    }
}
