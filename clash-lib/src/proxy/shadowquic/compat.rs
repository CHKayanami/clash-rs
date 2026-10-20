use std::{io, pin::Pin, task::{Context, Poll}};

use futures::{Sink, SinkExt, Stream};
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::PollSender;

use crate::{
    common::errors::new_io_error,
    proxy::datagram::{
        UdpPacket,
        batch::{BatchResult, DatagramBatch, PacketBatch, poll_send_channel, poll_send_single},
    },
    session::SocksAddr,
};

use super::{protocol::{payload_len, validate_addr}, registry::Packet};

pub struct UdpSessionWrapper {
    pub s: PollSender<UdpPacket>,
    pub r: Receiver<Packet>,
    pub src_addr: SocksAddr, /* source address of local socket, bound during
                              * associate task
                              * started */
}
impl Sink<UdpPacket> for UdpSessionWrapper {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut().s.poll_ready_unpin(cx).map_err(new_io_error)
    }

    fn start_send(
        self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        validate_packet(&item)?;
        self.get_mut().s.start_send_unpin(item).map_err(new_io_error)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut().s.poll_flush_unpin(cx).map_err(new_io_error)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut().s.poll_close_unpin(cx).map_err(new_io_error)
    }
}

impl Stream for UdpSessionWrapper {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.r.poll_recv(cx).map(|x| {
            x.map(|x| UdpPacket {
                data: x.0,
                src_addr: x.1,
                dst_addr: self.src_addr.clone(),
                inbound_user: None,
            })
        })
    }
}

fn validate_packet(packet: &UdpPacket) -> io::Result<()> {
    payload_len(packet.data.len())?;
    validate_addr(&packet.dst_addr)
}

impl DatagramBatch for UdpSessionWrapper {
    fn poll_send_batch(
        &mut self, cx: &mut Context<'_>, batch: &mut PacketBatch,
    ) -> Poll<BatchResult> {
        // Let the Sink path report the exact failing packet after any valid prefix.
        if batch.packets().any(|packet| validate_packet(packet).is_err()) {
            return poll_send_single(self, cx, batch);
        }
        match Pin::new(&mut *self).poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(BatchResult::terminated(err)),
            Poll::Ready(Ok(())) => {}
        }
        poll_send_channel(&mut self.s, cx, batch)
    }
}
