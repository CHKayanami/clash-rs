use futures::{Sink, Stream};
use super::UdpPacket;
use std::io::{Error, ErrorKind};
use tokio::sync::mpsc::{Receiver, Sender};
use super::batch::{BatchResult, DatagramBatch, PacketBatch, poll_send_channel};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_util::sync::PollSender;

#[derive(Debug)]
pub struct ChannelDatagram {
    rx: Receiver<UdpPacket>,
    tx: PollSender<UdpPacket>,
    pkt: Option<UdpPacket>,
}

impl ChannelDatagram {
    pub fn new(
        tx: Sender<UdpPacket>,
        rx: Receiver<UdpPacket>,
    ) -> Self {
        Self {
            rx,
            tx: PollSender::new(tx),
            pkt: None,
        }
    }
}

impl Stream for ChannelDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl Sink<UdpPacket> for ChannelDatagram {
    type Error = Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.pkt.is_some() {
            if let Poll::Pending = self.as_mut().poll_flush(cx)? {
                return Poll::Pending;
            }
        }

        match Pin::new(&mut self.get_mut().tx).poll_reserve(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_)) => Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "PollSender channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        self.pkt = Some(item);
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.pkt.is_none() {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();
        let pkt = this.pkt.take().unwrap();

        match Pin::new(&mut this.tx).send_item(pkt) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(_) => Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "PollSender failed to send item",
            ))),
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

impl DatagramBatch for ChannelDatagram {
    fn poll_send_batch(
        &mut self, cx: &mut Context<'_>, batch: &mut PacketBatch,
    ) -> Poll<BatchResult> {
        match Pin::new(&mut *self).poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(BatchResult::terminated(error)),
            Poll::Ready(Ok(())) => {}
        }
        poll_send_channel(&mut self.tx, cx, batch)
    }
}
