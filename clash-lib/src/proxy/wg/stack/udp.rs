use std::{future::Future, pin::Pin};

use futures::{Sink, Stream};
use tokio::sync::mpsc::{OwnedPermit, error::SendError};

use crate::proxy::datagram::UdpPacket;

pub const MAX_PACKET: usize = 65536;

type ReservingFuture = Pin<
    Box<
        dyn Future<Output = Result<OwnedPermit<UdpPacket>, SendError<()>>>
            + Send
            + Sync,
    >,
>;

pub struct UdpPair {
    send: tokio::sync::mpsc::Sender<UdpPacket>,
    recv: tokio::sync::mpsc::Receiver<UdpPacket>,

    permit: Option<OwnedPermit<UdpPacket>>,
    reserving: Option<ReservingFuture>,
}

impl UdpPair {
    pub fn new(
        recv: tokio::sync::mpsc::Receiver<UdpPacket>,
        send: tokio::sync::mpsc::Sender<UdpPacket>,
    ) -> Self {
        Self {
            send,
            recv,
            permit: None,
            reserving: None,
        }
    }
}

impl Stream for UdpPair {
    type Item = UdpPacket;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.get_mut().recv.poll_recv(cx)
    }
}

impl Sink<UdpPacket> for UdpPair {
    type Error = std::io::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if this.permit.is_some() {
            return std::task::Poll::Ready(Ok(()));
        }
        let reserving = this.reserving.get_or_insert_with(|| {
            let sender = this.send.clone();
            Box::pin(async move { sender.reserve_owned().await })
        });
        match reserving.as_mut().poll(cx) {
            std::task::Poll::Ready(Ok(permit)) => {
                this.reserving = None;
                this.permit = Some(permit);
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(_)) => {
                this.reserving = None;
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed",
                )))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn start_send(
        self: std::pin::Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let permit = this.permit.take().ok_or_else(|| {
            std::io::Error::other("UDP sink is not ready")
        })?;
        permit.send(item);
        Ok(())
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::{task::Poll, time::Duration};

    use futures::SinkExt;

    use super::{UdpPacket, UdpPair};

    #[tokio::test]
    async fn send_wakes_after_channel_has_capacity() {
        let (_incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(1);
        let (outgoing_tx, mut outgoing_rx) = tokio::sync::mpsc::channel(1);
        let mut pair = UdpPair::new(incoming_rx, outgoing_tx);

        pair.send(UdpPacket::default()).await.unwrap();
        let mut second_send = Box::pin(pair.send(UdpPacket::default()));
        assert!(matches!(
            futures::poll!(second_send.as_mut()),
            Poll::Pending
        ));

        outgoing_rx.recv().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), second_send)
            .await
            .unwrap()
            .unwrap();
        assert!(outgoing_rx.recv().await.is_some());
    }
}
