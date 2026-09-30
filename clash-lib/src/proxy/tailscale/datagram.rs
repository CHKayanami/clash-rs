use std::{
    collections::VecDeque,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{Sink, SinkExt, Stream, ready};
use tokio::sync::oneshot;
use tokio_util::sync::{CancellationToken, PollSender};

use super::UdpPortReservation;
use crate::{
    app::dns::ThreadSafeDNSResolver,
    common::errors::{map_io_error, new_io_error},
    proxy::datagram::UdpPacket,
    session::SocksAddr,
};

#[derive(Debug)]
struct SendRequest {
    packet: UdpPacket,
    result: oneshot::Sender<io::Result<()>>,
}

const UDP_SEND_QUEUE_SIZE: usize = 32;

#[derive(Debug)]
pub struct TailscaleDatagramOutbound {
    send_tx: PollSender<SendRequest>,
    pending_sends: VecDeque<oneshot::Receiver<io::Result<()>>>,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    port_reservation: Option<UdpPortReservation>,
    cancel: CancellationToken,
    send_task: Option<tokio::task::JoinHandle<()>>,
    recv_task: Option<tokio::task::JoinHandle<()>>,
}

impl TailscaleDatagramOutbound {
    pub(super) fn new(
        socket: ::tailscale::netstack::UdpSocket,
        resolver: ThreadSafeDNSResolver,
        port_reservation: UdpPortReservation,
    ) -> Self {
        let local_addr = socket.local_addr();
        let local_addr_socks: SocksAddr = local_addr.into();
        let socket = Arc::new(socket);
        let (send_tx, mut send_rx) =
            tokio::sync::mpsc::channel::<SendRequest>(UDP_SEND_QUEUE_SIZE);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let cancel = CancellationToken::new();

        let send_task = {
            let socket = Arc::clone(&socket);
            let resolver = resolver.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    let request = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => break,
                        pkt = send_rx.recv() => match pkt {
                            Some(p) => p,
                            None => break,
                        },
                    };

                    let result =
                        send_packet(&socket, &request.packet, &resolver).await;
                    let _ = request.result.send(result);
                }
            })
        };

        let recv_task = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    let recv = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => break,
                        r = socket.recv_from_bytes() => r,
                    };
                    let (remote, data) = match recv {
                        Ok(recv) => recv,
                        Err(err) => {
                            tracing::warn!("tailscale udp recv_from failed: {err}");
                            break;
                        }
                    };

                    if recv_tx
                        .send(UdpPacket {
                            data: data.into(),
                            src_addr: remote.into(),
                            dst_addr: local_addr_socks.clone(),
                            inbound_user: None,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            })
        };

        Self {
            send_tx: PollSender::new(send_tx),
            pending_sends: VecDeque::new(),
            recv_rx,
            port_reservation: Some(port_reservation),
            cancel,
            send_task: Some(send_task),
            recv_task: Some(recv_task),
        }
    }
}

impl Drop for TailscaleDatagramOutbound {
    fn drop(&mut self) {
        self.cancel.cancel();
        let send_task = self.send_task.take().unwrap();
        let recv_task = self.recv_task.take().unwrap();
        send_task.abort();
        recv_task.abort();
        let reservation = self.port_reservation.take().unwrap();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = tokio::join!(send_task, recv_task);
                drop(reservation);
            });
        }
    }
}

impl Sink<UdpPacket> for TailscaleDatagramOutbound {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.pending_sends.len() >= UDP_SEND_QUEUE_SIZE {
            ready!(poll_oldest_send(&mut self.pending_sends, cx))?;
        }
        self.send_tx
            .poll_ready_unpin(cx)
            .map_err(|_| new_io_error("tailscale udp send channel not ready"))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        let (tx, rx) = oneshot::channel();
        self.send_tx
            .start_send_unpin(SendRequest {
                packet: item,
                result: tx,
            })
            .map_err(|_| new_io_error("tailscale udp send channel closed"))?;
        self.pending_sends.push_back(rx);
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(
            self.send_tx.poll_flush_unpin(cx).map_err(|_| new_io_error(
                "tailscale udp send channel flush failed"
            ))
        )?;
        while !self.pending_sends.is_empty() {
            ready!(poll_oldest_send(&mut self.pending_sends, cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        self.send_tx
            .poll_close_unpin(cx)
            .map_err(|_| new_io_error("tailscale udp send channel close failed"))
    }
}

fn poll_oldest_send(
    pending: &mut VecDeque<oneshot::Receiver<io::Result<()>>>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    let Some(oldest) = pending.front_mut() else {
        return Poll::Ready(Ok(()));
    };
    let result = ready!(Pin::new(oldest).poll(cx));
    pending.pop_front();
    Poll::Ready(result.map_err(|_| new_io_error("tailscale udp send task stopped"))?)
}

async fn send_packet(
    socket: &::tailscale::netstack::UdpSocket,
    packet: &UdpPacket,
    resolver: &ThreadSafeDNSResolver,
) -> io::Result<()> {
    let dst = resolve_destination(
        &packet.dst_addr,
        socket.local_addr().is_ipv6(),
        resolver,
    )
    .await?;
    socket.send_to(dst, &packet.data).await.map_err(|err| {
        io::Error::other(format!("tailscale udp send_to failed for {dst}: {err}"))
    })
}

async fn resolve_destination(
    dst: &SocksAddr,
    is_ipv6: bool,
    resolver: &ThreadSafeDNSResolver,
) -> io::Result<SocketAddr> {
    let addr = match dst {
        SocksAddr::Ip(addr) => *addr,
        SocksAddr::Domain(domain, port) => {
            let ip = if is_ipv6 {
                resolver
                    .resolve_v6(domain, false)
                    .await
                    .map_err(map_io_error)?
                    .map(IpAddr::V6)
            } else {
                resolver
                    .resolve_v4(domain, false)
                    .await
                    .map_err(map_io_error)?
                    .map(IpAddr::V4)
            }
            .ok_or_else(|| {
                io::Error::other(format!("no matching DNS result for {domain}"))
            })?;
            (ip, *port).into()
        }
    };
    if addr.is_ipv6() != is_ipv6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "tailscale UDP destination {addr} has a different address family than the socket"
            ),
        ));
    }
    Ok(addr)
}

impl Stream for TailscaleDatagramOutbound {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.recv_rx.poll_recv(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        TailscaleDatagramOutbound, UDP_SEND_QUEUE_SIZE, resolve_destination,
    };
    use crate::{
        app::dns::ThreadSafeDNSResolver,
        proxy::{datagram::UdpPacket, utils::test_utils::noop::NoopResolver},
        session::SocksAddr,
    };
    use futures::SinkExt;
    use std::{
        collections::{HashSet, VecDeque},
        io,
        net::SocketAddr,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio_util::sync::{CancellationToken, PollSender};

    #[tokio::test]
    async fn tailscale_udp_buffers_multiple_sends_and_reports_errors_on_flush() {
        let (send_tx, mut send_rx) = tokio::sync::mpsc::channel(UDP_SEND_QUEUE_SIZE);
        let (_recv_tx, recv_rx) = tokio::sync::mpsc::channel(1);
        let ports = Arc::new(Mutex::new(HashSet::new()));
        let mut outbound = TailscaleDatagramOutbound {
            send_tx: PollSender::new(send_tx),
            pending_sends: VecDeque::new(),
            recv_rx,
            port_reservation: Some(super::super::reserve_udp_port(&ports).unwrap()),
            cancel: CancellationToken::new(),
            send_task: Some(tokio::spawn(std::future::pending::<()>())),
            recv_task: Some(tokio::spawn(std::future::pending::<()>())),
        };

        tokio::time::timeout(Duration::from_secs(1), async {
            outbound.feed(UdpPacket::default()).await.unwrap();
            outbound.feed(UdpPacket::default()).await.unwrap();
        })
        .await
        .expect(
            "sending a second packet must not wait for the first acknowledgement",
        );
        assert_eq!(outbound.pending_sends.len(), 2);

        send_rx.recv().await.unwrap().result.send(Ok(())).unwrap();
        send_rx
            .recv()
            .await
            .unwrap()
            .result
            .send(Err(io::Error::other("send failed")))
            .unwrap();
        let err = outbound.flush().await.unwrap_err();
        assert!(err.to_string().contains("send failed"));
    }

    #[tokio::test]
    async fn tailscale_rejects_destination_from_another_address_family() {
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let ipv6: SocketAddr = "[fd7a:115c:a1e0::1]:53".parse().unwrap();
        let err = resolve_destination(&SocksAddr::Ip(ipv6), false, &resolver)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
