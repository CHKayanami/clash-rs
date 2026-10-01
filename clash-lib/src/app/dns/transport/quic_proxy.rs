//! Adapt an outbound proxy datagram association to Quinn's UDP socket interface.

use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::task::AtomicWaker;
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::futures::OwnedNotified;
use tokio::sync::{Notify, mpsc};

use super::owned_task::OwnedTask;
use crate::proxy::AnyOutboundDatagram;
use crate::proxy::datagram::UdpPacket;
use crate::session::SocksAddr;

const QUEUE_CAPACITY: usize = 256;

#[derive(Default)]
struct BridgeState {
    error: Mutex<Option<(io::ErrorKind, String)>>,
    writable: Arc<Notify>,
    reader: AtomicWaker,
    cancelled: tokio_util::sync::CancellationToken,
}

impl BridgeState {
    fn fail(&self, error: io::Error) {
        self.error
            .lock()
            .get_or_insert((error.kind(), error.to_string()));
        self.cancelled.cancel();
        self.writable.notify_waiters();
        self.reader.wake();
    }

    fn check(&self) -> io::Result<()> {
        match &*self.error.lock() {
            Some((kind, message)) => Err(io::Error::new(*kind, message.clone())),
            None => Ok(()),
        }
    }
}

pub(super) struct ProxyQuicSocket {
    sender: mpsc::Sender<UdpPacket>,
    receiver: Mutex<mpsc::Receiver<UdpPacket>>,
    state: Arc<BridgeState>,
    tasks: Mutex<Vec<OwnedTask>>,
    local_addr: SocketAddr,
    target: SocketAddr,
}

impl fmt::Debug for ProxyQuicSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyQuicSocket")
            .field("target", &self.target)
            .finish()
    }
}

impl ProxyQuicSocket {
    pub(super) fn new(
        datagram: AnyOutboundDatagram,
        target: SocketAddr,
        active_tasks: Arc<AtomicUsize>,
    ) -> Arc<Self> {
        let local_addr = if target.is_ipv6() {
            SocketAddr::from(([0; 16], 0))
        } else {
            SocketAddr::from(([0; 4], 0))
        };
        let (mut sink, mut stream) = datagram.split();
        let (sender, mut outgoing) = mpsc::channel(QUEUE_CAPACITY);
        let (incoming, receiver) = mpsc::channel(QUEUE_CAPACITY);
        let state = Arc::new(BridgeState::default());
        let send_state = Arc::clone(&state);
        let send_task = OwnedTask::spawn(
            async move {
                while let Some(packet) = tokio::select! {
                    _ = send_state.cancelled.cancelled() => return,
                    packet = outgoing.recv() => packet,
                } {
                    send_state.writable.notify_waiters();
                    let result = tokio::select! {
                        _ = send_state.cancelled.cancelled() => return,
                        result = sink.send(packet) => result,
                    };
                    if let Err(error) = result {
                        send_state.fail(error);
                        return;
                    }
                }
            },
            Arc::clone(&active_tasks),
        );
        let receive_state = Arc::clone(&state);
        let receive_task = OwnedTask::spawn(
            async move {
                while let Some(packet) = tokio::select! {
                    _ = receive_state.cancelled.cancelled() => return,
                    packet = stream.next() => packet,
                } {
                    // Each association serves one DNS peer. Accept equivalent IPv4
                    // and mapped IPv6 addresses, while preserving the peer port check.
                    if !matches!(packet.src_addr, SocksAddr::Ip(source)
                        if source.port() == target.port()
                            && source.ip().to_canonical() == target.ip().to_canonical())
                        || packet.data.is_empty()
                    {
                        continue;
                    }
                    tokio::select! {
                        _ = receive_state.cancelled.cancelled() => return,
                        result = incoming.send(packet) => if result.is_err() { return; },
                    }
                }
                receive_state.fail(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "proxy QUIC UDP association closed",
                ));
            },
            active_tasks,
        );
        Arc::new(Self {
            sender,
            receiver: Mutex::new(receiver),
            state,
            tasks: Mutex::new(vec![send_task, receive_task]),
            local_addr,
            target,
        })
    }

    pub(super) fn is_closed(&self) -> bool {
        self.state.check().is_err()
    }

    pub(super) async fn close(&self) {
        self.state.fail(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "proxy QUIC socket closed",
        ));
        let tasks = std::mem::take(&mut *self.tasks.lock());
        for task in tasks {
            task.shutdown(Duration::ZERO).await;
        }
    }
}

impl AsyncUdpSocket for ProxyQuicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(ProxyUdpPoller {
            socket: self,
            notified: None,
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.state.check()?;
        if transmit.destination != self.target {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy QUIC peer changed",
            ));
        }
        // Quinn uses max_transmit_segments() == 1, so every send is one packet.
        if transmit
            .segment_size
            .is_some_and(|size| size < transmit.contents.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy QUIC socket does not support UDP segmentation",
            ));
        }
        if self.sender.capacity() == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.sender
            .try_send(UdpPacket::new(
                bytes::Bytes::copy_from_slice(transmit.contents),
                self.local_addr.into(),
                self.target.into(),
            ))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    io::Error::from(io::ErrorKind::WouldBlock)
                }
                mpsc::error::TrySendError::Closed(_) => io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "proxy QUIC sender closed",
                ),
            })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.state.reader.register(cx.waker());
        if let Err(error) = self.state.check() {
            return Poll::Ready(Err(error));
        }
        let mut receiver = self.receiver.lock();
        let mut count = 0;
        'buffers: for (buffer, meta) in bufs.iter_mut().zip(meta.iter_mut()) {
            let packet = loop {
                let packet = match receiver.poll_recv(cx) {
                    Poll::Ready(Some(packet)) => packet,
                    Poll::Ready(None) if count == 0 => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "proxy QUIC receiver closed",
                        )));
                    }
                    Poll::Ready(None) | Poll::Pending => break 'buffers,
                };
                if packet.data.len() > buffer.len() {
                    tracing::warn!(
                        peer = %self.target,
                        packet_len = packet.data.len(),
                        buffer_len = buffer.len(),
                        "dropping oversized proxy QUIC datagram"
                    );
                    continue;
                }
                break packet;
            };
            buffer[..packet.data.len()].copy_from_slice(&packet.data);
            *meta = RecvMeta {
                addr: self.target,
                len: packet.data.len(),
                stride: packet.data.len(),
                ecn: None,
                dst_ip: None,
            };
            count += 1;
        }
        if count == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(count))
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

struct ProxyUdpPoller {
    socket: Arc<ProxyQuicSocket>,
    notified: Option<Pin<Box<OwnedNotified>>>,
}

impl fmt::Debug for ProxyUdpPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyUdpPoller").finish()
    }
}

impl UdpPoller for ProxyUdpPoller {
    fn poll_writable(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let notified = this.notified.get_or_insert_with(|| {
                Box::pin(Arc::clone(&this.socket.state.writable).notified_owned())
            });
            // Register before checking capacity: draining the queue must not lose a wakeup.
            notified.as_mut().enable();
            if let Err(error) = this.socket.state.check() {
                return Poll::Ready(Err(error));
            }
            if this.socket.sender.capacity() > 0 {
                this.notified = None;
                return Poll::Ready(Ok(()));
            }
            if notified.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            this.notified = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::datagram::ChannelDatagram;
    use std::sync::atomic::Ordering;

    fn fixture() -> (
        Arc<ProxyQuicSocket>,
        mpsc::Sender<UdpPacket>,
        mpsc::Receiver<UdpPacket>,
        Arc<AtomicUsize>,
    ) {
        fixture_for_target("127.0.0.1:853".parse().unwrap())
    }

    fn fixture_for_target(
        target: SocketAddr,
    ) -> (
        Arc<ProxyQuicSocket>,
        mpsc::Sender<UdpPacket>,
        mpsc::Receiver<UdpPacket>,
        Arc<AtomicUsize>,
    ) {
        let (outgoing, receiver) = mpsc::channel(1);
        let (sender, incoming) = mpsc::channel(1);
        let active = Arc::new(AtomicUsize::new(0));
        let socket = ProxyQuicSocket::new(
            AnyOutboundDatagram::dynamic(ChannelDatagram::new(outgoing, incoming)),
            target,
            active.clone(),
        );
        (socket, sender, receiver, active)
    }

    fn transmit(socket: &ProxyQuicSocket) -> Transmit<'static> {
        Transmit {
            destination: socket.target,
            ecn: None,
            contents: b"QUIC packet",
            segment_size: None,
            src_ip: None,
        }
    }

    async fn recv(socket: &ProxyQuicSocket) -> io::Result<Vec<u8>> {
        let mut buffer = [0; 2048];
        let mut meta = [RecvMeta::default()];
        futures::future::poll_fn(|cx| {
            socket.poll_recv(cx, &mut [IoSliceMut::new(&mut buffer)], &mut meta)
        })
        .await?;
        assert_eq!(meta[0].addr, socket.target);
        assert_eq!(meta[0].stride, meta[0].len);
        assert_eq!(meta[0].ecn, None);
        Ok(buffer[..meta[0].len].to_vec())
    }

    #[tokio::test]
    async fn bridge_preserves_datagrams_and_wakes_multiple_writers() {
        let (socket, incoming, mut outgoing, active) = fixture();
        let packet = transmit(&socket);
        for _ in 0..QUEUE_CAPACITY {
            socket.try_send(&packet).unwrap();
        }
        assert_eq!(
            socket.try_send(&packet).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let mut first = socket.clone().create_io_poller();
        let mut second = socket.clone().create_io_poller();
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(first.as_mut().poll_writable(&mut cx).is_pending());
        assert!(second.as_mut().poll_writable(&mut cx).is_pending());
        tokio::time::timeout(Duration::from_secs(1), async {
            let (a, b) = tokio::join!(
                futures::future::poll_fn(|cx| first.as_mut().poll_writable(cx)),
                futures::future::poll_fn(|cx| second.as_mut().poll_writable(cx)),
            );
            a.unwrap();
            b.unwrap();
        })
        .await
        .unwrap();
        let sent = outgoing.recv().await.unwrap();
        assert_eq!(sent.dst_addr, SocksAddr::Ip(socket.target));
        assert_eq!(&sent.data[..], packet.contents);
        incoming
            .send(UdpPacket::new(
                bytes::Bytes::from_static(b"reply"),
                socket.target.into(),
                socket.local_addr.into(),
            ))
            .await
            .unwrap();
        assert_eq!(recv(&socket).await.unwrap(), b"reply");
        socket.close().await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn oversized_datagram_is_dropped_and_reader_waits_for_next_packet() {
        let (socket, incoming, _outgoing, active) = fixture();
        incoming
            .send(UdpPacket::new(
                bytes::Bytes::from(vec![0; 4096]),
                socket.target.into(),
                socket.local_addr.into(),
            ))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while socket.receiver.lock().len() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut buffer = [0; 2048];
        let mut meta = [RecvMeta::default()];
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(
            socket
                .poll_recv(&mut cx, &mut [IoSliceMut::new(&mut buffer)], &mut meta,)
                .is_pending()
        );
        assert!(!socket.is_closed());
        let producer = async {
            tokio::task::yield_now().await;
            incoming
                .send(UdpPacket::new(
                    bytes::Bytes::from_static(b"valid"),
                    socket.target.into(),
                    socket.local_addr.into(),
                ))
                .await
                .unwrap();
        };
        let (response, ()) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(recv(&socket), producer)
        })
        .await
        .unwrap();
        assert_eq!(response.unwrap(), b"valid");
        socket.close().await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn oversized_datagrams_do_not_discard_valid_packets_in_a_batch() {
        let (socket, incoming, _outgoing, active) = fixture();
        for data in [
            bytes::Bytes::from(vec![0; 4096]),
            bytes::Bytes::from_static(b"first"),
            bytes::Bytes::from(vec![0; 4096]),
            bytes::Bytes::from_static(b"second"),
        ] {
            incoming
                .send(UdpPacket::new(
                    data,
                    socket.target.into(),
                    socket.local_addr.into(),
                ))
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while socket.receiver.lock().len() != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut first = [0; 2048];
        let mut second = [0; 2048];
        let mut meta = [RecvMeta::default(); 2];
        let count = futures::future::poll_fn(|cx| {
            socket.poll_recv(
                cx,
                &mut [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)],
                &mut meta,
            )
        })
        .await
        .unwrap();
        assert_eq!(count, 2);
        assert_eq!(&first[..meta[0].len], b"first");
        assert_eq!(&second[..meta[1].len], b"second");
        assert!(!socket.is_closed());
        socket.close().await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn mapped_ipv6_peers_match_ipv4_in_both_directions_without_accepting_other_peers()
     {
        let ipv4: SocketAddr = "127.0.0.1:853".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:853".parse().unwrap();
        for (target, equivalent) in [(ipv4, mapped), (mapped, ipv4)] {
            let (socket, incoming, _outgoing, active) = fixture_for_target(target);
            for source in [
                "127.0.0.2:853",
                "[::ffff:127.0.0.2]:853",
                "[::ffff:127.0.0.1]:854",
                "[::127.0.0.1]:853",
            ] {
                incoming
                    .send(UdpPacket::new(
                        bytes::Bytes::from_static(b"unrelated"),
                        source.parse::<SocketAddr>().unwrap().into(),
                        socket.local_addr.into(),
                    ))
                    .await
                    .unwrap();
            }
            incoming
                .send(UdpPacket::new(
                    bytes::Bytes::from_static(b"equivalent"),
                    equivalent.into(),
                    socket.local_addr.into(),
                ))
                .await
                .unwrap();
            let response =
                tokio::time::timeout(Duration::from_secs(1), recv(&socket))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(response, b"equivalent");
            assert!(!socket.is_closed());
            socket.close().await;
            assert_eq!(active.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn association_eof_wakes_reader_and_fails_sender() {
        let (socket, incoming, _outgoing, active) = fixture();
        let closer = tokio::spawn(async move {
            tokio::task::yield_now().await;
            drop(incoming);
        });
        let error = tokio::time::timeout(Duration::from_secs(1), recv(&socket))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(
            socket.try_send(&transmit(&socket)).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        let mut poller = socket.clone().create_io_poller();
        assert!(
            futures::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
                .await
                .is_err()
        );
        closer.await.unwrap();
        socket.close().await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn send_failure_wakes_pending_reader() {
        let (socket, _incoming, outgoing, active) = fixture();
        drop(outgoing);
        socket.try_send(&transmit(&socket)).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), recv(&socket))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        socket.close().await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
