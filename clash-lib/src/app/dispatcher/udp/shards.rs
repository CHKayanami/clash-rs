use std::{
    array::from_fn, collections::VecDeque, net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}},
    task::{Context, Poll, ready},
};

use futures::stream::poll_fn;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio_util::task::AbortOnDropHandle;
use tracing::{Instrument, Span, debug};

use super::{QueueDrops, UDP_ROUTE_SHARDS, UdpDispatchContext, UdpQueueLimits,
    association::FlowClosed, routes};
use crate::{
    app::sniffer::ArcSniffer,
    proxy::datagram::UdpPacket,
    session::{Session, SocksAddr},
};

#[derive(Clone)]
pub(crate) struct UdpRouteIngress {
    shards: Arc<[RouteSender]>,
    drops: Option<Arc<QueueDrops>>,
}

impl UdpRouteIngress {
    /// Keep serving other flows when one shard is full. A closed shard ends
    /// the listener, as it can no longer route all client traffic.
    pub(crate) fn send_batch(&self, packets: impl IntoIterator<Item = UdpPacket>) -> bool {
        let mut dropped = 0;
        let mut batches: [_; UDP_ROUTE_SHARDS] = from_fn(|_| RoutePackets::default());
        for mut packet in packets {
            let SocksAddr::Ip(source) = &mut packet.src_addr else { continue };
            source.set_ip(source.ip().to_canonical());
            let index = route_shard(*source);
            if batches[index].len() == self.shards[index].capacity {
                dropped += 1;
            } else {
                batches[index].push_back(packet);
            }
        }
        let mut open = true;
        for (shard, batch) in self.shards.iter().zip(batches) {
            let Some(rejected) = shard.send(batch) else {
                open = false;
                break;
            };
            dropped += rejected;
        }
        if dropped > 0 {
            if let Some(drops) = &self.drops {
                drops.report("ingress", dropped);
            } else {
                debug!(dropped, "UDP route queue full");
            }
        }
        open
    }
}

/// A singleton goes through the queue without allocating a packet buffer.
#[derive(Default)]
struct RoutePackets {
    first: Option<UdpPacket>,
    rest: VecDeque<UdpPacket>,
}

impl RoutePackets {
    fn len(&self) -> usize { usize::from(self.first.is_some()) + self.rest.len() }

    fn push_back(&mut self, packet: UdpPacket) {
        if self.first.is_none() { self.first = Some(packet); }
        else { self.rest.push_back(packet); }
    }

    fn pop_front(&mut self) -> Option<UdpPacket> {
        self.first.take().or_else(|| self.rest.pop_front())
    }
}

struct RouteBatch {
    packets: RoutePackets,
    credits: Arc<AtomicUsize>,
}

impl RouteBatch {
    fn pop_front(&mut self) -> Option<UdpPacket> {
        let packet = self.packets.pop_front()?;
        self.credits.fetch_add(1, Ordering::Release);
        Some(packet)
    }
}

impl Drop for RouteBatch {
    fn drop(&mut self) {
        let remaining = self.packets.len();
        if remaining != 0 { self.credits.fetch_add(remaining, Ordering::Release); }
    }
}

struct RouteSender {
    channel: mpsc::Sender<RouteBatch>,
    capacity: usize,
    credits: Arc<AtomicUsize>,
}

impl RouteSender {
    /// Reserve the accepted prefix in one operation. Credits continue to
    /// cover packets held by the receiver between routing turns.
    fn send(&self, mut packets: RoutePackets) -> Option<usize> {
        let len = packets.len();
        if len == 0 { return Some(0); }
        let previous = self.credits.try_update(Ordering::AcqRel, Ordering::Acquire, |free| {
            (free != 0).then(|| free - len.min(free))
        });
        let Ok(previous) = previous else {
            return (!self.channel.is_closed()).then_some(len);
        };
        let admitted = previous.min(len);
        packets.rest.truncate(admitted - 1);
        let batch = RouteBatch { packets, credits: self.credits.clone() };
        // Each queued batch owns at least one packet credit. The channel
        // has that many slots, including when each message is a singleton.
        match self.channel.try_send(batch) {
            Ok(()) => Some(len - admitted),
            Err(TrySendError::Closed(_)) => None,
            Err(TrySendError::Full(_)) => Some(len),
        }
    }
}

struct RouteReceiver {
    channel: mpsc::Receiver<RouteBatch>,
    current: Option<RouteBatch>,
}

impl RouteReceiver {
    fn poll_packet(&mut self, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>> {
        if self.current.is_none() {
            self.current = ready!(self.channel.poll_recv(cx));
        }
        let Some(batch) = &mut self.current else { return Poll::Ready(None); };
        let packet = batch.pop_front();
        if batch.packets.len() == 0 {
            self.current = None;
        }
        Poll::Ready(packet)
    }
}

fn route_channel(capacity: usize) -> (RouteSender, RouteReceiver) {
    let (sender, receiver) = mpsc::channel(capacity);
    (RouteSender { channel: sender, capacity, credits: Arc::new(AtomicUsize::new(capacity)) },
        RouteReceiver { channel: receiver, current: None })
}

pub(super) struct RouteShards {
    pub(super) ingress: UdpRouteIngress,
    closed: Vec<mpsc::UnboundedSender<FlowClosed>>,
    _tasks: Vec<AbortOnDropHandle<()>>,
}

impl RouteShards {
    pub(super) fn spawn(
        sess: Session, ctx: UdpDispatchContext, sniffer: Option<ArcSniffer>,
        allow_quic: Arc<AtomicBool>, limits: UdpQueueLimits,
    ) -> Self {
        let mut packets = Vec::with_capacity(UDP_ROUTE_SHARDS);
        let mut closed = Vec::with_capacity(UDP_ROUTE_SHARDS);
        let mut tasks = Vec::with_capacity(UDP_ROUTE_SHARDS);
        for _ in 0..UDP_ROUTE_SHARDS {
            let (packet_tx, mut incoming) = route_channel(limits.per_route_shard);
            let (closed_tx, closed_rx) = mpsc::unbounded_channel();
            tasks.push(AbortOnDropHandle::new(tokio::spawn(routes::run(
                sess.clone(), ctx.clone(), sniffer.clone(), allow_quic.clone(),
                poll_fn(move |cx| incoming.poll_packet(cx)), closed_rx,
            ).instrument(Span::current()))));
            packets.push(packet_tx);
            closed.push(closed_tx);
        }
        let drops = limits.warn_on_drop.then(|| Arc::new(QueueDrops::default()));
        Self { ingress: UdpRouteIngress { shards: packets.into(), drops }, closed, _tasks: tasks }
    }

    pub(super) fn flow_closed(&self, flow: FlowClosed) {
        let _ = self.closed[route_shard(flow.source)].send(flow);
    }
}

fn route_shard(source: SocketAddr) -> usize {
    let ip = match source.ip() {
        IpAddr::V4(ip) => u32::from(ip),
        IpAddr::V6(ip) => ip.segments().iter().fold(0u32, |hash, value| hash.rotate_left(5) ^ u32::from(*value)),
    };
    (ip ^ u32::from(source.port())) as usize % UDP_ROUTE_SHARDS
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV6};

    use bytes::Bytes;
    use futures::task::noop_waker_ref;

    use super::*;

    #[test]
    fn ingress_drops_full_shard_packets_without_stalling_others() {
        let (senders, mut receivers): (Vec<_>, Vec<_>) =
            (0..UDP_ROUTE_SHARDS).map(|_| route_channel(1)).unzip();
        let drops = Arc::new(QueueDrops::default());
        let ingress = UdpRouteIngress { shards: senders.into(), drops: Some(drops.clone()) };
        let ip = Ipv4Addr::LOCALHOST;
        let first = SocketAddr::from((ip, 4000));
        let second = SocketAddr::from((ip, 4001));
        let mapped = SocketAddrV6::new(ip.to_ipv6_mapped(), first.port(), 0, 0);
        let dest = SocketAddr::from((ip, 5000));
        let packet = |source: SocketAddr, data| {
            UdpPacket::new(Bytes::from_static(data), source.into(), dest.into())
        };

        assert!(ingress.send_batch([
            packet(mapped.into(), b"first"),
            packet(first, b"drop"),
            packet(second, b"second"),
        ]));
        let mut cx = Context::from_waker(noop_waker_ref());
        let Poll::Ready(Some(received)) = receivers[route_shard(first)].poll_packet(&mut cx)
            else { panic!("expected a packet"); };
        assert_eq!(received.src_addr, first.into());
        assert_eq!(received.data.as_ref(), b"first");
        assert!(receivers[route_shard(first)].poll_packet(&mut cx).is_pending());
        assert_eq!(drops.0.load(Ordering::Relaxed), 1);
        let Poll::Ready(Some(received)) = receivers[route_shard(second)].poll_packet(&mut cx)
            else { panic!("expected a packet"); };
        assert_eq!(received.data.as_ref(), b"second");

        receivers[route_shard(first)].channel.close();
        assert!(!ingress.send_batch([packet(first, b"closed")]));
    }

    #[test]
    fn route_batches_hold_credits_until_packets_are_yielded() {
        let (senders, mut receivers): (Vec<_>, Vec<_>) =
            (0..UDP_ROUTE_SHARDS).map(|_| route_channel(3)).unzip();
        let drops = Arc::new(QueueDrops::default());
        let ingress = UdpRouteIngress { shards: senders.into(), drops: Some(drops.clone()) };
        let source = SocketAddr::from(([127, 0, 0, 1], 4000));
        let index = route_shard(source);
        let sender = &ingress.shards[index];
        let receiver = &mut receivers[index];
        let packet = |byte| UdpPacket { data: Bytes::from(vec![byte]), src_addr: source.into(),
            ..Default::default() };
        let mut cx = Context::from_waker(noop_waker_ref());
        let mut next = |receiver: &mut RouteReceiver| {
            let Poll::Ready(Some(packet)) = receiver.poll_packet(&mut cx)
                else { panic!("expected a packet"); };
            packet.data[0]
        };

        assert!(ingress.send_batch((1..=4).map(packet)));
        assert_eq!(receiver.channel.len(), 1);
        assert_eq!(sender.credits.load(Ordering::Acquire), 0);
        assert_eq!(next(receiver), 1);
        assert!(receiver.channel.is_empty());
        assert_eq!(sender.credits.load(Ordering::Acquire), 1);

        assert!(ingress.send_batch((5..=6).map(packet)));
        assert_eq!(drops.0.load(Ordering::Relaxed), 2);
        assert_eq!([next(receiver), next(receiver)], [2, 3]);
        assert_eq!(next(receiver), 5);
        assert!(receiver.current.is_none());
        assert_eq!(sender.credits.load(Ordering::Acquire), 3);

        assert!(ingress.send_batch((7..=9).map(packet)));
        assert_eq!(next(receiver), 7);
        drop(receivers);
        assert_eq!(sender.credits.load(Ordering::Acquire), 3);
    }
}
