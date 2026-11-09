//! Synchronously driven TCP owner for a combined device/protocol event loop.
use std::{io, pin::Pin, sync::Arc, task::{Context, Poll}, time::Duration};
use tokio::{sync::mpsc, time::{Instant, Sleep, sleep}};
use super::{Engine, Ready, ReadyQueue, SOCKET_BUDGET};
use crate::{Packet, TcpListener, TcpStream, link::device::NetstackDevice};

pub struct TcpDriver {
    engine: Engine,
    streams: mpsc::Sender<TcpStream>,
    ready: Vec<Arc<Ready>>,
    timer: Option<Pin<Box<Sleep>>>,
}

impl TcpDriver {
    /// No background task or TCP packet channels are created. Protocol input
    /// is bounded independently of device reads and output reservations.
    pub fn new(mtu: usize, output_packets: usize) -> io::Result<(Self, TcpListener)> {
        if !(1280..=65535).contains(&mtu) || output_packets == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid TCP device limits"));
        }
        let (streams, incoming) = mpsc::channel(256);
        let engine = Engine::with_device(NetstackDevice::local(output_packets),
            Arc::new(ReadyQueue::default()), mtu);
        let listener = TcpListener::local(incoming, engine.ready.clone());
        Ok((Self { engine, streams, ready: Vec::with_capacity(SOCKET_BUDGET), timer: None }, listener))
    }

    /// Enable native segmentation only when the caller preserves packet
    /// metadata and writes frames through a device supporting TCP offload.
    pub fn enable_tcp_gso(&mut self) { self.engine.driver.enable_tcp_gso(); }

    /// Returns non-TCP/ICMP packets to the caller even when TCP input is full.
    /// Congestion drops only the incoming TCP/ICMP packet, before socket state
    /// changes, rather than blocking the shared device reader.
    pub fn receive(&mut self, packet: Packet) -> io::Result<Option<Packet>> {
        self.engine.admit(packet, &self.streams)
    }

    pub fn take_output(&mut self) -> Option<Packet> { self.engine.device.pop_output() }

    /// Poll one bounded protocol/application pass and register native socket,
    /// application and deadline wakeups directly on the device-loop task.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_with_output(cx, &mut |_, _, _| false)
    }

    /// The transmitter may borrow header/payload only for the duration of the
    /// call. Headers contain a partial checksum seed and require device checksum
    /// offload. Return false without sending any bytes to use queued output.
    pub fn poll_with_output(&mut self, cx: &mut Context<'_>,
        transmit: &mut dyn FnMut(&[u8], &[u8], Option<u16>) -> bool) -> Poll<io::Result<()>> {
        if self.streams.is_closed() { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); }
        self.engine.ready.waker.register(cx.waker());
        let (work, delay) = self.engine.step_with_output(&mut self.ready, transmit);
        if work { return Poll::Ready(Ok(())); }
        if let Some(delay) = delay {
            let timer = self.timer.get_or_insert_with(|| Box::pin(sleep(Duration::ZERO)));
            timer.as_mut().reset(Instant::now() + Duration::from(delay));
            if timer.as_mut().poll(cx).is_ready() { return Poll::Ready(Ok(())); }
        }
        Poll::Pending
    }
}
