//! One owner for packet admission, socket registration and TCP polling.
use std::{collections::HashMap, io, net::SocketAddr, sync::{Arc, atomic::Ordering},
    task::{Context, Poll}, time::Duration};
use futures::task::waker_ref;
use smoltcp::{
    time::{Instant as StackInstant, Duration as StackDuration}, wire::{IpProtocol, TcpPacket}};
use tokio::{sync::mpsc, time::{Instant, sleep}};
use super::{driver::Driver, connections::{SocketHandle, SocketTable}, protocol as tcp};
use crate::{Packet, link::device::NetstackDevice, link::packet::IpPacket,
    tcp::ready::{Ready, ReadyQueue}, tcp::buffers::Buffers,
    tcp::forward::{Forward, past_handshake}, tcp::listener::{TcpStreamHandle,
        closed_error, new_stream}, tcp::stream::TcpStream};

const PACKET_BUDGET: usize = 32;
const SOCKET_BUDGET: usize = 128;
const MAX_CONNECTIONS: usize = 10_000;

struct Entry {
    socket: SocketHandle,
    buffers: Buffers,
    handle: Arc<TcpStreamHandle>,
    forward: Option<Forward>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.handle.close();
        if let Some(forward) = self.forward.take() { forward.finish(Err(closed_error())); }
        // Also release a handoff submitted just as the engine stopped.
        self.handle.forward.lock().unwrap().take();
    }
}

pub(crate) struct Engine {
    driver: Driver,
    device: NetstackDevice,
    sockets: SocketTable,
    entries: HashMap<u64, Entry>,
    ready: Arc<ReadyQueue>,
}

impl Engine {
    pub fn new(outbound: mpsc::Sender<Packet>, ready: Arc<ReadyQueue>, mtu: usize) -> Self {
        let device = NetstackDevice::new(outbound);
        let driver = Driver::new(mtu);
        Self { driver, device, sockets: SocketTable::new(), entries: HashMap::new(),
            ready }
    }

    pub async fn run(mut self, mut inbound: mpsc::Receiver<Packet>,
        streams: mpsc::Sender<TcpStream>) -> io::Result<()> {
        let mut packet = None;
        let mut ready_batch = Vec::with_capacity(SOCKET_BUDGET);
        let output = self.device.output().clone();
        let mut timer = Box::pin(sleep(Duration::ZERO));
        loop {
            // Keep the local device queue bounded to one ingress batch. Socket
            // registration and SYN injection happen together in admit().
            if self.device.is_empty() {
                for _ in 0..PACKET_BUDGET {
                    let frame = packet.take().or_else(|| inbound.try_recv().ok());
                    let Some(frame) = frame else { break; };
                    self.admit(frame, &streams)?;
                }
            }
            self.driver.ingress(StackInstant::now(), &mut self.device, &mut self.sockets);
            self.reap_completed();
            self.ready.take_batch(&mut ready_batch, SOCKET_BUDGET);
            for ready in ready_batch.drain(..) {
                ready.begin_service();
                if self.service(ready.id) && let Some(entry) = self.entries.get(&ready.id) {
                    self.driver.refresh(StackInstant::now(), entry.socket, &mut self.sockets);
                }
            }
            self.driver.poll_egress(StackInstant::now(), &mut self.device, &mut self.sockets);
            self.reap_completed();
            let delay = self.driver.poll_delay(StackInstant::now());
            let blocked_output = !self.device.output_available();
            if streams.is_closed() || output.is_closed() { return Ok(()); }
            if !self.ready.is_empty() || (!self.device.is_empty() && !blocked_output)
                || (self.device.is_empty() && !inbound.is_empty())
                || (self.driver.has_ready() && !blocked_output)
                || delay == Some(StackDuration::ZERO) {
                // Each pass services bounded ingress, application and protocol
                // work, including timers even while the output link is blocked.
                tokio::task::yield_now().await;
                continue;
            }
            let timer_enabled = delay.is_some();
            if let Some(delay) = delay {
                timer.as_mut().reset(Instant::now() + Duration::from(delay));
            }
            tokio::select! {
                value = inbound.recv(), if self.device.is_empty() => {
                    packet = value;
                    if packet.is_none() { return Ok(()); }
                }
                _ = self.ready.notify.notified() => {}
                // None means no protocol timer, not a request for a busy poll.
                _ = timer.as_mut(), if timer_enabled => {}
                permit = output.reserve(), if blocked_output => {
                    drop(permit.map_err(|_| io::ErrorKind::BrokenPipe)?);
                }
                _ = streams.closed() => return Ok(()),
                _ = output.closed() => return Ok(()),
            }
        }
    }

    fn admit(&mut self, frame: Packet, streams: &mpsc::Sender<TcpStream>) -> io::Result<()> {
        let packet = match IpPacket::new_checked(frame.data()) {
            Ok(packet) => packet,
            Err(_) => return Ok(()),
        };
        if matches!(packet.protocol(), IpProtocol::Icmp | IpProtocol::Icmpv6) {
            self.device.inject(frame);
            return Ok(());
        }
        if packet.protocol() != IpProtocol::Tcp { return Ok(()); }
        let tcp = match TcpPacket::new_checked(packet.payload()) {
            Ok(tcp) => tcp,
            Err(_) => return Ok(()),
        };
        if tcp.syn() && !tcp.ack() {
            let tuple = (SocketAddr::new(packet.src_addr(), tcp.src_port()),
                SocketAddr::new(packet.dst_addr(), tcp.dst_port()));
            if self.sockets.find(&tuple).is_some() { self.device.inject(frame); return Ok(()); }
            if !Driver::valid_syn(&frame) { return Ok(()); }
            if self.entries.len() >= MAX_CONNECTIONS { return Ok(()); }
            let permit = match streams.try_reserve() { Ok(permit) => permit, Err(_) => return Ok(()) };
            let (buffers, mut socket) = Buffers::new();
            socket.set_keep_alive(Some(StackDuration::from_secs(28)));
            socket.set_timeout(Some(StackDuration::from_secs(60)));
            socket.set_ack_delay(Some(Duration::from_millis(10).into()));
            socket.set_nagle_enabled(false);
            socket.set_congestion_control(tcp::CongestionControl::Cubic);
            socket.listen(tuple.1).map_err(|error| io::Error::other(error.to_string()))?;
            let socket = self.sockets.add(socket, tuple);
            let id = socket.0;
            let ready = Ready::new(id, self.ready.clone());
            let (stream, handle) = new_stream(tuple.0, tuple.1, ready.clone());
            self.entries.insert(id, Entry { socket, buffers, handle, forward: None });
            ready.schedule();
            permit.send(stream);
        }
        self.device.inject(frame);
        Ok(())
    }

    /// Protocol completion is reported directly, even if its one-shot waker
    /// was consumed before a budget-limited RST could be emitted.
    fn reap_completed(&mut self) {
        while let Some(handle) = self.driver.pop_completed() {
            assert_eq!(self.entries.get(&handle.0).expect("completed TCP entry").socket, handle);
            // Run final relay/adapter handling inline before dropping buffers.
            // No protocol waker or second ready-queue dispatch is required.
            self.service(handle.0);
            assert!(!self.entries.contains_key(&handle.0), "completed TCP entry retained");
        }
    }

    fn service(&mut self, id: u64) -> bool {
        let Some(entry) = self.entries.get_mut(&id) else { return false; };
        let started = self.sockets.started(entry.socket);
        let socket = self.sockets.get_mut(entry.socket);
        let before = (socket.state(), socket.recv_queue(), socket.send_queue());
        let waker = waker_ref(&entry.handle.ready);
        let mut cx = Context::from_waker(&waker);
        // Old registrations can still be armed from a previous service. There
        // is no concurrent TCP processing: disarm them while the owner mutates
        // the socket. Native Tokio I/O still uses the independent cx above.
        socket.clear_wakers();
        let aborted = entry.handle.abort.swap(false, Ordering::AcqRel);
        let mut grown = false;
        if aborted {
            socket.abort();
            entry.handle.close();
            entry.handle.forward.lock().unwrap().take();
            entry.handle.forward_pending.store(false, Ordering::Relaxed);
            if let Some(forward) = entry.forward.take() { forward.finish(Err(closed_error())); }
        } else if started || socket.state() != tcp::State::Listen {
            if entry.handle.forward_pending.load(Ordering::Acquire) {
                entry.forward = entry.handle.forward.lock().unwrap().take().map(Forward::new);
                entry.handle.forward_pending.store(false, Ordering::Relaxed);
            }
            if let Some(forward) = &mut entry.forward {
                if let Poll::Ready(result) = forward.poll(socket, &entry.handle, &mut cx) {
                    if result.is_err() { socket.abort(); }
                    entry.forward.take().unwrap().finish(result);
                }
            } else {
                pump_stream(socket, &entry.handle);
            }
            let consumed = before.1.saturating_sub(socket.recv_queue());
            let send_capacity = socket.send_capacity();
            // Count only a fresh fill by this relay pass, not an unchanged
            // full queue revisited by unrelated wakes or stalled peers.
            let send_limited = socket.may_send() && !socket.can_send()
                && socket.send_queue() > before.2;
            grown = socket.is_active() && past_handshake(socket)
                && entry.buffers.grow(socket, consumed, send_limited);
            if socket.send_capacity() > send_capacity { entry.handle.notify(); }
        }
        let changed = aborted || grown || before != (socket.state(), socket.recv_queue(), socket.send_queue());
        if !socket.is_active() && socket.remote_endpoint().is_none()
            && (started || socket.state() != tcp::State::Listen) {
            let socket_handle = entry.socket;
            self.driver.remove(socket_handle, &mut self.sockets);
            self.entries.remove(&id);
        } else {
            // Includes pending SYNs and aborts waiting for RST capacity. Arm
            // only after close/growth/abort can no longer consume these wakes.
            socket.register_recv_waker(&waker);
            socket.register_send_waker(&waker);
        }
        changed
    }

}

fn pump_stream(socket: &mut tcp::Socket<'_>, handle: &TcpStreamHandle) {
    // Publish before checking ring capacity: a concurrent consumer either
    // frees space for this pass or observes the flag and schedules another.
    handle.recv_pending.store(socket.can_recv(), Ordering::Release);
    let mut budget = 64 * 1024;
    while socket.can_recv() && !handle.recv().is_full() && budget > 0 {
        let n = socket.recv(|data| {
            let n = handle.recv().enqueue_slice(&data[..data.len().min(budget)]);
            (n, n)
        }).unwrap_or(0);
        if n == 0 { break; }
        budget -= n;
    }
    if budget < 64 * 1024 { handle.recv_waker.wake(); }
    if !socket.can_recv() { handle.recv_pending.store(false, Ordering::Release); }
    if budget == 0 && socket.can_recv() && !handle.recv().is_full() { handle.notify(); }
    let mut budget = 64 * 1024;
    if let Some(buffer) = handle.send_buffer.get() {
        while socket.can_send() && !buffer.is_empty() && budget > 0 {
            let n = socket.send(|data| {
                let length = data.len().min(budget);
                let n = buffer.dequeue_slice(&mut data[..length]);
                (n, n)
            }).unwrap_or(0);
            if n == 0 { break; }
            budget -= n;
        }
    }
    if budget < 64 * 1024 { handle.send_waker.wake(); }
    if budget == 0 && socket.can_send()
        && handle.send_buffer.get().is_some_and(|buffer| !buffer.is_empty()) { handle.notify(); }
    if past_handshake(socket) && !socket.may_recv() && !socket.can_recv()
        && !handle.read_closed.swap(true, Ordering::AcqRel) { handle.recv_waker.wake(); }
    let drained = handle.send_buffer.get().is_none_or(|buffer| buffer.is_empty());
    if drained && (handle.write_shutdown.load(Ordering::Acquire)
        || handle.socket_dropped.load(Ordering::Acquire)) { socket.close(); }
    if past_handshake(socket) && !socket.may_send()
        && !handle.write_closed.swap(true, Ordering::AcqRel) { handle.send_waker.wake(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::protocol::SocketBuffer;

    fn half_open() -> (Engine, TcpStream, Arc<ReadyQueue>, SocketHandle, mpsc::Receiver<Packet>) {
        let ready = Arc::new(ReadyQueue::default());
        let (output, receiver) = mpsc::channel(1);
        let mut engine = Engine::new(output, ready.clone(), 1500);
        let (buffers, mut socket) = Buffers::new();
        let flow = ("192.0.2.2:49152".parse().unwrap(), "198.51.100.2:80".parse().unwrap());
        let mut context = tcp::Context::new(1500);
        socket.connect(&mut context, flow.1, flow.0).unwrap();
        let handle = engine.sockets.add(socket, flow);
        let wake = Ready::new(handle.0, ready.clone());
        let (stream, shared) = new_stream(flow.0, flow.1, wake.clone());
        let waker = waker_ref(&wake);
        engine.sockets.get_mut(handle).register_recv_waker(&waker);
        engine.sockets.get_mut(handle).register_send_waker(&waker);
        engine.entries.insert(handle.0, Entry { socket: handle, buffers, handle: shared, forward: None });
        (engine, stream, ready, handle, receiver)
    }

    #[test]
    fn local_close_and_abort_do_not_self_wake_and_rearm_protocol_wakers() {
        for abort in [false, true] {
            let (mut engine, stream, ready, handle, _receiver) = half_open();
            if abort { stream.handle.abort.store(true, Ordering::Release); }
            else { stream.handle.write_shutdown.store(true, Ordering::Release); }
            assert!(engine.service(handle.0));
            assert!(ready.is_empty(), "local mutation consumed an old protocol waker");
            let socket = engine.sockets.get_mut(handle);
            assert_eq!(socket.state(), tcp::State::Closed);
            let capacity = socket.send_capacity() * 2;
            socket.grow_send_buffer(SocketBuffer::new(vec![0; capacity]));
            assert_eq!(ready.pop().unwrap().id, handle.0, "protocol waker was not rearmed");
        }
    }

    #[test]
    fn deferred_reset_completion_is_reaped_without_protocol_wakers() {
        let (mut engine, stream, ready, handle, mut receiver) = half_open();
        stream.handle.abort.store(true, Ordering::Release);
        assert!(engine.service(handle.0));
        engine.driver.refresh(StackInstant::ZERO, handle, &mut engine.sockets);
        engine.device.output().try_send(Packet::new(&b"busy"[..])).unwrap();
        engine.driver.poll_egress(StackInstant::ZERO, &mut engine.device, &mut engine.sockets);
        assert!(engine.entries.contains_key(&handle.0));
        // Simulate a consumed one-shot wake before output capacity returns.
        engine.sockets.get_mut(handle).clear_wakers();
        receiver.try_recv().unwrap();
        engine.driver.poll_egress(StackInstant::ZERO, &mut engine.device, &mut engine.sockets);
        assert!(receiver.try_recv().is_ok());
        assert!(ready.is_empty());
        engine.reap_completed();
        assert!(!engine.entries.contains_key(&handle.0));
        let flow = (stream.local_addr(), stream.remote_addr());
        assert!(engine.sockets.find(&flow).is_none());
        assert_eq!(engine.driver.poll_delay(StackInstant::ZERO), None);
    }
}
