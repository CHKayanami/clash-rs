//! One owner for packet admission, socket registration and TCP polling.
use std::{collections::HashMap, io, net::SocketAddr, sync::{Arc, atomic::Ordering},
    task::{Context, Poll}, time::Duration, future::pending};
use futures::task::waker_ref;
use smoltcp::{iface::{Interface, SocketHandle, SocketSet}, socket::tcp,
    time::{Instant as StackInstant, Duration as StackDuration}, wire::{IpProtocol, TcpPacket}};
use tokio::sync::mpsc;
use crate::{Packet, device::NetstackDevice, interface::new_interface, packet::IpPacket,
    ready::{Ready, ReadyQueue}, ring_buffer::acquire_vec,
    tcp_forward::{Forward, past_handshake}, tcp_listener::{TCP_BUFFER_SIZE, TcpStreamHandle,
        closed_error, new_stream}, tcp_stream::TcpStream};

const PACKET_BUDGET: usize = 32;
const SOCKET_BUDGET: usize = 128;
const MAX_CONNECTIONS: usize = 10_000;

struct Entry {
    socket: SocketHandle,
    handle: Arc<TcpStreamHandle>,
    forward: Option<Forward>,
    tuple: (SocketAddr, SocketAddr),
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
    iface: Interface,
    device: NetstackDevice,
    sockets: SocketSet<'static>,
    entries: HashMap<u64, Entry>,
    tuples: HashMap<(SocketAddr, SocketAddr), u64>,
    ready: Arc<ReadyQueue>,
    next_id: u64,
}

impl Engine {
    pub fn new(outbound: mpsc::Sender<Packet>, ready: Arc<ReadyQueue>) -> Self {
        let mut device = NetstackDevice::new(outbound);
        let iface = new_interface(&mut device);
        Self { iface, device, sockets: SocketSet::new(vec![]), entries: HashMap::new(),
            tuples: HashMap::new(), ready, next_id: 0 }
    }

    pub async fn run(mut self, mut inbound: mpsc::Receiver<Packet>,
        streams: mpsc::Sender<TcpStream>) -> io::Result<()> {
        let mut packet = None;
        let mut protocol_due = true;
        let mut ready_batch = Vec::with_capacity(SOCKET_BUDGET);
        let output = self.device.output().clone();
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
            // Native socket and stream wakes only need their own connection
            // serviced; ingress, timers and output-capacity wakes drive TCP.
            if protocol_due || !self.device.is_empty() {
                self.iface.poll(StackInstant::now(), &mut self.device, &mut self.sockets);
                protocol_due = false;
            }
            self.ready.take_batch(&mut ready_batch, SOCKET_BUDGET);
            let mut protocol_changed = false;
            for ready in ready_batch.drain(..) {
                ready.begin_service();
                protocol_changed |= self.service(ready.id);
            }
            // Only scan protocol output again if service changed a TCP socket.
            if protocol_changed {
                self.iface.poll(StackInstant::now(), &mut self.device, &mut self.sockets);
            }
            let delay = self.iface.poll_delay(StackInstant::now(), &self.sockets);
            let blocked_output = !self.device.output_available();
            if !self.ready.is_empty() || (!self.device.is_empty() && !blocked_output) {
                // A continuous stream of application wakes must not starve
                // retransmission and delayed-ACK timers.
                protocol_due |= delay == Some(StackDuration::ZERO) && !blocked_output;
                tokio::task::yield_now().await;
                continue;
            }
            tokio::select! {
                value = inbound.recv(), if self.device.is_empty() => {
                    packet = value;
                    if packet.is_none() { return Ok(()); }
                }
                _ = self.ready.notify.notified() => {}
                // None means no protocol timer, not a request for a busy poll.
                _ = async { match delay {
                    Some(delay) if !blocked_output || delay != StackDuration::ZERO =>
                        tokio::time::sleep(Duration::from(delay)).await,
                    Some(_) => pending().await,
                    None => pending().await,
                } } => { protocol_due = true; }
                permit = output.reserve(), if blocked_output => {
                    drop(permit.map_err(|_| io::ErrorKind::BrokenPipe)?);
                    protocol_due = true;
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
        let tuple = (SocketAddr::new(packet.src_addr(), tcp.src_port()),
            SocketAddr::new(packet.dst_addr(), tcp.dst_port()));
        if tcp.syn() && !tcp.ack() && !self.tuples.contains_key(&tuple) {
            if self.entries.len() >= MAX_CONNECTIONS { return Ok(()); }
            let permit = match streams.try_reserve() { Ok(permit) => permit, Err(_) => return Ok(()) };
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(acquire_vec(TCP_BUFFER_SIZE)),
                tcp::SocketBuffer::new(acquire_vec(TCP_BUFFER_SIZE)));
            socket.set_keep_alive(Some(StackDuration::from_secs(28)));
            socket.set_timeout(Some(StackDuration::from_secs(60)));
            socket.set_ack_delay(Some(Duration::from_millis(10).into()));
            socket.set_nagle_enabled(false);
            socket.set_congestion_control(tcp::CongestionControl::Cubic);
            socket.listen(tuple.1).map_err(|error| io::Error::other(error.to_string()))?;
            self.next_id += 1;
            let id = self.next_id;
            let ready = Ready::new(id, self.ready.clone());
            let (stream, handle) = new_stream(tuple.0, tuple.1, ready.clone());
            let socket = self.sockets.add(socket);
            self.entries.insert(id, Entry { socket, handle, forward: None, tuple });
            self.tuples.insert(tuple, id);
            ready.schedule();
            permit.send(stream);
        }
        self.device.inject(frame);
        Ok(())
    }

    fn service(&mut self, id: u64) -> bool {
        let Some(entry) = self.entries.get_mut(&id) else { return false; };
        let socket = self.sockets.get_mut::<tcp::Socket>(entry.socket);
        let before = (socket.state(), socket.recv_queue(), socket.send_queue());
        let waker = waker_ref(&entry.handle.ready);
        let mut cx = Context::from_waker(&waker);
        // smoltcp and Tokio readiness both enqueue this same connection ID.
        socket.register_recv_waker(&waker);
        socket.register_send_waker(&waker);
        if entry.handle.abort.load(Ordering::Acquire) {
            entry.handle.abort.store(false, Ordering::Relaxed);
            socket.abort();
            entry.handle.close();
            entry.handle.forward.lock().unwrap().take();
            entry.handle.forward_pending.store(false, Ordering::Relaxed);
            if let Some(forward) = entry.forward.take() { forward.finish(Err(closed_error())); }
            // Keep the socket until protocol polling sends its pending RST.
            return true;
        }
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
        let changed = before != (socket.state(), socket.recv_queue(), socket.send_queue());
        if !socket.is_active() && socket.remote_endpoint().is_none() {
            let socket_handle = entry.socket;
            self.sockets.remove(socket_handle);
            let entry = self.entries.remove(&id).unwrap();
            self.tuples.remove(&entry.tuple);
        }
        changed
    }
}

fn pump_stream(socket: &mut tcp::Socket<'_>, handle: &TcpStreamHandle) {
    let mut budget = 64 * 1024;
    while socket.can_recv() && !handle.recv().is_full() && budget > 0 {
        let n = socket.recv(|data| {
            let n = handle.recv().enqueue_slice(&data[..data.len().min(budget)]);
            (n, n)
        }).unwrap_or(0);
        if n == 0 { break; }
        budget -= n;
        handle.recv_waker.wake();
    }
    if budget == 0 { handle.notify(); }
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
            handle.send_waker.wake();
        }
    }
    if budget == 0 { handle.notify(); }
    if past_handshake(socket) && !socket.may_recv() && !socket.can_recv()
        && !handle.read_closed.swap(true, Ordering::AcqRel) { handle.recv_waker.wake(); }
    let drained = handle.send_buffer.get().is_none_or(|buffer| buffer.is_empty());
    if drained && (handle.write_shutdown.load(Ordering::Acquire)
        || handle.socket_dropped.load(Ordering::Acquire)) { socket.close(); }
    if past_handshake(socket) && !socket.may_send()
        && !handle.write_closed.swap(true, Ordering::AcqRel) { handle.send_waker.wake(); }
}
