//! One owner for packet admission, socket registration and TCP polling.
use super::{
    connections::{SocketHandle, SocketTable},
    driver::{
        Driver, Egress, IngressStatus, OUTPUT_BURST, OUTPUT_BYTES, OUTPUT_PACKETS,
        SOLO_OUTPUT_BURST,
    },
    protocol as tcp,
};
use crate::{
    Packet,
    link::device::NetstackDevice,
    link::packet::IpPacket,
    tcp::buffers::Buffers,
    tcp::forward::{Forward, past_handshake},
    tcp::listener::{TcpStreamHandle, closed_error, new_stream},
    tcp::ready::{Ready, ReadyQueue},
    tcp::schedule::Timers,
    tcp::stream::TcpStream,
};
use futures::task::waker_ref;
use smoltcp::{
    time::{Duration as StackDuration, Instant as StackInstant},
    wire::{IpProtocol, TcpPacket},
};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    sync::mpsc,
    task::consume_budget,
    time::{Instant, sleep},
};

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
        if let Some(forward) = self.forward.take() {
            forward.finish(Err(closed_error()));
        }
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
    buffer_timers: Timers<Instant>,
}

impl Engine {
    pub fn new(
        outbound: mpsc::Sender<Packet>,
        ready: Arc<ReadyQueue>,
        mtu: usize,
    ) -> Self {
        Self::with_device(NetstackDevice::new(outbound), ready, mtu)
    }

    fn with_device(
        device: NetstackDevice,
        ready: Arc<ReadyQueue>,
        mtu: usize,
    ) -> Self {
        let driver = Driver::new(mtu);
        Self {
            driver,
            device,
            sockets: SocketTable::new(),
            entries: HashMap::new(),
            ready,
            buffer_timers: Timers::default(),
        }
    }

    pub async fn run(
        mut self,
        mut inbound: mpsc::Receiver<Packet>,
        streams: mpsc::Sender<TcpStream>,
    ) -> io::Result<()> {
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
                    let Some(frame) = frame else {
                        break;
                    };
                    self.admit(frame, &streams)?;
                }
            }
            let (work, delay) = self.step(&mut ready_batch);
            let blocked_output = !self.device.output_available();
            if streams.is_closed() || output.is_closed() {
                return Ok(());
            }
            if work || (self.device.is_empty() && !inbound.is_empty()) {
                consume_budget().await;
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

    fn step(
        &mut self,
        ready_batch: &mut Vec<Arc<Ready>>,
    ) -> (bool, Option<StackDuration>) {
        self.step_with_output(ready_batch, &mut |_, _, _| false)
    }

    fn step_with_output(
        &mut self,
        ready_batch: &mut Vec<Arc<Ready>>,
        transmit: &mut dyn FnMut(&[u8], &[u8], Option<u16>) -> bool,
    ) -> (bool, Option<StackDuration>) {
        let now = Instant::now();
        let stack_now = StackInstant::now();
        self.expire_buffers(now);
        let ingress_status =
            self.driver
                .ingress(stack_now, &mut self.device, &mut self.sockets);
        self.reap_completed_at(now);
        let mut egress = self.driver.begin_egress(stack_now, &mut self.device);
        self.ready.take_batch(ready_batch, SOCKET_BUDGET);
        let mut remaining = ready_batch.drain(..);
        while let Some(ready) = remaining.next() {
            ready.begin_service();
            let contended = remaining.len() > 0
                || !self.ready.is_empty()
                || self.driver.has_other_ready(SocketHandle(ready.id));
            if self.service_with_egress(
                ready.id,
                now,
                Some(stack_now),
                contended,
                &mut egress,
                transmit,
            ) && let Some(entry) = self.entries.get(&ready.id)
            {
                self.driver
                    .refresh(stack_now, entry.socket, &mut self.sockets);
            }
        }
        self.driver.poll_egress_from(
            stack_now,
            &mut self.device,
            &mut self.sockets,
            &mut egress,
            transmit,
        );
        self.reap_completed_at(now);
        let protocol_delay = self.driver.poll_delay(stack_now);
        let buffer_delay = self.buffer_timers.first().map(|deadline| {
            StackDuration::from(deadline.saturating_duration_since(now))
        });
        let delay = protocol_delay.into_iter().chain(buffer_delay).min();
        let blocked_output = !self.device.output_available();
        // Egress may have drained a local reply after ingress stopped.
        // Resume remaining TCP input even if that used the last output slot.
        let ingress_ready = !self.device.is_empty()
            && match ingress_status {
                IngressStatus::Drained => false,
                IngressStatus::RepliesFull => self.driver.reply_capacity_available(),
                IngressStatus::OutputFull => !blocked_output,
            };
        let work = !self.ready.is_empty()
            || ingress_ready
            || (self.driver.has_ready() && !blocked_output)
            || delay == Some(StackDuration::ZERO);
        (work, delay)
    }

    fn expire_buffers(&mut self, now: Instant) {
        for _ in 0..SOCKET_BUDGET {
            let Some(handle) = self.buffer_timers.pop_due(now) else {
                break;
            };
            if let Some(entry) = self.entries.get(&handle.0) {
                entry.handle.notify();
            }
        }
    }

    pub(super) fn admit(
        &mut self,
        frame: Packet,
        streams: &mpsc::Sender<TcpStream>,
    ) -> io::Result<Option<Packet>> {
        let packet = match IpPacket::new_checked(frame.data()) {
            Ok(packet) => packet,
            Err(_) => return Ok(None),
        };
        if !matches!(
            packet.protocol(),
            IpProtocol::Tcp | IpProtocol::Icmp | IpProtocol::Icmpv6
        ) {
            return Ok(Some(frame));
        }
        if self.device.queue_len() == PACKET_BUDGET {
            log::trace!("TCP device input queue full, dropping packet");
            return Ok(None);
        }
        if matches!(packet.protocol(), IpProtocol::Icmp | IpProtocol::Icmpv6) {
            self.device.inject(frame);
            return Ok(None);
        }
        let tcp = match TcpPacket::new_checked(packet.payload()) {
            Ok(tcp) => tcp,
            Err(_) => return Ok(None),
        };
        if tcp.syn() && !tcp.ack() {
            let tuple = (
                SocketAddr::new(packet.src_addr(), tcp.src_port()),
                SocketAddr::new(packet.dst_addr(), tcp.dst_port()),
            );
            if self.sockets.find(&tuple).is_some() {
                self.device.inject(frame);
                return Ok(None);
            }
            if !Driver::valid_syn_parsed(&packet, &tcp, frame.rx_checksum_verified())
            {
                return Ok(None);
            }
            if self.entries.len() >= MAX_CONNECTIONS {
                return Ok(None);
            }
            let permit = match streams.try_reserve() {
                Ok(permit) => permit,
                Err(_) => return Ok(None),
            };
            let (buffers, mut socket) = Buffers::new();
            socket.set_keep_alive(Some(StackDuration::from_secs(28)));
            socket.set_timeout(Some(StackDuration::from_secs(60)));
            socket.set_ack_delay(Some(Duration::from_millis(10).into()));
            socket.set_nagle_enabled(false);
            socket.set_congestion_control(tcp::CongestionControl::Cubic);
            socket
                .listen(tuple.1)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let socket = self.sockets.add(socket, tuple);
            let id = socket.0;
            let ready = Ready::new(id, self.ready.clone());
            let (stream, handle) = new_stream(tuple.0, tuple.1, ready.clone());
            self.entries.insert(
                id,
                Entry {
                    socket,
                    buffers,
                    handle,
                    forward: None,
                },
            );
            ready.schedule();
            permit.send(stream);
        }
        self.device.inject(frame);
        Ok(None)
    }

    /// Protocol completion is reported directly, even if its one-shot waker
    /// was consumed before a budget-limited RST could be emitted.
    #[cfg(test)]
    fn reap_completed(&mut self) {
        self.reap_completed_at(Instant::now());
    }

    fn reap_completed_at(&mut self, now: Instant) {
        while let Some(handle) = self.driver.pop_completed() {
            assert_eq!(
                self.entries
                    .get(&handle.0)
                    .expect("completed TCP entry")
                    .socket,
                handle
            );
            // Run final relay/adapter handling inline before dropping buffers.
            // No protocol waker or second ready-queue dispatch is required.
            self.service_at(handle.0, now);
            assert!(
                !self.entries.contains_key(&handle.0),
                "completed TCP entry retained"
            );
        }
    }

    #[cfg(test)]
    fn service(&mut self, id: u64) -> bool {
        self.service_at(id, Instant::now())
    }

    fn service_at(&mut self, id: u64, now: Instant) -> bool {
        let mut egress = Egress {
            packets: 0,
            bytes: 0,
        };
        self.service_with_egress(
            id,
            now,
            None,
            false,
            &mut egress,
            &mut |_, _, _| false,
        )
    }

    fn service_with_egress(
        &mut self,
        id: u64,
        now: Instant,
        stack_now: Option<StackInstant>,
        contended: bool,
        egress: &mut Egress,
        transmit: &mut dyn FnMut(&[u8], &[u8], Option<u16>) -> bool,
    ) -> bool {
        let Some(entry) = self.entries.get_mut(&id) else {
            return false;
        };
        let socket_handle = entry.socket;
        let started = self.sockets.started(socket_handle);
        let socket = self.sockets.get_mut(socket_handle);
        let before = (socket.state(), socket.recv_queue(), socket.send_queue());
        let waker = waker_ref(&entry.handle.ready);
        let mut cx = Context::from_waker(&waker);
        // Old registrations can still be armed from a previous service. There
        // is no concurrent TCP processing: disarm them while the owner mutates
        // the socket. Native Tokio I/O still uses the independent cx above.
        socket.clear_wakers();
        let aborted = entry.handle.abort.swap(false, Ordering::AcqRel);
        let mut grown = false;
        let mut sent = false;
        if aborted {
            socket.abort();
            entry.handle.close();
            entry.handle.forward.lock().unwrap().take();
            entry.handle.forward_pending.store(false, Ordering::Relaxed);
            if let Some(forward) = entry.forward.take() {
                forward.finish(Err(closed_error()));
            }
        } else if started || socket.state() != tcp::State::Listen {
            if entry.handle.forward_pending.load(Ordering::Acquire) {
                if let Some(request) = entry.handle.forward.lock().unwrap().take() {
                    entry.forward = Some(Forward::new(request));
                }
                entry.handle.forward_pending.store(false, Ordering::Relaxed);
            }
            let mut packet_budget = if contended {
                OUTPUT_BURST
            } else {
                OUTPUT_PACKETS
            };
            let burst = if contended {
                OUTPUT_BURST
            } else {
                SOLO_OUTPUT_BURST
            };
            let driver = &mut self.driver;
            let device = &mut self.device;
            let mut flush = |socket: &mut tcp::Socket<'_>| {
                let Some(stack_now) = stack_now else { return false; };
                let n = driver.flush_socket(
                    stack_now,
                    device,
                    socket_handle,
                    socket,
                    packet_budget.min(burst),
                    egress,
                    transmit,
                );
                packet_budget -= n;
                sent |= n > 0;
                n > 0
            };
            if let Some(forward) = &mut entry.forward {
                if let Poll::Ready(result) =
                    forward.poll(socket, &entry.handle, &mut cx, now, &mut flush)
                {
                    entry.handle.close();
                    if result.is_err() {
                        socket.abort();
                    }
                    entry.forward.take().unwrap().finish(result);
                }
            } else if !entry.handle.socket_closed.load(Ordering::Acquire) {
                pump_stream(socket, &entry.handle, &mut flush);
            }
            let consumed = before.1.saturating_sub(socket.recv_queue());
            let send_capacity = socket.send_capacity();
            // Count only a fresh fill by this relay pass, not an unchanged
            // full queue revisited by unrelated wakes or stalled peers.
            let send_limited = socket.may_send()
                && !socket.can_send()
                && socket.send_queue() > before.2;
            grown |= socket.is_active()
                && past_handshake(socket)
                && entry.buffers.grow(
                    socket,
                    consumed,
                    send_limited,
                    self.device.output_available(),
                    now,
                );
            if socket.send_capacity() > send_capacity {
                entry.handle.notify();
            }
        }
        // A draining RX grant can become reclaimable during this relay pass.
        grown |= entry.buffers.reclaim(socket, now);
        let changed = aborted
            || grown
            || sent
            || before != (socket.state(), socket.recv_queue(), socket.send_queue());
        if !socket.is_active()
            && socket.remote_endpoint().is_none()
            && (started || socket.state() != tcp::State::Listen)
        {
            self.driver.remove(socket_handle, &mut self.sockets);
            self.entries.remove(&id);
            self.buffer_timers.remove(socket_handle);
        } else {
            // Includes pending SYNs and aborts waiting for RST capacity. Arm
            // only after close/growth/abort can no longer consume these wakes.
            socket.register_recv_waker(&waker);
            socket.register_send_waker(&waker);
            if let Some(deadline) = entry.buffers.idle_deadline(socket) {
                self.buffer_timers.set(socket_handle, deadline);
            } else {
                self.buffer_timers.remove(socket_handle);
            }
        }
        changed
    }
}

fn pump_stream(
    socket: &mut tcp::Socket<'_>,
    handle: &TcpStreamHandle,
    flush: &mut dyn FnMut(&mut tcp::Socket<'_>) -> bool,
) {
    // Publish before checking ring capacity: a concurrent consumer either
    // frees space for this pass or observes the flag and schedules another.
    handle
        .recv_pending
        .store(socket.can_recv(), Ordering::Release);
    let mut budget = 64 * 1024;
    while socket.can_recv() && !handle.recv().is_full() && budget > 0 {
        let n = socket
            .recv(|data| {
                let n = handle.recv().enqueue_slice(&data[..data.len().min(budget)]);
                (n, n)
            })
            .unwrap_or(0);
        if n == 0 {
            break;
        }
        budget -= n;
    }
    if budget < 64 * 1024 {
        handle.recv_waker.wake();
    }
    if !socket.can_recv() {
        handle.recv_pending.store(false, Ordering::Release);
    }
    if budget == 0 && socket.can_recv() && !handle.recv().is_full() {
        handle.notify();
    }
    let mut total_budget = OUTPUT_BYTES;
    let mut dequeued = false;
    let mut capped = false;
    if let Some(buffer) = handle.send_buffer.get() {
        while socket.can_send() && !buffer.is_empty() && total_budget > 0 {
            let mut budget = Buffers::read_budget(socket)
                .min(64 * 1024)
                .min(total_budget);
            if budget == 0 {
                if !flush(socket) {
                    break;
                }
                budget = Buffers::read_budget(socket)
                    .min(64 * 1024)
                    .min(total_budget);
                if budget == 0 {
                    break;
                }
            }
            let batch_budget = budget;
            while socket.can_send() && !buffer.is_empty() && budget > 0 {
                let n = socket
                    .send(|data| {
                        let length = data.len().min(budget);
                        let n = buffer.dequeue_slice(&mut data[..length]);
                        (n, n)
                    })
                    .unwrap_or(0);
                if n == 0 {
                    break;
                }
                budget -= n;
            }
            let read_bytes = batch_budget - budget;
            // A full batch may stop at the inline egress quota before all
            // readable data is consumed. Remaining read credit decides whether
            // to reschedule below, rather than waiting for an unrelated ACK.
            capped = budget == 0;
            total_budget -= read_bytes;
            if read_bytes == 0 {
                break;
            }
            dequeued = true;
            if !flush(socket) {
                break;
            }
        }
    }
    if dequeued {
        handle.send_waker.wake();
    }
    if (total_budget == 0 || capped) && socket.can_send()
        && Buffers::read_budget(socket) > 0
        && handle
            .send_buffer
            .get()
            .is_some_and(|buffer| !buffer.is_empty())
    {
        handle.notify();
    }
    if past_handshake(socket)
        && !socket.may_recv()
        && !socket.can_recv()
        && !handle.read_closed.swap(true, Ordering::AcqRel)
    {
        handle.recv_waker.wake();
    }
    let drained = handle
        .send_buffer
        .get()
        .is_none_or(|buffer| buffer.is_empty());
    if drained
        && (handle.write_shutdown.load(Ordering::Acquire)
            || handle.socket_dropped.load(Ordering::Acquire))
    {
        socket.close();
    }
    if past_handshake(socket)
        && !socket.may_send()
        && !handle.write_closed.swap(true, Ordering::AcqRel)
    {
        handle.send_waker.wake();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::protocol::SocketBuffer;
    use smoltcp::wire::{IpRepr, Ipv4Repr, TcpControl, TcpRepr, TcpSeqNumber};

    fn half_open() -> (
        Engine,
        TcpStream,
        Arc<ReadyQueue>,
        SocketHandle,
        mpsc::Receiver<Packet>,
    ) {
        let ready = Arc::new(ReadyQueue::default());
        let (output, receiver) = mpsc::channel(1);
        let mut engine = Engine::new(output, ready.clone(), 1500);
        let (buffers, mut socket) = Buffers::new();
        let flow = (
            "192.0.2.2:49152".parse().unwrap(),
            "198.51.100.2:80".parse().unwrap(),
        );
        let mut context = tcp::Context::new(1500);
        socket.connect(&mut context, flow.1, flow.0).unwrap();
        let handle = engine.sockets.add(socket, flow);
        let wake = Ready::new(handle.0, ready.clone());
        let (stream, shared) = new_stream(flow.0, flow.1, wake.clone());
        let waker = waker_ref(&wake);
        engine.sockets.get_mut(handle).register_recv_waker(&waker);
        engine.sockets.get_mut(handle).register_send_waker(&waker);
        engine.entries.insert(
            handle.0,
            Entry {
                socket: handle,
                buffers,
                handle: shared,
                forward: None,
            },
        );
        (engine, stream, ready, handle, receiver)
    }

    #[test]
    fn buffer_deadline_wakes_service_without_protocol_traffic() {
        let (mut engine, _stream, ready, handle, _receiver) = half_open();
        let deadline = Instant::now() + Duration::from_secs(30);
        engine.buffer_timers.set(handle, deadline);
        engine.expire_buffers(deadline - Duration::from_millis(1));
        assert!(ready.is_empty());
        engine.expire_buffers(deadline);
        assert!(!ready.is_empty());
        assert!(engine.buffer_timers.first().is_none());
    }

    #[test]
    fn local_close_and_abort_do_not_self_wake_and_rearm_protocol_wakers() {
        for abort in [false, true] {
            let (mut engine, stream, ready, handle, _receiver) = half_open();
            if abort {
                stream.handle.abort.store(true, Ordering::Release);
            } else {
                stream.handle.write_shutdown.store(true, Ordering::Release);
            }
            assert!(engine.service(handle.0));
            assert!(
                ready.is_empty(),
                "local mutation consumed an old protocol waker"
            );
            let socket = engine.sockets.get_mut(handle);
            assert_eq!(socket.state(), tcp::State::Closed);
            let capacity = socket.send_capacity() * 2;
            socket.grow_send_buffer(SocketBuffer::new(vec![0; capacity]));
            assert_eq!(
                ready.pop().unwrap().id,
                handle.0,
                "protocol waker was not rearmed"
            );
        }
    }

    #[test]
    fn deferred_reset_completion_is_reaped_without_protocol_wakers() {
        let (mut engine, stream, ready, handle, mut receiver) = half_open();
        stream.handle.abort.store(true, Ordering::Release);
        assert!(engine.service(handle.0));
        engine
            .driver
            .refresh(StackInstant::ZERO, handle, &mut engine.sockets);
        engine
            .device
            .output()
            .try_send(Packet::new(&b"busy"[..]))
            .unwrap();
        engine.driver.poll_egress(
            StackInstant::ZERO,
            &mut engine.device,
            &mut engine.sockets,
        );
        assert!(engine.entries.contains_key(&handle.0));
        // Simulate a consumed one-shot wake before output capacity returns.
        engine.sockets.get_mut(handle).clear_wakers();
        receiver.try_recv().unwrap();
        engine.driver.poll_egress(
            StackInstant::ZERO,
            &mut engine.device,
            &mut engine.sockets,
        );
        assert!(receiver.try_recv().is_ok());
        assert!(ready.is_empty());
        engine.reap_completed();
        assert!(!engine.entries.contains_key(&handle.0));
        let flow = (stream.local_addr(), stream.remote_addr());
        assert!(engine.sockets.find(&flow).is_none());
        assert_eq!(engine.driver.poll_delay(StackInstant::ZERO), None);
    }

    #[test]
    fn full_socket_preserves_adapter_bytes_without_self_waking() {
        let local: SocketAddr = "192.0.2.2:49152".parse().unwrap();
        let remote: SocketAddr = "198.51.100.2:80".parse().unwrap();
        let mut socket = tcp::Socket::new(
            SocketBuffer::new(vec![0; 64]),
            SocketBuffer::new(vec![0; 16]),
        );
        let mut cx = tcp::Context::new(1500);
        socket.connect(&mut cx, remote, local).unwrap();
        let mut sequence = None;
        socket
            .dispatch(&mut cx, |_, _, (_, syn)| {
                sequence = Some(syn.seq_number);
                Ok::<_, ()>(())
            })
            .unwrap();
        let ip = IpRepr::Ipv4(Ipv4Repr {
            src_addr: [198, 51, 100, 2].into(),
            dst_addr: [192, 0, 2, 2].into(),
            next_header: IpProtocol::Tcp,
            payload_len: 20,
            hop_limit: 64,
        });
        let synack = TcpRepr {
            src_port: 80,
            dst_port: 49152,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(100),
            ack_number: Some(sequence.unwrap() + 1),
            window_len: 4096,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        socket.process(&mut cx, &ip, &synack);
        assert_eq!(socket.state(), tcp::State::Established);
        let ready = Arc::new(ReadyQueue::default());
        let wake = Ready::new(1, ready.clone());
        let (_stream, handle) = new_stream(local, remote, wake);
        assert_eq!(handle.send().enqueue_slice(&[b'x'; 64]), 64);
        pump_stream(&mut socket, &handle, &mut |_| false);
        assert_eq!(socket.send_queue(), 16);
        assert!(!handle.send().is_empty());
        assert!(ready.is_empty());
        // A second service cannot consume more adapter bytes or self-wake
        // until an ACK frees actual socket storage.
        pump_stream(&mut socket, &handle, &mut |_| false);
        assert_eq!(socket.send_queue(), 16);
        assert!(!handle.send().is_empty());
        assert!(ready.is_empty());
        let mut remaining = [0; 64];
        assert_eq!(handle.send().dequeue_slice(&mut remaining), 48);
        assert_eq!(&remaining[..48], &[b'x'; 48]);
        assert!(ready.is_empty());
    }

    fn interleaved_engine(window: u16, shift: u8, queued: usize)
        -> (Engine, TcpStream, Arc<TcpStreamHandle>, Arc<ReadyQueue>, SocketHandle) {
        let ready = Arc::new(ReadyQueue::default());
        let mut engine =
            Engine::with_device(NetstackDevice::local(32), ready.clone(), 1500);
        engine.driver.enable_tcp_gso();
        let (buffers, mut socket) = Buffers::new();
        socket.grow_send_buffer(SocketBuffer::new(vec![0; 512 * 1024]));
        let flow = (
            "192.0.2.2:49152".parse().unwrap(),
            "198.51.100.2:80".parse().unwrap(),
        );
        let mut cx = tcp::Context::new(1500);
        socket.connect(&mut cx, flow.1, flow.0).unwrap();
        let mut sequence = None;
        socket
            .dispatch(&mut cx, |_, _, (_, syn)| {
                sequence = Some(syn.seq_number);
                Ok::<_, ()>(())
            })
            .unwrap();
        let ip = IpRepr::Ipv4(Ipv4Repr {
            src_addr: [198, 51, 100, 2].into(),
            dst_addr: [192, 0, 2, 2].into(),
            next_header: IpProtocol::Tcp,
            payload_len: 20,
            hop_limit: 64,
        });
        let synack = TcpRepr {
            src_port: 80,
            dst_port: 49152,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(100),
            ack_number: Some(sequence.unwrap() + 1),
            window_len: window,
            window_scale: Some(shift),
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        socket.process(&mut cx, &ip, &synack);
        socket.set_congestion_control(tcp::CongestionControl::None);
        socket.set_nagle_enabled(false);
        assert_eq!(
            socket.send_slice(&vec![b'a'; queued]).unwrap(),
            queued
        );

        let handle = engine.sockets.add(socket, flow);
        let wake = Ready::new(handle.0, ready.clone());
        let (stream, shared) = new_stream(flow.0, flow.1, wake.clone());
        let waker = waker_ref(&wake);
        engine.sockets.get_mut(handle).register_recv_waker(&waker);
        engine.sockets.get_mut(handle).register_send_waker(&waker);
        assert_eq!(
            shared.send().enqueue_slice(&vec![b'b'; 64 * 1024]),
            64 * 1024
        );
        engine.entries.insert(
            handle.0,
            Entry {
                socket: handle,
                buffers,
                handle: shared.clone(),
                forward: None,
            },
        );
        (engine, stream, shared, ready, handle)
    }

    #[test]
    fn interleaved_read_and_send_advances_multiple_batches_within_round_budget() {
        let (mut engine, _stream, shared, ready, handle) =
            interleaved_engine(32 * 1024, 0, 32 * 1024);
        shared.ready.schedule();

        let mut batch = Vec::new();
        let mut direct_bytes = 0;
        engine.step_with_output(&mut batch, &mut |_, payload, _| {
            direct_bytes += payload.len();
            true
        });
        // Initial read_budget was 32 KiB; reading 32 KiB filled read_budget to 0,
        // immediate send moved 32 KiB into flight and freed 32 KiB of read_budget,
        // allowing the remaining 32 KiB in send_buffer to be read in the same step.
        assert_eq!(direct_bytes, 32 * 1024);
        assert!(shared.send().is_empty());
        assert_eq!(engine.sockets.get_mut(handle).send_queue(), 96 * 1024);
        assert!(ready.is_empty());
    }

    #[test]
    fn contended_service_limits_inline_output_to_one_burst() {
        let (mut engine, _stream, _shared, _ready, handle) =
            interleaved_engine(u16::MAX, 4, 128 * 1024);
        let mut egress = Egress { packets: 0, bytes: 0 };
        let mut emitted = 0;
        engine.service_with_egress(handle.0, Instant::now(), Some(StackInstant::ZERO),
            true, &mut egress, &mut |_, _, _| { emitted += 1; true });
        assert_eq!(emitted, OUTPUT_BURST);
        assert_eq!(egress.packets, OUTPUT_BURST);
    }

    #[test]
    fn full_stream_batch_reschedules_when_flush_is_blocked_and_reader_has_credit() {
        let (mut engine, _stream, shared, ready, handle) =
            interleaved_engine(u16::MAX, 4, 0);
        let socket = engine.sockets.get_mut(handle);
        pump_stream(socket, &shared, &mut |_| {
            // Model the producer refilling the ring after this batch was read.
            assert_eq!(shared.send().enqueue_slice(&vec![b'c'; 64 * 1024]), 64 * 1024);
            false
        });
        assert!(Buffers::read_budget(socket) > 0);
        assert!(!ready.is_empty(), "a full batch needs another service without waiting for ACK");
    }

    #[tokio::test]
    async fn full_forward_batch_reschedules_without_native_pending_or_ack() {
        use crate::tcp::forward::ForwardRequest;
        use tokio::net::{TcpListener, TcpStream as NativeTcpStream};
        use tokio::sync::oneshot;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let native = NativeTcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (_peer, _) = listener.accept().await.unwrap();
        let (mut engine, _stream, _shared, ready, handle) =
            interleaved_engine(u16::MAX, 4, 0);
        let (done, _result) = oneshot::channel();
        engine.entries.get_mut(&handle.0).unwrap().forward = Some(Forward::new(ForwardRequest {
            socket: native, prefix: Vec::new(), counter: Box::new(|_, _| {}), done,
            upload_timeout: Duration::from_secs(30), download_timeout: Duration::from_secs(30),
        }));
        // Exhausted output makes flush fail after the full adapter batch, before
        // poll_read can register a native Pending wake. No ACK is injected.
        let mut egress = Egress { packets: OUTPUT_PACKETS, bytes: OUTPUT_BYTES };
        engine.service_with_egress(handle.0, Instant::now(), Some(StackInstant::ZERO),
            true, &mut egress, &mut |_, _, _| panic!("output budget exhausted"));
        assert!(Buffers::read_budget(engine.sockets.get_mut(handle)) > 0);
        assert!(!ready.is_empty(), "forward must continue reading without waiting for ACK");
    }

}

mod integrated;
pub use integrated::TcpDriver;
