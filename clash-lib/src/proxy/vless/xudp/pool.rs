use bytes::{Bytes, BytesMut};
use futures::{Sink, Stream};
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    runtime::Handle,
    sync::{
        Notify,
        mpsc::{self, error::TrySendError},
    },
};
use tokio_util::sync::PollSender;
use tracing::{debug, trace};

use super::frame::{
    SessionStatus, XudpFrame, decode_xudp_frame_from_buf,
};
use crate::{
    proxy::{AnyStream, datagram::UdpPacket},
    session::SocksAddr,
};

const DEFAULT_MAX_CARRIERS: usize = 4;
const DEFAULT_MAX_STREAMS_PER_CARRIER: usize = 256;
const UDP_BUFFER_CAPACITY: usize = 128;
const WRITER_QUEUE_CAPACITY: usize = 256;
const RECV_BUFFER_INITIAL_CAPACITY: usize = 64 * 1024;
const IDLE_CARRIER_TIMEOUT_MS: u64 = 120 * 1000;

#[inline]
fn current_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

struct ChildSession {
    tx: mpsc::Sender<UdpPacket>,
    peer: SocksAddr,
}

pub struct XudpCarrier {
    carrier_id: u64,
    sessions: Arc<RwLock<HashMap<u16, ChildSession>>>,
    writer_tx: mpsc::Sender<Bytes>,
    active_streams: Arc<AtomicUsize>,
    closed: Arc<AtomicBool>,
    last_active_ms: Arc<AtomicU64>,
    next_session_id: AtomicU16,
    max_streams: usize,
}

impl XudpCarrier {
    pub fn new(stream: AnyStream, carrier_id: u64, max_streams: usize) -> Arc<Self> {
        let (read_half, write_half) = tokio::io::split(stream);
        let (writer_tx, writer_rx) = mpsc::channel(WRITER_QUEUE_CAPACITY);

        let sessions = Arc::new(RwLock::new(HashMap::new()));
        let active_streams = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicBool::new(false));
        let last_active_ms = Arc::new(AtomicU64::new(current_epoch_ms()));

        let carrier = Arc::new(Self {
            carrier_id,
            sessions: sessions.clone(),
            writer_tx,
            active_streams: active_streams.clone(),
            closed: closed.clone(),
            last_active_ms: last_active_ms.clone(),
            next_session_id: AtomicU16::new(1),
            max_streams,
        });

        // Spawn coalescing writer task
        let closed_w = closed.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::writer_loop(write_half, writer_rx).await {
                debug!("XUDP carrier [{}] writer error: {}", carrier_id, e);
            }
            closed_w.store(true, Ordering::SeqCst);
        });

        // Spawn zero-allocation reader task
        let closed_r = closed.clone();
        let sessions_r = sessions.clone();
        let last_active_ms_r = last_active_ms.clone();
        tokio::spawn(async move {
            if let Err(e) =
                Self::reader_loop(carrier_id, read_half, sessions_r.clone(), last_active_ms_r).await
            {
                debug!("XUDP carrier [{}] reader error/EOF: {}", carrier_id, e);
            }
            closed_r.store(true, Ordering::SeqCst);
            // Drop all senders to notify active child datagrams of stream closure
            sessions_r.write().clear();
        });

        carrier
    }

    async fn writer_loop(
        mut writer: WriteHalf<AnyStream>,
        mut rx: mpsc::Receiver<Bytes>,
    ) -> io::Result<()> {
        while let Some(frame) = rx.recv().await {
            writer.write_all(&frame).await?;

            // Coalesce all queued pending frames into this write cycle to reduce syscalls
            while let Ok(next) = rx.try_recv() {
                writer.write_all(&next).await?;
            }

            writer.flush().await?;
        }
        let _ = writer.shutdown().await;
        Ok(())
    }

    async fn reader_loop(
        carrier_id: u64,
        mut reader: ReadHalf<AnyStream>,
        sessions: Arc<RwLock<HashMap<u16, ChildSession>>>,
        last_active_ms: Arc<AtomicU64>,
    ) -> io::Result<()> {
        let mut recv_buf = BytesMut::with_capacity(RECV_BUFFER_INITIAL_CAPACITY);

        loop {
            // Drain and decode all fully received frames in buffer
            loop {
                match decode_xudp_frame_from_buf(&mut recv_buf) {
                    Ok(Some(frame)) => {
                        last_active_ms.store(current_epoch_ms(), Ordering::Relaxed);
                        let session_id = frame.session_id;

                        if let Some(payload) = frame.payload {
                            let tx_and_peer = {
                                let map = sessions.read();
                                map.get(&session_id).map(|s| (s.tx.clone(), s.peer.clone()))
                            };

                            if let Some((tx, default_peer)) = tx_and_peer {
                                let peer = frame.peer_addr.unwrap_or(default_peer);
                                let packet = UdpPacket {
                                    data: payload,
                                    src_addr: peer,
                                    dst_addr: SocksAddr::any_ipv4(),
                                    inbound_user: None,
                                };
                                if let Err(e) = tx.try_send(packet) {
                                    trace!("XUDP carrier [{}] dropped packet for session {}: {}", carrier_id, session_id, e);
                                }
                            }
                        }

                        if frame.status == SessionStatus::End {
                            trace!("XUDP carrier [{}] session {} ended by server", carrier_id, session_id);
                            sessions.write().remove(&session_id);
                        }
                    }
                    Ok(None) => break, // Need more data from wire
                    Err(e) => {
                        debug!("XUDP carrier [{}] invalid frame: {}", carrier_id, e);
                        return Err(e);
                    }
                }
            }

            // Read more data into buffer from TCP stream
            let n = reader.read_buf(&mut recv_buf).await?;
            if n == 0 {
                trace!("XUDP carrier [{}] closed gracefully (EOF)", carrier_id);
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub fn active_streams(&self) -> usize {
        self.active_streams.load(Ordering::SeqCst)
    }

    pub fn is_idle_expired(&self) -> bool {
        if self.active_streams() == 0 {
            let last = self.last_active_ms.load(Ordering::Relaxed);
            current_epoch_ms().saturating_sub(last) >= IDLE_CARRIER_TIMEOUT_MS
        } else {
            false
        }
    }

    pub fn is_available(&self) -> bool {
        if self.is_closed() || self.is_idle_expired() {
            return false;
        }
        let active = self.active_streams();
        active < self.max_streams
    }

    fn allocate_session_id(&self) -> io::Result<u16> {
        let sessions = self.sessions.read();
        for _ in 0..=u16::MAX as u32 {
            let id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
            if id != 0 && !sessions.contains_key(&id) {
                return Ok(id);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "no free XUDP session id on carrier",
        ))
    }

    pub fn open_child(
        self: &Arc<Self>,
        target: SocksAddr,
    ) -> io::Result<XudpChildDatagram> {
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "XUDP carrier is closed",
            ));
        }

        self.active_streams
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |active| {
                if active < self.max_streams {
                    Some(active + 1)
                } else {
                    None
                }
            })
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "XUDP carrier stream limit reached",
                )
            })?;

        let session_id = match self.allocate_session_id() {
            Ok(id) => id,
            Err(e) => {
                self.active_streams.fetch_sub(1, Ordering::SeqCst);
                return Err(e);
            }
        };
        let (tx, rx) = mpsc::channel(UDP_BUFFER_CAPACITY);

        {
            let mut sessions = self.sessions.write();
            sessions.insert(session_id, ChildSession { tx, peer: target });
        }

        self.last_active_ms.store(current_epoch_ms(), Ordering::Relaxed);

        Ok(XudpChildDatagram {
            session_id,
            carrier: self.clone(),
            writer_tx: PollSender::new(self.writer_tx.clone()),
            rx,
            first_packet: true,
            ended: false,
            pending_frame: None,
        })
    }

    fn remove_child(&self, session_id: u16) {
        self.sessions.write().remove(&session_id);
    }
}

pub struct XudpChildDatagram {
    session_id: u16,
    carrier: Arc<XudpCarrier>,
    writer_tx: PollSender<Bytes>,
    rx: mpsc::Receiver<UdpPacket>,
    first_packet: bool,
    ended: bool,
    pending_frame: Option<Bytes>,
}

impl Stream for XudpChildDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl Sink<UdpPacket> for XudpChildDatagram {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.ended {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XUDP session is already closed",
            )));
        }
        if self.pending_frame.is_some() {
            match self.as_mut().poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.carrier.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XUDP carrier connection closed",
            )));
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        if self.ended {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XUDP session is already closed",
            ));
        }
        let frame = XudpFrame::encode_data_frame(
            self.session_id,
            self.first_packet,
            Some(&item.dst_addr),
            &item.data,
        )?;
        self.first_packet = false;
        self.pending_frame = Some(frame);
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.pending_frame.is_none() {
            return Poll::Ready(Ok(()));
        }

        match self.writer_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let frame = self.pending_frame.take().unwrap();
                match self.writer_tx.send_item(frame) {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(_) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "XUDP carrier writer closed",
                    ))),
                }
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XUDP carrier writer closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        futures::ready!(self.as_mut().poll_flush(cx))?;

        if !self.ended {
            let end_frame = XudpFrame::encode_end_frame(self.session_id);
            self.pending_frame = Some(end_frame);
            self.ended = true;
            self.carrier.remove_child(self.session_id);
            self.carrier
                .active_streams
                .fetch_sub(1, Ordering::SeqCst);
            futures::ready!(self.as_mut().poll_flush(cx))?;
        }

        Poll::Ready(Ok(()))
    }
}

impl Drop for XudpChildDatagram {
    fn drop(&mut self) {
        let (pending_data, end_frame) = if !self.ended {
            self.ended = true;
            self.carrier.remove_child(self.session_id);
            self.carrier
                .active_streams
                .fetch_sub(1, Ordering::SeqCst);
            (
                self.pending_frame.take(),
                Some(XudpFrame::encode_end_frame(self.session_id)),
            )
        } else {
            (None, self.pending_frame.take())
        };

        let frames_to_send: Vec<Bytes> = pending_data.into_iter().chain(end_frame).collect();
        if frames_to_send.is_empty() {
            return;
        }

        if let Some(tx) = self.writer_tx.get_ref().cloned() {
            let mut it = frames_to_send.into_iter();
            let mut remaining = Vec::new();
            while let Some(frame) = it.next() {
                match tx.try_send(frame) {
                    Ok(()) => {}
                    Err(TrySendError::Full(f)) => {
                        remaining.push(f);
                        remaining.extend(it);
                        break;
                    }
                    Err(TrySendError::Closed(_)) => return,
                }
            }
            if !remaining.is_empty() {
                if let Ok(handle) = Handle::try_current() {
                    handle.spawn(async move {
                        for frame in remaining {
                            if tx.send(frame).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    }
}

pub struct XudpPool {
    carriers: tokio::sync::Mutex<Vec<Arc<XudpCarrier>>>,
    max_carriers: usize,
    max_streams_per_carrier: usize,
    next_carrier_id: AtomicU64,
    dialing_carriers: AtomicUsize,
    dial_notify: Arc<Notify>,
}

struct DialGuard<'a> {
    pool: &'a XudpPool,
}

impl<'a> Drop for DialGuard<'a> {
    fn drop(&mut self) {
        self.pool.dialing_carriers.fetch_sub(1, Ordering::SeqCst);
        self.pool.dial_notify.notify_waiters();
    }
}

impl XudpPool {
    pub fn new(max_carriers: usize, max_streams_per_carrier: usize) -> Arc<Self> {
        Arc::new(Self {
            carriers: tokio::sync::Mutex::new(Vec::new()),
            max_carriers: if max_carriers == 0 {
                DEFAULT_MAX_CARRIERS
            } else {
                max_carriers
            },
            max_streams_per_carrier: if max_streams_per_carrier == 0 {
                DEFAULT_MAX_STREAMS_PER_CARRIER
            } else {
                max_streams_per_carrier
            },
            next_carrier_id: AtomicU64::new(1),
            dialing_carriers: AtomicUsize::new(0),
            dial_notify: Arc::new(Notify::new()),
        })
    }

    pub async fn open_stream<F, Fut>(
        &self,
        destination: &SocksAddr,
        dial_carrier: F,
    ) -> io::Result<XudpChildDatagram>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: Future<Output = io::Result<AnyStream>> + Send,
    {
        loop {
            let notified = self.dial_notify.notified();
            let (carrier_candidate, can_dial) = {
                let mut carriers = self.carriers.lock().await;
                // Retain active, non-expired carriers
                carriers.retain(|c| !c.is_closed() && !c.is_idle_expired());

                // Find candidate with lowest active streams
                let mut best_idx = None;
                let mut min_active = usize::MAX;

                for (i, c) in carriers.iter().enumerate() {
                    if c.is_available() {
                        let active = c.active_streams();
                        if active < min_active {
                            min_active = active;
                            best_idx = Some(i);
                        }
                    }
                }

                if let Some(i) = best_idx {
                    (Some(carriers[i].clone()), false)
                } else {
                    let total = carriers.len() + self.dialing_carriers.load(Ordering::SeqCst);
                    if total < self.max_carriers {
                        self.dialing_carriers.fetch_add(1, Ordering::SeqCst);
                        (None, true)
                    } else {
                        (None, false)
                    }
                }
            };

            if let Some(carrier) = carrier_candidate {
                match carrier.open_child(destination.clone()) {
                    Ok(datagram) => return Ok(datagram),
                    Err(e) => {
                        debug!(
                            "failed to open child on XUDP carrier [{}]: {}, retrying",
                            carrier.carrier_id, e
                        );
                        continue;
                    }
                }
            }

            if can_dial {
                let _guard = DialGuard { pool: self };
                debug!("dialing new carrier connection for XUDP pool");
                let stream = dial_carrier().await?;
                let cid = self.next_carrier_id.fetch_add(1, Ordering::SeqCst);
                let new_carrier =
                    XudpCarrier::new(stream, cid, self.max_streams_per_carrier);
                let datagram = new_carrier.open_child(destination.clone())?;

                {
                    let mut carriers = self.carriers.lock().await;
                    carriers.retain(|c| !c.is_closed() && !c.is_idle_expired());
                    carriers.push(new_carrier);
                }

                return Ok(datagram);
            }

            // Both carrier acquisition and dial capacity are unavailable.
            // If another task is currently dialing, wait for it to finish.
            if self.dialing_carriers.load(Ordering::SeqCst) > 0 {
                notified.await;
                continue;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "XUDP carrier limit reached and all carriers are full",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_xudp_pool_multiplexing_and_graceful_end() {
        let (client_stream, mut server_stream) = duplex(64 * 1024);
        let pool = XudpPool::new(2, 64);

        let target1: SocksAddr = "1.1.1.1:53".parse().unwrap();
        let target2: SocksAddr = "8.8.8.8:53".parse().unwrap();

        let client_holder = Arc::new(tokio::sync::Mutex::new(Some(Box::new(client_stream) as AnyStream)));
        let client_holder_clone = client_holder.clone();

        // 1. Open child 1
        let mut dgram1 = pool
            .open_stream(&target1, move || {
                let holder = client_holder_clone.clone();
                async move {
                    let mut guard = holder.lock().await;
                    guard.take().ok_or_else(|| io::Error::new(io::ErrorKind::Other, "stream already used"))
                }
            })
            .await
            .expect("open child 1");

        // 2. Open child 2 (should reuse the carrier)
        let mut dgram2 = pool
            .open_stream(&target2, || async { panic!("should not dial new carrier") })
            .await
            .expect("open child 2");

        // 3. Child 1 sends a packet
        let pkt1 = UdpPacket {
            data: Bytes::from_static(b"dns query 1"),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: target1.clone(),
            inbound_user: None,
        };
        dgram1.send(pkt1).await.expect("send pkt1");

        // Server reads frame 1
        let mut s_buf = BytesMut::with_capacity(4096);
        let mut frame1 = None;
        while frame1.is_none() {
            server_stream.read_buf(&mut s_buf).await.expect("read");
            frame1 = decode_xudp_frame_from_buf(&mut s_buf).expect("decode");
        }
        let frame1 = frame1.unwrap();
        assert_eq!(frame1.status, SessionStatus::New);
        assert_eq!(frame1.payload.unwrap().as_ref(), b"dns query 1");
        let session_id_1 = frame1.session_id;

        // 4. Child 2 sends a packet
        let pkt2 = UdpPacket {
            data: Bytes::from_static(b"dns query 2"),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: target2.clone(),
            inbound_user: None,
        };
        dgram2.send(pkt2).await.expect("send pkt2");

        // Server reads frame 2
        let mut frame2 = None;
        while frame2.is_none() {
            server_stream.read_buf(&mut s_buf).await.expect("read");
            frame2 = decode_xudp_frame_from_buf(&mut s_buf).expect("decode");
        }
        let frame2 = frame2.unwrap();
        assert_eq!(frame2.status, SessionStatus::New);
        assert_eq!(frame2.payload.unwrap().as_ref(), b"dns query 2");
        let session_id_2 = frame2.session_id;
        assert_ne!(session_id_1, session_id_2, "sessions must have different IDs");

        // 5. Server replies to child 1
        let reply1 = XudpFrame::encode_data_frame(
            session_id_1,
            false,
            None,
            b"dns response 1",
        ).unwrap();
        server_stream.write_all(&reply1).await.unwrap();

        let resp_pkt1 = dgram1.next().await.expect("dgram1 recv reply");
        assert_eq!(resp_pkt1.data.as_ref(), b"dns response 1");

        // 6. Drop child 1 -> Server should receive END frame for session 1
        drop(dgram1);
        let mut end_frame = None;
        while end_frame.is_none() {
            server_stream.read_buf(&mut s_buf).await.expect("read");
            end_frame = decode_xudp_frame_from_buf(&mut s_buf).expect("decode");
        }
        let end_frame = end_frame.unwrap();
        assert_eq!(end_frame.session_id, session_id_1);
        assert_eq!(end_frame.status, SessionStatus::End);

        // 7. Child 2 should still be able to communicate
        let reply2 = XudpFrame::encode_data_frame(
            session_id_2,
            false,
            None,
            b"dns response 2",
        ).unwrap();
        server_stream.write_all(&reply2).await.unwrap();

        let resp_pkt2 = dgram2.next().await.expect("dgram2 recv reply");
        assert_eq!(resp_pkt2.data.as_ref(), b"dns response 2");
    }

    #[tokio::test]
    async fn test_xudp_pool_carrier_limit_enforced() {
        let (client_stream, _server_stream) = duplex(64 * 1024);
        // max 1 carrier, 1 stream per carrier
        let pool = XudpPool::new(1, 1);

        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();
        let client_holder = Arc::new(tokio::sync::Mutex::new(Some(Box::new(client_stream) as AnyStream)));

        // 1. Open child 1 (takes the only slot on the only carrier)
        let _dgram1 = pool
            .open_stream(&target, {
                let holder = client_holder.clone();
                move || {
                    let holder = holder.clone();
                    async move {
                        let mut guard = holder.lock().await;
                        guard.take().ok_or_else(|| io::Error::new(io::ErrorKind::Other, "already dialed"))
                    }
                }
            })
            .await
            .expect("open child 1");

        // 2. Open child 2: carrier is full and max_carriers is reached.
        // It must fail without dialing a new carrier.
        let result = pool
            .open_stream(&target, || async {
                panic!("should not attempt to dial new carrier when limit reached");
            })
            .await;

        assert!(result.is_err(), "should return error when carrier limit reached and carriers are full");
    }

    #[tokio::test]
    async fn test_xudp_concurrent_dial_limit() {
        // max 1 carrier, 4 streams per carrier
        let pool = XudpPool::new(1, 4);
        let dial_count = Arc::new(AtomicUsize::new(0));
        let servers_holder = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();

        let mut handles = Vec::new();
        for _ in 0..10 {
            let pool = pool.clone();
            let dial_count = dial_count.clone();
            let servers = servers_holder.clone();
            let target = target.clone();
            handles.push(tokio::spawn(async move {
                pool.open_stream(&target, move || {
                    let dial_count = dial_count.clone();
                    let servers = servers.clone();
                    async move {
                        dial_count.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        let (client, server) = duplex(64 * 1024);
                        servers.lock().await.push(server);
                        Ok(Box::new(client) as AnyStream)
                    }
                })
                .await
            }));
        }

        let mut successes = 0;
        let mut dgrams = Vec::new();
        for h in handles {
            if let Ok(Ok(dgram)) = h.await {
                successes += 1;
                dgrams.push(dgram);
            }
        }

        // Must NEVER dial more than max_carriers (1)
        assert_eq!(
            dial_count.load(Ordering::SeqCst),
            1,
            "must not dial more than max_carriers times concurrently"
        );
        // Successes should be at most 4 (max_streams_per_carrier)
        assert!(successes <= 4, "successes must not exceed max streams");
        assert!(successes >= 1, "at least one stream must succeed");
    }

    #[tokio::test]
    async fn test_xudp_carrier_stream_limit_race() {
        let (client, _server) = duplex(64 * 1024);
        // max 2 streams
        let carrier = XudpCarrier::new(Box::new(client), 1, 2);
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();

        let mut handles = Vec::new();
        for _ in 0..10 {
            let carrier = carrier.clone();
            let target = target.clone();
            handles.push(tokio::spawn(async move {
                carrier.open_child(target)
            }));
        }

        let mut success_count = 0;
        let mut err_count = 0;
        let mut dgrams = Vec::new();
        for h in handles {
            match h.await.unwrap() {
                Ok(dgram) => {
                    success_count += 1;
                    dgrams.push(dgram);
                }
                Err(_) => err_count += 1,
            }
        }

        assert_eq!(success_count, 2, "exactly max_streams children must succeed");
        assert_eq!(err_count, 8, "remaining children must fail due to limit");
        assert_eq!(carrier.active_streams(), 2, "active streams must not exceed max_streams");
    }

    #[tokio::test(start_paused = true)]
    async fn test_xudp_wait_carrier_dial_does_not_timeout_prematurely() {
        let pool = Arc::new(XudpPool::new(1, 4));
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();

        let servers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let servers_clone = servers.clone();

        // Task 1 dials slowly (takes 2 seconds)
        let pool_1 = pool.clone();
        let target_1 = target.clone();
        let h1 = tokio::spawn(async move {
            pool_1
                .open_stream(&target_1, || {
                    let servers_clone = servers_clone.clone();
                    async move {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        let (client, server) = duplex(64 * 1024);
                        servers_clone.lock().unwrap().push(server);
                        Ok(Box::new(client) as AnyStream)
                    }
                })
                .await
        });

        // Yield to allow Task 1 to start dialing and register dialing_carriers
        tokio::task::yield_now().await;

        // Task 2 concurrently tries to open stream, must wait for Task 1's dial without failing prematurely
        let pool_2 = pool.clone();
        let target_2 = target.clone();
        let h2 = tokio::spawn(async move {
            pool_2
                .open_stream(&target_2, || async {
                    panic!("task 2 should not dial since max_carriers is 1");
                })
                .await
        });

        let (res1, res2) = tokio::join!(h1, h2);
        assert!(res1.unwrap().is_ok());
        assert!(res2.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_xudp_poll_close_and_drop_send_end_frame_under_pressure() {
        let (client_stream, mut server_stream) = duplex(64 * 1024);
        let carrier = XudpCarrier::new(Box::new(client_stream), 1, 10);
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();

        // 1. Test poll_close sends End frame
        let mut dgram1 = carrier.open_child(target.clone()).unwrap();
        let sid1 = dgram1.session_id;
        // Close explicitly
        dgram1.close().await.unwrap();

        // Server should receive End frame for sid1
        let mut buf = vec![0u8; 1024];
        let n = server_stream.read(&mut buf).await.unwrap();
        let frame = decode_xudp_frame_from_buf(&mut BytesMut::from(&buf[..n])).unwrap().unwrap();
        assert_eq!(frame.session_id, sid1);
        assert_eq!(frame.status, SessionStatus::End);

        // 2. Test Drop sends End frame even if writer queue was temporarily full
        let dgram2 = carrier.open_child(target.clone()).unwrap();
        let sid2 = dgram2.session_id;

        // Fill writer_tx capacity (WRITER_QUEUE_CAPACITY is 256)
        let tx = carrier.writer_tx.clone();
        let dummy_frame = XudpFrame::encode_end_frame(999);
        while tx.try_send(dummy_frame.clone()).is_ok() {}

        // Dropping dgram2 while channel is full: must spawn background send and eventually deliver
        drop(dgram2);

        // Drain the server stream to make room in the queue and verify sid2 End frame is received
        let mut received_sid2_end = false;
        let mut read_buf = BytesMut::new();
        let mut temp = [0u8; 4096];

        let start = tokio::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(2) {
            if let Ok(Ok(n)) = tokio::time::timeout(std::time::Duration::from_millis(100), server_stream.read(&mut temp)).await {
                if n > 0 {
                    read_buf.extend_from_slice(&temp[..n]);
                    while let Ok(Some(f)) = decode_xudp_frame_from_buf(&mut read_buf) {
                        if f.session_id == sid2 && f.status == SessionStatus::End {
                            received_sid2_end = true;
                            break;
                        }
                    }
                    if received_sid2_end {
                        break;
                    }
                }
            }
        }

        assert!(received_sid2_end, "End frame for sid2 must be delivered even when dropped under queue pressure");
    }

    #[tokio::test]
    async fn test_xudp_drop_with_pending_data_sends_both_data_and_end_frame() {
        let (client_stream, mut server_stream) = duplex(64 * 1024);
        let carrier = XudpCarrier::new(Box::new(client_stream), 1, 10);
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();

        let mut dgram = carrier.open_child(target.clone()).unwrap();
        let sid = dgram.session_id;

        // Queue a packet via start_send without flushing
        let pkt = UdpPacket {
            data: Bytes::from_static(b"hello-before-drop"),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: target.clone(),
            inbound_user: None,
        };
        Pin::new(&mut dgram).start_send(pkt).unwrap();

        // Dropping dgram must send both the pending data frame AND the End frame
        drop(dgram);

        // Read frames on server side
        let mut read_buf = BytesMut::new();
        let mut temp = [0u8; 1024];

        let mut received_data = false;
        let mut received_end = false;

        let start = tokio::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(2) {
            if let Ok(Ok(n)) = tokio::time::timeout(std::time::Duration::from_millis(100), server_stream.read(&mut temp)).await {
                if n > 0 {
                    read_buf.extend_from_slice(&temp[..n]);
                    while let Ok(Some(f)) = decode_xudp_frame_from_buf(&mut read_buf) {
                        if f.session_id == sid {
                            if matches!(f.status, SessionStatus::New | SessionStatus::Keep) && f.payload.as_deref() == Some(&b"hello-before-drop"[..]) {
                                received_data = true;
                            } else if f.status == SessionStatus::End {
                                received_end = true;
                            }
                        }
                    }
                    if received_data && received_end {
                        break;
                    }
                }
            }
        }

        assert!(received_data, "pending data frame must be delivered on drop");
        assert!(received_end, "End frame must be delivered on drop");
    }

    #[tokio::test]
    async fn test_xudp_send_after_close_rejected() {
        let (client_stream, _server_stream) = duplex(64 * 1024);
        let carrier = XudpCarrier::new(Box::new(client_stream), 1, 10);
        let target: SocksAddr = "1.1.1.1:53".parse().unwrap();

        let mut dgram = carrier.open_child(target.clone()).unwrap();
        dgram.close().await.unwrap();

        // After close, start_send and poll_ready must return BrokenPipe
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut dgram).poll_ready(&mut cx).is_ready());
        match Pin::new(&mut dgram).poll_ready(&mut cx) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
            other => panic!("expected BrokenPipe, got {:?}", other),
        }

        let pkt = UdpPacket {
            data: Bytes::from_static(b"fail"),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: target,
            inbound_user: None,
        };
        let send_res = Pin::new(&mut dgram).start_send(pkt);
        assert!(send_res.is_err());
        assert_eq!(send_res.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }
}
