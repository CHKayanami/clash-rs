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
    sync::mpsc,
};
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

        let session_id = self.allocate_session_id()?;
        let (tx, rx) = mpsc::channel(UDP_BUFFER_CAPACITY);

        {
            let mut sessions = self.sessions.write();
            sessions.insert(session_id, ChildSession { tx, peer: target });
        }

        self.last_active_ms.store(current_epoch_ms(), Ordering::Relaxed);
        self.active_streams.fetch_add(1, Ordering::SeqCst);

        Ok(XudpChildDatagram {
            session_id,
            carrier: self.clone(),
            writer_tx: self.writer_tx.clone(),
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
    writer_tx: mpsc::Sender<Bytes>,
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
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if let Some(frame) = self.pending_frame.take() {
            match self.writer_tx.try_send(frame) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(mpsc::error::TrySendError::Full(frame)) => {
                    self.pending_frame = Some(frame);
                    Poll::Pending
                }
                Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "XUDP carrier writer closed",
                ))),
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.as_mut().poll_flush(cx)
    }
}

impl Drop for XudpChildDatagram {
    fn drop(&mut self) {
        if !self.ended {
            self.ended = true;
            let end_frame = XudpFrame::encode_end_frame(self.session_id);
            let _ = self.writer_tx.try_send(end_frame);
            self.carrier.remove_child(self.session_id);
            self.carrier
                .active_streams
                .fetch_sub(1, Ordering::SeqCst);
        }
    }
}

pub struct XudpPool {
    carriers: tokio::sync::Mutex<Vec<Arc<XudpCarrier>>>,
    max_carriers: usize,
    max_streams_per_carrier: usize,
    next_carrier_id: std::sync::atomic::AtomicU64,
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
            next_carrier_id: std::sync::atomic::AtomicU64::new(1),
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
        for _attempt in 0..2 {
            let carrier = {
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

                // If no available carrier and we have capacity to dial a new one
                if best_idx.is_none() && carriers.len() < self.max_carriers {
                    drop(carriers);
                    debug!("dialing new carrier connection for XUDP pool");
                    let stream = dial_carrier().await?;
                    let cid = self.next_carrier_id.fetch_add(1, Ordering::SeqCst);
                    let new_carrier =
                        XudpCarrier::new(stream, cid, self.max_streams_per_carrier);
                    let mut carriers = self.carriers.lock().await;
                    carriers.retain(|c| !c.is_closed() && !c.is_idle_expired());
                    carriers.push(new_carrier.clone());
                    new_carrier
                } else if let Some(i) = best_idx {
                    carriers[i].clone()
                } else {
                    // All full and max carriers reached: dial new or take error
                    drop(carriers);
                    let stream = dial_carrier().await?;
                    let cid = self.next_carrier_id.fetch_add(1, Ordering::SeqCst);
                    let new_carrier =
                        XudpCarrier::new(stream, cid, self.max_streams_per_carrier);
                    let mut carriers = self.carriers.lock().await;
                    carriers.retain(|c| !c.is_closed() && !c.is_idle_expired());
                    carriers.push(new_carrier.clone());
                    new_carrier
                }
            };

            match carrier.open_child(destination.clone()) {
                Ok(datagram) => return Ok(datagram),
                Err(e) => {
                    debug!("failed to open child on XUDP carrier [{}]: {}, retrying", carrier.carrier_id, e);
                }
            }
        }

        // Final attempt
        let stream = dial_carrier().await?;
        let cid = self.next_carrier_id.fetch_add(1, Ordering::SeqCst);
        let new_carrier = XudpCarrier::new(stream, cid, self.max_streams_per_carrier);
        {
            let mut carriers = self.carriers.lock().await;
            carriers.retain(|c| !c.is_closed() && !c.is_idle_expired());
            carriers.push(new_carrier.clone());
        }
        new_carrier.open_child(destination.clone())
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
}
