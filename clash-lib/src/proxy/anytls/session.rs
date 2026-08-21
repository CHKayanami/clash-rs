//! AnyTLS Client Session Implementation
//!
//! Provides AnyTLS client session management for multiplexed outbound connections.

use bytes::{BufMut, Bytes, BytesMut};
use parking_lot::{Mutex, RwLock};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, trace, warn};

use crate::proxy::AnyStream;
use crate::session::SocksAddr;

use super::padding::PaddingFactory;
use super::stream::{AnyTlsStream, STREAM_CHANNEL_BUFFER};
use super::types::{
    Command, FRAME_HEADER_SIZE, Frame, FrameCodec, MAX_FRAME_DATA_SIZE, StringMap,
};

/// Outgoing message types for the unified writer channel
enum OutgoingMessage {
    /// Buffered frames (Settings + SYN + destination) - sent as single TLS record
    Buffered { data: Bytes },
    /// Control frame (Settings, SYN, etc.)
    Control {
        cmd: Command,
        stream_id: u32,
        data: Bytes,
    },
    /// Data frame for a stream (PSH)
    Data { stream_id: u32, data: Bytes },
    /// FIN frame for a stream
    Fin { stream_id: u32 },
}

/// AnyTLS client session - manages multiplexed streams over a connection
pub struct AnyTlsClientSession {
    /// Active streams mapping (stream_id -> data sender)
    streams: RwLock<HashMap<u32, mpsc::Sender<Bytes>>>,
    /// Lock-free active stream counter
    active_streams: AtomicUsize,
    stream_id_counter: AtomicU32,

    /// Channel for all outgoing messages (control and data)
    outgoing_tx: mpsc::UnboundedSender<OutgoingMessage>,

    /// Session closure flag
    is_closed: Arc<AtomicBool>,

    /// Padding configuration
    padding: Arc<PaddingFactory>,

    /// Negotiated protocol version
    peer_version: AtomicU8,

    /// Pending stream opens waiting for SynAck (stream_id -> completion sender)
    pending_opens: Mutex<HashMap<u32, oneshot::Sender<Result<(), String>>>>,

    /// Padding enabled state
    send_padding: AtomicBool,
    /// Packet counter for padding calculation
    pkt_counter: AtomicU32,

    /// Initial buffer for coalescing Settings + first SYN + first destination into one TLS record
    initial_buffer: Mutex<Option<BytesMut>>,

    /// Last active timestamp in Unix seconds
    last_active: AtomicU64,

    /// Notify handle to break loops on session drop
    close_notify: Arc<tokio::sync::Notify>,
}

fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl std::fmt::Debug for AnyTlsClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsClientSession")
            .field("is_closed", &self.is_closed.load(Ordering::Relaxed))
            .field("peer_version", &self.peer_version.load(Ordering::Relaxed))
            .finish()
    }
}

impl Drop for AnyTlsClientSession {
    fn drop(&mut self) {
        self.close_notify.notify_waiters();
    }
}

impl AnyTlsClientSession {
    /// Create a new client session on the given transport.
    pub async fn new(
        mut transport: AnyStream,
        password: &str,
        padding: Arc<PaddingFactory>,
    ) -> io::Result<Arc<Self>> {
        let password_hash = Sha256::digest(password.as_bytes());

        // Send authentication packet (packet 0)
        Self::send_auth(&mut transport, password_hash.as_slice(), &padding).await?;

        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();
        let initial_buffer = Self::create_initial_buffer(&padding);

        let session = Arc::new(Self {
            streams: RwLock::new(HashMap::new()),
            active_streams: AtomicUsize::new(0),
            stream_id_counter: AtomicU32::new(0),
            outgoing_tx,
            is_closed: Arc::new(AtomicBool::new(false)),
            padding: Arc::clone(&padding),
            peer_version: AtomicU8::new(1), // Assume v1 until server confirms v2
            pending_opens: Mutex::new(HashMap::new()),
            send_padding: AtomicBool::new(true),
            pkt_counter: AtomicU32::new(0),
            initial_buffer: Mutex::new(Some(initial_buffer)),
            last_active: AtomicU64::new(current_unix_timestamp()),
            close_notify: Arc::new(tokio::sync::Notify::new()),
        });

        let (read_half, write_half) = tokio::io::split(transport);
        Self::spawn_tasks(Arc::clone(&session), read_half, write_half, outgoing_rx);

        Ok(session)
    }

    /// Check if the session is closed
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }

    /// Get current active streams count (lock-free atomic load)
    pub fn active_streams_count(&self) -> usize {
        self.active_streams.load(Ordering::Relaxed)
    }

    /// Update last active timestamp to current time
    pub fn touch_last_active(&self) {
        self.last_active
            .store(current_unix_timestamp(), Ordering::Relaxed);
    }

    /// Get last active timestamp in Unix seconds
    pub fn last_active_secs(&self) -> u64 {
        self.last_active.load(Ordering::Relaxed)
    }

    /// Pre-encode Settings frame into initial buffer
    fn create_initial_buffer(padding: &PaddingFactory) -> BytesMut {
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert(
            "client",
            format!("clash-rs/{}", env!("CLASH_VERSION_OVERRIDE")),
        );
        settings.insert("padding-md5", padding.md5());

        let settings_frame =
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));

        let mut buffer = BytesMut::with_capacity(256);
        settings_frame.encode_into(&mut buffer);
        buffer
    }

    /// Send authentication packet (packet 0: password_hash + padding_len + padding)
    async fn send_auth<W>(
        writer: &mut W,
        password_hash: &[u8],
        padding: &PaddingFactory,
    ) -> io::Result<()>
    where
        W: AsyncWrite + Send + Unpin,
    {
        let sizes = padding.generate_record_payload_sizes(0);
        // clamped for the same reason as `write_with_padding`: the length is
        // written as a u16
        let padding_size = (sizes.first().copied().unwrap_or(0).max(0) as usize)
            .min(MAX_FRAME_DATA_SIZE);
        let mut buf =
            BytesMut::with_capacity(password_hash.len() + 2 + padding_size);

        buf.extend_from_slice(password_hash);
        buf.put_u16(padding_size as u16);
        if padding_size > 0 {
            buf.put_bytes(0, padding_size);
        }

        writer.write_all(&buf).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Send control frame
    fn send_control_frame(
        &self,
        cmd: Command,
        stream_id: u32,
        data: Bytes,
    ) -> io::Result<()> {
        self.outgoing_tx
            .send(OutgoingMessage::Control {
                cmd,
                stream_id,
                data,
            })
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "Session writer closed")
            })
    }

    /// Send buffered initial frames
    fn send_buffered(&self, data: Bytes) -> io::Result<()> {
        self.outgoing_tx
            .send(OutgoingMessage::Buffered { data })
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "Session writer closed")
            })
    }

    /// Spawn background reader and writer tasks
    fn spawn_tasks<R, W>(
        session: Arc<Self>,
        reader: R,
        writer: W,
        outgoing_rx: mpsc::UnboundedReceiver<OutgoingMessage>,
    ) where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let session_weak_w = Arc::downgrade(&session);
        let close_notify_w = Arc::clone(&session.close_notify);
        tokio::spawn(async move {
            if let Err(e) = Self::writer_loop(
                session_weak_w,
                writer,
                outgoing_rx,
                close_notify_w,
            )
            .await
            {
                debug!("AnyTLS client writer ended: {}", e);
            }
        });

        let session_weak_r = Arc::downgrade(&session);
        let close_notify_r = Arc::clone(&session.close_notify);
        tokio::spawn(async move {
            if let Err(e) =
                Self::reader_loop(session_weak_r, reader, close_notify_r).await
            {
                debug!("AnyTLS client reader ended: {}", e);
            }
        });
    }

    /// Writer loop: consumes OutgoingMessages and sends them over transport with optional padding
    async fn writer_loop<W>(
        session_weak: std::sync::Weak<Self>,
        mut writer: W,
        mut outgoing_rx: mpsc::UnboundedReceiver<OutgoingMessage>,
        close_notify: Arc<tokio::sync::Notify>,
    ) -> io::Result<()>
    where
        W: AsyncWrite + Send + Unpin,
    {
        let mut write_buf = BytesMut::with_capacity(65536 + FRAME_HEADER_SIZE + 64);
        let mut padding_buf =
            BytesMut::with_capacity(65536 + FRAME_HEADER_SIZE * 2 + 64);

        loop {
            let msg = tokio::select! {
                m = outgoing_rx.recv() => m,
                _ = close_notify.notified() => {
                    break;
                }
            };

            let session = match session_weak.upgrade() {
                Some(s) => s,
                None => break,
            };

            if session.is_closed.load(Ordering::Relaxed) {
                break;
            }

            let msg = match msg {
                Some(m) => m,
                None => break,
            };

            write_buf.clear();

            match msg {
                OutgoingMessage::Buffered { data } => {
                    Self::write_with_padding(
                        &session,
                        &mut writer,
                        &data,
                        &mut padding_buf,
                    )
                    .await?;
                    writer.flush().await?;
                }
                OutgoingMessage::Control {
                    cmd,
                    stream_id,
                    data,
                } => {
                    Frame::with_data(cmd, stream_id, data)
                        .encode_into(&mut write_buf);
                    Self::write_with_padding(
                        &session,
                        &mut writer,
                        &write_buf,
                        &mut padding_buf,
                    )
                    .await?;
                    writer.flush().await?;
                }
                OutgoingMessage::Data { stream_id, data } => {
                    Frame::with_data(Command::Psh, stream_id, data)
                        .encode_into(&mut write_buf);
                    Self::write_with_padding(
                        &session,
                        &mut writer,
                        &write_buf,
                        &mut padding_buf,
                    )
                    .await?;
                    writer.flush().await?;
                }
                OutgoingMessage::Fin { stream_id } => {
                    Frame::control(Command::Fin, stream_id)
                        .encode_into(&mut write_buf);
                    Self::write_with_padding(
                        &session,
                        &mut writer,
                        &write_buf,
                        &mut padding_buf,
                    )
                    .await?;
                    writer.flush().await?;

                    let mut streams = session.streams.write();
                    if streams.remove(&stream_id).is_some() {
                        session.active_streams.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            }
        }
        Ok(())
    }

    /// Helper to write bytes with optional random padding
    async fn write_with_padding<W>(
        session: &Self,
        writer: &mut W,
        data: &[u8],
        padding_buf: &mut BytesMut,
    ) -> io::Result<()>
    where
        W: AsyncWrite + Send + Unpin,
    {
        if session.send_padding.load(Ordering::Relaxed) {
            let count = session.pkt_counter.fetch_add(1, Ordering::Relaxed);
            if count >= session.padding.stop() {
                session.send_padding.store(false, Ordering::Relaxed);
                writer.write_all(data).await?;
                return Ok(());
            }

            let sizes = session.padding.generate_record_payload_sizes(count);
            if let Some(&target_size) = sizes.first() {
                let target_size = target_size.max(0) as usize;
                if target_size > data.len() {
                    // A frame's length field is 16 bits. Writing more than that
                    // while declaring the truncated length would put the peer
                    // permanently out of frame sync, so cap the run instead.
                    let padding_len =
                        (target_size - data.len()).min(MAX_FRAME_DATA_SIZE);
                    padding_buf.clear();
                    padding_buf
                        .reserve(data.len() + FRAME_HEADER_SIZE + padding_len);
                    padding_buf.extend_from_slice(data);
                    padding_buf.put_u8(Command::Waste as u8);
                    padding_buf.put_u32(0);
                    padding_buf.put_u16(padding_len as u16);
                    padding_buf.put_bytes(0, padding_len);
                    writer.write_all(padding_buf).await?;
                    return Ok(());
                }
            }
        }

        writer.write_all(data).await?;
        Ok(())
    }

    /// Reader loop: parses incoming frames and dispatches data to corresponding streams
    async fn reader_loop<R>(
        session_weak: std::sync::Weak<Self>,
        mut reader: R,
        close_notify: Arc<tokio::sync::Notify>,
    ) -> io::Result<()>
    where
        R: AsyncRead + Send + Unpin,
    {
        let mut buffer = BytesMut::with_capacity(8192);

        loop {
            let has_closed = {
                let session = match session_weak.upgrade() {
                    Some(s) => s,
                    None => return Ok(()),
                };

                if session.is_closed.load(Ordering::Relaxed) {
                    return Ok(());
                }

                while let Some(frame) = FrameCodec::decode(&mut buffer)? {
                    if let Err(e) = session.handle_frame(frame).await {
                        warn!("AnyTLS client error handling frame: {}", e);
                        return Err(e);
                    }
                }

                false
            };

            if has_closed {
                return Ok(());
            }

            let read_result = tokio::select! {
                res = reader.read_buf(&mut buffer) => res,
                _ = close_notify.notified() => {
                    return Ok(());
                }
            };

            let n = read_result?;
            if n == 0 {
                if let Some(session) = session_weak.upgrade() {
                    session.is_closed.store(true, Ordering::Relaxed);
                    session.close_notify.notify_waiters();
                }
                return Ok(());
            }
        }
    }

    /// Handle received frame
    async fn handle_frame(&self, frame: Frame) -> io::Result<()> {
        match frame.cmd {
            Command::Psh => {
                if frame.data.is_empty() {
                    return Ok(());
                }

                let tx = {
                    let streams = self.streams.read();
                    streams.get(&frame.stream_id).cloned()
                };

                if let Some(tx) = tx {
                    // Awaiting here blocks the reader loop, and therefore every
                    // other stream on this session, while one consumer catches
                    // up. That is deliberate: AnyTLS has no per-stream flow
                    // control, so refusing to read the shared transport is the
                    // only backpressure available. Dropping instead would
                    // silently corrupt a reliable stream, and buffering instead
                    // would be unbounded. Head-of-line blocking is the
                    // protocol's cost, not a bug to code around here.
                    if tx.send(frame.data).await.is_err() {
                        trace!("Stream {} channel closed", frame.stream_id);
                    }
                } else {
                    trace!("Data for unknown stream {}", frame.stream_id);
                }
            }

            Command::Fin => {
                let tx = {
                    let mut streams = self.streams.write();
                    let removed = streams.remove(&frame.stream_id);
                    if removed.is_some() {
                        self.active_streams.fetch_sub(1, Ordering::Relaxed);
                    }
                    removed
                };

                if let Some(tx) = tx {
                    let _ = tx.send(Bytes::new()).await;
                }
            }

            Command::SynAck => {
                let mut pending = self.pending_opens.lock();
                if let Some(sender) = pending.remove(&frame.stream_id) {
                    if frame.data.is_empty() {
                        let _ = sender.send(Ok(()));
                    } else {
                        let error = String::from_utf8_lossy(&frame.data).to_string();
                        let _ = sender.send(Err(error));
                    }
                }
            }

            Command::ServerSettings => {
                let settings = StringMap::from_bytes(&frame.data);
                if let Some(v) = settings.get("v").and_then(|s| s.parse::<u8>().ok())
                {
                    self.peer_version.store(v, Ordering::Relaxed);
                    debug!("AnyTLS server version: {}", v);
                }
            }

            Command::Alert => {
                let msg = String::from_utf8_lossy(&frame.data);
                warn!("AnyTLS server alert: {}", msg);
                self.is_closed.store(true, Ordering::Relaxed);
                self.close_notify.notify_waiters();
            }

            // Keep-alive. Silently dropping these left servers that use
            // heartbeats for liveness tearing sessions down under us.
            Command::HeartRequest => {
                trace!("AnyTLS heartbeat request, replying");
                if self
                    .outgoing_tx
                    .send(OutgoingMessage::Control {
                        cmd: Command::HeartResponse,
                        stream_id: frame.stream_id,
                        data: Bytes::new(),
                    })
                    .is_err()
                {
                    trace!("AnyTLS writer gone, cannot answer heartbeat");
                }
            }

            // We deliberately do not adopt a server-supplied padding scheme:
            // it is attacker-controlled input driving our record sizes, and
            // `write_with_padding` is only bounded because the scheme is ours.
            // Say so rather than dropping it silently.
            Command::UpdatePaddingScheme => {
                debug!(
                    "AnyTLS ignoring server padding scheme update ({} bytes); \
                     keeping the locally configured scheme",
                    frame.data.len()
                );
            }

            Command::Waste | Command::HeartResponse => {}

            Command::Syn | Command::Settings => {}
        }
        Ok(())
    }

    /// Open a new multiplexed stream to destination
    pub async fn open_stream(
        self: &Arc<Self>,
        destination: &SocksAddr,
    ) -> io::Result<AnyTlsStream> {
        if self.is_closed.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "AnyTLS session is closed",
            ));
        }

        self.touch_last_active();

        let stream_id = self.stream_id_counter.fetch_add(1, Ordering::Relaxed) + 1;

        let (data_tx, data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);

        {
            let mut streams = self.streams.write();
            streams.insert(stream_id, data_tx);
            self.active_streams.fetch_add(1, Ordering::Relaxed);
        }

        let mut dest_data = BytesMut::new();
        destination.write_buf(&mut dest_data);
        let dest_bytes = dest_data.freeze();

        let buffered_data = {
            let mut buf_guard = self.initial_buffer.lock();
            if let Some(ref mut buf) = *buf_guard {
                Frame::control(Command::Syn, stream_id).encode_into(buf);
                Frame::data(stream_id, dest_bytes.clone()).encode_into(buf);
                buf_guard.take().map(|b| b.freeze())
            } else {
                None
            }
        };

        if let Some(data) = buffered_data {
            self.send_buffered(data)?;
        } else {
            self.send_control_frame(Command::Syn, stream_id, Bytes::new())?;
            self.send_control_frame(Command::Psh, stream_id, dest_bytes)?;
        }

        let (stream_write_tx, mut stream_write_rx) =
            mpsc::channel::<(u32, Bytes)>(STREAM_CHANNEL_BUFFER);

        let outgoing_tx = self.outgoing_tx.clone();
        let is_closed = Arc::clone(&self.is_closed);
        tokio::spawn(async move {
            while let Some((sid, data)) = stream_write_rx.recv().await {
                if is_closed.load(Ordering::Relaxed) {
                    break;
                }
                let msg = if data.is_empty() {
                    OutgoingMessage::Fin { stream_id: sid }
                } else {
                    OutgoingMessage::Data {
                        stream_id: sid,
                        data,
                    }
                };
                if outgoing_tx.send(msg).is_err() {
                    break;
                }
            }
        });

        let stream = AnyTlsStream::with_keepalive(
            stream_id,
            data_rx,
            stream_write_tx,
            Arc::clone(&self.is_closed),
            Arc::clone(self),
        );

        Ok(stream)
    }
}
