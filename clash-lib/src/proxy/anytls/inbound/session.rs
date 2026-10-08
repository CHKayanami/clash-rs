//! Multiplexed server session. FIN closes one stream, not its TLS transport.

use bytes::{Bytes, BytesMut};
use std::{collections::HashMap, future::Future, io};
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream,
        duplex, split,
    },
    sync::mpsc,
    task::JoinSet,
    time::{Duration, sleep},
};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::{
    proxy::anytls::{
        stream::STREAM_CHANNEL_BUFFER,
        types::{Command, Frame, FrameCodec, StringMap},
    },
    session::SocksAddr,
};

const DUPLEX_BUFFER_SIZE: usize = 64 * 1024;
const RELAY_BUFFER_SIZE: usize = 16 * 1024;
const OUTGOING_BUFFER_SIZE: usize = STREAM_CHANNEL_BUFFER * 8;

/// Keeps partial frames across cancelled reads in the session select loop.
struct FrameReader<R> {
    reader: R,
    buffer: BytesMut,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: BytesMut::with_capacity(8192),
        }
    }

    async fn read(&mut self) -> io::Result<Option<Frame>> {
        loop {
            if let Some(frame) = FrameCodec::decode(&mut self.buffer)? {
                return Ok(Some(frame));
            }
            if self.reader.read_buf(&mut self.buffer).await? == 0 {
                return if self.buffer.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated AnyTLS frame",
                    ))
                };
            }
        }
    }
}

enum StreamState {
    Pending,
    Active {
        incoming: mpsc::Sender<Bytes>,
        cancel: CancellationToken,
    },
}

enum TaskResult {
    Writer(io::Result<()>),
    Stream(u32, io::Result<()>),
}

async fn write_frames<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut outgoing: mpsc::Receiver<Frame>,
) -> io::Result<()> {
    let mut buffer = BytesMut::with_capacity(RELAY_BUFFER_SIZE + 7);
    while let Some(frame) = outgoing.recv().await {
        buffer.clear();
        frame.encode_into(&mut buffer);
        // One plaintext write avoids a separate 7-byte TLS header record.
        writer.write_all(&buffer).await?;
        writer.flush().await?;
    }
    Ok(())
}

/// Relay one stream with bounded backpressure in both directions. The shared
/// reader may stall on a slow stream, matching the protocol's lack of flow control.
async fn relay_stream<F>(
    stream_id: u32,
    relay: DuplexStream,
    mut incoming: mpsc::Receiver<Bytes>,
    outgoing: mpsc::Sender<Frame>,
    cancel: CancellationToken,
    dispatch: F,
) -> io::Result<()>
where
    F: Future<Output = ()>,
{
    let _cancel_on_drop = cancel.clone().drop_guard();
    let (mut reader, mut writer) = split(relay);
    let receive = async move {
        while let Some(data) = incoming.recv().await {
            writer.write_all(&data).await?;
        }
        Ok(())
    };
    let send = async {
        let mut buffer = BytesMut::with_capacity(RELAY_BUFFER_SIZE);
        loop {
            buffer.reserve(RELAY_BUFFER_SIZE);
            let n = (&mut reader)
                .take(RELAY_BUFFER_SIZE as u64)
                .read_buf(&mut buffer)
                .await?;
            if n == 0 {
                return Ok(());
            }
            outgoing
                .send(Frame::data(stream_id, buffer.split().freeze()))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "AnyTLS writer closed")
                })?;
        }
    };
    tokio::pin!(send);
    let relay = async {
        let result = tokio::select! {
            _ = cancel.cancelled() => Ok(()),
            result = receive => match result {
                Ok(()) => Ok(()),
                Err(err) => {
                    // The target may close while request data is still queued.
                    // Preserve its buffered response before sending FIN.
                    let drained = tokio::select! {
                        _ = cancel.cancelled() => Ok(()),
                        result = &mut send => result,
                    };
                    drained.and(Err(err))
                }
            },
            result = &mut send => result,
        };
        cancel.cancel();
        result
    };
    // Dispatcher completion drops its application end; drain its buffered
    // response before declaring this stream closed.
    let (result, ()) = tokio::join!(relay, dispatch);
    result
}

struct ServerSession<F> {
    streams: HashMap<u32, StreamState>,
    outgoing: mpsc::Sender<Frame>,
    tasks: JoinSet<TaskResult>,
    dispatch: F,
    started: bool,
}

impl<F, D> ServerSession<F>
where
    F: Fn(SocksAddr, DuplexStream, CancellationToken) -> D,
    D: Future<Output = ()> + Send + 'static,
{
    async fn send(&self, frame: Frame) -> io::Result<()> {
        self.outgoing.send(frame).await.map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "AnyTLS writer closed")
        })
    }

    async fn open_stream(&mut self, stream_id: u32, data: Bytes) -> io::Result<()> {
        let mut cursor = io::Cursor::new(&data[..]);
        let dest = match SocksAddr::read_from(&mut cursor).await {
            Ok(dest) => dest,
            Err(err) => {
                debug!("anytls inbound destination parse failed: {err}");
                self.streams.remove(&stream_id);
                return self.send(Frame::control(Command::Fin, stream_id)).await;
            }
        };
        let consumed = cursor.position() as usize;
        let (app, relay) = duplex(DUPLEX_BUFFER_SIZE);
        let (incoming, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let cancel = CancellationToken::new();
        let dispatch = (self.dispatch)(dest, app, cancel.clone());
        let sender = self.outgoing.clone();
        let stream_cancel = cancel.clone();
        self.tasks.spawn(async move {
            let result = relay_stream(
                stream_id, relay, incoming_rx, sender, stream_cancel, dispatch,
            ).await;
            TaskResult::Stream(stream_id, result)
        });
        if consumed < data.len() {
            let _ = incoming.send(data.slice(consumed..)).await;
        }
        self.streams.insert(
            stream_id, StreamState::Active { incoming, cancel },
        );
        self.started = true;
        Ok(())
    }

    async fn handle_frame(&mut self, frame: Frame) -> io::Result<()> {
        match frame.cmd {
            Command::Syn => {
                if self.streams.insert(frame.stream_id, StreamState::Pending)
                    .is_some()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData, "duplicate AnyTLS SYN",
                    ));
                }
            }
            Command::Psh => match self.streams.get(&frame.stream_id) {
                Some(StreamState::Pending) => {
                    self.open_stream(frame.stream_id, frame.data).await?;
                }
                Some(StreamState::Active { incoming, .. }) => {
                    // Completion drops the receiver; join_next then sends FIN.
                    let _ = incoming.send(frame.data).await;
                }
                None => {}
            },
            Command::Fin => {
                if let Some(StreamState::Active { cancel, .. }) =
                    self.streams.remove(&frame.stream_id)
                {
                    cancel.cancel();
                }
            }
            Command::HeartRequest => {
                self.send(Frame::control(Command::HeartResponse, frame.stream_id))
                    .await?;
            }
            Command::Alert => return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                String::from_utf8_lossy(&frame.data).into_owned(),
            )),
            Command::Settings | Command::Waste | Command::HeartResponse => {}
            _ => return Err(io::Error::new(
                io::ErrorKind::InvalidData, "unexpected AnyTLS client command",
            )),
        }
        Ok(())
    }
}

pub(super) async fn run_session<T, F, D>(transport: T, dispatch: F) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(SocksAddr, DuplexStream, CancellationToken) -> D,
    D: Future<Output = ()> + Send + 'static,
{
    let (reader, writer) = split(transport);
    let mut reader = FrameReader::new(reader);
    let (outgoing, outgoing_rx) = mpsc::channel(OUTGOING_BUFFER_SIZE);
    let mut session = ServerSession {
        streams: HashMap::new(),
        outgoing,
        tasks: JoinSet::new(),
        dispatch,
        started: false,
    };
    session.tasks.spawn(async move {
        TaskResult::Writer(write_frames(writer, outgoing_rx).await)
    });
    let mut settings = StringMap::new();
    // Dispatcher does not expose target-dial confirmation. Retain v1 opening
    // semantics rather than advertising v2 and acknowledging before the dial.
    settings.insert("v", "1");
    session.send(Frame::with_data(
        Command::ServerSettings, 0, Bytes::from(settings.to_bytes()),
    )).await?;

    let first_stream_timeout = sleep(Duration::from_secs(10));
    tokio::pin!(first_stream_timeout);
    let mut handshake_frames = 0;
    loop {
        tokio::select! {
            _ = &mut first_stream_timeout, if !session.started => {
                return Err(io::Error::new(io::ErrorKind::TimedOut,
                    "AnyTLS first stream handshake timed out"));
            }
            result = reader.read() => match result? {
                Some(frame) => {
                    if !session.started {
                        handshake_frames += 1;
                        if handshake_frames > 64 {
                            return Err(io::Error::new(io::ErrorKind::InvalidData,
                                "too many AnyTLS handshake frames"));
                        }
                    }
                    session.handle_frame(frame).await?;
                }
                None => return Ok(()),
            },
            result = session.tasks.join_next() => {
                match result.expect("session writer task must exist")
                    .map_err(io::Error::other)?
                {
                    TaskResult::Writer(result) => return result,
                    TaskResult::Stream(stream_id, result) => {
                        if let Err(err) = result {
                            debug!("anytls inbound stream {stream_id} ended: {err}");
                        }
                        if session.streams.remove(&stream_id).is_some() {
                            session.send(Frame::control(Command::Fin, stream_id))
                                .await?;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
