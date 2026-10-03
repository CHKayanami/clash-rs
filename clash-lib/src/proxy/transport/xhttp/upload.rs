use std::{io, sync::Arc, time::Duration};
use bytes::{Bytes, BytesMut};
use tokio::{sync::{mpsc, oneshot}, task::JoinSet, time::{Instant, sleep_until, timeout}};
use super::{
    body::BodyChunk,
    connection::{REQUEST_TIMEOUT, HttpTransport, drain, response},
    options::Options,
    stream::Shared,
};

pub(super) enum Command { Data(Bytes), Flush(oneshot::Sender<()>), Shutdown(oneshot::Sender<()>) }

fn batch(first: Bytes, commands: &mut mpsc::Receiver<Command>, deferred: &mut Option<Command>) -> Bytes {
    let second = match commands.try_recv() {
        Ok(Command::Data(data)) => data,
        Ok(control) => { *deferred = Some(control); return first; }
        Err(_) => return first,
    };
    let mut batch = BytesMut::with_capacity(first.len() + second.len());
    batch.extend_from_slice(&first);
    batch.extend_from_slice(&second);
    while batch.len() < 131_072 {
        match commands.try_recv() {
            Ok(Command::Data(data)) => batch.extend_from_slice(&data),
            Ok(control) => { *deferred = Some(control); break; }
            Err(_) => break,
        }
    }
    batch.freeze()
}

pub(super) struct Packets {
    transport: Arc<HttpTransport>,
    options: Arc<Options>,
    session: Arc<str>,
    sequence: u64,
    next_post: Instant,
    pending: JoinSet<io::Result<()>>,
}
impl Packets {
    pub(super) fn new(transport: Arc<HttpTransport>, options: Arc<Options>, session: String) -> Self {
        Self { transport, options, session: session.into(), sequence: 0,
            next_post: Instant::now(), pending: JoinSet::new() }
    }

    async fn completed(&mut self) -> io::Result<()> {
        if let Some(reply) = self.pending.join_next().await { reply.map_err(io::Error::other)??; }
        Ok(())
    }

    async fn write(&mut self, mut bytes: Bytes) -> io::Result<()> {
        while !bytes.is_empty() {
            if self.pending.len() >= 16 { self.completed().await?; }
            sleep_until(self.next_post).await;
            let length = bytes.len().min(rand::random_range(self.options.post_bytes.clone()) as usize);
            let payload = bytes.split_to(length);
            let sequence = self.sequence;
            self.sequence = sequence.checked_add(1).ok_or_else(|| io::Error::other("XHTTP upload sequence exhausted"))?;
            let transport = self.transport.clone();
            let options = self.options.clone();
            let session = self.session.clone();
            self.pending.spawn(async move {
                timeout(REQUEST_TIMEOUT, async {
                    let reply = transport.start(|version| options.packet_request(&session, sequence, payload, version)).await?;
                    drain(response(reply).await?).await
                }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XHTTP packet upload timed out"))?
            });
            self.next_post = Instant::now() + Duration::from_millis(rand::random_range(self.options.interval_ms.clone()) as u64);
        }
        Ok(())
    }

    async fn flush(&mut self) -> io::Result<()> {
        while !self.pending.is_empty() { self.completed().await?; }
        Ok(())
    }
}

pub(super) enum Upload { Stream(mpsc::Sender<BodyChunk>), Packets(Packets) }
impl Upload {
    async fn write(&mut self, data: Bytes) -> io::Result<()> {
        match self {
            Self::Stream(sender) => {
                let (consumed, receiver) = oneshot::channel();
                sender.send(BodyChunk { data, consumed }).await
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "XHTTP upload closed"))?;
                receiver.await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "XHTTP upload body was not consumed"))
            }
            Self::Packets(packets) => packets.write(data).await,
        }
    }

    async fn next(&mut self, commands: &mut mpsc::Receiver<Command>) -> io::Result<Option<Command>> {
        if let Self::Packets(packets) = self {
            loop {
                tokio::select! {
                    reply = packets.completed(), if !packets.pending.is_empty() => { reply?; }
                    command = commands.recv() => return Ok(command),
                }
            }
        }
        Ok(commands.recv().await)
    }

    async fn flush(&mut self) -> io::Result<()> {
        if let Self::Packets(packets) = self { packets.flush().await?; }
        Ok(())
    }

    pub(super) async fn run(mut self, commands: &mut mpsc::Receiver<Command>, shared: &Shared) {
        let mut deferred = None;
        loop {
            let command = match deferred.take() {
                Some(command) => command,
                None => match self.next(commands).await {
                    Ok(Some(command)) => command,
                    Ok(None) => return,
                    Err(error) => { shared.fail(error); return; }
                },
            };
            let result = match command {
                Command::Data(data) => {
                    let data = if matches!(self, Self::Packets(_)) {
                        batch(data, commands, &mut deferred)
                    } else { data };
                    self.write(data).await
                }
                Command::Flush(reply) => {
                    if let Err(error) = self.flush().await { shared.fail(error); return; }
                    let _ = reply.send(());
                    Ok(())
                }
                Command::Shutdown(reply) => {
                    if let Err(error) = self.flush().await { shared.fail(error); return; }
                    drop(self); // Emits END_STREAM/chunked EOF for a streaming upload.
                    let _ = reply.send(());
                    return;
                }
            };
            if let Err(error) = result { shared.fail(error); return; }
        }
    }
}
