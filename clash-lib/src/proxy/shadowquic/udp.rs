use std::{collections::{HashMap, hash_map::Entry}, io, sync::{Arc, Once}};

use bytes::{BufMut, Bytes, BytesMut};
use quinn_jls::{Connection, RecvStream, SendStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::{self, Receiver, Sender},
    task::JoinSet,
    time::{interval, timeout},
};
use tokio_util::sync::CancellationToken;

use crate::{common::errors::new_io_error, proxy::datagram::UdpPacket, session::SocksAddr};

use super::{
    protocol::{ASSOCIATE_DATAGRAM, ASSOCIATE_STREAM, encode_addr, payload_len, write_request},
    registry::{Packet, REGISTER_TIMEOUT, Registry, Route},
};

#[derive(Clone)]
pub(super) struct ClientConnection(Arc<ConnectionState>);

struct ConnectionState {
    conn: Connection,
    registry: Arc<Registry>,
    cancel: CancellationToken,
    receiver_started: Once,
}

impl Drop for ConnectionState {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl ClientConnection {
    pub fn new(conn: Connection) -> Self {
        let registry = Arc::new(Registry::default());
        let cancel = CancellationToken::new();
        Self(Arc::new(ConnectionState {
            conn, registry, cancel, receiver_started: Once::new(),
        }))
    }

    pub fn connection(&self) -> &Connection {
        &self.0.conn
    }

    pub async fn associate(
        &self, addr: SocksAddr, over_stream: bool,
    ) -> io::Result<(Sender<UdpPacket>, Receiver<Packet>)> {
        self.0.receiver_started.call_once(|| {
            tokio::spawn(receive_packets(
                self.0.conn.clone(), self.0.registry.clone(), self.0.cancel.clone(),
            ));
        });
        let (mut send, recv) = self.0.conn.open_bi().await.map_err(new_io_error)?;
        let command = if over_stream { ASSOCIATE_STREAM } else { ASSOCIATE_DATAGRAM };
        write_request(&mut send, command, &addr).await?;
        let (outgoing, input) = mpsc::channel(32);
        let (output, incoming) = mpsc::channel(32);
        let state = self.0.clone();
        let session = Association {
            id: state.registry.session(),
            registry: state.registry.clone(),
            send_ids: Vec::new(),
            cancel: state.cancel.child_token(),
        };
        tokio::spawn(async move {
            let cancel = session.cancel.clone();
            let result = tokio::select! {
                _ = state.cancel.cancelled() => Ok(()),
                _ = output.closed() => Ok(()),
                result = run_association(
                    &state.conn, send, recv, input, &output, over_stream, session,
                ) => result,
            };
            cancel.cancel();
            if let Err(err) = result {
                tracing::debug!("shadowquic UDP association closed: {err}");
            }
        });
        Ok((outgoing, incoming))
    }
}

struct Association {
    id: u64,
    registry: Arc<Registry>,
    send_ids: Vec<u16>,
    cancel: CancellationToken,
}

impl Drop for Association {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.registry.remove_session(self.id, &self.send_ids);
    }
}

async fn run_association(
    conn: &Connection, mut send: SendStream, mut recv: RecvStream,
    mut input: Receiver<UdpPacket>, output: &Sender<Packet>, over_stream: bool,
    mut session: Association,
) -> io::Result<()> {
    let registry = session.registry.clone();
    let cancel = session.cancel.clone();
    let session_id = session.id;
    let receive_control = receive_control(
        &mut recv, &registry, session_id, output, &cancel,
    );
    let send_packets = async {
        if over_stream {
            send_over_stream(conn, &mut send, &mut input, &mut session).await
        } else {
            send_over_datagram(conn, &mut send, &mut input, &mut session).await
        }
    };
    tokio::select! {
        result = receive_control => result,
        result = send_packets => result,
    }
}

async fn register_destination(
    send: &mut SendStream, session: &mut Association, addr: &SocksAddr,
) -> io::Result<u16> {
    let mut header = encode_addr(addr)?;
    let id = session.registry.allocate()?;
    session.send_ids.push(id);
    header.put_u16(id);
    send.write_all(&header).await?;
    Ok(id)
}

async fn send_over_stream(
    conn: &Connection, control: &mut SendStream,
    input: &mut Receiver<UdpPacket>, session: &mut Association,
) -> io::Result<()> {
    let mut destinations = HashMap::new();
    while let Some(packet) = input.recv().await {
        let len = payload_len(packet.data.len())?;
        let stream = match destinations.entry(packet.dst_addr) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let id = register_destination(control, session, entry.key()).await?;
                let mut stream = conn.open_uni().await.map_err(new_io_error)?;
                stream.write_u16(id).await?;
                entry.insert(stream)
            }
        };
        stream.write_u16(len).await?;
        stream.write_all(&packet.data).await?;
    }
    Ok(())
}

async fn send_over_datagram(
    conn: &Connection, control: &mut SendStream,
    input: &mut Receiver<UdpPacket>, session: &mut Association,
) -> io::Result<()> {
    let mut destinations = HashMap::new();
    while let Some(packet) = input.recv().await {
        payload_len(packet.data.len())?;
        let id = match destinations.entry(packet.dst_addr) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let id = register_destination(control, session, entry.key()).await?;
                *entry.insert(id)
            }
        };
        let mut data = BytesMut::with_capacity(2 + packet.data.len());
        data.put_u16(id);
        data.extend_from_slice(&packet.data);
        conn.send_datagram(data.freeze()).map_err(new_io_error)?;
    }
    Ok(())
}

async fn receive_packets(
    conn: Connection, registry: Arc<Registry>, cancel: CancellationToken,
) {
    let mut streams = JoinSet::new();
    let mut expiry = interval(REGISTER_TIMEOUT);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = expiry.tick() => registry.expire(),
            Some(_) = streams.join_next() => {},
            packet = conn.read_datagram() => {
                let Ok(packet) = packet else { break };
                if packet.len() >= 2 {
                    let id = u16::from_be_bytes([packet[0], packet[1]]);
                    registry.deliver(id, packet.slice(2..));
                } else {
                    tracing::debug!("discarding shadowquic datagram without context ID");
                }
            }
            stream = conn.accept_uni(), if streams.len() < 500 => {
                let Ok(stream) = stream else { break };
                let registry = registry.clone();
                streams.spawn(async move {
                    if let Err(err) = receive_stream(stream, registry).await {
                        tracing::debug!("shadowquic UDP stream closed: {err}");
                    }
                });
            }
        }
    }
    cancel.cancel();
    // JoinSet aborts all outstanding receive tasks on drop.
}

async fn receive_stream(mut stream: RecvStream, registry: Arc<Registry>) -> io::Result<()> {
    let route: Route = timeout(REGISTER_TIMEOUT, async {
        let id = stream.read_u16().await?;
        loop {
            // Register before checking the table to avoid a lost notification.
            let changed = registry.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(route) = registry.route(id) {
                return Ok::<Route, io::Error>(route);
            }
            changed.await;
        }
    }).await.map_err(new_io_error)??;
    let receive = receive_payload(&mut stream, &route);
    tokio::select! {
        _ = route.cancel.cancelled() => Ok(()),
        result = receive => result,
    }
}

async fn receive_control(
    recv: &mut RecvStream, registry: &Registry, session: u64,
    output: &Sender<Packet>, cancel: &CancellationToken,
) -> io::Result<()> {
    loop {
        let addr = SocksAddr::read_from(recv).await?;
        let id = recv.read_u16().await?;
        registry.register(session, id, addr, output.clone(), cancel.clone())?;
    }
}

async fn receive_payload(stream: &mut RecvStream, route: &Route) -> io::Result<()> {
    loop {
        let len = stream.read_u16().await? as usize;
        let mut packet = vec![0; len];
        AsyncReadExt::read_exact(stream, &mut packet).await?;
        route.sender.send((Bytes::from(packet), route.addr.clone())).await
            .map_err(new_io_error)?;
    }
}
