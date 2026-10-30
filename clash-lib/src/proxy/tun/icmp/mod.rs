//! Real direct echo forwarding. No proxy dialer and no remote fake-success fallback.
use std::{collections::HashMap, io, net::IpAddr, time::Duration};
use ipnet::{Ipv4Net, Ipv6Net};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinSet, time::timeout};
use tracing::{debug, trace, warn};
use super::packet_queue::Sender as ReplySender;
use packet::{Flow, Request};
mod packet;
mod socket;

const MAX_SESSIONS: usize = 16;
const INBOUND_PACKETS: usize = 64;
const SESSION_PACKETS: usize = 16;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const SEND_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) struct Client { sender: mpsc::Sender<Request>, mtu: usize }
struct Session { generation: u64, sender: mpsc::Sender<Request> }
pub(super) struct Relay {
    receiver: mpsc::Receiver<Request>,
    replies: ReplySender,
    mtu: usize,
    so_mark: Option<u32>,
}

pub(super) fn channel(mtu: usize, replies: ReplySender, so_mark: Option<u32>) -> (Client, Relay) {
    let (sender, receiver) = mpsc::channel(INBOUND_PACKETS);
    (Client { sender, mtu }, Relay { receiver, replies, mtu, so_mark })
}

pub(super) fn is_gateway(address: IpAddr, ipv4: Ipv4Net, ipv6: Option<Ipv6Net>) -> bool {
    match address {
        IpAddr::V4(ip) => ip == ipv4.addr(),
        IpAddr::V6(ip) => ipv6.is_some_and(|net| ip == net.addr()),
    }
}

impl Client {
    /// Return true only when consumed here. Local/FakeIP echo keeps the existing
    /// in-stack responder. A full direct queue drops ICMP, never stalls TUN RX.
    pub fn intercept(&self, bytes: &[u8], local: impl FnOnce(IpAddr) -> bool) -> bool {
        match packet::decode(bytes, self.mtu) {
            Ok(Some(request)) => {
                if local(request.flow.destination) { return false; }
                if !packet::valid_address(request.flow.source)
                    || !packet::valid_address(request.flow.destination) { return true; }
                if self.sender.try_send(request).is_err() {
                    trace!("dropping ICMP echo: direct queue unavailable");
                }
                true
            }
            Err(()) => { trace!("dropping invalid ICMP echo"); true }
            Ok(None) => false,
        }
    }
}

impl Relay {
    pub async fn run(mut self) -> io::Result<()> {
        let mut sessions: HashMap<Flow, Session> = HashMap::new();
        let mut tasks = JoinSet::new();
        let mut generation = 0u64;
        loop {
            tokio::select! {
                request = self.receiver.recv() => {
                    let Some(request) = request else { break; };
                    sessions.retain(|_, session| !session.sender.is_closed());
                    let flow = request.flow;
                    if let Some(session) = sessions.get(&flow) {
                        let _ = session.sender.try_send(request);
                        continue;
                    }
                    if sessions.len() >= MAX_SESSIONS {
                        trace!("dropping ICMP echo: direct session limit");
                        continue;
                    }
                    let socket = match socket::open(flow.destination, self.so_mark) {
                        Ok(socket) => socket,
                        Err(error) => {
                            warn!("cannot create direct ICMP socket: {error}");
                            continue;
                        }
                    };
                    let (sender, receiver) = mpsc::channel(SESSION_PACKETS);
                    let _ = sender.try_send(request);
                    generation = generation.wrapping_add(1);
                    let id = generation;
                    sessions.insert(flow, Session { generation: id, sender });
                    let replies = self.replies.clone();
                    let mtu = self.mtu;
                    tasks.spawn(async move {
                        if let Err(error) = session(socket, flow, receiver, replies, mtu).await {
                            debug!("direct ICMP session ended: {error}");
                        }
                        (flow, id)
                    });
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    match completed {
                        Some(Ok((flow, id))) => {
                            if sessions.get(&flow).is_some_and(|session| session.generation == id) {
                                sessions.remove(&flow);
                            }
                        }
                        Some(Err(error)) => warn!("direct ICMP task failed: {error}"),
                        None => {},
                    }
                }
            }
        }
        drop(sessions);
        tasks.shutdown().await;
        Ok(())
    }
}

async fn session(socket: UdpSocket, flow: Flow, mut requests: mpsc::Receiver<Request>,
    replies: ReplySender, mtu: usize) -> io::Result<()> {
    let mut buffer = vec![0; mtu + 1];
    loop {
        let event = timeout(IDLE_TIMEOUT, async {
            tokio::select! {
                request = requests.recv() => {
                    let Some(request) = request else { return Ok(false); };
                    socket::set_hop_limit(&socket, flow.destination.is_ipv6(), request.hop_limit)?;
                    let length = timeout(SEND_TIMEOUT, socket.send(&request.payload)).await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ICMP send timed out"))??;
                    if length != request.payload.len() {
                        return Err(io::Error::new(io::ErrorKind::WriteZero, "partial ICMP send"));
                    }
                }
                received = socket::receive(&socket, &mut buffer, flow.destination.is_ipv6()) => {
                    let (length, hop_limit) = received?;
                    if let Some(packet) = packet::reply(flow, &buffer[..length], mtu, hop_limit) {
                        replies.send(packet).await?;
                    }
                }
            }
            Ok(true)
        }).await;
        match event {
            Ok(Ok(true)) => {},
            Ok(Ok(false)) | Err(_) => return Ok(()),
            Ok(Err(error)) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests;
