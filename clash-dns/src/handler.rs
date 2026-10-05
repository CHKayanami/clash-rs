use futures::stream::{FuturesUnordered, StreamExt};
use std::{io::ErrorKind, net::SocketAddr, sync::Arc, time::Duration};
use bytes::Bytes;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, error, info};

use crate::{DNSListenAddr, DnsIngress, DnsMessageExchanger};

#[derive(Error, Debug)]
pub enum DNSError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid OP code: {0}")]
    InvalidOpQuery(String),
    #[error("query failed: {0}")]
    QueryFailed(String),
}

const MAX_CONCURRENT_UDP_QUERIES: usize = 4096;
const MAX_TCP_CONNECTIONS: usize = 256;
const TCP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn get_dns_listener<X>(
    listen: DNSListenAddr,
    exchanger: X,
) -> Result<impl std::future::Future<Output = ()>, DNSError>
where
    X: DnsMessageExchanger + Clone,
{
    start_listener(
        listen, exchanger, MAX_CONCURRENT_UDP_QUERIES,
        MAX_TCP_CONNECTIONS, TCP_REQUEST_TIMEOUT,
    ).await
}

async fn start_listener<X>(
    listen: DNSListenAddr,
    exchanger: X,
    udp_limit: usize,
    tcp_limit: usize,
    tcp_timeout: Duration,
) -> Result<impl std::future::Future<Output = ()>, DNSError>
where
    X: DnsMessageExchanger + Clone,
{
    // Bind everything before spawning so a partial startup cannot leave tasks.
    let udp = match listen.udp {
        Some(addr) => Some(Arc::new(UdpSocket::bind(addr).await?)),
        None => None,
    };
    let tcp = match listen.tcp {
        Some(addr) => Some(TcpListener::bind(addr).await?),
        None => None,
    };
    // Dropping the returned future aborts listeners and workers. The TCP
    // listener owns its connection tasks in another JoinSet for the same reason.
    let mut tasks = JoinSet::new();
    if let Some(socket) = udp {
        info!("DNS UDP server listening on {}", socket.local_addr()?);
        let num_workers = std::thread::available_parallelism()
            .map_or(32, |n| (n.get() * 4).clamp(16, 128));
        let permits = Arc::new(Semaphore::new(udp_limit));
        let mut senders = Vec::with_capacity(num_workers);
        let per_worker_capacity = (udp_limit / num_workers).max(1);

        for _ in 0..num_workers {
            let (tx, mut rx) = mpsc::channel::<(
                Bytes, SocketAddr, OwnedSemaphorePermit,
            )>(per_worker_capacity);
            senders.push(tx);
            let ex = exchanger.clone();
            let socket = Arc::clone(&socket);
            tasks.spawn(async move {
                let mut inflight = FuturesUnordered::new();
                loop {
                    tokio::select! {
                        biased;
                        Some(()) = inflight.next(), if !inflight.is_empty() => {}
                        msg = rx.recv() => {
                            match msg {
                                Some((req, src, permit)) => {
                                    let ex = ex.clone();
                                    let socket = Arc::clone(&socket);
                                    inflight.push(async move {
                                        let _permit = permit;
                                        match ex.exchange(req, Some(src.ip()), DnsIngress::Udp).await {
                                            Ok(resp) => {
                                                let _ = socket.send_to(&resp, src).await;
                                            }
                                            Err(e) => {
                                                debug!("DNS UDP query from {} failed: {}", src, e);
                                            }
                                        }
                                    });
                                }
                                None => {
                                    while inflight.next().await.is_some() {}
                                    break;
                                }
                            }
                        }
                    }
                }
            });
        }

        tasks.spawn(async move {
            let mut buf = [0u8; 4096];
            let mut round_robin = 0usize;
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        // Count queued and executing queries together; release
                        // the permit on completion, rejection or cancellation.
                        let Ok(permit) = permits.clone().try_acquire_owned() else {
                            debug!("DNS UDP query dropped due to concurrency saturation");
                            continue;
                        };
                        let req = Bytes::copy_from_slice(&buf[..len]);
                        let idx = round_robin % num_workers;
                        round_robin = round_robin.wrapping_add(1);
                        if senders[idx].try_send((req, src, permit)).is_err() {
                            debug!("DNS UDP query dropped due to concurrency saturation");
                        }
                    }
                    Err(e) => {
                        error!("DNS UDP socket recv error: {}", e);
                        break;
                    }
                }
            }
        });
    }

    if let Some(listener) = tcp {
        info!("DNS TCP server listening on {}", listener.local_addr()?);
        tasks.spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, peer)) => {
                                if connections.len() >= tcp_limit {
                                    debug!("DNS TCP connection rejected due to concurrency saturation");
                                    continue;
                                }
                                connections.spawn(serve_tcp(
                                    stream, peer, exchanger.clone(), tcp_timeout,
                                ));
                            }
                            Err(e) => {
                                error!("DNS TCP accept error: {}", e);
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    Ok(async move {
        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result {
                error!("DNS listener task failed: {}", e);
                break;
            }
        }
    })
}

async fn serve_tcp<X>(
    mut stream: TcpStream,
    peer: SocketAddr,
    exchanger: X,
    request_timeout: Duration,
) where
    X: DnsMessageExchanger,
{
    let mut out_buf = Vec::with_capacity(512);
    loop {
        // A whole request deadline also bounds partial frames, stalled
        // exchanges and peers that stop reading responses.
        let result = timeout(request_timeout, async {
            let mut len_buf = [0u8; 2];
            if let Err(e) = stream.read_exact(&mut len_buf).await {
                if e.kind() == ErrorKind::UnexpectedEof {
                    return Ok::<bool, DNSError>(false);
                }
                return Err(e.into());
            }
            let msg_len = u16::from_be_bytes(len_buf) as usize;
            if msg_len == 0 {
                return Ok::<bool, DNSError>(false);
            }
            let mut req = vec![0; msg_len];
            stream.read_exact(&mut req).await?;
            let resp = exchanger.exchange(
                Bytes::from(req), Some(peer.ip()), DnsIngress::Tcp,
            ).await?;
            let resp_len = u16::try_from(resp.len()).map_err(|_| {
                DNSError::QueryFailed("DNS TCP response exceeds frame size".into())
            })?;
            out_buf.clear();
            out_buf.extend_from_slice(&resp_len.to_be_bytes());
            out_buf.extend_from_slice(&resp);
            stream.write_all(&out_buf).await?;
            stream.flush().await?;
            Ok(true)
        }).await;
        match result {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => break,
            Ok(Err(e)) => {
                debug!("DNS TCP query from {} failed: {}", peer, e);
                break;
            }
            Err(_) => {
                debug!("DNS TCP request from {} timed out", peer);
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::Duration;
    use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

    #[derive(Clone)]
    struct EchoExchanger {
        sources: UnboundedSender<(Option<IpAddr>, DnsIngress)>,
    }

    impl DnsMessageExchanger for EchoExchanger {
        fn ipv6(&self) -> bool {
            false
        }
        async fn exchange(&self, message: Bytes, source_ip: Option<IpAddr>, ingress: DnsIngress) -> Result<Vec<u8>, DNSError> {
            self.sources.send((source_ip, ingress)).unwrap();
            let mut resp = message.to_vec();
            if resp.len() >= 4 {
                resp[2] |= 0x80; // Set QR flag to indicate response
            }
            Ok(resp)
        }
    }

    #[tokio::test]
    async fn test_dns_listener_udp_and_tcp() -> anyhow::Result<()> {
        let udp_sock = UdpSocket::bind("127.0.0.1:0").await?;
        let udp_addr = udp_sock.local_addr()?;
        drop(udp_sock);

        let tcp_sock = TcpListener::bind("127.0.0.1:0").await?;
        let tcp_addr = tcp_sock.local_addr()?;
        drop(tcp_sock);

        let listen = DNSListenAddr {
            udp: Some(udp_addr),
            tcp: Some(tcp_addr),
            dot: None,
            doh: None,
            doh3: None,
        };

        let (sources, mut received_sources) = unbounded_channel();
        let listener_fut = get_dns_listener(listen, EchoExchanger { sources }).await?;
        let listener = tokio::spawn(listener_fut);

        tokio::time::sleep(Duration::from_millis(50)).await;

        // 1. Test UDP query
        let client_udp = UdpSocket::bind("127.0.0.1:0").await?;
        let query_data = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        client_udp.send_to(&query_data, udp_addr).await?;

        let mut buf = vec![0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client_udp.recv_from(&mut buf)).await??;
        assert!(len >= 4);
        assert_eq!(buf[0], 0x12);
        assert_eq!(buf[1], 0x34);
        assert_eq!(buf[2] & 0x80, 0x80); // Response bit set

        // 2. Test TCP query
        let mut client_tcp = tokio::net::TcpStream::connect(tcp_addr).await?;
        let msg_len = (query_data.len() as u16).to_be_bytes();
        client_tcp.write_all(&msg_len).await?;
        client_tcp.write_all(&query_data).await?;
        client_tcp.flush().await?;

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(2), client_tcp.read_exact(&mut len_buf)).await??;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        assert_eq!(resp_len, query_data.len());

        let mut resp_buf = vec![0u8; resp_len];
        tokio::time::timeout(Duration::from_secs(2), client_tcp.read_exact(&mut resp_buf)).await??;
        assert_eq!(resp_buf[0], 0x12);
        assert_eq!(resp_buf[1], 0x34);
        assert_eq!(resp_buf[2] & 0x80, 0x80);

        assert_eq!(
            received_sources.recv().await,
            Some((Some(client_udp.local_addr()?.ip()), DnsIngress::Udp)),
        );
        assert_eq!(
            received_sources.recv().await,
            Some((Some(client_tcp.local_addr()?.ip()), DnsIngress::Tcp)),
        );

        listener.abort();
        let _ = listener.await;
        Ok(())
    }

    #[derive(Clone)]
    struct BlockingExchanger {
        entered: UnboundedSender<()>,
        release: Arc<Semaphore>,
    }

    impl DnsMessageExchanger for BlockingExchanger {
        fn ipv6(&self) -> bool {
            false
        }

        async fn exchange(
            &self, message: Bytes, _: Option<IpAddr>, _: DnsIngress,
        ) -> Result<Vec<u8>, DNSError> {
            self.entered.send(()).unwrap();
            let permit = self.release.acquire().await.unwrap();
            permit.forget();
            Ok(message.to_vec())
        }
    }

    async fn available_addresses() -> anyhow::Result<DNSListenAddr> {
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        Ok(DNSListenAddr {
            udp: Some(udp.local_addr()?),
            tcp: Some(tcp.local_addr()?),
            ..DNSListenAddr::default()
        })
    }

    #[tokio::test]
    async fn test_udp_limit_and_listener_drop() -> anyhow::Result<()> {
        let listen = available_addresses().await?;
        let (entered, mut events) = unbounded_channel();
        let release = Arc::new(Semaphore::new(0));
        let weak = Arc::downgrade(&release);
        let listener = start_listener(
            listen.clone(), BlockingExchanger { entered, release: release.clone() },
            2, 2, Duration::from_secs(1),
        ).await?;
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        for _ in 0..2 {
            client.send_to(&[1], listen.udp.unwrap()).await?;
            timeout(Duration::from_secs(1), events.recv()).await?.unwrap();
        }
        client.send_to(&[2], listen.udp.unwrap()).await?;
        assert!(timeout(Duration::from_millis(100), events.recv()).await.is_err());
        release.add_permits(1);
        let mut buf = [0; 16];
        timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
        client.send_to(&[3], listen.udp.unwrap()).await?;
        timeout(Duration::from_secs(1), events.recv()).await?.unwrap();

        // Cancellation must release active UDP and TCP exchanges,
        // even when the returned future has never been polled.
        let mut tcp = TcpStream::connect(listen.tcp.unwrap()).await?;
        tcp.write_all(&[0, 1, 9]).await?;
        timeout(Duration::from_secs(1), events.recv()).await?.unwrap();
        drop(release);
        drop(listener);
        timeout(Duration::from_secs(1), async {
            while weak.upgrade().is_some() { tokio::task::yield_now().await; }
        }).await?;
        assert_eq!(timeout(Duration::from_secs(1), tcp.read(&mut buf)).await??, 0);
        let _udp = UdpSocket::bind(listen.udp.unwrap()).await?;
        let _tcp = TcpListener::bind(listen.tcp.unwrap()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_tcp_limit_and_partial_frame_timeout() -> anyhow::Result<()> {
        let listen = available_addresses().await?;
        let (sources, _events) = unbounded_channel();
        let listener = start_listener(
            listen.clone(), EchoExchanger { sources }, 2, 1,
            Duration::from_millis(300),
        ).await?;
        let mut first = TcpStream::connect(listen.tcp.unwrap()).await?;
        // A response proves the first connection was admitted before the next.
        first.write_all(&[0, 1, 7]).await?;
        let mut response = [0; 3];
        timeout(Duration::from_secs(1), first.read_exact(&mut response)).await??;
        let mut rejected = TcpStream::connect(listen.tcp.unwrap()).await?;
        let mut buf = [0; 1];
        assert_eq!(timeout(Duration::from_millis(200), rejected.read(&mut buf)).await??, 0);
        // Sending only part of the length prefix must not keep a slot forever.
        first.write_all(&[0]).await?;
        assert_eq!(timeout(Duration::from_secs(1), first.read(&mut buf)).await??, 0);
        let mut next = TcpStream::connect(listen.tcp.unwrap()).await?;
        next.write_all(&[0, 1, 8]).await?;
        timeout(Duration::from_secs(1), next.read_exact(&mut response)).await??;
        assert_eq!(response, [0, 1, 8]);
        drop(listener);
        Ok(())
    }

    #[tokio::test]
    async fn test_partial_bind_failure_releases_udp() -> anyhow::Result<()> {
        let listen = available_addresses().await?;
        let _occupied = TcpListener::bind(listen.tcp.unwrap()).await?;
        let (sources, _events) = unbounded_channel();
        assert!(get_dns_listener(listen.clone(), EchoExchanger { sources }).await.is_err());
        let _udp = UdpSocket::bind(listen.udp.unwrap()).await?;
        Ok(())
    }
}
