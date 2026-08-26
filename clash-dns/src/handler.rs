use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info};

use crate::{DNSListenAddr, DnsMessageExchanger};

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

pub async fn get_dns_listener<X>(
    listen: DNSListenAddr,
    exchanger: X,
) -> Result<impl std::future::Future<Output = ()>, DNSError>
where
    X: DnsMessageExchanger + Clone,
{
    let mut tasks = Vec::new();

    // 1. UDP Listener
    if let Some(udp_addr) = listen.udp {
        let socket = Arc::new(UdpSocket::bind(udp_addr).await?);
        info!("DNS UDP server listening on {}", udp_addr);
        let num_workers = std::thread::available_parallelism()
            .map_or(32, |n| (n.get() * 4).clamp(16, 128));
        let mut senders = Vec::with_capacity(num_workers);
        let per_worker_capacity = (MAX_CONCURRENT_UDP_QUERIES / num_workers).max(32);

        for _ in 0..num_workers {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<(bytes::Bytes, std::net::SocketAddr)>(per_worker_capacity);
            senders.push(tx);
            let ex = exchanger.clone();
            let socket = Arc::clone(&socket);
            tasks.push(tokio::spawn(async move {
                let mut inflight = FuturesUnordered::new();
                loop {
                    tokio::select! {
                        biased;
                        Some(()) = inflight.next(), if !inflight.is_empty() => {}
                        msg = rx.recv() => {
                            match msg {
                                Some((req, src)) => {
                                    let ex = ex.clone();
                                    let socket = Arc::clone(&socket);
                                    inflight.push(async move {
                                        match ex.exchange(&req).await {
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
            }));
        }

        let mut round_robin = 0usize;
        tasks.push(tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        let req = bytes::Bytes::copy_from_slice(&buf[..len]);
                        let idx = round_robin % num_workers;
                        round_robin = round_robin.wrapping_add(1);
                        if senders[idx].try_send((req, src)).is_err() {
                            debug!("DNS UDP query dropped due to concurrency saturation");
                        }
                    }
                    Err(e) => {
                        error!("DNS UDP socket recv error: {}", e);
                        break;
                    }
                }
            }
        }));
    }

    // 2. TCP Listener
    if let Some(tcp_addr) = listen.tcp {
        let listener = TcpListener::bind(tcp_addr).await?;
        info!("DNS TCP server listening on {}", tcp_addr);
        let ex = exchanger.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, peer)) => {
                        let ex = ex.clone();
                        tokio::spawn(async move {
                            let mut len_buf = [0u8; 2];
                            let mut req_buf = Vec::with_capacity(512);
                            let mut out_buf = Vec::with_capacity(512);
                            while stream.read_exact(&mut len_buf).await.is_ok() {
                                let msg_len = u16::from_be_bytes(len_buf) as usize;
                                if msg_len == 0 {
                                    break;
                                }
                                req_buf.resize(msg_len, 0);
                                if stream.read_exact(&mut req_buf).await.is_err() {
                                    break;
                                }
                                match ex.exchange(&req_buf).await {
                                    Ok(resp) => {
                                        let resp_len = resp.len() as u16;
                                        out_buf.clear();
                                        out_buf.extend_from_slice(&resp_len.to_be_bytes());
                                        out_buf.extend_from_slice(&resp);
                                        if stream.write_all(&out_buf).await.is_err() {
                                            break;
                                        }
                                        if stream.flush().await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        debug!("DNS TCP query from {} failed: {}", peer, e);
                                        break;
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("DNS TCP accept error: {}", e);
                        break;
                    }
                }
            }
        }));
    }

    Ok(async move {
        for task in tasks {
            let _ = task.await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[derive(Clone)]
    struct EchoExchanger;

    impl DnsMessageExchanger for EchoExchanger {
        fn ipv6(&self) -> bool {
            false
        }
        async fn exchange(&self, message: &[u8]) -> Result<Vec<u8>, DNSError> {
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

        let listener_fut = get_dns_listener(listen, EchoExchanger).await?;
        tokio::spawn(listener_fut);

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

        Ok(())
    }
}
