use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use super::dial::dial_candidates;
use crate::app::dns::endpoint::DnsEndpoint;

pub async fn dns_quic_config(alpn: &[&[u8]]) -> anyhow::Result<quinn::ClientConfig> {
    let client_config = crate::common::tls::build_tls_client_config(
        Arc::new(crate::common::tls::DefaultTlsVerifier::new(None, false)),
        None,
        None,
    )?;
    let mut tls_config = client_config;
    tls_config.alpn_protocols = alpn.iter().map(|&x| x.to_vec()).collect();

    let quic_client_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| anyhow::anyhow!("QUIC client config error: {e}"))?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic_client_config));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    config.transport_config(Arc::new(transport));

    Ok(config)
}

struct CachedEndpoint {
    endpoint: quinn::Endpoint,
    proxy_socket: Option<Arc<super::quic_proxy::ProxyQuicSocket>>,
}

struct RetiredEndpoint {
    cached: CachedEndpoint,
    task: super::owned_task::OwnedTask,
    finished: Arc<AtomicBool>,
}

pub struct SharedQuicEndpoint {
    endpoints:
        tokio::sync::Mutex<HashMap<(bool, Option<SocketAddr>), CachedEndpoint>>,
    retired: tokio::sync::Mutex<Vec<RetiredEndpoint>>,
    iface: Option<crate::app::net::OutboundInterface>,
    so_mark: Option<u32>,
    dial: Option<super::dial::DialContext>,
    active_tasks: Arc<AtomicUsize>,
}

impl SharedQuicEndpoint {
    pub fn new() -> Self {
        Self::with_options(None, None)
    }

    pub fn with_options(
        iface: Option<crate::app::net::OutboundInterface>,
        so_mark: Option<u32>,
    ) -> Self {
        Self {
            endpoints: tokio::sync::Mutex::new(HashMap::new()),
            retired: tokio::sync::Mutex::new(Vec::new()),
            iface,
            so_mark,
            dial: None,
            active_tasks: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn with_dial(
        dial: super::dial::DialContext,
        active_tasks: Arc<AtomicUsize>,
    ) -> Self {
        let mut endpoint = Self::with_options(dial.iface.clone(), dial.so_mark);
        if dial.outbound.is_some() {
            endpoint.dial = Some(dial);
        }
        endpoint.active_tasks = active_tasks;
        endpoint
    }

    async fn get(&self, address: SocketAddr) -> anyhow::Result<quinn::Endpoint> {
        let key = (address.is_ipv6(), self.dial.as_ref().map(|_| address));
        let mut endpoints = self.endpoints.lock().await;
        if let Some(cached) = endpoints.get(&key)
            && !cached
                .proxy_socket
                .as_ref()
                .is_some_and(|socket| socket.is_closed())
        {
            return Ok(cached.endpoint.clone());
        }
        if let Some(old) = endpoints.remove(&key) {
            old.endpoint
                .close(0_u32.into(), b"proxy association failed");
            if let Some(socket) = old.proxy_socket {
                socket.close().await;
            }
        }
        let cached = if let Some(dial) = &self.dial {
            let datagram = dial.dial_udp(address).await?;
            let socket = super::quic_proxy::ProxyQuicSocket::new(
                datagram,
                address,
                Arc::clone(&self.active_tasks),
            );
            let endpoint = quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                socket.clone(),
                Arc::new(quinn::TokioRuntime),
            )?;
            CachedEndpoint {
                endpoint,
                proxy_socket: Some(socket),
            }
        } else {
            let socket = super::dial::direct_udp_socket(
                address,
                self.iface.as_ref(),
                self.so_mark,
            )?;
            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                socket,
                Arc::new(quinn::TokioRuntime),
            )?;
            CachedEndpoint {
                endpoint,
                proxy_socket: None,
            }
        };
        let endpoint = cached.endpoint.clone();
        endpoints.insert(key, cached);
        Ok(endpoint)
    }

    async fn prune(&self, candidates: &[SocketAddr]) {
        if self.dial.is_none() {
            return;
        }
        let removed = {
            let mut endpoints = self.endpoints.lock().await;
            let keys: Vec<_> = endpoints
                .iter()
                .filter_map(|(key, _cached)| {
                    let obsolete =
                        key.1.is_some_and(|address| !candidates.contains(&address));
                    obsolete.then_some(*key)
                })
                .collect();
            keys.into_iter()
                .filter_map(|key| endpoints.remove(&key))
                .collect::<Vec<_>>()
        };
        let mut retired = self.retired.lock().await;
        retired.retain(|entry| !entry.finished.load(Ordering::Acquire));
        for cached in removed {
            if cached.endpoint.open_connections() == 0 {
                cached.endpoint.close(0_u32.into(), b"address retired");
                if let Some(socket) = cached.proxy_socket {
                    socket.close().await;
                }
            } else {
                // Quinn includes draining connections in open_connections(). Wait
                // for them without interrupting queries or retaining sockets forever.
                let endpoint = cached.endpoint.clone();
                let socket = cached.proxy_socket.clone();
                let finished = Arc::new(AtomicBool::new(false));
                let done = finished.clone();
                let task = super::owned_task::OwnedTask::spawn(
                    async move {
                        endpoint.wait_idle().await;
                        endpoint.close(0_u32.into(), b"address retired");
                        if let Some(socket) = socket {
                            socket.close().await;
                        }
                        done.store(true, Ordering::Release);
                    },
                    self.active_tasks.clone(),
                );
                retired.push(RetiredEndpoint {
                    cached,
                    task,
                    finished,
                });
            }
        }
    }

    pub async fn close(&self, timeout: Duration) {
        let endpoints = std::mem::take(&mut *self.endpoints.lock().await);
        let retired = std::mem::take(&mut *self.retired.lock().await);
        for entry in retired {
            entry.cached.endpoint.close(0_u32.into(), b"shutdown");
            if let Some(socket) = entry.cached.proxy_socket {
                socket.close().await;
            }
            entry.task.shutdown(Duration::ZERO).await;
        }
        for cached in endpoints.into_values() {
            cached.endpoint.close(0_u32.into(), b"shutdown");
            let _ = tokio::time::timeout(timeout, cached.endpoint.wait_idle()).await;
            if let Some(socket) = cached.proxy_socket {
                socket.close().await;
            }
        }
    }
}

async fn quic_connect(
    endpoint: &SharedQuicEndpoint,
    config: &quinn::ClientConfig,
    addr: std::net::SocketAddr,
    sni: &str,
    label: &str,
) -> anyhow::Result<quinn::Connection> {
    let ep = endpoint.get(addr).await?;
    let connecting = ep
        .connect_with(config.clone(), addr, sni)
        .map_err(|e| anyhow::anyhow!("{label} connect_with: {e}"))?;
    connecting
        .await
        .map_err(|e| anyhow::anyhow!("{label} handshake: {e}"))
}

pub async fn quic_connect_endpoint(
    endpoint: &SharedQuicEndpoint,
    config: &quinn::ClientConfig,
    target: &DnsEndpoint,
    deadline: tokio::time::Instant,
    label: &str,
) -> anyhow::Result<quinn::Connection> {
    let addresses = tokio::time::timeout_at(deadline, target.resolve_addrs())
        .await
        .map_err(|_| anyhow::anyhow!("{label} address resolution timed out"))??;
    endpoint.prune(&addresses).await;
    let result = dial_candidates(addresses, deadline, label, |address, _| {
        quic_connect(endpoint, config, address, &target.sni, label)
    })
    .await;
    if result.is_err() {
        target.invalidate_addresses();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::endpoint::{DnsProtocol, DnsStrategy};
    use crate::proxy::direct;
    use std::sync::atomic::Ordering;

    fn dial() -> super::super::dial::DialContext {
        super::super::dial::DialContext {
            endpoint: DnsEndpoint::parse(
                "127.0.0.1:853",
                DnsProtocol::Quic,
                None,
                None,
                DnsStrategy::PreferIpv4,
            )
            .unwrap(),
            dial_timeout: Duration::from_secs(1),
            query_timeout: Duration::from_secs(1),
            outbound: Some(Arc::new(direct::Handler::new("test-outbound"))),
            iface: None,
            so_mark: None,
            resolver: None,
        }
    }

    #[tokio::test]
    async fn obsolete_idle_proxy_associations_are_reclaimed() {
        let active = Arc::new(AtomicUsize::new(0));
        let shared = SharedQuicEndpoint::with_dial(dial(), active.clone());
        let old = "127.0.0.1:853".parse().unwrap();
        let current = "127.0.0.2:853".parse().unwrap();
        shared.get(old).await.unwrap();
        shared.get(current).await.unwrap();
        let old_socket = shared.endpoints.lock().await[&(false, Some(old))]
            .proxy_socket
            .clone()
            .unwrap();
        let current_socket = shared.endpoints.lock().await[&(false, Some(current))]
            .proxy_socket
            .clone()
            .unwrap();
        shared.prune(&[current]).await;
        assert!(old_socket.is_closed());
        assert!(!current_socket.is_closed());
        assert_eq!(shared.endpoints.lock().await.len(), 1);
        assert_eq!(active.load(Ordering::SeqCst), 2);
        shared.close(Duration::ZERO).await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn obsolete_proxy_association_survives_until_its_connection_finishes() {
        let (server, config) = super::super::quic_test_support::server(b"doq");
        let target = server.local_addr().unwrap();
        let active = Arc::new(AtomicUsize::new(0));
        let shared = SharedQuicEndpoint::with_dial(dial(), active.clone());
        let endpoint = shared.get(target).await.unwrap();
        let (client, remote) = tokio::join!(
            endpoint.connect_with(config, target, "localhost").unwrap(),
            async { server.accept().await.unwrap().await.unwrap() },
        );
        let connection = client.unwrap();
        let socket = shared.endpoints.lock().await[&(false, Some(target))]
            .proxy_socket
            .clone()
            .unwrap();
        shared.prune(&[]).await;
        assert!(!socket.is_closed());
        assert!(shared.endpoints.lock().await.is_empty());
        assert_eq!(shared.retired.lock().await.len(), 1);
        assert!(connection.close_reason().is_none());
        connection.close(0_u32.into(), b"done");
        remote.closed().await;
        tokio::time::timeout(Duration::from_secs(5), async {
            endpoint.wait_idle().await;
            while active.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        shared.prune(&[]).await;
        assert!(shared.retired.lock().await.is_empty());
        assert!(socket.is_closed());
        assert!(shared.endpoints.lock().await.is_empty());
        assert_eq!(active.load(Ordering::SeqCst), 0);
        server.close(0_u32.into(), b"done");
    }

    #[tokio::test]
    async fn shutdown_closes_retiring_associations_and_cleanup_tasks() {
        let (server, config) = super::super::quic_test_support::server(b"doq");
        let target = server.local_addr().unwrap();
        let active = Arc::new(AtomicUsize::new(0));
        let shared = SharedQuicEndpoint::with_dial(dial(), active.clone());
        let endpoint = shared.get(target).await.unwrap();
        let (client, remote) = tokio::join!(
            endpoint.connect_with(config, target, "localhost").unwrap(),
            async { server.accept().await.unwrap().await.unwrap() },
        );
        let connection = client.unwrap();
        shared.prune(&[]).await;
        assert_eq!(shared.retired.lock().await.len(), 1);
        shared.close(Duration::ZERO).await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(shared.retired.lock().await.is_empty());
        assert!(connection.close_reason().is_some());
        remote.close(0_u32.into(), b"done");
        server.close(0_u32.into(), b"done");
    }

    #[tokio::test]
    async fn failed_proxy_association_is_recreated() {
        let active = Arc::new(AtomicUsize::new(0));
        let shared = SharedQuicEndpoint::with_dial(dial(), active.clone());
        let target = "127.0.0.1:853".parse().unwrap();
        let key = (false, Some(target));
        let first_endpoint = shared.get(target).await.unwrap();
        let first = shared.endpoints.lock().await[&key]
            .proxy_socket
            .clone()
            .unwrap();
        first.close().await;
        let second_endpoint = shared.get(target).await.unwrap();
        let second = shared.endpoints.lock().await[&key]
            .proxy_socket
            .clone()
            .unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(!second.is_closed());
        assert_eq!(shared.endpoints.lock().await.len(), 1);
        shared.close(Duration::ZERO).await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
        drop((first_endpoint, second_endpoint));
    }

    #[tokio::test]
    async fn outbound_without_udp_fails_without_direct_fallback() {
        let active = Arc::new(AtomicUsize::new(0));
        let mut context = dial();
        context.outbound =
            Some(Arc::new(crate::proxy::reject::Handler::new("no-udp")));
        let shared = SharedQuicEndpoint::with_dial(context, active.clone());
        let result = shared.get("127.0.0.1:853".parse().unwrap()).await;
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("does not support UDP")
        );
        assert!(shared.endpoints.lock().await.is_empty());
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
