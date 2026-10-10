use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use parking_lot::Mutex;
use tokio::sync::Mutex as AsyncMutex;

use super::{
    dial::{DialContext, dial_candidates, direct_udp_socket},
    owned_task::OwnedTask,
    quic_proxy::ProxyQuicSocket,
};
use crate::app::{
    dns::{endpoint::DnsEndpoint, upstream_pool::AdmissionGate},
    net::OutboundInterface,
};

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
    proxy_socket: Option<Arc<ProxyQuicSocket>>,
}

impl Drop for CachedEndpoint {
    fn drop(&mut self) {
        self.endpoint.close(0_u32.into(), b"endpoint released");
        if let Some(socket) = &self.proxy_socket {
            socket.abort();
        }
    }
}

struct EndpointSlot {
    cached: ArcSwapOption<CachedEndpoint>,
    initialize: Arc<AsyncMutex<()>>,
}

impl EndpointSlot {
    fn new() -> Self {
        Self {
            cached: ArcSwapOption::empty(),
            initialize: Arc::new(AsyncMutex::new(())),
        }
    }
}

struct RetiredEndpoint {
    cached: Arc<CachedEndpoint>,
    task: OwnedTask,
    finished: Arc<AtomicBool>,
}

pub struct SharedQuicEndpoint {
    endpoints: Mutex<HashMap<(bool, Option<SocketAddr>), Arc<EndpointSlot>>>,
    retired: Mutex<Vec<RetiredEndpoint>>,
    admission: AdmissionGate,
    iface: Option<OutboundInterface>,
    so_mark: Option<u32>,
    dial: Option<DialContext>,
    active_tasks: Arc<AtomicUsize>,
}

impl SharedQuicEndpoint {
    pub fn new() -> Self {
        Self::with_options(None, None)
    }

    pub fn with_options(
        iface: Option<OutboundInterface>,
        so_mark: Option<u32>,
    ) -> Self {
        Self {
            endpoints: Mutex::new(HashMap::new()),
            retired: Mutex::new(Vec::new()),
            admission: AdmissionGate::new(),
            iface,
            so_mark,
            dial: None,
            active_tasks: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn with_dial(
        dial: DialContext,
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
        let _permit = self.admission.admit()
            .ok_or_else(|| anyhow::anyhow!("QUIC endpoint is closed"))?;
        let key = (address.is_ipv6(), self.dial.as_ref().map(|_| address));
        let (slot, _initialize) = loop {
            let slot = self.endpoints.lock().entry(key)
                .or_insert_with(|| Arc::new(EndpointSlot::new())).clone();
            if let Some(cached) = slot.cached.load().as_ref()
                && !cached.proxy_socket.as_ref()
                    .is_some_and(|socket| socket.is_closed())
            {
                return Ok(cached.endpoint.clone());
            }
            let initialize = slot.initialize.clone().lock_owned().await;
            if !self.endpoints.lock().get(&key)
                .is_some_and(|current| Arc::ptr_eq(current, &slot))
            {
                continue;
            }
            if let Some(cached) = slot.cached.load().as_ref()
                && !cached.proxy_socket.as_ref()
                    .is_some_and(|socket| socket.is_closed())
            {
                return Ok(cached.endpoint.clone());
            }
            if let Some(old) = slot.cached.swap(None) {
                old.endpoint.close(0_u32.into(), b"proxy association failed");
                if let Some(socket) = &old.proxy_socket {
                    socket.close().await;
                }
            }
            break (slot, initialize);
        };
        let cached = self.build(address).await?;
        let endpoint = cached.endpoint.clone();
        slot.cached.store(Some(Arc::new(cached)));
        Ok(endpoint)
    }

    async fn build(&self, address: SocketAddr) -> anyhow::Result<CachedEndpoint> {
        let cached = if let Some(dial) = &self.dial {
            let datagram = dial.dial_udp(address).await?;
            let socket = ProxyQuicSocket::new(
                datagram,
                address,
                Arc::clone(&self.active_tasks),
            );
            let endpoint = match quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                socket.clone(),
                Arc::new(quinn::TokioRuntime),
            ) {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    socket.abort();
                    return Err(error.into());
                }
            };
            CachedEndpoint {
                endpoint,
                proxy_socket: Some(socket),
            }
        } else {
            let socket = direct_udp_socket(
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
        Ok(cached)
    }

    async fn prune(&self, candidates: &[SocketAddr]) {
        if self.dial.is_none() {
            return;
        }
        let Some(_permit) = self.admission.admit() else {
            return;
        };
        let obsolete: Vec<_> = self.endpoints.lock().iter()
            .filter(|(key, _)| {
                key.1.is_some_and(|address| !candidates.contains(&address))
            })
            .map(|(key, slot)| (*key, slot.clone()))
            .collect();
        let completed: Vec<_> = self.retired.lock()
            .extract_if(.., |entry| entry.finished.load(Ordering::Acquire))
            .collect();
        drop(completed);
        for (key, slot) in obsolete {
            // Keep the slot registered while initialization is in progress.
            let initialize = slot.initialize.clone().lock_owned().await;
            let removed = {
                let mut endpoints = self.endpoints.lock();
                if endpoints.get(&key)
                    .is_some_and(|current| Arc::ptr_eq(current, &slot))
                {
                    endpoints.remove(&key);
                    slot.cached.swap(None)
                } else {
                    None
                }
            };
            drop(initialize);
            let Some(cached) = removed else {
                continue;
            };
            if cached.endpoint.open_connections() == 0 {
                cached.endpoint.close(0_u32.into(), b"address retired");
                if let Some(socket) = &cached.proxy_socket {
                    socket.close().await;
                }
            } else {
                // Quinn includes draining connections in open_connections(). Wait
                // for them without interrupting queries or retaining sockets forever.
                let endpoint = cached.endpoint.clone();
                let socket = cached.proxy_socket.clone();
                let finished = Arc::new(AtomicBool::new(false));
                let done = finished.clone();
                let task = OwnedTask::spawn(
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
                self.retired.lock().push(RetiredEndpoint {
                    cached,
                    task,
                    finished,
                });
            }
        }
    }

    pub async fn close(&self, timeout: Duration) {
        let Some(close) = self.admission.acquire_close().await else {
            return;
        };
        self.admission.wait_for_idle().await;
        let endpoints = std::mem::take(&mut *self.endpoints.lock());
        let retired = std::mem::take(&mut *self.retired.lock());
        for entry in retired {
            entry.cached.endpoint.close(0_u32.into(), b"shutdown");
            if let Some(socket) = &entry.cached.proxy_socket {
                socket.close().await;
            }
            entry.task.shutdown(Duration::ZERO).await;
        }
        for slot in endpoints.into_values() {
            let Some(cached) = slot.cached.swap(None) else {
                continue;
            };
            cached.endpoint.close(0_u32.into(), b"shutdown");
            let _ = tokio::time::timeout(timeout, cached.endpoint.wait_idle()).await;
            if let Some(socket) = &cached.proxy_socket {
                socket.close().await;
            }
        }
        close.complete();
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
#[path = "quic_tests.rs"]
mod tests;
