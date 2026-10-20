mod tls;
mod http;
mod https;
mod write_deadline;
mod h3;
pub(crate) mod runtime;

use std::{net::UdpSocket, sync::Arc, time::Duration};
use quinn::{Endpoint, EndpointConfig, ServerConfig as QuicConfig, TransportConfig, crypto::rustls::QuicServerConfig};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet, time::timeout};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};
use crate::{DNSListenAddr, DNSError, DnsIngress, DnsMessageExchanger, PreparedDnsListener};
use rustls::ServerConfig;
use ::http::uri::Authority;
use crate::framing::serve_stream;
use crate::handler::{MAX_TCP_CONNECTIONS, TCP_REQUEST_TIMEOUT};
use self::http::Service;
use runtime::OwnedRuntime;

#[derive(Clone)]
struct PreparedTls {
    config: Arc<ServerConfig>,
    hostname: Option<Authority>,
}

#[derive(Clone, Default)]
pub(crate) struct PreparedEncrypted {
    dot: Option<Arc<ServerConfig>>,
    doh: Option<PreparedTls>,
    h3: Option<(QuicConfig, Option<Authority>)>,
}

impl PreparedEncrypted {
    pub fn new(listen: &DNSListenAddr) -> Result<Self, DNSError> {
        let hostname = |value: &Option<String>| -> Result<Option<Authority>, DNSError> {
            value.as_deref().map(str::parse).transpose()
                .map_err(|error| DNSError::Configuration(format!("invalid DNS hostname: {error}")))
        };
        let dot = listen.dot.as_ref().map(|cfg| {
            tls::config(cfg.ca_cert.as_deref(), cfg.ca_key.as_deref(), &[b"dot"])
        }).transpose()?;
        let doh = listen.doh.as_ref().map(|cfg| {
            Ok::<_, DNSError>(PreparedTls {
                config: tls::config(cfg.ca_cert.as_deref(), cfg.ca_key.as_deref(), &[b"h2", b"http/1.1"] )?,
                hostname: hostname(&cfg.hostname)?,
            })
        }).transpose()?;
        let h3 = listen.doh3.as_ref().map(|cfg| {
            let tls = tls::config(cfg.ca_cert.as_deref(), cfg.ca_key.as_deref(), &[b"h3"])?;
            let crypto = QuicServerConfig::try_from((*tls).clone())
                .map_err(|error| DNSError::Configuration(format!("DoH3 TLS: {error}")))?;
            let mut quic = QuicConfig::with_crypto(Arc::new(crypto));
            let mut transport = TransportConfig::default();
            transport.max_concurrent_bidi_streams(64_u32.into());
            transport.max_concurrent_uni_streams(8_u32.into());
            transport.stream_receive_window(65536_u32.into());
            transport.receive_window((1024_u32 * 1024).into());
            transport.send_window(1024 * 1024);
            transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
            quic.transport_config(Arc::new(transport));
            quic.max_incoming(MAX_TCP_CONNECTIONS);
            Ok::<_, DNSError>((quic, hostname(&cfg.hostname)?))
        }).transpose()?;
        Ok(Self { dot, doh, h3 })
    }
}

struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    hostname: Option<Authority>,
}

pub(crate) struct EncryptedListeners {
    dot: Option<TlsListener>,
    doh: Option<TlsListener>,
    h3: Option<(Endpoint, Arc<OwnedRuntime>, Option<Authority>)>,
}

impl EncryptedListeners {
    pub async fn bind(prepared: &PreparedDnsListener) -> Result<Self, DNSError> {
        let listen = &prepared.listen;
        let tls = &prepared.encrypted;
        let dot = if let (Some(cfg), Some(config)) = (&listen.dot, &tls.dot) {
            Some(TlsListener { listener: TcpListener::bind(cfg.addr).await?,
                acceptor: TlsAcceptor::from(config.clone()), hostname: None })
        } else { None };
        let doh = if let (Some(cfg), Some(tls)) = (&listen.doh, &tls.doh) {
            Some(TlsListener { listener: TcpListener::bind(cfg.addr).await?,
                acceptor: TlsAcceptor::from(tls.config.clone()), hostname: tls.hostname.clone() })
        } else { None };
        // Construct the QUIC endpoint last, after all fallible TCP binding.
        let h3 = if let (Some(cfg), Some((quic, hostname))) = (&listen.doh3, &tls.h3) {
            let socket = UdpSocket::bind(cfg.addr)?;
            socket.set_nonblocking(true)?;
            let runtime = Arc::new(OwnedRuntime::default());
            let endpoint = Endpoint::new(EndpointConfig::default(), Some(quic.clone()), socket, runtime.clone())?;
            Some((endpoint, runtime, hostname.clone()))
        } else { None };
        Ok(Self { dot, doh, h3 })
    }

    pub fn spawn<X: DnsMessageExchanger + Clone + 'static>(
        self, tasks: &mut JoinSet<()>, exchanger: X,
    ) -> (Option<Endpoint>, Option<Arc<OwnedRuntime>>) {
        let permits = Arc::new(Semaphore::new(1024));
        if let Some(dot) = self.dot {
            tasks.spawn(serve_tls(dot, exchanger.clone(), permits.clone(), false));
        }
        if let Some(doh) = self.doh {
            tasks.spawn(serve_tls(doh, exchanger.clone(), permits.clone(), true));
        }
        if let Some((endpoint, runtime, hostname)) = self.h3 {
            info!(address = ?endpoint.local_addr(), "DNS DoH3 server listening");
            let service = Arc::new(Service { exchanger, hostname, permits });
            tasks.spawn(h3::serve(endpoint.clone(), service));
            (Some(endpoint), Some(runtime))
        } else { (None, None) }
    }
}

async fn serve_tls<X: DnsMessageExchanger + Clone + 'static>(
    bound: TlsListener, exchanger: X, permits: Arc<Semaphore>, doh: bool,
) {
    let protocol = if doh { "DoH" } else { "DoT" };
    info!(address = ?bound.listener.local_addr(), protocol, "DNS TLS server listening");
    let mut connections = JoinSet::new();
    let service = Arc::new(Service { exchanger: exchanger.clone(), hostname: bound.hostname, permits });
    loop {
        tokio::select! {
            biased;
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            accepted = bound.listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(error) => {
                        error!(%error, protocol, address = ?bound.listener.local_addr(), "DNS TLS accept failed");
                        break;
                    }
                };
                if connections.len() >= MAX_TCP_CONNECTIONS { continue; }
                let acceptor = bound.acceptor.clone();
                let exchanger = exchanger.clone();
                let service = service.clone();
                connections.spawn(async move {
                    match timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                        Ok(Ok(stream)) if doh => https::serve(stream, peer, service).await,
                        Ok(Ok(stream)) => serve_stream(stream, peer, exchanger, TCP_REQUEST_TIMEOUT, DnsIngress::Dot).await,
                        Ok(Err(error)) => debug!(%peer, %error, protocol, "DNS TLS handshake failed"),
                        Err(_) => debug!(%peer, protocol, "DNS TLS handshake timed out"),
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod https_tests;
