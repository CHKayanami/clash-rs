use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

#[allow(unused_imports)]
use tracing::{error, info, warn};

#[allow(unused_imports)]
use super::offloader::{DirectOffloader, RoutingAction};
#[allow(unused_imports)]
use super::utils::resolve_and_aggregate_ip_cidrs;
use crate::app::dispatcher::Dispatcher;
use crate::app::dns::ThreadSafeDNSResolver;
use crate::config::def::EbpfConfig;
use crate::proxy::inbound::InboundHandlerTrait;

#[cfg(target_os = "linux")]
use crate::app::remote_content_manager::providers::rule_provider::CidrTrie;
#[cfg(target_os = "linux")]
use crate::proxy::datagram::{ChannelDatagram, UdpPacket};
#[cfg(target_os = "linux")]
use tokio::sync::OnceCell;

#[allow(dead_code)]
pub struct EbpfInbound {
    config: EbpfConfig,
    dispatcher: Arc<Dispatcher>,
    dns_resolver: ThreadSafeDNSResolver,
    #[cfg(target_os = "linux")]
    manager: Arc<OnceCell<Arc<clash_ebpf::EbpfManager>>>,
    #[cfg(target_os = "linux")]
    listener: Arc<OnceCell<Arc<clash_ebpf::EbpfListener>>>,
    #[cfg(target_os = "linux")]
    offloader: Arc<OnceCell<DirectOffloader>>,
}

impl EbpfInbound {
    pub fn new(
        config: EbpfConfig,
        dispatcher: Arc<Dispatcher>,
        dns_resolver: ThreadSafeDNSResolver,
    ) -> Self {
        Self {
            config,
            dispatcher,
            dns_resolver,
            #[cfg(target_os = "linux")]
            manager: Arc::new(OnceCell::new()),
            #[cfg(target_os = "linux")]
            listener: Arc::new(OnceCell::new()),
            #[cfg(target_os = "linux")]
            offloader: Arc::new(OnceCell::new()),
        }
    }

    #[cfg(target_os = "linux")]
    async fn get_or_init_offloader(&self) -> DirectOffloader {
        self.offloader
            .get_or_init(|| async {
                let rule_providers = self.dispatcher.router().get_rule_providers();
                let bypass_ips =
                    resolve_and_aggregate_ip_cidrs(&self.config.bypass_ips, rule_providers);
                let bypass_dst_ips =
                    resolve_and_aggregate_ip_cidrs(&self.config.bypass_dst_ips, rule_providers);

                let mut trie = CidrTrie::new();
                for ip in bypass_ips.iter().chain(bypass_dst_ips.iter()) {
                    trie.insert(ip);
                }

                DirectOffloader::new(
                    self.manager.clone(),
                    self.dns_resolver.clone(),
                    Arc::new(trie),
                )
            })
            .await
            .clone()
    }

    #[cfg(target_os = "linux")]
    async fn get_or_init_listener(&self) -> std::io::Result<Arc<clash_ebpf::EbpfListener>> {
        self.listener
            .get_or_try_init(|| async {
                use clash_ebpf::{EbpfConfig as CoreEbpfConfig, EbpfManager};

                let rule_providers = self.dispatcher.router().get_rule_providers();

                let bypass_ips =
                    resolve_and_aggregate_ip_cidrs(&self.config.bypass_ips, rule_providers);
                let bypass_src_ips =
                    resolve_and_aggregate_ip_cidrs(&self.config.bypass_src_ips, rule_providers);
                let bypass_dst_ips =
                    resolve_and_aggregate_ip_cidrs(&self.config.bypass_dst_ips, rule_providers);
                let proxy_ips =
                    resolve_and_aggregate_ip_cidrs(&self.config.proxy_ips, rule_providers);
                let proxy_src_ips =
                    resolve_and_aggregate_ip_cidrs(&self.config.proxy_src_ips, rule_providers);
                let proxy_dst_ips =
                    resolve_and_aggregate_ip_cidrs(&self.config.proxy_dst_ips, rule_providers);

                info!(
                    "eBPF IP configs resolved & aggregated -> bypass_ips: {}, bypass_src_ips: {}, bypass_dst_ips: {}, proxy_ips: {}, proxy_src_ips: {}, proxy_dst_ips: {}",
                    bypass_ips.len(),
                    bypass_src_ips.len(),
                    bypass_dst_ips.len(),
                    proxy_ips.len(),
                    proxy_src_ips.len(),
                    proxy_dst_ips.len()
                );

                let core_config = CoreEbpfConfig {
                    enable: self.config.enable,
                    lan_interface: self.config.lan_interface.clone(),
                    wan_interface: self.config.wan_interface.clone(),
                    tproxy_port: self.config.tproxy_port,
                    tproxy_udp_port: self.config.tproxy_udp_port,
                    bypass_ports: self.config.bypass_ports.clone(),
                    bypass_src_ports: self.config.bypass_src_ports.clone(),
                    bypass_dst_ports: self.config.bypass_dst_ports.clone(),
                    bypass_ips,
                    bypass_src_ips,
                    bypass_dst_ips,
                    proxy_ports: self.config.proxy_ports.clone(),
                    proxy_src_ports: self.config.proxy_src_ports.clone(),
                    proxy_dst_ports: self.config.proxy_dst_ports.clone(),
                    proxy_ips,
                    proxy_src_ips,
                    proxy_dst_ips,
                    auto_direct_offload: self.config.auto_direct_offload,
                    proxy_local: self.config.proxy_local,
                    proxy_processes: self.config.proxy_processes.clone(),
                    bypass_processes: self.config.bypass_processes.clone(),
                };

                let mut manager = EbpfManager::new(core_config);
                let listener = manager
                    .start()
                    .await
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

                let _ = self.manager.set(Arc::new(manager));

                Ok(listener)
            })
            .await
            .cloned()
    }

    pub async fn init(&self) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let _ = self.get_or_init_listener().await?;
            if self.config.auto_direct_offload {
                let offloader = self.get_or_init_offloader().await;
                let router = self.dispatcher.router().clone();
                let hook = Arc::new(move |domain: &str, ips: &[IpAddr], ttl: Duration| {
                    let offloader = offloader.clone();
                    let router = router.clone();
                    let domain = domain.to_string();
                    let ips = ips.to_vec();
                    tokio::spawn(async move {
                        let is_direct = router.is_domain_direct(&domain).await;
                        let action = if is_direct {
                            RoutingAction::Direct
                        } else {
                            RoutingAction::Proxy
                        };
                        offloader.observe(domain, ips, action, ttl).await;
                    });
                });
                self.dns_resolver.register_resolution_hook(hook);
            }
        }
        Ok(())
    }

    pub async fn stop(&self) {
        #[cfg(target_os = "linux")]
        {
            if let Some(mgr) = self.manager.get() {
                mgr.stop().await;
            }
        }
    }
}

#[async_trait]
impl InboundHandlerTrait for EbpfInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        true
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            warn!("eBPF inbound is only supported on Linux");
            futures::future::pending::<()>().await;
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            use super::dns::handle_tcp_dns;
            use crate::session::{Network, Session, Type};

            let listener = self.get_or_init_listener().await?;
            info!("clash-ebpf TCP inbound worker running");

            loop {
                match listener.accept_tcp().await {
                    Ok((stream, session_info)) => {
                        let dst = session_info.destination;

                        // 1. Intercept TCP port 53 (DNS-over-TCP)
                        if dst.port() == 53 {
                            let resolver = self.dns_resolver.clone();
                            tokio::spawn(async move {
                                handle_tcp_dns(stream, resolver).await;
                            });
                            continue;
                        }

                        // 2. Regular TCP proxy stream
                        info!("[eBPF TCP] Intercepted: {} -> {}", session_info.source, dst);
                        let session = Session {
                            network: Network::Tcp,
                            typ: Type::Ebpf,
                            source: session_info.source,
                            destination: dst.into(),
                            ..Default::default()
                        };

                        let dispatcher = self.dispatcher.clone();
                        tokio::spawn(async move {
                            dispatcher.dispatch_stream(session, Box::new(stream)).await;
                        });
                    }
                    Err(err) => {
                        error!("eBPF TCP accept error: {err}");
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            futures::future::pending::<()>().await;
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            use crate::session::{Network, Session, Type};

            let listener = self.get_or_init_listener().await?;
            info!("clash-ebpf UDP inbound worker running");

            const UDP_CHANNEL_CAPACITY: usize = 1024;
            let (l_tx, mut l_rx) = tokio::sync::mpsc::channel::<UdpPacket>(UDP_CHANNEL_CAPACITY);
            let (d_tx, d_rx) = tokio::sync::mpsc::channel::<UdpPacket>(UDP_CHANNEL_CAPACITY);

            let udp_stream = ChannelDatagram::new(l_tx, d_rx);

            let default_outbound = crate::app::net::DEFAULT_OUTBOUND_INTERFACE.read().await;
            let sess = Session {
                network: Network::Udp,
                typ: Type::Ebpf,
                iface: default_outbound.clone(),
                ..Default::default()
            };

            let _closer = self
                .dispatcher
                .dispatch_datagram(sess, Box::new(udp_stream))
                .await;

            let listener_for_send = listener.clone();
            // Dispatcher -> client outbound reply task
            let send_task = tokio::spawn(async move {
                let mut reply_sockets: std::collections::HashMap<
                    std::net::SocketAddr,
                    (std::sync::Arc<tokio::net::UdpSocket>, std::time::Instant),
                > = std::collections::HashMap::with_capacity(128);

                while let Some(packet) = l_rx.recv().await {
                    if let Some(client_target) = packet.dst_addr.try_into_socket_addr() {
                        if let Some(orig_dst) = packet.src_addr.try_into_socket_addr() {
                            let now = std::time::Instant::now();
                            let reply_sock = if let Some((sock, exp)) = reply_sockets.get_mut(&orig_dst) {
                                if now < *exp {
                                    *exp = now + std::time::Duration::from_secs(60);
                                    Some(std::sync::Arc::clone(sock))
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                            let reply_sock = match reply_sock {
                                Some(s) => Some(s),
                                None => {
                                    if reply_sockets.len() > 1024 {
                                        reply_sockets.retain(|_, (_, exp)| now < *exp);
                                    }
                                    match listener_for_send.create_reply_socket(orig_dst) {
                                        Ok(new_sock) => {
                                            let sock_arc = std::sync::Arc::new(new_sock);
                                            reply_sockets.insert(
                                                orig_dst,
                                                (
                                                    std::sync::Arc::clone(&sock_arc),
                                                    now + std::time::Duration::from_secs(60),
                                                ),
                                            );
                                            Some(sock_arc)
                                        }
                                        Err(e) => {
                                            tracing::warn!("failed to create transparent reply socket for {orig_dst}: {e}");
                                            None
                                        }
                                    }
                                }
                            };

                            if let Some(sock) = reply_sock {
                                let _ = sock.send_to(&packet.data, client_target).await;
                                continue;
                            }
                        }
                        let socket = if client_target.is_ipv6() {
                            listener_for_send.udp_socket_v6().unwrap_or_else(|| listener_for_send.udp_socket())
                        } else {
                            listener_for_send.udp_socket()
                        };
                        let _ = socket.send_to(&packet.data, client_target).await;
                    }
                }
            });

            // Client inbound receive tasks -> Dispatcher / DNS
            let v4_socket = listener.udp_socket_v4();
            let v4_task = tokio::spawn(udp_listener_loop(
                v4_socket,
                "IPv4",
                d_tx.clone(),
                self.dns_resolver.clone(),
                listener.clone(),
            ));

            let v6_task = if let Some(v6_socket) = listener.udp_socket_v6() {
                Some(tokio::spawn(udp_listener_loop(
                    v6_socket,
                    "IPv6",
                    d_tx,
                    self.dns_resolver.clone(),
                    listener.clone(),
                )))
            } else {
                None
            };

            tokio::select! {
                _ = send_task => {},
                _ = v4_task => {},
                _ = async {
                    if let Some(t) = v6_task {
                        let _ = t.await;
                    } else {
                        futures::future::pending::<()>().await;
                    }
                } => {},
            }

            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
async fn udp_listener_loop(
    socket: Arc<tokio::net::UdpSocket>,
    family: &'static str,
    d_tx: tokio::sync::mpsc::Sender<UdpPacket>,
    resolver: ThreadSafeDNSResolver,
    listener_for_dns: Arc<clash_ebpf::EbpfListener>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        match clash_ebpf::EbpfListener::recv_from_socket(&socket, &mut buf).await {
            Ok((n, src, dst)) => {
                let data = &buf[..n];
                // 1. Intercept UDP port 53 (DNS)
                if dst.port() == 53 {
                    let req_bytes = data.to_vec();
                    let resolver = resolver.clone();
                    let listener_for_dns = listener_for_dns.clone();
                    tokio::spawn(async move {
                        match crate::app::dns::exchange_with_resolver(&resolver, &req_bytes, true)
                            .await
                        {
                            Ok(resp_bytes) => {
                                match listener_for_dns
                                    .send_dns_reply(&resp_bytes, dst, src)
                                    .await
                                {
                                    Ok(_) => {
                                        tracing::info!(
                                            "[eBPF DNS] Replied {} -> {}",
                                            dst,
                                            src
                                        );
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "[eBPF DNS] Failed to send UDP DNS reply {} -> {}: {}",
                                            dst,
                                            src,
                                            e
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "[eBPF DNS] DNS resolution failed for query from {}: {}",
                                    src,
                                    e
                                );
                            }
                        }
                    });
                    continue;
                }

                // 2. Regular UDP packet -> Dispatcher
                info!("[eBPF UDP] Intercepted: {} -> {}", src, dst);
                let payload = bytes::Bytes::copy_from_slice(data);
                let packet = UdpPacket::new(payload, src.into(), dst.into());

                if d_tx.send(packet).await.is_err() {
                    break;
                }
            }
            Err(err) => {
                error!("eBPF {} UDP recv error: {err}", family);
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }
}
