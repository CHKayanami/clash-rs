use crate::app::dispatcher::Dispatcher;
use crate::app::dns::ThreadSafeDNSResolver;
use crate::config::def::EbpfConfig;
#[cfg(target_os = "linux")]
use crate::proxy::datagram::{ChannelDatagram, UdpPacket};
use crate::proxy::inbound::InboundHandlerTrait;
use async_trait::async_trait;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use tokio::sync::{Mutex, OnceCell};
#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};

pub mod runner;
pub use runner::EbpfRunner;

#[allow(dead_code)]
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct DirectOffloader {
    tx: tokio::sync::mpsc::UnboundedSender<std::net::IpAddr>,
    resolver: ThreadSafeDNSResolver,
}

#[cfg(target_os = "linux")]
impl DirectOffloader {
    pub fn new(
        manager: Arc<Mutex<Option<clash_ebpf::EbpfManager>>>,
        resolver: ThreadSafeDNSResolver,
    ) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<std::net::IpAddr>();
        let resolver_clone = resolver.clone();

        tokio::spawn(async move {
            let recent_cache = moka::sync::Cache::builder()
                .max_capacity(4096)
                .time_to_live(std::time::Duration::from_secs(300))
                .build();
            while let Some(ip) = rx.recv().await {
                // Dynamically check against DNS module's configured Fake-IP pool & reserved IPs
                if is_reserved_ip(ip) || resolver_clone.is_fake_ip(ip).await {
                    continue;
                }
                if recent_cache.get(&ip).is_some() {
                    continue;
                }
                recent_cache.insert(ip, ());

                let mgr_guard = manager.lock().await;
                if let Some(mgr) = mgr_guard.as_ref() {
                    if let Err(e) = mgr.add_dynamic_bypass_ip(ip).await {
                        tracing::debug!("eBPF dynamic bypass failed for {ip}: {e}");
                    }
                }
            }
        });

        Self { tx, resolver }
    }

    pub async fn offload(&self, ip: std::net::IpAddr) {
        if !is_reserved_ip(ip) && !self.resolver.is_fake_ip(ip).await {
            let _ = self.tx.send(ip);
        }
    }
}

/// Check if an IP is in the standard reserved/loopback/broadcast range.
fn is_reserved_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4 (multicast), 255.255.255.255
            octets[0] == 0 
                || octets[0] == 127 
                || (octets[0] == 169 && octets[1] == 254) 
                || (octets[0] >= 224 && octets[0] <= 239) 
                || octets == [255, 255, 255, 255]
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified()
        }
    }
}

fn extract_ips_from_dns_response(resp: &hickory_proto::op::Message) -> Vec<std::net::IpAddr> {
    use hickory_proto::rr::RData;
    let mut ips = Vec::new();
    for record in &resp.answers {
        match &record.data {
            RData::A(a) => {
                let ip = std::net::IpAddr::V4(a.0);
                if !is_reserved_ip(ip) {
                    ips.push(ip);
                }
            }
            RData::AAAA(aaaa) => {
                let ip = std::net::IpAddr::V6(aaaa.0);
                if !is_reserved_ip(ip) {
                    ips.push(ip);
                }
            }
            _ => {}
        }
    }
    ips
}

#[allow(dead_code)]
pub struct EbpfInbound {
    config: EbpfConfig,
    dispatcher: Arc<Dispatcher>,
    dns_resolver: ThreadSafeDNSResolver,
    #[cfg(target_os = "linux")]
    manager: Arc<Mutex<Option<clash_ebpf::EbpfManager>>>,
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
            manager: Arc::new(Mutex::new(None)),
            #[cfg(target_os = "linux")]
            listener: Arc::new(OnceCell::new()),
            #[cfg(target_os = "linux")]
            offloader: Arc::new(OnceCell::new()),
        }
    }

    #[cfg(target_os = "linux")]
    async fn get_or_init_offloader(&self) -> DirectOffloader {
        self.offloader
            .get_or_init(|| async { DirectOffloader::new(self.manager.clone(), self.dns_resolver.clone()) })
            .await
            .clone()
    }

    #[cfg(target_os = "linux")]
    async fn get_or_init_listener(&self) -> std::io::Result<Arc<clash_ebpf::EbpfListener>> {
        self.listener
            .get_or_try_init(|| async {
                use clash_ebpf::{EbpfConfig as CoreEbpfConfig, EbpfManager};

                let core_config = CoreEbpfConfig {
                    enable: self.config.enable,
                    lan_interface: self.config.lan_interface.clone(),
                    wan_interface: self.config.wan_interface.clone(),
                    tproxy_port: self.config.tproxy_port,
                    tproxy_udp_port: self.config.tproxy_udp_port,
                    auto_route: self.config.auto_route,
                    bypass_ports: self.config.bypass_ports.clone(),
                    bypass_src_ports: self.config.bypass_src_ports.clone(),
                    bypass_dst_ports: self.config.bypass_dst_ports.clone(),
                    bypass_ips: self.config.bypass_ips.clone(),
                    bypass_src_ips: self.config.bypass_src_ips.clone(),
                    bypass_dst_ips: self.config.bypass_dst_ips.clone(),
                    proxy_ports: self.config.proxy_ports.clone(),
                    proxy_src_ports: self.config.proxy_src_ports.clone(),
                    proxy_dst_ports: self.config.proxy_dst_ports.clone(),
                    proxy_ips: self.config.proxy_ips.clone(),
                    proxy_src_ips: self.config.proxy_src_ips.clone(),
                    proxy_dst_ips: self.config.proxy_dst_ips.clone(),
                    auto_direct_offload: self.config.auto_direct_offload,
                };

                let mut manager = EbpfManager::new(core_config);
                let listener = manager
                    .start()
                    .await
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

                let mut manager_guard = self.manager.lock().await;
                *manager_guard = Some(manager);

                Ok(listener)
            })
            .await
            .cloned()
    }

    pub async fn stop(&self) {
        #[cfg(target_os = "linux")]
        {
            let mut manager_guard = self.manager.lock().await;
            if let Some(mut mgr) = manager_guard.take() {
                mgr.stop().await;
            }
        }
    }

}


#[cfg(target_os = "linux")]
async fn handle_tcp_dns(
    mut stream: tokio::net::TcpStream,
    resolver: ThreadSafeDNSResolver,
    dispatcher: Arc<Dispatcher>,
    offloader: Option<DirectOffloader>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    debug!("error reading TCP DNS length prefix: {e}");
                }
                break;
            }
        }
        let length = u16::from_be_bytes(len_buf) as usize;
        if length == 0 || length > 4096 {
            debug!("invalid TCP DNS message length: {length}");
            break;
        }
        let mut query_buf = vec![0u8; length];
        if let Err(e) = stream.read_exact(&mut query_buf).await {
            debug!("error reading TCP DNS message body: {e}");
            break;
        }

        match hickory_proto::op::Message::from_vec(&query_buf) {
            Ok(msg) => {
                trace!("eBPF intercepted TCP DNS query: {:?}", msg);
                match crate::app::dns::exchange_with_resolver(&resolver, &msg, true).await {
                    Ok(mut resp) => {
                        resp.metadata.id = msg.metadata.id;

                        // Async Direct Offload learning
                        if let Some(offloader) = &offloader {
                            let ips = extract_ips_from_dns_response(&resp);
                            if !ips.is_empty() {
                                let router = dispatcher.router().clone();
                                let offloader = offloader.clone();
                                let query_name = msg.queries.first().map(|q| q.name().to_utf8()).unwrap_or_default();
                                tokio::spawn(async move {
                                    let domain_clean = query_name.trim_end_matches('.');
                                    if router.is_domain_direct(domain_clean).await {
                                        for ip in ips {
                                            offloader.offload(ip).await;
                                        }
                                    }
                                });
                            }
                        }

                        match resp.to_vec() {
                            Ok(resp_bytes) => {
                                let resp_len = (resp_bytes.len() as u16).to_be_bytes();
                                if let Err(e) = stream.write_all(&resp_len).await {
                                    debug!("failed to write TCP DNS response length: {e}");
                                    break;
                                }
                                if let Err(e) = stream.write_all(&resp_bytes).await {
                                    debug!("failed to write TCP DNS response body: {e}");
                                    break;
                                }
                                if let Err(e) = stream.flush().await {
                                    debug!("failed to flush TCP DNS response: {e}");
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("failed to serialize TCP DNS response: {e}");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("failed to exchange TCP DNS query with resolver: {e}");
                        break;
                    }
                }
            }
            Err(e) => {
                warn!("failed to parse TCP DNS query message: {e}");
                break;
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
            use crate::session::{Network, Session, Type};

            let listener = self.get_or_init_listener().await?;
            let offloader = if self.config.auto_direct_offload {
                Some(self.get_or_init_offloader().await)
            } else {
                None
            };
            info!("clash-ebpf TCP inbound worker running");

            loop {
                match listener.accept_tcp().await {
                    Ok((stream, session_info)) => {
                        let dst = session_info.destination;

                        // 1. Intercept TCP port 53 (DNS-over-TCP)
                        if dst.port() == 53 {
                            let resolver = self.dns_resolver.clone();
                            let dispatcher = self.dispatcher.clone();
                            let offloader = offloader.clone();
                            tokio::spawn(async move {
                                handle_tcp_dns(stream, resolver, dispatcher, offloader).await;
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
            let offloader = if self.config.auto_direct_offload {
                Some(self.get_or_init_offloader().await)
            } else {
                None
            };
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


            let _closer = self.dispatcher.dispatch_datagram(sess, Box::new(udp_stream)).await;

            let listener_for_send = listener.clone();
            // Dispatcher -> client outbound reply task
            let send_task = tokio::spawn(async move {
                while let Some(packet) = l_rx.recv().await {
                    if let Some(target) = packet.src_addr.try_into_socket_addr() {
                        if let Some(orig_dst) = packet.dst_addr.try_into_socket_addr() {
                            if let Ok(reply_sock) = listener_for_send.create_reply_socket(orig_dst) {
                                let _ = reply_sock.send_to(&packet.data, target).await;
                                continue;
                            }
                        }
                        let socket = listener_for_send.udp_socket();
                        let _ = socket.send_to(&packet.data, target).await;
                    }
                }
            });

            // Client inbound receive tasks -> Dispatcher / DNS (aligned with honk architecture)
            let v4_socket = listener.udp_socket_v4();
            let v4_task = tokio::spawn(udp_listener_loop(
                v4_socket,
                "IPv4",
                d_tx.clone(),
                self.dns_resolver.clone(),
                self.dispatcher.clone(),
                listener.clone(),
                offloader.clone(),
            ));

            let v6_task = if let Some(v6_socket) = listener.udp_socket_v6() {
                Some(tokio::spawn(udp_listener_loop(
                    v6_socket,
                    "IPv6",
                    d_tx,
                    self.dns_resolver.clone(),
                    self.dispatcher.clone(),
                    listener.clone(),
                    offloader,
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
    socket: std::sync::Arc<tokio::net::UdpSocket>,
    family: &'static str,
    d_tx: tokio::sync::mpsc::Sender<UdpPacket>,
    resolver: crate::app::dns::ThreadSafeDNSResolver,
    dispatcher: Arc<Dispatcher>,
    listener_for_dns: std::sync::Arc<clash_ebpf::EbpfListener>,
    offloader: Option<DirectOffloader>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        match clash_ebpf::EbpfListener::recv_from_socket(&socket, &mut buf).await {
            Ok((n, src, dst)) => {
                let data = &buf[..n];
                // 1. Intercept UDP port 53 (DNS)
                if dst.port() == 53 {
                    if let Ok(msg) = hickory_proto::op::Message::from_vec(data) {
                        let q_info = msg
                            .queries
                            .first()
                            .map(|q| format!("{}({:?})", q.name(), q.query_type()))
                            .unwrap_or_default();
                        info!(
                            "[eBPF DNS] Intercepted DNS query {} from {} to {}",
                            q_info, src, dst
                        );

                        let resolver = resolver.clone();
                        let dispatcher = dispatcher.clone();
                        let listener_for_dns = listener_for_dns.clone();
                        let offloader = offloader.clone();
                        tokio::spawn(async move {
                            match crate::app::dns::exchange_with_resolver(&resolver, &msg, true).await {
                                Ok(mut resp) => {
                                    resp.metadata.id = msg.metadata.id;

                                    // Async Direct Offload learning
                                    if let Some(offloader) = &offloader {
                                        let ips = extract_ips_from_dns_response(&resp);
                                        if !ips.is_empty() {
                                            let router = dispatcher.router().clone();
                                            let offloader = offloader.clone();
                                            let query_name = msg.queries.first().map(|q| q.name().to_utf8()).unwrap_or_default();
                                            tokio::spawn(async move {
                                                let domain_clean = query_name.trim_end_matches('.');
                                                if router.is_domain_direct(domain_clean).await {
                                                    for ip in ips {
                                                        offloader.offload(ip).await;
                                                    }
                                                }
                                            });
                                        }
                                    }

                                    match resp.to_vec() {
                                        Ok(resp_bytes) => {
                                            match listener_for_dns.send_dns_reply(&resp_bytes, dst, src).await {
                                                Ok(_) => {
                                                    tracing::info!("[eBPF DNS] Replied {} -> {}", dst, src);
                                                }
                                                Err(e) => {
                                                    tracing::warn!("[eBPF DNS] send_dns_reply {} -> {} failed: {}", dst, src, e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("[eBPF DNS] failed to serialize DNS response for {}: {}", q_info, e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("[eBPF DNS] Resolution failed for {}: {}", q_info, e);
                                }
                            }
                        });
                        continue;
                    } else {
                        info!("[eBPF DNS] Intercepted raw DNS from {} to {}", src, dst);
                    }
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
