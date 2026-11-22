use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use clash_common::udp::{BatchReceiver, MAX_BATCH};
use clash_ebpf::{
    DAE_BYPASS_MARK, EbpfConfig as CoreEbpfConfig, EbpfHostConfig as CoreEbpfHostConfig,
    EbpfLanConfig as CoreEbpfLanConfig, EbpfListener, EbpfManager,
    EbpfTargetConfig as CoreEbpfTargetConfig,
};
use tokio::net::UdpSocket;
use tokio::task::{JoinSet, consume_budget};
use tracing::{Instrument, Span, debug, error, info, warn};

use super::dns::handle_tcp_dns;
use super::offloader::{DirectOffloader, RoutingAction};
use super::utils::resolve_and_aggregate_ip_cidrs;
use crate::app::dispatcher::{Dispatcher, udp::UdpRouteIngress};
use crate::app::dns::query::IngressProfile;
use crate::app::dns::{DnsResolutionHook, ThreadSafeDNSResolver, exchange_with_resolver};
use crate::app::net::get_default_outbound_interface;
use crate::app::remote_content_manager::providers::rule_provider::CidrTrie;
use crate::config::def::EbpfConfig;
use crate::proxy::AnyStream;
use crate::proxy::datagram::UdpPacket;
use crate::session::{Network, Session, Type};

pub struct EbpfInbound {
    dispatcher: Arc<Dispatcher>,
    dns_resolver: ThreadSafeDNSResolver,
    manager: Arc<EbpfManager>,
    listener: Arc<EbpfListener>,
    offloader: Option<DirectOffloader>,
}

impl EbpfInbound {
    pub async fn start(
        config: EbpfConfig,
        dispatcher: Arc<Dispatcher>,
        dns_resolver: ThreadSafeDNSResolver,
    ) -> io::Result<Self> {
        config.lan.validate().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("ebpf.lan: {e}"))
        })?;

        let rule_providers = dispatcher.router().get_rule_providers();
        let bypass_src_ips =
            resolve_and_aggregate_ip_cidrs(&config.lan.bypass_src_ips, rule_providers);
        let bypass_dst_ips =
            resolve_and_aggregate_ip_cidrs(&config.target.bypass_dst_ips, rule_providers);
        let proxy_src_ips =
            resolve_and_aggregate_ip_cidrs(&config.lan.proxy_src_ips, rule_providers);
        let proxy_dst_ips =
            resolve_and_aggregate_ip_cidrs(&config.target.proxy_dst_ips, rule_providers);

        info!(
            "eBPF IP configs resolved & aggregated -> bypass_src_ips: {}, bypass_dst_ips: {}, proxy_src_ips: {}, proxy_dst_ips: {}",
            bypass_src_ips.len(),
            bypass_dst_ips.len(),
            proxy_src_ips.len(),
            proxy_dst_ips.len()
        );

        let auto_direct_offload = config.auto_direct_offload;
        let offload_ips = auto_direct_offload
            .then(|| (bypass_dst_ips.clone(), proxy_dst_ips.clone()));

        let core_config = CoreEbpfConfig {
            enable: config.enable,
            lan_interface: config.lan_interface,
            wan_interface: config.wan_interface,
            tproxy_port: config.tproxy_port,
            auto_direct_offload,
            routing_mark: config.routing_mark,
            lan: CoreEbpfLanConfig {
                bypass_src_ports: config.lan.bypass_src_ports,
                proxy_src_ports: config.lan.proxy_src_ports,
                bypass_src_ips,
                proxy_src_ips,
                proxy_src_macs: config.lan.proxy_src_macs,
            },
            target: CoreEbpfTargetConfig {
                bypass_dst_ports: config.target.bypass_dst_ports,
                proxy_dst_ports: config.target.proxy_dst_ports,
                bypass_dst_ips,
                proxy_dst_ips,
            },
            host: CoreEbpfHostConfig {
                proxy_local: config.host.proxy_local,
                proxy_processes: config.host.proxy_processes,
                bypass_processes: config.host.bypass_processes,
            },
            bypass_dscps: config.bypass_dscps,
            bypass_fwmarks: config.bypass_fwmarks,
        };

        let (manager, listener) = EbpfManager::start(core_config)
            .await
            .map_err(io::Error::other)?;
        let manager = Arc::new(manager);

        let offloader = if let Some((bypass_dst_ips, proxy_dst_ips)) = offload_ips {
            let mut bypass_trie = CidrTrie::new();
            for ip in &bypass_dst_ips {
                bypass_trie.insert(ip);
            }
            let mut proxy_trie = CidrTrie::new();
            for ip in &proxy_dst_ips {
                proxy_trie.insert(ip);
            }
            let offloader = DirectOffloader::new(
                Arc::downgrade(&manager),
                dns_resolver.clone(),
                Arc::new(bypass_trie),
                Arc::new(proxy_trie),
            );
            let hook_offloader = offloader.clone();
            let router = dispatcher.router().clone();
            let hook: DnsResolutionHook =
                Arc::new(move |domain: &str, ips: &[IpAddr], _ttl: Duration| {
                    let offloader = hook_offloader.clone();
                    let router = router.clone();
                    let domain: Arc<str> = Arc::from(domain);
                    let ips = ips.to_vec();
                    tokio::spawn(async move {
                        let is_direct =
                            router.is_domain_direct_with_ips(&domain, &ips).await;
                        let action = if is_direct {
                            RoutingAction::Direct
                        } else {
                            RoutingAction::Proxy
                        };
                        offloader.observe(domain, ips, action).await;
                    });
                });
            dns_resolver.register_resolution_hook(hook);
            Some(offloader)
        } else {
            None
        };

        Ok(Self {
            dispatcher,
            dns_resolver,
            manager,
            listener,
            offloader,
        })
    }

    pub async fn stop(self) {
        if let Some(offloader) = &self.offloader {
            self.dns_resolver.clear_resolution_hook();
            offloader.stop();
        }
        self.manager.stop().await;
    }

    pub async fn run_tcp(&self) {
        info!("clash-ebpf TCP inbound worker running");
        let mut connections = JoinSet::new();

        loop {
            while connections.try_join_next().is_some() {}
            match self.listener.accept_tcp().await {
                Ok((stream, session_info)) => {
                    let dst = session_info.destination;

                    // 1. Intercept TCP port 53 (DNS-over-TCP)
                    if dst.port() == 53 {
                        let resolver = self.dns_resolver.clone();
                        connections.spawn(async move {
                            handle_tcp_dns(stream, resolver).await;
                        });
                        continue;
                    }

                    // 2. Regular TCP proxy stream
                    let session = Session {
                        network: Network::Tcp,
                        typ: Type::Ebpf,
                        source: session_info.source,
                        destination: dst.into(),
                        so_mark: Some(DAE_BYPASS_MARK),
                        ..Default::default()
                    };

                    let dispatcher = self.dispatcher.clone();
                    connections.spawn(async move {
                        dispatcher
                            .dispatch_stream(session, AnyStream::Tcp(stream))
                            .await;
                    });
                }
                Err(err) => {
                    error!("eBPF TCP accept error: {err}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    pub async fn run_udp(&self) {
        info!("clash-ebpf UDP inbound worker running");

        let default_outbound = get_default_outbound_interface();
        let sess = Session {
            network: Network::Udp,
            typ: Type::Ebpf,
            iface: default_outbound,
            so_mark: Some(DAE_BYPASS_MARK),
            ..Default::default()
        };

        let listener = self.listener.clone();
        let reply_listener = self.listener.clone();
        let resolver = self.dns_resolver.clone();
        self.dispatcher
            .dispatch_transparent_udp(
                sess,
                move |ingress| async move {
                    let mut tasks = JoinSet::new();
                    tasks.spawn(
                        udp_listener_loop(
                            listener.udp_socket_v4(),
                            "IPv4",
                            ingress.clone(),
                            resolver.clone(),
                            listener.clone(),
                        )
                        .instrument(Span::current()),
                    );

                    if let Some(v6_socket) = listener.udp_socket_v6() {
                        tasks.spawn(
                            udp_listener_loop(
                                v6_socket,
                                "IPv6",
                                ingress,
                                resolver,
                                listener,
                            )
                            .instrument(Span::current()),
                        );
                    }

                    // Dropping JoinSet aborts the remaining listeners and their DNS work.
                    if let Some(Err(error)) = tasks.join_next().await {
                        warn!(%error, "eBPF UDP receive task failed");
                    }
                },
                move |source| reply_listener.create_reply_socket(source),
            )
            .await;
    }
}

async fn udp_listener_loop(
    socket: Arc<UdpSocket>,
    family: &'static str,
    ingress: UdpRouteIngress,
    resolver: ThreadSafeDNSResolver,
    listener_for_dns: Arc<EbpfListener>,
) {
    let mut receiver = BatchReceiver::default();
    let mut batch = Vec::with_capacity(MAX_BATCH);
    let mut dns_tasks = JoinSet::new();
    loop {
        while dns_tasks.try_join_next().is_some() {}
        match receiver.recv_batch(&socket, &mut batch, MAX_BATCH).await {
            Ok(count) => {
                if count == 0 {
                    continue;
                }
                let incoming = batch.drain(..).filter_map(|(payload, src, dst)| {
                    // 1. Intercept UDP port 53 (DNS)
                    if dst.port() == 53 {
                        let req_bytes = payload;
                        let resolver = resolver.clone();
                        let listener_for_dns = listener_for_dns.clone();
                        dns_tasks.spawn(async move {
                            match exchange_with_resolver(
                                &resolver,
                                req_bytes,
                                IngressProfile::Udp {
                                    advertised_size: 512,
                                },
                                Some(src.ip()),
                            )
                            .await
                            {
                                Ok(resp_bytes) => {
                                    match listener_for_dns
                                        .send_dns_reply(&resp_bytes, dst, src)
                                        .await
                                    {
                                        Ok(_) => {
                                            debug!(
                                                "[eBPF DNS] Replied {} -> {}",
                                                dst, src
                                            );
                                        }
                                        Err(e) => {
                                            warn!(
                                                "[eBPF DNS] Failed to send UDP DNS reply {} -> {}: {}",
                                                dst, src, e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        "[eBPF DNS] DNS resolution failed for query from {}: {}",
                                        src, e
                                    );
                                }
                            }
                        });
                        return None;
                    }

                    debug!("[eBPF UDP] Intercepted: {} -> {}", src, dst);
                    Some(UdpPacket::new(payload, src.into(), dst.into()))
                });
                if !ingress.send_batch(incoming) {
                    warn!("dispatcher route queue closed, stopping eBPF UDP listener");
                    return;
                }
                consume_budget().await;
            }
            Err(err) => {
                error!("eBPF {} UDP recv error: {err}", family);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
