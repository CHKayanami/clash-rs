use super::{ClashResolver, Client, EdnsClientSubnet, runtime::DnsRuntimeProvider};
use std::{
    fmt::{Debug, Display, Formatter},
    net::{self, IpAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use tracing::{trace};
use async_trait::async_trait;

use hickory_net::{
    DnsHandle, client, h2::HttpsClientStream, tcp::TcpClientStream,
    tls::tls_client_connect, udp::UdpClientStream, xfer::FirstAnswer,
};
use hickory_proto::{
    op::{self, DnsRequest, DnsRequestOptions, Message},
    rr::{
        RecordType,
        rdata::opt::{ClientSubnet, EdnsCode, EdnsOption},
    },
};
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{info, instrument, warn};

use crate::{
    Error,
    app::{
        dns::{self, RuleDispatch},
        net::OutboundInterface,
    },
    common::tls::{self, GLOBAL_ROOT_STORE},
    dns::{ThreadSafeDNSClient, dhcp::DhcpClient},
    proxy::OutboundHandler,
};
use anyhow::anyhow;

#[derive(Clone, Debug, PartialEq)]
pub enum DNSNetMode {
    Udp,
    Tcp,
    DoT,
    DoH,
    Dhcp,
}

impl Display for DNSNetMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp => write!(f, "UDP"),
            Self::Tcp => write!(f, "TCP"),
            Self::DoT => write!(f, "DoT"),
            Self::DoH => write!(f, "DoH"),
            Self::Dhcp => write!(f, "DHCP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy;
    use hickory_proto::{
        op,
        rr::{Name, rdata::opt::EdnsOption},
    };
    fn client_with_ecs(ecs: Option<EdnsClientSubnet>) -> DnsClient {
        let proxy = Arc::new(proxy::direct::Handler::new("test-proxy"));
        let addr = net::SocketAddr::new(net::IpAddr::from([127, 0, 0, 1]), 53);
        DnsClient {
            inner: Arc::new(RwLock::new(Inner {
                c: None,
                bg_handle: None,
            })),
            cfg: DnsConfig::Udp(addr, None, proxy.clone(), None),
            proxy,
            host: url::Host::Domain("example.org".to_string()),
            port: 53,
            net: DNSNetMode::Udp,
            iface: None,
            ecs,
            rule_dispatch: None,
        }
    }

    fn build_message(record_type: RecordType) -> Message {
        let mut msg = Message::new(
            0,
            hickory_proto::op::MessageType::Query,
            hickory_proto::op::OpCode::Query,
        );
        let mut query = op::Query::new();
        query.set_name(Name::from_ascii("example.org").expect("valid name"));
        query.set_query_type(record_type);
        msg.add_query(query);
        msg
    }

    #[test]
    fn apply_edns_client_subnet_adds_ipv4_option() {
        let ecs = EdnsClientSubnet {
            ipv4: Some("1.2.3.4/24".parse().unwrap()),
            ipv6: None,
        };
        let client = client_with_ecs(Some(ecs));
        let mut msg = build_message(RecordType::A);

        client.apply_edns_client_subnet(&mut msg);

        let edns = msg.edns.as_ref().expect("edns should exist");
        let option = edns
            .option(EdnsCode::Subnet)
            .expect("subnet option missing");
        match option {
            EdnsOption::Subnet(subnet) => {
                assert_eq!(subnet.addr(), net::IpAddr::from([1, 2, 3, 0]));
                assert_eq!(subnet.source_prefix(), 24);
                assert_eq!(subnet.scope_prefix(), 24);
            }
            _ => panic!("unexpected edns option"),
        }
    }

    #[test]
    fn apply_edns_client_subnet_prefers_ipv6_for_aaaa() {
        let ecs = EdnsClientSubnet {
            ipv4: Some("1.2.3.4/24".parse().unwrap()),
            ipv6: Some("2001:db8::/48".parse().unwrap()),
        };
        let client = client_with_ecs(Some(ecs));
        let mut msg = build_message(RecordType::AAAA);

        client.apply_edns_client_subnet(&mut msg);

        let _edns = msg.edns.as_ref().expect("edns should exist");
        let ecs = EdnsClientSubnet {
            ipv4: Some("1.2.3.4/24".parse().unwrap()),
            ipv6: None,
        };
        let client = client_with_ecs(Some(ecs));
        let mut msg = build_message(RecordType::A);

        let mut edns = hickory_proto::op::Edns::new();
        {
            let opts = edns.options_mut();
            opts.insert(EdnsOption::Subnet(ClientSubnet::new(
                net::IpAddr::from([9, 8, 7, 0]),
                24,
                24,
            )));
        }
        msg.set_edns(edns);

        client.apply_edns_client_subnet(&mut msg);

        let edns = msg.edns.as_ref().expect("edns should remain");
        let option = edns
            .option(EdnsCode::Subnet)
            .expect("subnet option missing");
        match option {
            EdnsOption::Subnet(subnet) => {
                assert_eq!(subnet.addr(), net::IpAddr::from([9, 8, 7, 0]));
                assert_eq!(subnet.source_prefix(), 24);
                assert_eq!(subnet.scope_prefix(), 24);
            }
            _ => panic!("unexpected edns option"),
        }
    }
}

impl FromStr for DNSNetMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "UDP" => Ok(Self::Udp),
            "TCP" => Ok(Self::Tcp),
            "DoH" => Ok(Self::DoH),
            "DoT" => Ok(Self::DoT),
            "DHCP" => Ok(Self::Dhcp),
            _ => Err(Error::DNSError("unsupported protocol".into())),
        }
    }
}

#[derive(Clone)]
pub struct Opts {
    pub father: Option<Arc<dyn ClashResolver>>,
    pub host: url::Host<String>,
    pub port: u16,
    pub net: DNSNetMode,
    pub iface: Option<OutboundInterface>,
    pub proxy: Arc<dyn OutboundHandler>,
    pub ecs: Option<EdnsClientSubnet>,
    pub fw_mark: Option<u32>,
    /// When set, upstream dials consult the rule engine (see
    /// `DnsRuntimeProvider::pick_outbound`). Only populated for `nameserver`,
    /// `fallback`, and `nameserver-policy` clients when `dns.respect-rules`
    /// is true; bootstrap clients (`default-nameserver`,
    /// `proxy-server-nameserver`) leave this `None`.
    pub rule_dispatch: Option<Arc<RuleDispatch>>,
}

type FwMark = Option<u32>;

enum DnsConfig {
    Udp(
        net::SocketAddr,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
        FwMark,
    ),
    Tcp(
        net::SocketAddr,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
        FwMark,
    ),
    Tls(
        net::SocketAddr,
        url::Host<String>,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
        FwMark,
    ),
    Https(
        net::SocketAddr,
        url::Host<String>,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
        FwMark,
    ),
}

impl Display for DnsConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            DnsConfig::Udp(addr, iface, proxy, _) => {
                write!(f, "UDP: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {iface} ")?;
                }
                write!(f, "via proxy: {}", proxy.name())?;
                Ok(())
            }
            DnsConfig::Tcp(addr, iface, proxy, _) => {
                write!(f, "TCP: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {iface} ")?;
                }
                write!(f, "via proxy: {}", proxy.name())?;
                Ok(())
            }
            DnsConfig::Tls(addr, host, iface, proxy, _) => {
                write!(f, "TLS: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {iface} ")?;
                }
                write!(f, "host: {host}")?;
                write!(f, "via proxy: {}", proxy.name())
            }
            DnsConfig::Https(addr, host, iface, proxy, _) => {
                write!(f, "HTTPS: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {iface} ")?;
                }
                write!(f, "host: {host}")?;
                write!(f, "via proxy: {}", proxy.name())
            }
        }
    }
}

struct Inner {
    c: Option<client::Client<DnsRuntimeProvider>>,
    bg_handle: Option<JoinHandle<()>>,
}

/// DnsClient
pub struct DnsClient {
    inner: Arc<RwLock<Inner>>,

    cfg: DnsConfig,
    proxy: Arc<dyn OutboundHandler>,

    // debug purpose
    host: url::Host<String>,
    port: u16,
    net: DNSNetMode,
    iface: Option<OutboundInterface>,
    ecs: Option<EdnsClientSubnet>,
    rule_dispatch: Option<Arc<RuleDispatch>>,
}

impl DnsClient {
    /// Rebuild the DNS stream with retries, waiting between attempts.
    /// Observed on iOS: EADDRNOTAVAIL during network transitions can break
    /// DNS client connections; retrying gives the OS time to settle.
    async fn rebuild_with_retries(
        &self,
    ) -> anyhow::Result<(client::Client<DnsRuntimeProvider>, JoinHandle<()>)> {
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY: Duration = Duration::from_millis(200);

        for attempt in 0..=MAX_RETRIES {
            match dns_stream_builder(&self.cfg, self.rule_dispatch.clone()).await {
                Ok(result) => {
                    if attempt > 0 {
                        info!(
                            "{}: dns client rebuild succeeded on attempt {}/{}",
                            self.id(),
                            attempt + 1,
                            MAX_RETRIES + 1
                        );
                    }
                    return Ok(result);
                }
                Err(e) if attempt < MAX_RETRIES => {
                    warn!(
                        "{}: dns client rebuild attempt {}/{} failed: {e:#}, \
                         retrying in {}ms",
                        self.id(),
                        attempt + 1,
                        MAX_RETRIES + 1,
                        RETRY_DELAY.as_millis()
                    );
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                Err(e) => {
                    warn!(
                        "{}: dns client rebuild failed after {} attempts: {e:#}",
                        self.id(),
                        MAX_RETRIES + 1
                    );
                    return Err(e.into());
                }
            }
        }
        unreachable!()
    }
}

impl DnsClient {
    pub async fn new_client(opts: Opts) -> anyhow::Result<ThreadSafeDNSClient> {
        // TODO: use proxy to connect?

        if matches!(opts.net, DNSNetMode::Dhcp) {
            let host = opts.host.to_string();
            return Ok(Arc::new(DhcpClient::new(&host, opts.fw_mark).await));
        }

        let mut ip: Option<IpAddr> = None;
        let need_resolve = match &opts.host {
            url::Host::Domain(v) => Some(v),
            url::Host::Ipv4(v) => {
                ip = Some(net::IpAddr::V4(*v));
                None
            }
            url::Host::Ipv6(v) => {
                ip = Some(net::IpAddr::V6(*v));
                None
            }
        };

        let resolved_ip = match need_resolve {
            Some(domain) => match opts.father {
                Some(father) => match father.resolve(domain, false).await? {
                    Some(ip) => Some(ip),
                    _ => {
                        return Err(Error::InvalidConfig(format!(
                            "can't resolve default DNS: {}",
                            domain
                        ))
                        .into());
                    }
                },
                _ => {
                    return Err(Error::DNSError(format!(
                        "unable to resolve DNS hostname {} without a default \
                         resolver",
                        domain
                    ))
                    .into());
                }
            },
            None => None,
        };
        let ip = ip.or(resolved_ip).ok_or_else(|| {
            anyhow!(
                "invalid DNS host: {}, unable to parse as IP and no default \
                 resolver",
                opts.host
            )
        })?;
        match opts.net {
            DNSNetMode::Udp => {
                let cfg = DnsConfig::Udp(
                    net::SocketAddr::new(ip, opts.port),
                    opts.iface.clone(),
                    opts.proxy.clone(),
                    opts.fw_mark,
                );
                Ok(Arc::new(Self {
                    inner: Arc::new(RwLock::new(Inner {
                        c: None,
                        bg_handle: None,
                    })),
                    cfg,
                    proxy: opts.proxy,
                    host: opts.host,
                    port: opts.port,
                    net: opts.net,
                    iface: opts.iface,
                    ecs: opts.ecs.clone(),
                    rule_dispatch: opts.rule_dispatch.clone(),
                }))
            }
            DNSNetMode::Tcp => {
                let cfg = DnsConfig::Tcp(
                    net::SocketAddr::new(ip, opts.port),
                    opts.iface.clone(),
                    opts.proxy.clone(),
                    opts.fw_mark,
                );
                Ok(Arc::new(Self {
                    inner: Arc::new(RwLock::new(Inner {
                        c: None,
                        bg_handle: None,
                    })),

                    cfg,
                    proxy: opts.proxy,
                    host: opts.host,
                    port: opts.port,
                    net: opts.net,
                    iface: opts.iface,
                    ecs: opts.ecs.clone(),
                    rule_dispatch: opts.rule_dispatch.clone(),
                }))
            }
            DNSNetMode::DoT => {
                let cfg = DnsConfig::Tls(
                    net::SocketAddr::new(ip, opts.port),
                    opts.host.clone(),
                    opts.iface.clone(),
                    opts.proxy.clone(),
                    opts.fw_mark,
                );
                Ok(Arc::new(Self {
                    inner: Arc::new(RwLock::new(Inner {
                        c: None,
                        bg_handle: None,
                    })),
                    cfg,
                    proxy: opts.proxy,
                    host: opts.host,
                    port: opts.port,
                    net: opts.net,
                    iface: opts.iface,
                    ecs: opts.ecs.clone(),
                    rule_dispatch: opts.rule_dispatch.clone(),
                }))
            }
            DNSNetMode::DoH => {
                let cfg = DnsConfig::Https(
                    net::SocketAddr::new(ip, opts.port),
                    opts.host.clone(),
                    opts.iface.clone(),
                    opts.proxy.clone(),
                    opts.fw_mark,
                );
                Ok(Arc::new(Self {
                    inner: Arc::new(RwLock::new(Inner {
                        c: None,
                        bg_handle: None,
                    })),

                    cfg,
                    proxy: opts.proxy,
                    host: opts.host,
                    port: opts.port,
                    net: opts.net,
                    iface: opts.iface,
                    ecs: opts.ecs.clone(),
                    rule_dispatch: opts.rule_dispatch.clone(),
                }))
            }
            DNSNetMode::Dhcp => unreachable!("."),
        }
    }

    fn apply_edns_client_subnet(&self, message: &mut Message) {
        let Some(ecs) = &self.ecs else {
            return;
        };

        if ecs.ipv4.is_none() && ecs.ipv6.is_none() {
            return;
        }

        if message
            .edns
            .as_ref()
            .is_some_and(|edns| edns.option(EdnsCode::Subnet).is_some())
        {
            return;
        }

        let prefer_ipv6 = matches!(
            message.queries.first().map(|q| q.query_type()),
            Some(RecordType::AAAA)
        );

        let candidate = if prefer_ipv6 {
            ecs.ipv6
                .map(|ipv6| (net::IpAddr::from(ipv6.network()), ipv6.prefix_len()))
                .or_else(|| {
                    ecs.ipv4.map(|ipv4| {
                        (net::IpAddr::from(ipv4.network()), ipv4.prefix_len())
                    })
                })
        } else {
            ecs.ipv4
                .map(|ipv4| (net::IpAddr::from(ipv4.network()), ipv4.prefix_len()))
                .or_else(|| {
                    ecs.ipv6.map(|ipv6| {
                        (net::IpAddr::from(ipv6.network()), ipv6.prefix_len())
                    })
                })
        };

        let Some((addr, prefix)) = candidate else {
            return;
        };

        let edns = message
            .edns
            .get_or_insert_with(hickory_proto::op::Edns::new);

        let options = edns.options_mut();
        options.remove(EdnsCode::Subnet);
        options.insert(EdnsOption::Subnet(ClientSubnet::new(addr, prefix, prefix)));
    }
}

impl Debug for DnsClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsClient")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("net", &self.net)
            .field("iface", &self.iface)
            .field("proxy", &self.proxy.name())
            .finish()
    }
}

#[async_trait]
impl Client for DnsClient {
    fn id(&self) -> String {
        format!("{}#{}:{}", &self.net, &self.host, &self.port)
    }

    #[instrument(skip(msg), level = "trace")]
    async fn exchange(&self, msg: &Message) -> anyhow::Result<Message> {
    // 💡 状态判定：检查是否需要进行初始化或自愈重建
        let need_initialize = {
            let inner = self.inner.read().await;
            inner.c.is_none() || inner.bg_handle.as_ref().is_none_or(|bg| bg.is_finished())
        };

        if need_initialize {
            let mut inner = self.inner.write().await;
            // Double check lock 保证高并发下只有一个协程触发重建
            if inner.c.is_none() || inner.bg_handle.as_ref().is_none_or(|bg| bg.is_finished()) {
                if inner.c.is_some() && inner.bg_handle.as_ref().map(|bg| bg.is_finished()).unwrap_or(false) {
                    warn!("dns client background task is finished, likely connection closed, restarting a new one");
                    
                    // 💡 优化 2：在重建前，强制对旧驱动进行主动熔断清理，防止孤儿任务常驻
                    if let Some(old_bg) = inner.bg_handle.take() {
                        old_bg.abort();
                    }

                    let (client, bg) = self.rebuild_with_retries().await?;
                    inner.c.replace(client);
                    inner.bg_handle.replace(bg);
                } else {
                    info!("initializing dns client: {}", &self.cfg);
                    if let Some(old_bg) = inner.bg_handle.take() {
                        old_bg.abort();
                    }
                    let (client, bg) = self.rebuild_with_retries().await?;
                    inner.c.replace(client);
                    inner.bg_handle.replace(bg);
                }
            }
        }

        // EDNS 机制和请求 ID 构造保持不变
        let mut outbound = msg.clone();
        self.apply_edns_client_subnet(&mut outbound);
        let mut req = DnsRequest::new(outbound, DnsRequestOptions::default());
        if req.metadata.id == 0 {
            req.metadata.id = rand::random::<u16>();
        }

        // 💡 优化 1：快进快出！利用 Hickory-DNS Client 天生支持无锁 Clone 的高级特性！
        let client_clone = {
            let inner_guard = self.inner.read().await;
            let Some(client) = inner_guard.c.as_ref() else {
                return Err(anyhow::anyhow!("DNS client is uninitialized"));
            };
            client.clone() // ✨ 核心操作：在这里迅速 clone 一份轻量的通道句柄
        }; // 🔒 读锁（inner_guard）在这里伴随着大括号结束【瞬间被主动释放】！

        // 💡 优化 3：完全在锁的外部执行耗时的公网异步网络 IO。
        // 现在哪怕这个 .await 挂起并卡住 5 秒钟，它也绝不持有任何 RwLock 锁！
        // 其他并发协程、自愈重建写锁可以畅通无阻地并发执行，彻底终结了假死风险！
        client_clone
            .send(req)
            .first_answer()
            .await
            .map_err(|x| Error::DNSError(x.to_string()).into())
            .map(|x: op::DnsResponse| x.into_message())
    }
}

async fn dns_stream_builder(
    cfg: &DnsConfig,
    rule_dispatch: Option<Arc<RuleDispatch>>,
) -> Result<(client::Client<DnsRuntimeProvider>, JoinHandle<()>), Error> {
 let dns_resolver = Arc::new(dns::SystemResolver::new(false)?);
    
    match cfg {
        DnsConfig::Udp(addr, iface, proxy, fw_mark) => {
            let stream = UdpClientStream::builder(
                *addr,
                DnsRuntimeProvider::new(
                    proxy.clone(),
                    dns_resolver,
                    iface.clone(),
                    *fw_mark,
                    rule_dispatch.clone(),
                ),
            )
            .with_timeout(Some(Duration::from_secs(5)))
            .build();

            let (x, y) = client::Client::<DnsRuntimeProvider>::from_sender(stream);
            
            // 💡 规范化：为后台驱动注入追踪性日志，防止孤儿协程静默挂起
            let bg_task = tokio::spawn(async move {
                trace!("[DNS Driver] DNS background loop started");
                y.await; // 💡 它的返回值就是 ()，直接在这里挂起运行
                warn!("[DNS Driver] DNS background loop exited (likely connection closed or link rotated)");
            });
            Ok((x, bg_task))
        }

        DnsConfig::Tcp(addr, iface, proxy, fw_mark) => {
            // 💡 优化 1：强制开启 bind_default 或通过底层的 RuntimeProvider 确保 TCP_NODELAY 激活
            // 确保高并发短包 DNS 请求直接发射，将查询延迟死死压制在 0ms 排队级
            let (stream_future, sender) = TcpClientStream::new(
                *addr,
                None, // 默认不限制本地端口绑定
                Some(Duration::from_secs(5)),
                DnsRuntimeProvider::new(
                    proxy.clone(),
                    dns_resolver,
                    iface.clone(),
                    *fw_mark,
                    rule_dispatch.clone(),
                ),
            );

            let stream = stream_future
                .await
                .map_err(|x| Error::DNSError(format!("TCP stream connection failed: {}", x)))?;
            
            let (x, y) = client::Client::<DnsRuntimeProvider>::new(stream, sender);
            
            let bg_task = tokio::spawn(async move {
                trace!("[DNS Driver] DNS background loop started");
                y.await; // 💡 它的返回值就是 ()，直接在这里挂起运行
                warn!("[DNS Driver] DNS background loop exited (likely connection closed or link rotated)");
            });
            Ok((x, bg_task))
        }

        DnsConfig::Tls(addr, host, iface, proxy, fw_mark) => {
            let mut tls_config = ClientConfig::builder()
                .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                .with_no_client_auth();
            // 💡 规范化：DoT 协议标准 ALPN 仅包含 "dot"
            tls_config.alpn_protocols = vec![b"dot".to_vec()];

            let addr = *addr;
            let host = host.clone();
            let iface = iface.clone();

            let server_name = ServerName::try_from(host.to_string())
                .map_err(|e| Error::DNSError(format!("Invalid DoT hostname: {}", e)))?;
                
            let (stream_future, sender) = tls_client_connect(
                addr,
                server_name,
                Arc::new(tls_config),
                DnsRuntimeProvider::new(
                    proxy.clone(),
                    dns_resolver,
                    iface.clone(),
                    *fw_mark,
                    rule_dispatch.clone(),
                ),
            );

            let stream = stream_future
                .await
                .map_err(|x| Error::DNSError(format!("DoT TLS handshake failed: {}", x)))?;
            
            let (x, y) = client::Client::<DnsRuntimeProvider>::with_timeout(
                stream,
                sender,
                Duration::from_secs(5),
            );
            
            let bg_task = tokio::spawn(async move {
                trace!("[DNS Driver] DNS background loop started");
                y.await; // 💡 它的返回值就是 ()，直接在这里挂起运行
                warn!("[DNS Driver] DNS background loop exited (likely connection closed or link rotated)");
            });
            Ok((x, bg_task))
        }

        DnsConfig::Https(addr, host, iface, proxy, fw_mark) => {
            let mut tls_config = ClientConfig::builder()
                .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                .with_no_client_auth();
            // 💡 规范化：DoH 建立在 HTTP/2 之上，ALPN 必须强制锁定 "h2"
            tls_config.alpn_protocols = vec![b"h2".to_vec()];

            let host_ip = match host {
                url::Host::Ipv4(ip) => Some(IpAddr::V4(*ip)),
                url::Host::Ipv6(ip) => Some(IpAddr::V6(*ip)),
                _ => None,
            };
            if host_ip == Some(addr.ip()) {
                tls_config.dangerous().set_certificate_verifier(Arc::new(
                    tls::NoHostnameTlsVerifier::new(),
                ));
            }
            
            let stream = HttpsClientStream::builder(
                Arc::new(tls_config),
                DnsRuntimeProvider::new(
                    proxy.clone(),
                    dns_resolver,
                    iface.clone(),
                    *fw_mark,
                    rule_dispatch.clone(),
                ),
            )
            .build(*addr, host.to_string().into(), "/dns-query".into())
            .await
            .map_err(|x| Error::DNSError(format!("DoH connection failed: {}", x)))?;

            let (x, y) = client::Client::<DnsRuntimeProvider>::from_sender(stream);
            
            let bg_task = tokio::spawn(async move {
                trace!("[DNS Driver] DNS background loop started");
                y.await; // 💡 它的返回值就是 ()，直接在这里挂起运行
                warn!("[DNS Driver] DNS background loop exited (likely connection closed or link rotated)");
            });
            Ok((x, bg_task))
        }
    }
    
}
