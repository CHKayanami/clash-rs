#[cfg(all(test, docker_test))]
use crate::proxy::OutboundNode;

pub(crate) use stack::{tcp::SocketPair, udp::UdpPair};
use self::wireguard::Config;
use super::{
    AnyOutboundDatagram, AnyStream, DialWithConnector,
    HandlerCommonOptions, OutboundHandler, OutboundType, PlainProxyAPIResponse,
    utils::RemoteConnector,
};
use crate::{
    Error,
    app::dns::ThreadSafeDNSResolver,
    common::errors::{map_io_error, new_io_error},
    impl_default_connector,
    session::Session,
};
use arc_swap::ArcSwapOption;
use erased_serde::Serialize as ErasedSerialize;
use futures::TryFutureExt;
use ipnet::IpNet;
use rand::seq::IndexedRandom;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinHandle,
};

mod device;
mod events;
mod keys;
pub(crate) use keys::KeyBytes;
mod ports;
mod stack;
mod wireguard;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub ip: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub private_key: String,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub remote_dns_resolve: bool,
    pub dns: Option<Vec<String>>,
    pub mtu: Option<u16>,
    pub udp: bool,
    pub allowed_ips: Option<Vec<String>>,
    pub reserved_bits: Option<Vec<u8>>,
}

const WG_CLOSING_BIT: usize = 1usize << (usize::BITS - 1);

pub(super) struct Inner {
    device_manager: Arc<device::DeviceManager>,
    #[allow(unused)]
    wg_handle: JoinHandle<()>,
    #[allow(unused)]
    device_manager_handle: JoinHandle<()>,
    active_streams: AtomicUsize,
    keep_idle: Arc<AtomicBool>,
    cache_slot: Weak<ArcSwapOption<Inner>>,
}

impl Inner {
    fn try_acquire_lease(self: &Arc<Self>) -> Option<StreamLease> {
        self.active_streams
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |val| {
                if val & WG_CLOSING_BIT != 0 {
                    None
                } else {
                    Some(val + 1)
                }
            })
            .ok()
            .map(|_| StreamLease(self.clone()))
    }

    fn evict_from_cache(self: &Arc<Self>) {
        if let Some(slot) = self.cache_slot.upgrade() {
            let _ = slot.rcu(|current| match current {
                Some(cached) if Arc::ptr_eq(cached, self) => None,
                _ => current.clone(),
            });
        }
    }

    fn release_lease(self: &Arc<Self>) {
        let keep_idle = self.keep_idle.load(Ordering::SeqCst);
        let mut evict = false;
        let mut became_zero = false;
        let _ = self.active_streams.try_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |val| {
                let closing = (val & WG_CLOSING_BIT) != 0;
                let count = (val & !WG_CLOSING_BIT).saturating_sub(1);
                let next_closing = closing || (!keep_idle && count == 0);
                evict = !closing && next_closing;
                became_zero = !next_closing && count == 0;
                Some(if next_closing {
                    WG_CLOSING_BIT | count
                } else {
                    count
                })
            },
        );
        if evict {
            self.evict_from_cache();
        } else if became_zero && !self.keep_idle.load(Ordering::SeqCst) {
            self.close_if_idle();
        }
    }

    fn close_if_idle(self: &Arc<Self>) {
        if self
            .active_streams
            .compare_exchange(
                0,
                WG_CLOSING_BIT,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            self.evict_from_cache();
        }
    }

    #[cfg(test)]
    pub(super) fn new_for_test(
        device_manager: Arc<device::DeviceManager>,
        wg_handle: JoinHandle<()>,
        device_manager_handle: JoinHandle<()>,
        keep_idle: Arc<AtomicBool>,
        cache_slot: Weak<ArcSwapOption<Inner>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            device_manager,
            wg_handle,
            device_manager_handle,
            active_streams: AtomicUsize::new(0),
            keep_idle,
            cache_slot,
        })
    }

    #[cfg(test)]
    pub(super) fn is_closing(&self) -> bool {
        (self.active_streams.load(Ordering::Acquire) & WG_CLOSING_BIT) != 0
    }
}

pub(crate) struct StreamLease(Arc<Inner>);

impl std::fmt::Debug for StreamLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamLease").finish()
    }
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        self.0.release_lease();
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.wg_handle.abort();
        self.device_manager_handle.abort();
    }
}

pub struct Handler {
    opts: HandlerOptions,
    inner: Arc<ArcSwapOption<Inner>>,
    init_lock: Mutex<()>,
    keep_idle: Arc<AtomicBool>,

    connector: Option<Arc<RemoteConnector>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuard")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl_default_connector!(Handler);

impl Drop for Handler {
    fn drop(&mut self) {
        self.keep_idle.store(false, Ordering::SeqCst);
        if let Some(inner) = self.inner.swap(None) {
            inner.close_if_idle();
        }
    }
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        connector: Option<Arc<RemoteConnector>>,
    ) -> Self {
        Self {
            opts,
            inner: Arc::new(ArcSwapOption::empty()),
            init_lock: Mutex::new(()),
            keep_idle: Arc::new(AtomicBool::new(true)),
            connector,
        }
    }

    /// Initialize or return the cached WireGuard tunnel and smoltcp device
    /// manager together with a stream lease that covers the full dial path.
    async fn initialize_inner(
        &self,
        resolver: ThreadSafeDNSResolver,
        sess: &Session,
    ) -> Result<(Arc<Inner>, StreamLease), Error> {
        if let Some(inner) = self.inner.load_full()
            && let Some(lease) = inner.try_acquire_lease()
        {
            return Ok((inner, lease));
        }
        let _guard = self.init_lock.lock().await;
        if let Some(inner) = self.inner.load_full()
            && let Some(lease) = inner.try_acquire_lease()
        {
            return Ok((inner, lease));
        }

        let recv_pair = mpsc::channel(1024);
        let send_pair = mpsc::channel(1024);
        let server_ip = resolver
            .resolve(&self.opts.server, false)
            .await
            .map_err(map_io_error)?
            .ok_or(new_io_error(
                format!("invalid remote server: {}", self.opts.server).as_str(),
            ))?;
        let allowed_ips = self
            .opts
            .allowed_ips
            .as_ref()
            .map(|ips| {
                ips.iter()
                    .map(|ip| {
                        ip.parse::<IpNet>().map_err(|e| {
                            new_io_error(format!("invalid allowed ip: {e}").as_str())
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();

        let wg = wireguard::WireguardTunnel::new(
            Config {
                private_key: self
                    .opts
                    .private_key
                    .parse::<KeyBytes>()
                    .map_err(|e| Error::InvalidConfig(format!("invalid WireGuard private key: {e}")))?
                    .0
                    .into(),
                endpoint_public_key: self
                    .opts
                    .public_key
                    .parse::<KeyBytes>()
                    .map_err(|e| Error::InvalidConfig(format!("invalid WireGuard public key: {e}")))?
                    .0
                    .into(),
                pre_shared_key: self
                    .opts
                    .pre_shared_key
                    .as_ref()
                    .map(|s| {
                        s.parse::<KeyBytes>()
                            .map(|key| key.0.into())
                            .map_err(|e| Error::InvalidConfig(format!("invalid WireGuard pre-shared key: {e}")))
                    })
                    .transpose()?,
                remote_endpoint: (server_ip, self.opts.port).into(),
                source_peer_ip: self.opts.ip,
                source_peer_ipv6: self.opts.ipv6,
                keepalive_seconds: Some(10),
                allowed_ips,
                reserved_bits: match &self.opts.reserved_bits {
                    Some(bits) if bits.len() >= 3 => [bits[0], bits[1], bits[2]],
                    _ => [0, 0, 0],
                },
            },
            recv_pair.0,
            send_pair.1,
            resolver.clone(),
            self.connector.clone(),
            sess,
        )
        .await
        .map_err(map_io_error)?;

        let wg_handle = tokio::spawn(async move {
            wg.start_polling().await;
        });

        // use to notify the device manager to poll sockets
        let packet_notifier = tokio::sync::mpsc::channel(1024);

        let device = device::VirtualIpDevice::new(
            send_pair.0,
            recv_pair.1,
            packet_notifier.0,
            self.opts.mtu.unwrap_or(1420) as usize,
        );

        let device_manager = Arc::new(device::DeviceManager::new(
            self.opts.ip,
            self.opts.ipv6,
            resolver,
            if self.opts.remote_dns_resolve {
                self.opts
                    .dns
                    .as_ref()
                    .map(|server| {
                        server
                            .iter()
                            .map(|s| {
                                s.parse::<IpAddr>()
                                    .map(|ip| (ip, 53).into())
                                    .map_err(|e| Error::InvalidConfig(format!("invalid WireGuard DNS server {s}: {e}")))
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?
                    .unwrap_or_default()
            } else {
                vec![]
            },
            packet_notifier.1,
        ));

        let device_manager_clone = device_manager.clone();
        let device_manager_handle = tokio::spawn(async move {
            device_manager_clone.poll_sockets(device).await;
        });

        let inner = Arc::new(Inner {
            device_manager,
            wg_handle,
            device_manager_handle,
            active_streams: AtomicUsize::new(0),
            keep_idle: self.keep_idle.clone(),
            cache_slot: Arc::downgrade(&self.inner),
        });
        let lease = inner
            .try_acquire_lease()
            .expect("fresh wireguard tunnel must accept initial lease");
        self.inner.store(Some(inner.clone()));
        Ok((inner, lease))
    }
}

impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.server)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::WireGuard
    }

    fn support_udp(&self) -> bool {
        self.opts.udp
    }

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        let (inner, lease) = self
            .initialize_inner(resolver.clone(), sess)
            .await
            .map_err(map_io_error)?;

        let ip = if self.opts.remote_dns_resolve
            && sess.destination.is_domain()
            && self.opts.dns.as_ref().is_some_and(|x| !x.is_empty())
        {
            let server = self
                .opts
                .dns
                .as_ref()
                .unwrap()
                .choose(&mut rand::rng())
                .unwrap();

            inner
                .device_manager
                .look_up_dns(
                    sess.destination.host_cow().as_ref(),
                    (server.parse::<IpAddr>().unwrap(), 53).into(),
                )
                .await
                .ok_or(new_io_error("invalid remote address"))?
        } else {
            resolver
                .resolve(sess.destination.host_cow().as_ref(), false)
                .map_err(map_io_error)
                .await?
                .ok_or(new_io_error("invalid remote address"))?
        };

        let remote = (ip, sess.destination.port()).into();
        if ip.is_ipv6() && self.opts.ipv6.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "WireGuard IPv6 address is required for an IPv6 destination",
            ));
        }

        let socket = inner
            .device_manager
            .new_tcp_socket_with_lease(remote, lease)
            .await;
        sess.push_chain(self.name());
        Ok(AnyStream::new(socket))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyOutboundDatagram> {
        let (inner, lease) = self
            .initialize_inner(resolver, sess)
            .await
            .map_err(map_io_error)?;

        let socket = inner
            .device_manager
            .new_udp_socket()
            .await
            .with_lease(lease);
        sess.push_chain(self.name());
        Ok(AnyOutboundDatagram::new(socket))
    }

    fn set_keep_idle(&self, keep: bool) {
        self.keep_idle.store(keep, Ordering::SeqCst);
        if !keep {
            self.close_idle_connections();
        }
    }

    fn close_idle_connections(&self) {
        if let Some(inner) = self.inner.load_full() {
            inner.close_if_idle();
        }
    }

}

impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        m.insert("server".to_owned(), Box::new(self.opts.server.clone()) as _);
        m.insert("port".to_owned(), Box::new(self.opts.port) as _);
        m.insert(
            "public-key".to_owned(),
            Box::new(self.opts.public_key.clone()) as _,
        );
        m
    }
}

#[cfg(all(test, docker_test))]
mod tests {

    use crate::proxy::utils::{
        GLOBAL_DIRECT_CONNECTOR,
        test_utils::{
            Suite,
            config_helper::test_config_base_dir,
            docker_runner::{DockerTestRunnerBuilder, alloc_docker_port},
        },
    };

    use super::{
        super::utils::test_utils::{consts::*, docker_runner::DockerTestRunner},
        *,
    };
    use crate::{
        proxy::utils::test_utils::run_test_suites_and_cleanup, tests::initialize,
    };

    // see: https://github.com/linuxserver/docker-wireguard?tab=readme-ov-file#usage
    // we shouldn't run the wireguard server with host mode, or
    // the sysctl of `net.ipv4.conf.all.src_valid_mark` will fail
    async fn get_runner(host_port: u16) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let wg_config = test_config_dir.join("wg");
        // the following configs is in accordance with the config in `wg`
        // dir
        DockerTestRunnerBuilder::new()
            .image(IMAGE_WG)
            .env(&[
                "PUID=1000",
                "PGID=1000",
                "TZ=Etc/UTC",
                "SERVERPORT=10002",
                "SERVERURL=127.0.0.1",
                "PEERS=1",
                "PEERDNS=auto",
                "INTERNAL_SUBNET=10.13.13.0",
                "ALLOWEDIPS=0.0.0.0/0",
            ])
            .mounts(&[(wg_config.to_str().unwrap(), "/config")])
            .sysctls(&[("net.ipv4.conf.all.src_valid_mark", "1")])
            .cap_add(&["NET_ADMIN"])
            .net_mode("bridge") // the default network mode for testing is `host`
            .host_port(host_port, 10002)
            .build()
            .await
    }

    #[tokio::test]
    async fn test_wg() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();

        let runner = get_runner(host_port).await?;

        let opts = HandlerOptions {
            name: "wg".to_owned(),
            common_opts: Default::default(),
            server: runner.container_ip().unwrap_or("127.0.0.1".to_owned()),
            port: 10002,
            ip: Ipv4Addr::new(10, 13, 13, 2),
            ipv6: None,
            private_key: "KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=".to_owned(),
            public_key: "INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=".to_owned(),
            pre_shared_key: Some(
                "+JmZErvtDT4ZfQequxWhZSydBV+ItqUcPMHUWY1j2yc=".to_owned(),
            ),
            remote_dns_resolve: false,
            dns: None,
            mtu: Some(1000),
            udp: true,
            allowed_ips: Some(vec!["0.0.0.0/0".to_owned()]),
            reserved_bits: None,
        };
        let handler =
            Arc::new(Handler::new(opts, Some(GLOBAL_DIRECT_CONNECTOR.clone())));

        // cannot run the ping pong test, since the wireguard server is running
        // on bridge network mode and the `net.ipv4.conf.all.
        // src_valid_mark` is not supported in the host network mode the
        // latency test should be enough

        // FIXME: wait for the startup of the test runner in a more elegant way
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        run_test_suites_and_cleanup(
            OutboundNode::protocol(handler),
            runner,
            &[Suite::LatencyTcp, Suite::DnsUdp],
        )
        .await
    }
}
