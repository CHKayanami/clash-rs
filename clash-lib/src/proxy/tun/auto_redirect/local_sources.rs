use std::{io, net::IpAddr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};

use crate::config::internal::config::TunConfig;

// Match on-link source prefixes, as sing-tun does. A source outside these
// prefixes cannot turn a WAN request to a host address into a DNS query.
pub(super) fn prefixes(cfg: &TunConfig, device: &str) -> io::Result<Vec<IpNet>> {
    let interfaces = NetworkInterface::show().map_err(io::Error::other)?;
    prefixes_from(interfaces, cfg, device)
}

fn prefixes_from(
    interfaces: impl IntoIterator<Item = NetworkInterface>,
    cfg: &TunConfig,
    device: &str,
) -> io::Result<Vec<IpNet>> {
    let mut prefixes = Vec::new();
    for interface in interfaces {
        if interface.name == "lo" || interface.name == device {
            continue;
        }
        if cfg.exclude_interface.iter().any(|name| name == &interface.name) {
            continue;
        }
        if !cfg.include_interface.is_empty()
            && !cfg.include_interface.iter().any(|name| name == &interface.name)
        {
            continue;
        }
        for address in interface.addr {
            let prefix = match address {
                Addr::V4(address) => {
                    if address.ip.is_loopback()
                        || address.ip.is_link_local()
                        || address.ip.is_unspecified()
                        || address.ip.is_multicast()
                        || address.ip.is_broadcast()
                    {
                        continue;
                    }
                    // An unavailable or /0 mask grants trust only to this address.
                    match address.netmask {
                        Some(mask) => {
                            let net = Ipv4Net::with_netmask(address.ip, mask)
                                .map(IpNet::V4)
                                .map_err(io::Error::other)?;
                            if net.prefix_len() == 0 {
                                IpNet::from(IpAddr::V4(address.ip))
                            } else {
                                net
                            }
                        }
                        None => IpNet::from(IpAddr::V4(address.ip)),
                    }
                }
                Addr::V6(address) => {
                    if address.ip.is_loopback()
                        || address.ip.is_unicast_link_local()
                        || address.ip.is_unspecified()
                        || address.ip.is_multicast()
                    {
                        continue;
                    }
                    match address.netmask {
                        Some(mask) => {
                            let net = Ipv6Net::with_netmask(address.ip, mask)
                                .map(IpNet::V6)
                                .map_err(io::Error::other)?;
                            if net.prefix_len() == 0 {
                                IpNet::from(IpAddr::V6(address.ip))
                            } else {
                                net
                            }
                        }
                        None => IpNet::from(IpAddr::V6(address.ip)),
                    }
                }
            };
            prefixes.push(prefix.trunc());
        }
    }
    Ok(IpNet::aggregate(&prefixes))
}

#[cfg(target_os = "linux")]
pub(super) use monitor::SourceMonitor;

#[cfg(target_os = "linux")]
mod monitor {
    use std::{io, time::Duration};

    use futures::{StreamExt, channel::mpsc::UnboundedReceiver};
    use rtnetlink::{
        constants::{RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR, RTMGRP_LINK},
        new_connection,
        packet_core::{NetlinkMessage, NetlinkPayload},
        packet_route::RouteNetlinkMessage,
        proto::Connection,
        sys::{AsyncSocket, SocketAddr},
    };
    use tokio::{
        sync::mpsc::{self, Receiver, Sender},
        task::JoinHandle,
        time::sleep,
    };
    use tracing::warn;

    const DEBOUNCE_DELAY: Duration = Duration::from_millis(150);
    const RECONNECT_DELAY: Duration = Duration::from_secs(1);

    pub(in crate::proxy::tun::auto_redirect) struct SourceMonitor {
        rx: Receiver<()>,
        pending: bool,
        task: JoinHandle<()>,
    }

    impl SourceMonitor {
        pub(in crate::proxy::tun::auto_redirect) fn new() -> io::Result<Self> {
            let initial = bind_netlink()?;
            let (tx, rx) = mpsc::channel(1);
            let _ = tx.try_send(());
            let task = tokio::spawn(run_loop(initial, tx));
            Ok(Self { rx, pending: false, task })
        }

        pub(in crate::proxy::tun::auto_redirect) async fn changed(&mut self) -> bool {
            if !self.pending {
                if self.rx.recv().await.is_none() {
                    return false;
                }
                self.pending = true;
            }
            // Coalesce bursts of link/address netlink notifications into one refresh.
            // `pending` stays true if cancelled during debounce so the next poll still runs.
            sleep(DEBOUNCE_DELAY).await;
            while self.rx.try_recv().is_ok() {}
            self.pending = false;
            true
        }
    }

    impl Drop for SourceMonitor {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    type NetlinkStream = UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>;
    type NetlinkConnection = Connection<RouteNetlinkMessage>;

    fn bind_netlink() -> io::Result<(NetlinkConnection, NetlinkStream)> {
        let (mut connection, _handle, messages) = new_connection()?;
        let groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
        connection
            .socket_mut()
            .socket_mut()
            .bind(&SocketAddr::new(0, groups))?;
        Ok((connection, messages))
    }

    async fn run_loop(
        initial: (NetlinkConnection, NetlinkStream),
        tx: Sender<()>,
    ) {
        let mut active = Some(initial);
        loop {
            let (connection, mut messages) = match active.take() {
                Some(pair) => pair,
                None => match bind_netlink() {
                    Ok(pair) => {
                        let _ = tx.try_send(());
                        pair
                    }
                    Err(error) => {
                        warn!("failed to rebind netlink source monitor: {error}");
                        sleep(RECONNECT_DELAY).await;
                        if tx.is_closed() {
                            return;
                        }
                        continue;
                    }
                },
            };

            // Drive connection in the same task so aborting SourceMonitor drops
            // both the connection and the message receiver together.
            tokio::pin!(connection);
            loop {
                tokio::select! {
                    () = &mut connection => {
                        warn!("netlink source monitor connection exited; reconnecting");
                        break;
                    }
                    item = messages.next() => {
                        let Some((message, _)) = item else {
                            warn!("netlink source monitor stream ended; reconnecting");
                            break;
                        };
                        if matches!(
                            message.payload,
                            NetlinkPayload::InnerMessage(
                                RouteNetlinkMessage::NewAddress(_)
                                    | RouteNetlinkMessage::DelAddress(_)
                                    | RouteNetlinkMessage::NewLink(_)
                                    | RouteNetlinkMessage::DelLink(_)
                            )
                        ) {
                            let _ = tx.try_send(());
                        }
                    }
                }
                if tx.is_closed() {
                    return;
                }
            }

            if tx.is_closed() {
                return;
            }
            sleep(RECONNECT_DELAY).await;
        }
    }

    #[cfg(test)]
    mod tests {
        use std::future::pending;

        use tokio::time::timeout;

        use super::*;

        #[tokio::test]
        async fn cancelled_changed_during_debounce_preserves_pending_refresh() {
            let (tx, rx) = mpsc::channel(1);
            tx.try_send(()).unwrap();
            let mut monitor = SourceMonitor {
                rx,
                pending: false,
                task: tokio::spawn(pending()),
            };
            let cancelled = tokio::select! {
                _ = monitor.changed() => false,
                _ = sleep(Duration::from_millis(20)) => true,
            };
            assert!(cancelled);
            assert!(monitor.pending);
            assert!(timeout(Duration::from_secs(1), monitor.changed()).await.unwrap());
            assert!(!monitor.pending);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use network_interface::{V4IfAddr, V6IfAddr};

    use super::*;

    fn iface(name: &str, addr: Vec<Addr>) -> NetworkInterface {
        NetworkInterface {
            name: name.to_owned(),
            addr,
            mac_addr: None,
            index: 0,
            internal: false,
        }
    }

    fn v4(ip: [u8; 4], netmask: Option<[u8; 4]>) -> Addr {
        Addr::V4(V4IfAddr {
            ip: Ipv4Addr::from(ip),
            broadcast: None,
            netmask: netmask.map(Ipv4Addr::from),
        })
    }

    fn v6(ip: Ipv6Addr, netmask: Option<Ipv6Addr>) -> Addr {
        Addr::V6(V6IfAddr { ip, broadcast: None, netmask })
    }

    #[test]
    fn filters_loopback_tun_scope_and_zero_masks_while_aggregating() {
        let interfaces = vec![
            iface("lo", vec![v4([127, 0, 0, 1], Some([255, 0, 0, 0]))]),
            iface("tun0", vec![v4([198, 18, 0, 1], Some([255, 255, 0, 0]))]),
            iface("wan0", vec![v4([203, 0, 113, 2], Some([255, 255, 255, 0]))]),
            iface(
                "lan0",
                vec![
                    v4([127, 0, 0, 2], Some([255, 0, 0, 0])),
                    v4([169, 254, 1, 2], Some([255, 255, 0, 0])),
                    v4([192, 168, 1, 1], Some([255, 255, 255, 0])),
                    v4([192, 168, 0, 1], Some([255, 255, 255, 0])),
                    v6("fe80::1".parse().unwrap(), Some("ffff:ffff:ffff:ffff::".parse().unwrap())),
                    v6("fd00:23::1".parse().unwrap(), Some("ffff:ffff:ffff:ffff::".parse().unwrap())),
                ],
            ),
            iface(
                "wg0",
                vec![
                    v4([10, 8, 0, 1], Some([0, 0, 0, 0])),
                    v6("fd00:99::1".parse().unwrap(), Some(Ipv6Addr::UNSPECIFIED)),
                ],
            ),
        ];

        let cfg = TunConfig {
            exclude_interface: vec!["wan0".into()],
            ..Default::default()
        };
        let result = prefixes_from(interfaces.clone(), &cfg, "tun0").unwrap();
        assert_eq!(
            result,
            vec![
                "10.8.0.1/32".parse::<IpNet>().unwrap(),
                "192.168.0.0/23".parse().unwrap(),
                "fd00:23::/64".parse().unwrap(),
                "fd00:99::1/128".parse().unwrap(),
            ]
        );

        let included = TunConfig {
            include_interface: vec!["lan0".into()],
            ..Default::default()
        };
        assert_eq!(
            prefixes_from(interfaces, &included, "tun0").unwrap(),
            vec![
                "192.168.0.0/23".parse::<IpNet>().unwrap(),
                "fd00:23::/64".parse().unwrap(),
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires an isolated network namespace"]
    async fn source_monitor_notifies_on_interface_address_change() {
        use std::{process::Command, time::Duration};
        use tokio::time::timeout;

        let mut monitor = SourceMonitor::new().unwrap();
        // Drain the initial sync signal emitted on startup.
        assert!(timeout(Duration::from_secs(1), monitor.changed()).await.unwrap());

        let status = Command::new("ip")
            .args(["link", "add", "dummy-src", "type", "dummy"])
            .status()
            .unwrap();
        assert!(status.success());
        let status = Command::new("ip")
            .args(["addr", "add", "10.77.0.1/24", "dev", "dummy-src"])
            .status()
            .unwrap();
        assert!(status.success());
        let status = Command::new("ip")
            .args(["link", "set", "dummy-src", "up"])
            .status()
            .unwrap();
        assert!(status.success());

        assert!(timeout(Duration::from_secs(2), monitor.changed()).await.unwrap());
        let updated = prefixes(&TunConfig::default(), "tun0").unwrap();
        assert!(updated.contains(&"10.77.0.0/24".parse().unwrap()));
    }
}
