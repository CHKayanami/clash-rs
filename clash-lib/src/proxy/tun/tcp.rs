use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, sync::Arc, time::Duration};

use tokio::{net::TcpListener, task::JoinSet};
use futures::{StreamExt, future::pending};
use tracing::{debug, error, trace};
use clash_netstack::TcpListener as NetstackTcpListener;
use super::{stream::{TcpContext, handle_inbound_stream, handle_inbound_netstack_stream},
    system_stack::SystemTcpNat};

use crate::{Error, config::internal::config::TunConfig};

pub(super) struct BoundListener<A> {
    pub listener: TcpListener,
    pub nat: (A, A, u16),
}

impl<A: Copy + Into<IpAddr>> BoundListener<A> {
    async fn bind(server: A, client: A) -> Result<Self, Error> {
        let address = SocketAddr::new(server.into(), 0);
        let listener = TcpListener::bind(address).await.map_err(|error| {
            Error::Operation(format!("bind TUN system TCP listener on {address}: {error}"))
        })?;
        let port = listener.local_addr()?.port();
        Ok(Self { listener, nat: (server, client, port) })
    }
}

pub(super) struct TcpListeners {
    pub system: bool,
    pub ipv4: Option<BoundListener<Ipv4Addr>>,
    pub ipv6: Option<BoundListener<Ipv6Addr>>,
}

impl TcpListeners {
    pub async fn bind(cfg: &TunConfig) -> Result<Self, Error> {
        let stack = cfg.stack.as_deref().unwrap_or("system");
        let system = if ["system", "mixed"].iter().any(|mode| stack.eq_ignore_ascii_case(mode)) {
            true
        } else if ["smoltcp", "gvisor"].iter().any(|mode| stack.eq_ignore_ascii_case(mode)) {
            false
        } else {
            return Err(Error::InvalidConfig(format!("unknown TUN stack: {stack}")));
        };
        let mut result = Self { system, ipv4: None, ipv6: None };
        if !system || !cfg.enable_tcp { return Ok(result); }
        let server = cfg.gateway.addr();
        let client = u32::from(server).checked_add(1).map(Ipv4Addr::from)
            .ok_or_else(|| Error::InvalidConfig("TUN IPv4 NAT address overflow".to_owned()))?;
        result.ipv4 = Some(BoundListener::bind(server, client).await?);
        if let Some(network) = cfg.gateway_v6 {
            let server = network.addr();
            let client = u128::from(server).checked_add(1).map(Ipv6Addr::from)
                .ok_or_else(|| Error::InvalidConfig("TUN IPv6 NAT address overflow".to_owned()))?;
            result.ipv6 = Some(BoundListener::bind(server, client).await?);
        }
        Ok(result)
    }
    pub(super) async fn run(self, incoming: Option<NetstackTcpListener>,
        nat: Arc<SystemTcpNat>, context: Arc<TcpContext>, enabled: bool) -> Result<(), Error> {
        if !enabled { return pending().await; }
        let mut tasks = JoinSet::new();
        if self.system {
            for listener in [self.ipv4.map(|bound| bound.listener),
                self.ipv6.map(|bound| bound.listener)].into_iter().flatten() {
                tasks.spawn(run_system_listener(listener, nat.clone(), context.clone()));
            }
            let mut cleanup = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = cleanup.tick() => nat.cleanup_timeout(Duration::from_secs(300)),
                    result = tasks.join_next() => return Err(Error::Operation(format!(
                        "system TCP listener stopped unexpectedly: {result:?}"
                    ))),
                }
            }
        } else {
            let mut incoming = incoming.ok_or_else(|| Error::Operation(
                "TUN TCP netstack listener missing".to_owned()
            ))?;
            loop {
                tokio::select! {
                    stream = incoming.next() => match stream {
                        Some(stream) => {
                            tasks.spawn(handle_inbound_netstack_stream(stream, context.clone()));
                        }
                        None => return Err(Error::Operation("TUN TCP listener closed".to_owned())),
                    },
                    Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                        if let Err(error) = result { error!("TUN TCP relay task failed: {error}"); }
                    }
                }
            }
        }
    }
}

/// Owns accepted connection tasks so cancellation releases their streams.
pub(super) async fn run_system_listener(
    tcp_listener: TcpListener, nat: Arc<SystemTcpNat>, context: Arc<TcpContext>,
) {
    // The listener owns its connection tasks; cancellation drops the set and
    // aborts all relays instead of retaining an old runtime generation.
    let mut connections = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            accepted = tcp_listener.accept() => accepted,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result { error!("system TCP relay task failed: {error}"); }
                continue;
            }
        };
        match accepted {
            Ok((stream, peer_addr)) => {
                let nat_port = peer_addr.port();
                let Some((source, destination)) = nat.lookup_back(nat_port) else {
                    debug!("system stack: unknown incoming TCP connection from {peer_addr}");
                    continue;
                };

                trace!("system stack: accepted connection {source} -> {destination}");

                let context = context.clone();
                connections.spawn(async move {
                    handle_inbound_stream(stream, source, destination, context).await;
                });
            }
            Err(e) => {
                error!("system stack: TCP listener accept error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn listener_failures_are_returned_during_initialization() {
        let cfg = TunConfig { gateway: "255.255.255.255/32".parse().unwrap(),
            ..Default::default() };
        assert!(TcpListeners::bind(&cfg).await.err().unwrap().to_string().contains("overflow"));
        let cfg = TunConfig { stack: Some("typo".to_owned()), ..Default::default() };
        assert!(TcpListeners::bind(&cfg).await.is_err());
    }

    #[tokio::test]
    async fn disabled_tcp_never_opens_a_system_listener() {
        let cfg = TunConfig { enable_tcp: false, ..Default::default() };
        let listeners = TcpListeners::bind(&cfg).await.unwrap();
        assert!(listeners.ipv4.is_none());
        assert!(listeners.ipv6.is_none());
    }
}
