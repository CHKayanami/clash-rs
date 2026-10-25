use std::{collections::{BTreeMap, BTreeSet}, io, net::{IpAddr, Ipv6Addr}};

use ipnet::IpNet;
use route_manager::{Route as NativeRoute, RouteKind, RouteManager};
use tracing::warn;

use crate::{app::net::{get_explicit_outbound_interface, get_interface_by_name},
    config::internal::config::TunConfig};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Route {
    destination: IpNet,
    interface: String,
    gateway: Option<IpAddr>,
    scoped: bool,
}

impl Route {
    fn from_native(route: &NativeRoute) -> Option<Self> {
        if route.kind() != RouteKind::Unicast { return None; }
        let interface = route.if_name()?.clone();
        Some(Self { destination: IpNet::new(route.destination(), route.prefix()).ok()?.trunc(),
            interface, gateway: route.gateway(), scoped: route.if_scope() })
    }

    fn native(&self, index: u32) -> io::Result<NativeRoute> {
        let mut route = NativeRoute::new(self.destination.network(), self.destination.prefix_len())
            .with_if_index(index).with_if_scope(self.scoped);
        if let Some(ip) = self.gateway {
            // Darwin's routing ABI embeds a link-local scope in address bytes
            // 2..4. RouteManager normalizes it when reading; restore it on write.
            let ip = match ip {
                IpAddr::V6(ip) if ip.is_unicast_link_local() => {
                    let index = u16::try_from(index)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                    let mut bytes = ip.octets();
                    bytes[2..4].copy_from_slice(&index.to_be_bytes());
                    IpAddr::V6(Ipv6Addr::from(bytes))
                }
                ip => ip,
            };
            route = route.with_gateway(ip);
        }
        Ok(route)
    }
}

/// Static capture prefixes are built once, not on every network notification.
pub(super) struct Plan {
    routes: BTreeSet<Route>,
    defaults: BTreeSet<Route>,
    route_all: bool,
    name: String,
}

impl Plan {
    pub(super) fn new(cfg: &TunConfig, name: &str) -> Self {
        let networks = if cfg.route_all {
            let mut networks = vec!["0.0.0.0/1".parse().unwrap(), "128.0.0.0/1".parse().unwrap()];
            if cfg.gateway_v6.is_some() {
                networks.extend(["::/1".parse::<IpNet>().unwrap(), "8000::/1".parse::<IpNet>().unwrap()]);
            }
            networks
        } else { cfg.routes.clone() };
        let mut capture: BTreeSet<_> = exclude_networks(networks, &cfg.route_exclude_address)
            .into_iter().flat_map(|net| net.subnets(net.prefix_len().max(1)).unwrap())
            .map(|destination| Route { destination, interface: name.to_owned(),
                gateway: None, scoped: false }).collect();
        if let Some(server) = super::dns::server(cfg) {
            capture.insert(Route { destination: IpNet::new(IpAddr::V4(server), 32).unwrap(),
                interface: name.to_owned(), gateway: None, scoped: false });
        }
        Self { routes: capture, defaults: BTreeSet::new(), route_all: cfg.route_all, name: name.to_owned() }
    }

    fn desired(&mut self, snapshot: &BTreeSet<Route>) -> &BTreeSet<Route> {
        if !self.route_all { return &self.routes; }
        let mut defaults = BTreeSet::new();
        let explicit = get_explicit_outbound_interface();
        for ipv6 in [false, true] {
            let default = snapshot.iter().filter(|route| {
                route.destination.prefix_len() == 0
                    && route.destination.addr().is_ipv6() == ipv6
                    && route.interface != self.name
                    && match &explicit {
                        Some(interface) => route.interface == interface.name,
                        None => !route.scoped,
                    }
            }).min_by_key(|route| route.scoped);
            if let Some(route) = default {
                let mut route = route.clone();
                route.scoped = true;
                defaults.insert(route);
            }
        }
        if defaults != self.defaults {
            for route in &self.defaults { self.routes.remove(route); }
            for route in &defaults { self.routes.insert(route.clone()); }
            self.defaults = defaults;
        }
        &self.routes
    }
}

/// Leave exclusions to the original LAN/VPN routes. Aggregate exclusions first
/// to avoid repeatedly splitting overlapping prefixes.
fn exclude_networks(mut networks: Vec<IpNet>, excludes: &[IpNet]) -> Vec<IpNet> {
    for exclude in IpNet::aggregate(&excludes.to_vec()) {
        let mut pending = networks;
        networks = Vec::new();
        while let Some(network) = pending.pop() {
            if exclude.contains(&network) { continue; }
            if network.contains(&exclude) {
                pending.extend(network.subnets(network.prefix_len() + 1).unwrap());
            } else { networks.push(network.trunc()); }
        }
    }
    IpNet::aggregate(&networks)
}

pub(super) trait Backend {
    fn refresh(&mut self) -> io::Result<()>;
    fn contains(&self, route: &Route) -> bool;
    /// Returns false for an exact pre-existing route.
    fn add(&mut self, route: &Route) -> io::Result<bool>;
    fn delete(&mut self, route: &Route) -> io::Result<()>;
}

pub(super) struct SystemRoutes {
    manager: RouteManager,
    snapshot: BTreeSet<Route>,
    interfaces: BTreeMap<String, u32>,
}

impl SystemRoutes {
    pub(super) fn new() -> io::Result<Self> {
        Ok(Self { manager: RouteManager::new()?, snapshot: BTreeSet::new(),
            interfaces: BTreeMap::new() })
    }
}

impl Backend for SystemRoutes {
    fn refresh(&mut self) -> io::Result<()> {
        let routes = self.manager.list()?;
        self.interfaces = routes.iter().filter_map(|route| {
            Some((route.if_name()?.clone(), route.if_index()?))
        }).collect();
        self.snapshot = routes.iter().filter_map(Route::from_native).collect();
        Ok(())
    }

    fn contains(&self, route: &Route) -> bool { self.snapshot.contains(route) }

    fn add(&mut self, route: &Route) -> io::Result<bool> {
        if self.contains(route) { return Ok(false); }
        let index = self.interfaces.get(&route.interface).copied()
            .or_else(|| get_interface_by_name(&route.interface).map(|iface| iface.index))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "route interface disappeared"))?;
        self.interfaces.insert(route.interface.clone(), index);
        let native = route.native(index)?;
        match self.manager.add(&native) {
            Ok(()) => { self.snapshot.insert(route.clone()); Ok(true) }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                // Resolve a concurrent system update without stealing ownership.
                self.refresh()?;
                if self.contains(route) { Ok(false) } else { Err(error) }
            }
            Err(error) => Err(error),
        }
    }

    fn delete(&mut self, route: &Route) -> io::Result<()> {
        if !self.contains(route) { return Ok(()); }
        let index = self.interfaces.get(&route.interface).copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "route interface disappeared"))?;
        let native = route.native(index)?;
        match self.manager.delete(&native) {
            Ok(()) => { self.snapshot.remove(route); Ok(()) }
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                self.snapshot.remove(route); Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

/// Ownership is local to a runner. Membership checks and diffs are O(log n).
pub(super) struct Routes<B: Backend> {
    backend: B,
    active: BTreeMap<Route, bool>,
}

impl Routes<SystemRoutes> {
    pub(super) fn reconcile(&mut self, plan: &mut Plan) -> io::Result<()> {
        self.backend.refresh()?;
        let desired = plan.desired(&self.backend.snapshot);
        self.update_snapshot(desired)
    }
}

impl<B: Backend> Routes<B> {
    pub(super) fn new(backend: B) -> Self {
        Self { backend, active: BTreeMap::new() }
    }

    #[cfg(test)]
    pub(super) fn update(&mut self, desired: impl IntoIterator<Item = Route>) -> io::Result<()> {
        self.backend.refresh()?;
        self.update_snapshot(&desired.into_iter().collect())
    }

    fn update_snapshot(&mut self, desired: &BTreeSet<Route>) -> io::Result<()> {
        // Kernel state, rather than a cached desired list, decides whether a
        // route needs repairing after sleep, link changes or external deletion.
        self.active.retain(|route, _| self.backend.contains(route));
        if self.active.len() == desired.len() && self.active.keys().eq(desired.iter()) {
            return Ok(());
        }
        // A rollback snapshot is needed only when the actual route set changes.
        let previous: BTreeSet<_> = self.active.keys().cloned().collect();
        let result = self.apply(desired).and_then(|()| {
            self.backend.refresh()?;
            if desired.iter().all(|route| self.backend.contains(route)) { Ok(()) }
            else { Err(io::Error::other("kernel did not install the requested TUN routes")) }
        });
        if let Err(error) = result {
            if let Err(rollback) = self.apply(&previous) {
                warn!("failed to roll back macOS TUN routes: {rollback}");
            }
            return Err(error);
        }
        Ok(())
    }

    fn apply(&mut self, desired: &BTreeSet<Route>) -> io::Result<()> {
        let stale: Vec<_> = self.active.keys().filter(|route| !desired.contains(*route)).cloned().collect();
        for route in stale {
            if self.active[&route] { self.backend.delete(&route)?; }
            self.active.remove(&route);
        }
        for route in desired {
            if !self.active.contains_key(route) {
                let owned = self.backend.add(route)?;
                self.active.insert(route.clone(), owned);
            }
        }
        Ok(())
    }
}

impl<B: Backend> Drop for Routes<B> {
    fn drop(&mut self) {
        // Re-read the kernel so cleanup cannot remove a service's replacement.
        if let Err(error) = self.backend.refresh() {
            warn!("cannot verify macOS TUN routes before cleanup: {error}");
            return;
        }
        for (route, owned) in self.active.iter().rev() {
            if *owned {
                if let Err(error) = self.backend.delete(route) {
                    warn!("failed to clean up macOS TUN route {route:?}: {error}");
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "routes_tests.rs"]
mod tests;
