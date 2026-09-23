use arc_swap::ArcSwapOption;
use network_interface::{
    NetworkInterface, NetworkInterfaceConfig, V4IfAddr, V6IfAddr,
};
use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize};
use tracing::{trace, warn};

use std::sync::Mutex;

static DEFAULT_OUTBOUND_INTERFACE: ArcSwapOption<OutboundInterface> =
    ArcSwapOption::const_empty();

/// Protects write operations (init_net_config vs auto_detect) from lost updates and race conditions.
static WRITE_MUTEX: Mutex<WriteState> = Mutex::new(WriteState {
    is_explicit: false,
});

struct WriteState {
    is_explicit: bool,
}

static TUN_SOMARK_RAW: AtomicU64 = AtomicU64::new(0);
const SOMARK_VALID_MASK: u64 = 1 << 32;

pub fn get_tun_somark() -> Option<u32> {
    let raw = TUN_SOMARK_RAW.load(Ordering::Relaxed);
    if (raw & SOMARK_VALID_MASK) != 0 {
        Some(raw as u32)
    } else {
        None
    }
}

pub fn set_tun_somark(mark: Option<u32>) {
    let raw = match mark {
        Some(m) => (m as u64) | SOMARK_VALID_MASK,
        None => 0,
    };
    TUN_SOMARK_RAW.store(raw, Ordering::Relaxed);
}

pub fn get_default_outbound_interface() -> Option<Arc<OutboundInterface>> {
    DEFAULT_OUTBOUND_INTERFACE.load_full()
}

pub fn get_default_outbound_interface_cloned() -> Option<OutboundInterface> {
    DEFAULT_OUTBOUND_INTERFACE.load().as_deref().cloned()
}


/// Atomically compare and update the default outbound interface if it has changed.
/// Returns true if updated, false if unchanged or if an explicit interface is configured.
pub fn update_default_outbound_interface_if_changed(
    new_iface: OutboundInterface,
) -> bool {
    let state = WRITE_MUTEX.lock().unwrap();
    if state.is_explicit {
        return false;
    }

    let current = DEFAULT_OUTBOUND_INTERFACE.load();
    let changed = match current.as_deref() {
        Some(old) => old.name != new_iface.name || old.index != new_iface.index,
        None => true,
    };

    if changed {
        DEFAULT_OUTBOUND_INTERFACE.store(Some(Arc::new(new_iface)));
        true
    } else {
        false
    }
}

/// Initialize network configuration
/// globally manage default outbound interface
/// This function should be called as early as possible
/// so that other config initialization can use the default outbound interface
pub async fn init_net_config(explicit_iface: Option<&str>, tun_somark: Option<u32>) {
    let explicit_matched = explicit_iface.and_then(get_interface_by_name);
    if explicit_iface.is_some() && explicit_matched.is_none() {
        warn!(
            "configured explicit interface {:?} not found, falling back to auto-detected outbound interface",
            explicit_iface
        );
    }
    let is_explicit = explicit_matched.is_some();
    let iface = explicit_matched.or_else(get_outbound_interface);

    {
        let mut state = WRITE_MUTEX.lock().unwrap();
        state.is_explicit = is_explicit;
        DEFAULT_OUTBOUND_INTERFACE.store(iface.map(Arc::new));
    }
    set_tun_somark(tun_somark);

    trace!(
        "default outbound interface: {:?}, tun somark: {:?}",
        get_default_outbound_interface(),
        get_tun_somark()
    );
}

/// Represents a parsed outbound interface for use in runtime.
#[derive(Serialize, Debug, Clone, Default)]
pub struct OutboundInterface {
    pub name: String,
    pub addr_v4: Option<Ipv4Addr>,
    pub netmask_v4: Option<Ipv4Addr>,
    pub broadcast_v4: Option<Ipv4Addr>,
    pub addr_v6: Option<Ipv6Addr>,
    pub netmask_v6: Option<Ipv6Addr>,
    pub broadcast_v6: Option<Ipv6Addr>,
    pub index: u32,
    pub mac_addr: Option<String>,
}

impl From<NetworkInterface> for OutboundInterface {
    fn from(iface: NetworkInterface) -> Self {
        fn get_outbound_ip_from_interface(
            iface: &NetworkInterface,
        ) -> (Option<V4IfAddr>, Option<V6IfAddr>) {
            let mut v4 = None;
            let mut v6 = None;

            for addr in iface.addr.iter() {
                trace!("inspect interface address: {:?} on {}", addr, iface.name);

                if v4.is_some() && v6.is_some() {
                    break;
                }

                match addr {
                    network_interface::Addr::V4(addr) => {
                        if !addr.ip.is_loopback() && v4.is_none() {
                            v4 = Some(*addr);
                        }
                    }
                    network_interface::Addr::V6(addr) => {
                        if !addr.ip.is_loopback() && v6.is_none() {
                            v6 = Some(*addr);
                        }
                    }
                }
            }

            (v4, v6)
        }

        let (v4, v6) = get_outbound_ip_from_interface(&iface);

        Self {
            name: iface.name,
            addr_v4: v4.map(|x| x.ip),
            netmask_v4: v4.and_then(|x| x.netmask),
            broadcast_v4: v4.and_then(|x| x.broadcast),
            addr_v6: v6.map(|x| x.ip),
            netmask_v6: v6.and_then(|x| x.netmask),
            broadcast_v6: v6.and_then(|x| x.broadcast),
            index: iface.index,
            mac_addr: iface.mac_addr,
        }
    }
}
impl std::fmt::Display for OutboundInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (v4: {}, v6: {}, index: {}, mac: {})",
            self.name,
            self.addr_v4
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "None".to_string()),
            self.addr_v6
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "None".to_string()),
            self.index,
            self.mac_addr.clone().unwrap_or_else(|| "None".to_string())
        )
    }
}

pub fn get_interface_by_name(name: &str) -> Option<OutboundInterface> {
    let now = std::time::Instant::now();

    let outbound = network_interface::NetworkInterface::show()
        .ok()?
        .into_iter()
        .find(|iface| iface.name == name)?
        .into();

    trace!(
        "found interface by name: {:?}, took: {}ms",
        outbound,
        now.elapsed().as_millis()
    );

    Some(outbound)
}

pub fn get_outbound_interface() -> Option<OutboundInterface> {
    let now = std::time::Instant::now();

    let mut all_outbounds = network_interface::NetworkInterface::show()
        .ok()?
        .into_iter()
        .map(Into::into)
        .filter(|iface: &OutboundInterface| {
            !iface.name.contains("tun")
                && !iface.name.starts_with("br-")
                && !iface.name.starts_with("docker")
                && !iface.name.starts_with("veth")
                && !iface.name.starts_with("dummy")
                && !iface.name.contains("dummy")
                && !iface.name.starts_with("lo")
                && !iface.name.ends_with("-lan")
                && !iface.name.starts_with("lan")
                && (iface.addr_v4.is_some() || iface.addr_v6.is_some())
        })
        .collect::<Vec<_>>();

    let priority: &[&str] = if cfg!(target_os = "android") {
        &[
            "wlan",  // Android Wi-Fi interface
            "rmnet", // Android mobile data interface
        ]
    } else if cfg!(target_os = "windows") {
        &["Ethernet", "Wi-Fi", "Tailscale"]
    } else if cfg!(target_os = "linux") {
        &["pppoe", "wan", "ppp", "eth", "wlp", "en", "Tailscale"]
    } else if cfg!(target_os = "macos") {
        &["en", "pdp_ip", "Tailscale"]
    } else {
        &["pppoe", "wan", "ppp", "eth", "en", "wlp"]
    };

    all_outbounds.sort_by(|left, right| {
        let left_p = priority
            .iter()
            .position(|x| left.name.contains(x))
            .unwrap_or(usize::MAX);
        let right_p = priority
            .iter()
            .position(|x| right.name.contains(x))
            .unwrap_or(usize::MAX);

        if left_p != right_p {
            return left_p.cmp(&right_p);
        }

        match (left.addr_v6, right.addr_v6) {
            (Some(l), Some(r)) => {
                if l.is_unicast_global() && !r.is_unicast_global() {
                    return std::cmp::Ordering::Less;
                } else if !l.is_unicast_global() && r.is_unicast_global() {
                    return std::cmp::Ordering::Greater;
                }
            }
            (Some(l), None) if l.is_unicast_global() => {
                return std::cmp::Ordering::Less;
            }
            (None, Some(r)) if r.is_unicast_global() => {
                return std::cmp::Ordering::Greater;
            }
            _ => {}
        }

        std::cmp::Ordering::Equal
    });

    trace!(
        "sorted outbound interfaces: {:?}, took: {}ms",
        all_outbounds,
        now.elapsed().as_millis()
    );

    all_outbounds.into_iter().next()
}

/// Represents a network interface in configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Interface {
    IpAddr(IpAddr),
    Name(String),
}

impl From<&str> for Interface {
    fn from(s: &str) -> Self {
        Self::Name(s.to_owned())
    }
}

impl From<IpAddr> for Interface {
    fn from(ip: IpAddr) -> Self {
        Self::IpAddr(ip)
    }
}

impl Display for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Interface::IpAddr(ip) => write!(f, "{ip}"),
            Interface::Name(name) => write!(f, "{name}"),
        }
    }
}

impl Interface {
    pub fn into_ip_addr(self) -> Option<IpAddr> {
        match self {
            Interface::IpAddr(ip) => Some(ip),
            _ => None,
        }
    }

    pub fn into_socket_addr(self) -> Option<SocketAddr> {
        match self {
            Interface::IpAddr(ip) => Some(SocketAddr::new(ip, 0)),
            _ => None,
        }
    }

    pub fn into_iface_name(self) -> Option<String> {
        match self {
            Interface::IpAddr(_) => None,
            Interface::Name(name) => Some(name),
        }
    }
}
