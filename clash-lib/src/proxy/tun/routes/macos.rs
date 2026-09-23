use parking_lot::Mutex;
use std::{collections::HashSet, net::Ipv4Addr, sync::LazyLock};

use ipnet::IpNet;
use tracing::warn;

use crate::{
    app::net::{OutboundInterface, get_outbound_interface},
    common::errors::new_io_error,
    config::internal::config::TunConfig,
};

static CREATED_ROUTES: LazyLock<Mutex<HashSet<(String, IpNet)>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
struct DefaultScopeRoute {
    iface_name: String,
    is_ipv6: bool,
    gateway: String,
}

static CREATED_DEFAULT_SCOPE_ROUTES: LazyLock<Mutex<HashSet<DefaultScopeRoute>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

fn is_output_already_exists(output: &std::process::Output) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    stderr.contains("File exists") || stdout.contains("File exists")
}

fn get_route_interface(dest: &IpNet) -> Option<String> {
    let mut cmd = std::process::Command::new("route");
    cmd.arg("-n").arg("get");
    match dest {
        IpNet::V4(_) => {
            cmd.arg("-inet").arg(dest.addr().to_string());
        }
        IpNet::V6(_) => {
            cmd.arg("-inet6").arg(dest.addr().to_string());
        }
    }
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("interface:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// let's assume that the `route` command is available on macOS
pub fn add_route(via: &OutboundInterface, dest: &IpNet) -> std::io::Result<()> {
    let mut cmd = std::process::Command::new("route");
    cmd.arg("add");

    match dest {
        IpNet::V4(_) => {
            cmd.arg("-net")
                .arg(dest.to_string())
                .arg("-interface")
                .arg(&via.name);
            warn!("executing: route add -net {} -interface {}", dest, via.name);
        }
        IpNet::V6(_) => {
            cmd.arg("-inet6")
                .arg(dest.to_string())
                .arg("-interface")
                .arg(&via.name);
            warn!(
                "executing: route add -inet6 {} -interface {}",
                dest, via.name
            );
        }
    }

    let output = cmd.output()?;

    if !output.status.success() {
        if is_output_already_exists(&output) {
            if let Some(actual_iface) = get_route_interface(dest) {
                if actual_iface == via.name {
                    warn!(
                        "route to destination {} via {} already exists, maintaining",
                        dest, via.name
                    );
                    // Route already existed prior to clash; do not record in CREATED_ROUTES
                    return Ok(());
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "route to destination {} already exists on interface {}, expected {}",
                            dest, actual_iface, via.name
                        ),
                    ));
                }
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "route to destination {} already exists but interface could not be determined",
                        dest
                    ),
                ));
            }
        } else {
            return Err(new_io_error("add route failed"));
        }
    }

    // Only record routes newly created by clash for cleanup
    CREATED_ROUTES.lock().insert((via.name.clone(), *dest));
    Ok(())
}

pub fn delete_route(via: &OutboundInterface, dest: &IpNet) -> std::io::Result<()> {
    let mut cmd = std::process::Command::new("route");
    cmd.arg("delete");

    match dest {
        IpNet::V4(_) => {
            cmd.arg("-net")
                .arg(dest.to_string())
                .arg("-interface")
                .arg(&via.name);
            warn!("executing: route delete -net {} -interface {}", dest, via.name);
        }
        IpNet::V6(_) => {
            cmd.arg("-inet6")
                .arg(dest.to_string())
                .arg("-interface")
                .arg(&via.name);
            warn!(
                "executing: route delete -inet6 {} -interface {}",
                dest, via.name
            );
        }
    }

    let output = cmd.output()?;

    CREATED_ROUTES.lock().remove(&(via.name.clone(), *dest));

    if !output.status.success() {
        Err(new_io_error("delete route failed"))
    } else {
        Ok(())
    }
}

fn get_default_gateway()
-> std::io::Result<(Option<Ipv4Addr>, Option<std::net::Ipv6Addr>)> {
    // IPv4
    let cmd_v4 = std::process::Command::new("route")
        .arg("-n")
        .arg("get")
        .arg("-inet")
        .arg("default")
        .output()?;

    let mut gateway_v4 = None;
    if cmd_v4.status.success() {
        let output = String::from_utf8_lossy(&cmd_v4.stdout);
        for line in output.lines() {
            if line.trim().contains("gateway:") {
                gateway_v4 = line
                    .split_whitespace()
                    .last()
                    .and_then(|x| x.parse::<Ipv4Addr>().ok());
                break;
            }
        }
    }

    // IPv6
    let cmd_v6 = std::process::Command::new("route")
        .arg("-n")
        .arg("get")
        .arg("-inet6")
        .arg("default")
        .output()?;

    let mut gateway_v6 = None;
    if cmd_v6.status.success() {
        let output = String::from_utf8_lossy(&cmd_v6.stdout);
        for line in output.lines() {
            if line.trim().contains("gateway:") {
                gateway_v6 = line
                    .split_whitespace()
                    .last()
                    .and_then(|x| x.parse::<std::net::Ipv6Addr>().ok());
                break;
            }
        }
    }

    Ok((gateway_v4, gateway_v6))
}

/// it seems to be fine to add the default route multiple times
pub fn maybe_add_default_route() -> std::io::Result<()> {
    let (gateway_v4, gateway_v6) = get_default_gateway()?;
    let default_interface =
        get_outbound_interface().ok_or(new_io_error("get default interface"))?;

    // Add IPv4 default route if gateway found
    if let Some(gateway) = gateway_v4 {
        let cmd = std::process::Command::new("route")
            .arg("add")
            .arg("-ifscope")
            .arg(&default_interface.name)
            .arg("0/0")
            .arg(gateway.to_string())
            .output()?;

        warn!(
            "executing: route add -ifscope {} 0/0 {}",
            default_interface.name, gateway
        );

        if cmd.status.success() {
            CREATED_DEFAULT_SCOPE_ROUTES.lock().insert(DefaultScopeRoute {
                iface_name: default_interface.name.clone(),
                is_ipv6: false,
                gateway: gateway.to_string(),
            });
        } else if is_output_already_exists(&cmd) {
            warn!(
                "default route 0/0 on {} already exists, keeping existing route",
                default_interface.name
            );
        } else {
            return Err(new_io_error("add default route failed"));
        }
    }

    if let Some(gateway) = gateway_v6 {
        let cmd = std::process::Command::new("route")
            .arg("add")
            .arg("-inet6")
            .arg("-ifscope")
            .arg(&default_interface.name)
            .arg("::/0")
            .arg(gateway.to_string())
            .output()?;

        warn!(
            "executing: route add -inet6 -ifscope {} ::/0 {}",
            default_interface.name, gateway
        );

        if cmd.status.success() {
            CREATED_DEFAULT_SCOPE_ROUTES.lock().insert(DefaultScopeRoute {
                iface_name: default_interface.name.clone(),
                is_ipv6: true,
                gateway: gateway.to_string(),
            });
        } else if is_output_already_exists(&cmd) {
            warn!(
                "default IPv6 route ::/0 on {} already exists, keeping existing route",
                default_interface.name
            );
        } else {
            return Err(new_io_error("add default IPv6 route failed"));
        }
    }

    Ok(())
}

/// failing to delete the default route won't cause route failure
pub fn maybe_routes_clean_up(cfg: &TunConfig) -> std::io::Result<()> {
    if !cfg.route_all && cfg.routes.is_empty() && cfg.route_exclude_address.is_empty() {
        return Ok(());
    }

    let routes_to_delete = std::mem::take(&mut *CREATED_ROUTES.lock());

    for (iface_name, r) in routes_to_delete {
        warn!("cleaning up clash-created route {} on {}", r, iface_name);
        let iface = OutboundInterface {
            name: iface_name,
            ..Default::default()
        };
        let _ = delete_route(&iface, &r);
    }

    if !cfg.route_all {
        return Ok(());
    }

    let mut result = Ok(());

    let default_scope_routes_to_delete =
        std::mem::take(&mut *CREATED_DEFAULT_SCOPE_ROUTES.lock());

    for route in default_scope_routes_to_delete {
        warn!(
            "cleaning up clash-created default route on {} (is_ipv6: {}, gateway: {})",
            route.iface_name, route.is_ipv6, route.gateway
        );

        let mut cmd = std::process::Command::new("route");
        cmd.arg("delete");
        if route.is_ipv6 {
            cmd.arg("-inet6");
        }
        cmd.arg("-ifscope")
            .arg(&route.iface_name)
            .arg(if route.is_ipv6 { "::/0" } else { "0/0" })
            .arg(&route.gateway);

        let output = cmd.output()?;
        if !output.status.success() {
            result = Err(new_io_error(format!(
                "delete default {} route failed",
                if route.is_ipv6 { "IPv6" } else { "IPv4" }
            )));
        }
    }

    result
}
