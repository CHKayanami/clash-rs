use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};

use futures::stream::TryStreamExt;
use ipnet::IpNet;
use netlink_packet_route::{
    AddressFamily,
    route::{RouteAddress, RouteAttribute},
    rule::{RuleAction, RuleAttribute, RuleFlags, RulePortRange},
};
use rtnetlink::{IpVersion, RouteMessageBuilder, new_connection};
use tracing::warn;
use url::Url;

use crate::{
    app::net::OutboundInterface, common::errors::new_io_error,
    config::internal::config::TunConfig,
};

static LAST_TUN_IFINDEX: AtomicU32 = AtomicU32::new(0);

const FIB_RULE_INVERT: RuleFlags = RuleFlags::from_bits_retain(0x02);
pub const DEFAULT_IPROUTE2_RULE_INDEX: u32 = 9000;
pub const DEFAULT_SO_MARK: u32 = 0x162;

async fn get_rtnetlink_handle() -> std::io::Result<rtnetlink::Handle> {
    let (conn, handle, _) = new_connection().map_err(new_io_error)?;
    tokio::spawn(conn);
    Ok(handle)
}

fn run_netlink_async<F, T>(fut: F) -> std::io::Result<T>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(fut)),
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(fut)
        }
    }
}

fn ignore_already_exists<T>(res: Result<T, rtnetlink::Error>) -> std::io::Result<()> {
    match res {
        Ok(_) => Ok(()),
        Err(rtnetlink::Error::NetlinkError(err_msg))
            if err_msg.code.map(|c| c.get().abs()) == Some(17) =>
        {
            // -EEXIST (17): File exists, rule already present in kernel
            Ok(())
        }
        Err(e) => Err(new_io_error(e)),
    }
}

async fn verify_existing_route_interface(
    handle: &rtnetlink::Handle,
    expected_ifindex: u32,
    dest: &IpNet,
    target_table_id: u32,
) -> std::io::Result<()> {
    let req = match dest {
        IpNet::V4(_) => {
            let route = RouteMessageBuilder::<Ipv4Addr>::new().build();
            handle.route().get(route)
        }
        IpNet::V6(_) => {
            let route = RouteMessageBuilder::<Ipv6Addr>::new().build();
            handle.route().get(route)
        }
    };
    let mut stream = req.execute();
    while let Some(msg) = stream.try_next().await.map_err(new_io_error)? {
        let mut table = None;
        let mut dest_matched = false;
        let mut oif = None;
        for attr in &msg.attributes {
            match attr {
                RouteAttribute::Table(t) => {
                    table = Some(*t);
                }
                RouteAttribute::Destination(addr) => match (dest, addr) {
                    (IpNet::V4(v4), RouteAddress::Inet(a))
                        if *a == v4.addr()
                            && msg.header.destination_prefix_length == v4.prefix_len() =>
                    {
                        dest_matched = true;
                    }
                    (IpNet::V6(v6), RouteAddress::Inet6(a))
                        if *a == v6.addr()
                            && msg.header.destination_prefix_length == v6.prefix_len() =>
                    {
                        dest_matched = true;
                    }
                    _ => {}
                },
                RouteAttribute::Oif(index) => {
                    oif = Some(*index);
                }
                _ => {}
            }
        }
        let route_table = table.unwrap_or(msg.header.table as u32);
        if route_table != target_table_id {
            continue;
        }

        if dest.prefix_len() == 0 && msg.header.destination_prefix_length == 0 {
            dest_matched = true;
        }
        if dest_matched {
            if let Some(actual_ifindex) = oif {
                if actual_ifindex == expected_ifindex {
                    warn!(
                        "route for {} in table {} already exists on expected interface index {}, maintaining",
                        dest, target_table_id, expected_ifindex
                    );
                    return Ok(());
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "route for {} in table {} already exists on interface index {}, expected {}",
                            dest, target_table_id, actual_ifindex, expected_ifindex
                        ),
                    ));
                }
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "route for {} in table {} already exists but matching interface could not be verified",
            dest, target_table_id
        ),
    ))
}

async fn verify_table_default_route_interface(
    handle: &rtnetlink::Handle,
    table_id: u32,
    expected_ifindex: u32,
    v6: bool,
) -> std::io::Result<()> {
    let req = if !v6 {
        let route = RouteMessageBuilder::<Ipv4Addr>::new().build();
        handle.route().get(route)
    } else {
        let route = RouteMessageBuilder::<Ipv6Addr>::new().build();
        handle.route().get(route)
    };
    let mut stream = req.execute();
    while let Some(msg) = stream.try_next().await.map_err(new_io_error)? {
        let mut table = None;
        let mut oif = None;
        for attr in &msg.attributes {
            match attr {
                RouteAttribute::Table(t) => table = Some(*t),
                RouteAttribute::Oif(index) => oif = Some(*index),
                _ => {}
            }
        }
        let in_table = table == Some(table_id)
            || (table.is_none() && msg.header.table as u32 == table_id);
        if in_table && msg.header.destination_prefix_length == 0 {
            if let Some(actual_ifindex) = oif {
                if actual_ifindex == expected_ifindex {
                    warn!(
                        "default route in table {} already exists on expected interface index {}, maintaining",
                        table_id, expected_ifindex
                    );
                    return Ok(());
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "default route in table {} already exists on interface index {}, expected {}",
                            table_id, actual_ifindex, expected_ifindex
                        ),
                    ));
                }
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "default route in table {} already exists but matching interface could not be verified",
            table_id
        ),
    ))
}

async fn add_route_internal(via: &OutboundInterface, dest: &IpNet) -> std::io::Result<()> {
    let handle = get_rtnetlink_handle().await?;
    match dest {
        IpNet::V4(v4) => {
            let route = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(v4.addr(), v4.prefix_len())
                .output_interface(via.index)
                .build();
            match handle.route().add(route).execute().await {
                Ok(_) => Ok(()),
                Err(rtnetlink::Error::NetlinkError(err_msg))
                    if err_msg.code.map(|c| c.get().abs()) == Some(17) =>
                {
                    verify_existing_route_interface(&handle, via.index, dest, 254).await
                }
                Err(e) => Err(new_io_error(e)),
            }
        }
        IpNet::V6(v6) => {
            let route = RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(v6.addr(), v6.prefix_len())
                .output_interface(via.index)
                .build();
            match handle.route().add(route).execute().await {
                Ok(_) => Ok(()),
                Err(rtnetlink::Error::NetlinkError(err_msg))
                    if err_msg.code.map(|c| c.get().abs()) == Some(17) =>
                {
                    verify_existing_route_interface(&handle, via.index, dest, 254).await
                }
                Err(e) => Err(new_io_error(e)),
            }
        }
    }
}

pub fn add_route(via: &OutboundInterface, dest: &IpNet) -> std::io::Result<()> {
    warn!("adding route {} dev {}", dest, via.name);
    run_netlink_async(add_route_internal(via, dest))
}

async fn add_default_route_to_table(
    handle: &rtnetlink::Handle,
    table_id: u32,
    ifindex: u32,
    v6: bool,
) -> std::io::Result<()> {
    if !v6 {
        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .output_interface(ifindex)
            .table_id(table_id)
            .build();
        match handle.route().add(route).execute().await {
            Ok(_) => Ok(()),
            Err(rtnetlink::Error::NetlinkError(err_msg))
                if err_msg.code.map(|c| c.get().abs()) == Some(17) =>
            {
                verify_table_default_route_interface(handle, table_id, ifindex, false).await
            }
            Err(e) => Err(new_io_error(e)),
        }
    } else {
        let route = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
            .output_interface(ifindex)
            .table_id(table_id)
            .build();
        match handle.route().add(route).execute().await {
            Ok(_) => Ok(()),
            Err(rtnetlink::Error::NetlinkError(err_msg))
                if err_msg.code.map(|c| c.get().abs()) == Some(17) =>
            {
                verify_table_default_route_interface(handle, table_id, ifindex, true).await
            }
            Err(e) => Err(new_io_error(e)),
        }
    }
}

async fn add_rule_not_fwmark(
    handle: &rtnetlink::Handle,
    table_id: u32,
    so_mark: u32,
    rule_index: u32,
    family: AddressFamily,
) -> std::io::Result<()> {
    match family {
        AddressFamily::Inet => {
            let mut req = handle.rule().add().v4();
            let msg = req.message_mut();
            msg.header.flags |= FIB_RULE_INVERT;
            msg.header.action = RuleAction::ToTable;
            msg.attributes.push(RuleAttribute::FwMark(so_mark));
            msg.attributes.push(RuleAttribute::Table(table_id));
            msg.attributes.push(RuleAttribute::Priority(rule_index));
            ignore_already_exists(req.execute().await)?;
        }
        AddressFamily::Inet6 => {
            let mut req = handle.rule().add().v6();
            let msg = req.message_mut();
            msg.header.flags |= FIB_RULE_INVERT;
            msg.header.action = RuleAction::ToTable;
            msg.attributes.push(RuleAttribute::FwMark(so_mark));
            msg.attributes.push(RuleAttribute::Table(table_id));
            msg.attributes.push(RuleAttribute::Priority(rule_index));
            ignore_already_exists(req.execute().await)?;
        }
        _ => {}
    }
    Ok(())
}

async fn add_rule_suppress_prefixlength_main(
    handle: &rtnetlink::Handle,
    rule_index: u32,
    family: AddressFamily,
) -> std::io::Result<()> {
    match family {
        AddressFamily::Inet => {
            let mut req = handle.rule().add().v4();
            let msg = req.message_mut();
            msg.header.action = RuleAction::ToTable;
            msg.attributes.push(RuleAttribute::Table(254));
            msg.attributes.push(RuleAttribute::SuppressPrefixLen(0));
            msg.attributes
                .push(RuleAttribute::Priority(rule_index.saturating_sub(1)));
            ignore_already_exists(req.execute().await)?;
        }
        AddressFamily::Inet6 => {
            let mut req = handle.rule().add().v6();
            let msg = req.message_mut();
            msg.header.action = RuleAction::ToTable;
            msg.attributes.push(RuleAttribute::Table(254));
            msg.attributes.push(RuleAttribute::SuppressPrefixLen(0));
            msg.attributes
                .push(RuleAttribute::Priority(rule_index.saturating_sub(1)));
            ignore_already_exists(req.execute().await)?;
        }
        _ => {}
    }
    Ok(())
}

async fn add_rule_dport(
    handle: &rtnetlink::Handle,
    table_id: u32,
    port: u16,
    rule_index: u32,
    family: AddressFamily,
) -> std::io::Result<()> {
    match family {
        AddressFamily::Inet => {
            let mut req = handle.rule().add().v4();
            let msg = req.message_mut();
            msg.header.action = RuleAction::ToTable;
            msg.attributes.push(RuleAttribute::Table(table_id));
            msg.attributes
                .push(RuleAttribute::DestinationPortRange(RulePortRange {
                    start: port,
                    end: port,
                }));
            msg.attributes
                .push(RuleAttribute::Priority(rule_index.saturating_sub(2)));
            ignore_already_exists(req.execute().await)?;
        }
        AddressFamily::Inet6 => {
            let mut req = handle.rule().add().v6();
            let msg = req.message_mut();
            msg.header.action = RuleAction::ToTable;
            msg.attributes.push(RuleAttribute::Table(table_id));
            msg.attributes
                .push(RuleAttribute::DestinationPortRange(RulePortRange {
                    start: port,
                    end: port,
                }));
            msg.attributes
                .push(RuleAttribute::Priority(rule_index.saturating_sub(2)));
            ignore_already_exists(req.execute().await)?;
        }
        _ => {}
    }
    Ok(())
}

async fn add_rule_strict_blackhole(
    handle: &rtnetlink::Handle,
    rule_index: u32,
    family: AddressFamily,
) -> std::io::Result<()> {
    match family {
        AddressFamily::Inet => {
            let mut req = handle.rule().add().v4();
            let msg = req.message_mut();
            msg.header.action = RuleAction::Blackhole;
            msg.attributes
                .push(RuleAttribute::Priority(rule_index.saturating_add(1)));
            ignore_already_exists(req.execute().await)?;
        }
        AddressFamily::Inet6 => {
            let mut req = handle.rule().add().v6();
            let msg = req.message_mut();
            msg.header.action = RuleAction::Blackhole;
            msg.attributes
                .push(RuleAttribute::Priority(rule_index.saturating_add(1)));
            ignore_already_exists(req.execute().await)?;
        }
        _ => {}
    }
    Ok(())
}

async fn setup_policy_routing_async(
    tun_cfg: &TunConfig,
    via: &OutboundInterface,
) -> std::io::Result<()> {
    LAST_TUN_IFINDEX.store(via.index, Ordering::SeqCst);
    // 0. Clean up any stale rules/routes for this TUN interface from a previous crashed run
    let _ = routes_clean_up_async(tun_cfg, Some(via.index)).await;

    let handle = get_rtnetlink_handle().await?;
    let table = tun_cfg.route_table;
    let rule_index = tun_cfg
        .iproute2_rule_index
        .unwrap_or(DEFAULT_IPROUTE2_RULE_INDEX);
    let so_mark = tun_cfg.so_mark.unwrap_or(DEFAULT_SO_MARK);
    let enable_v6 = tun_cfg.gateway_v6.is_some();

    // 1. Add default route in table
    add_default_route_to_table(&handle, table, via.index, false).await?;
    if enable_v6 {
        add_default_route_to_table(&handle, table, via.index, true).await?;
    }

    // 2. Add rule not fwmark table
    add_rule_not_fwmark(
        &handle,
        table,
        so_mark,
        rule_index,
        AddressFamily::Inet,
    )
    .await?;
    if enable_v6 {
        add_rule_not_fwmark(
            &handle,
            table,
            so_mark,
            rule_index,
            AddressFamily::Inet6,
        )
        .await?;
    }

    // 3. Add rule suppress_prefixlength 0 table main
    add_rule_suppress_prefixlength_main(&handle, rule_index, AddressFamily::Inet)
        .await?;
    if enable_v6 {
        add_rule_suppress_prefixlength_main(
            &handle,
            rule_index,
            AddressFamily::Inet6,
        )
        .await?;
    }

    // 4. Add rule dport 53 table (if dns_hijack is enabled)
    if tun_cfg.dns_hijack.is_enabled() {
        add_rule_dport(&handle, table, 53, rule_index, AddressFamily::Inet)
            .await?;
        if enable_v6 {
            add_rule_dport(&handle, table, 53, rule_index, AddressFamily::Inet6)
                .await?;
        }
    }

    // 5. Add strict route blackhole rule (if strict_route is enabled)
    if tun_cfg.strict_route {
        warn!(
            "strict_route is enabled, adding blackhole rule to prevent direct \
             route leaks"
        );
        add_rule_strict_blackhole(&handle, rule_index, AddressFamily::Inet).await?;
        if enable_v6 {
            add_rule_strict_blackhole(&handle, rule_index, AddressFamily::Inet6)
                .await?;
        }
    }

    Ok(())
}

pub fn setup_policy_routing(
    tun_cfg: &TunConfig,
    via: &OutboundInterface,
) -> std::io::Result<()> {
    warn!("setting up policy routing via netlink for {}", via.name);
    run_netlink_async(setup_policy_routing_async(tun_cfg, via))
}

async fn cleanup_rules_for_family(
    handle: &rtnetlink::Handle,
    family: IpVersion,
    table_id: u32,
    so_mark: u32,
    rule_index: u32,
    has_dns_hijack: bool,
    strict_route: bool,
) -> std::io::Result<()> {
    let mut rules_stream = handle.rule().get(family).execute();
    let mut to_delete = Vec::new();

    while let Some(msg) = rules_stream.try_next().await.map_err(new_io_error)? {
        let is_invert = msg.header.flags.contains(FIB_RULE_INVERT);
        let mut table = None;
        let mut fwmark = None;
        let mut suppress_prefixlen = None;
        let mut dport_range = None;
        let mut priority = None;

        for nla in &msg.attributes {
            match nla {
                RuleAttribute::Table(t) => table = Some(*t),
                RuleAttribute::FwMark(m) => fwmark = Some(*m),
                RuleAttribute::SuppressPrefixLen(l) => {
                    suppress_prefixlen = Some(*l)
                }
                RuleAttribute::DestinationPortRange(r) => {
                    dport_range = Some((r.start, r.end))
                }
                RuleAttribute::Priority(p) => priority = Some(*p),
                _ => {}
            }
        }

        let is_our_not_fwmark = is_invert
            && fwmark == Some(so_mark)
            && table == Some(table_id)
            && priority == Some(rule_index);

        let is_our_suppress = suppress_prefixlen == Some(0)
            && (table == Some(254) || msg.header.table == 254)
            && priority == Some(rule_index.saturating_sub(1));

        let is_our_dport = has_dns_hijack
            && dport_range == Some((53, 53))
            && table == Some(table_id)
            && priority == Some(rule_index.saturating_sub(2));

        let is_our_blackhole = strict_route
            && msg.header.action == RuleAction::Blackhole
            && priority == Some(rule_index.saturating_add(1));

        if is_our_not_fwmark || is_our_suppress || is_our_dport || is_our_blackhole {
            to_delete.push(msg);
        }
    }

    for msg in to_delete {
        if let Err(e) = handle.rule().del(msg).execute().await {
            warn!("failed to delete rule: {}", e);
        }
    }

    Ok(())
}

fn extract_tun_name(device_id: &str) -> String {
    if let Ok(u) = Url::parse(device_id) {
        if let Some(host) = u.host_str() {
            return host.to_string();
        }
    }
    device_id.to_string()
}

async fn cleanup_routes_for_table(
    handle: &rtnetlink::Handle,
    table_id: u32,
    family: IpVersion,
    expected_ifindex: Option<u32>,
) -> std::io::Result<()> {
    // If expected_ifindex is None, NEVER delete routes blindly to avoid deleting other programs' default routes
    let Some(expected_index) = expected_ifindex else {
        warn!(
            "skipping route deletion in table {}: TUN interface index unknown, preserving existing default routes",
            table_id
        );
        return Ok(());
    };

    let req = match family {
        IpVersion::V4 => {
            let route = RouteMessageBuilder::<Ipv4Addr>::new().build();
            handle.route().get(route)
        }
        IpVersion::V6 => {
            let route = RouteMessageBuilder::<Ipv6Addr>::new().build();
            handle.route().get(route)
        }
    };

    let mut routes_stream = req.execute();
    let mut to_delete = Vec::new();

    while let Some(msg) = routes_stream.try_next().await.map_err(new_io_error)? {
        let mut table = None;
        let mut oif = None;
        for nla in &msg.attributes {
            match nla {
                RouteAttribute::Table(t) => {
                    table = Some(*t);
                }
                RouteAttribute::Oif(i) => {
                    oif = Some(*i);
                }
                _ => {}
            }
        }
        let in_table = table == Some(table_id)
            || (table.is_none() && msg.header.table as u32 == table_id);
        if !in_table {
            continue;
        }

        // Only clean up default routes (prefix length 0) added by clash for TUN
        if msg.header.destination_prefix_length != 0 {
            continue;
        }

        // Only delete routes pointing to this TUN interface
        if oif != Some(expected_index) {
            continue;
        }

        to_delete.push(msg);
    }

    for msg in to_delete {
        if let Err(e) = handle.route().del(msg).execute().await {
            warn!("failed to delete route in table {}: {}", table_id, e);
        }
    }

    Ok(())
}

async fn routes_clean_up_async(
    tun_cfg: &TunConfig,
    expected_ifindex: Option<u32>,
) -> std::io::Result<()> {
    let handle = get_rtnetlink_handle().await?;
    let table = tun_cfg.route_table;
    let rule_index = tun_cfg
        .iproute2_rule_index
        .unwrap_or(DEFAULT_IPROUTE2_RULE_INDEX);
    let so_mark = tun_cfg.so_mark.unwrap_or(DEFAULT_SO_MARK);
    let enable_v6 = tun_cfg.gateway_v6.is_some();
    let has_dns_hijack = tun_cfg.dns_hijack.is_enabled();
    let strict_route = tun_cfg.strict_route;

    // Clean up rules
    cleanup_rules_for_family(
        &handle,
        IpVersion::V4,
        table,
        so_mark,
        rule_index,
        has_dns_hijack,
        strict_route,
    )
    .await?;

    if enable_v6 {
        cleanup_rules_for_family(
            &handle,
            IpVersion::V6,
            table,
            so_mark,
            rule_index,
            has_dns_hijack,
            strict_route,
        )
        .await?;
    }

    // Clean up default routes in table for TUN
    cleanup_routes_for_table(&handle, table, IpVersion::V4, expected_ifindex).await?;
    if enable_v6 {
        cleanup_routes_for_table(&handle, table, IpVersion::V6, expected_ifindex).await?;
    }

    Ok(())
}

pub fn maybe_routes_clean_up(tun_cfg: &TunConfig) -> std::io::Result<()> {
    if !(tun_cfg.enable && tun_cfg.route_all) {
        return Ok(());
    }

    warn!("cleaning up policy routing via netlink");
    let tun_name = extract_tun_name(&tun_cfg.device_id);
    let mut ifindex = crate::app::net::get_interface_by_name(&tun_name).map(|i| i.index);
    if ifindex.is_none() {
        let recorded = LAST_TUN_IFINDEX.load(Ordering::SeqCst);
        if recorded != 0 {
            ifindex = Some(recorded);
        }
    }
    run_netlink_async(routes_clean_up_async(tun_cfg, ifindex))
}
