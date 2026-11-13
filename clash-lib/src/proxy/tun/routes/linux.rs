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
use tracing::{info, warn};

use crate::{
    app::net::OutboundInterface, common::errors::new_io_error,
    config::internal::config::TunConfig,
};

use super::super::auto_redirect::INPUT_MARK as AUTO_REDIRECT_MARK;
use crate::config::internal::tun::{AUTO_REDIRECT_BYPASS_MARK, TunDevice, parse_device_id};

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

async fn add_rule_fwmark(
    handle: &rtnetlink::Handle,
    table_id: u32,
    so_mark: u32,
    rule_index: u32,
    family: AddressFamily,
    mark_mask: Option<u32>,
) -> std::io::Result<()> {
    match family {
        AddressFamily::Inet => {
            let mut req = handle.rule().add().v4();
            let msg = req.message_mut();
            if mark_mask.is_none() { msg.header.flags |= FIB_RULE_INVERT; }
            msg.header.action = RuleAction::ToTable;
            msg.attributes.push(RuleAttribute::FwMark(so_mark));
            if let Some(mask) = mark_mask { msg.attributes.push(RuleAttribute::FwMask(mask)); }
            msg.attributes.push(RuleAttribute::Table(table_id));
            msg.attributes.push(RuleAttribute::Priority(rule_index));
            ignore_already_exists(req.execute().await)?;
        }
        AddressFamily::Inet6 => {
            let mut req = handle.rule().add().v6();
            let msg = req.message_mut();
            if mark_mask.is_none() { msg.header.flags |= FIB_RULE_INVERT; }
            msg.header.action = RuleAction::ToTable;
            msg.attributes.push(RuleAttribute::FwMark(so_mark));
            if let Some(mask) = mark_mask { msg.attributes.push(RuleAttribute::FwMask(mask)); }
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
    mark_mask: Option<u32>,
) -> std::io::Result<()> {
    match family {
        AddressFamily::Inet => {
            let mut req = handle.rule().add().v4();
            let msg = req.message_mut();
            msg.header.action = RuleAction::Blackhole;
            if let Some(mask) = mark_mask {
                msg.attributes.push(RuleAttribute::FwMark(AUTO_REDIRECT_MARK));
                msg.attributes.push(RuleAttribute::FwMask(mask));
            }
            msg.attributes
                .push(RuleAttribute::Priority(rule_index.saturating_add(1)));
            ignore_already_exists(req.execute().await)?;
        }
        AddressFamily::Inet6 => {
            let mut req = handle.rule().add().v6();
            let msg = req.message_mut();
            msg.header.action = RuleAction::Blackhole;
            if let Some(mask) = mark_mask {
                msg.attributes.push(RuleAttribute::FwMark(AUTO_REDIRECT_MARK));
                msg.attributes.push(RuleAttribute::FwMask(mask));
            }
            msg.attributes
                .push(RuleAttribute::Priority(rule_index.saturating_add(1)));
            ignore_already_exists(req.execute().await)?;
        }
        _ => {}
    }
    Ok(())
}

// Like sing-tun, match only the bits used by active redirect mark values.
// This changes RPDB matching, not nft's complete packet/connection mark writes.
fn auto_redirect_rule_mask(cfg: &TunConfig) -> Option<u32> {
    cfg.auto_redirect.then(|| AUTO_REDIRECT_MARK | AUTO_REDIRECT_BYPASS_MARK
        | cfg.so_mark.unwrap_or(DEFAULT_SO_MARK))
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
    let so_mark = if tun_cfg.auto_redirect { AUTO_REDIRECT_MARK }
        else { tun_cfg.so_mark.unwrap_or(DEFAULT_SO_MARK) };
    let enable_v6 = tun_cfg.gateway_v6.is_some();
    let mark_mask = auto_redirect_rule_mask(tun_cfg);

    // 1. Add default route in table
    add_default_route_to_table(&handle, table, via.index, false).await?;
    if enable_v6 {
        add_default_route_to_table(&handle, table, via.index, true).await?;
    }

    // 2. Add rule not fwmark table
    add_rule_fwmark(
        &handle,
        table,
        so_mark,
        rule_index,
        AddressFamily::Inet,
        mark_mask,
    )
    .await?;
    if enable_v6 {
        add_rule_fwmark(
            &handle,
            table,
            so_mark,
            rule_index,
            AddressFamily::Inet6,
            mark_mask,
        )
        .await?;
    }

    // 3. Add rule suppress_prefixlength 0 table main
    if !tun_cfg.auto_redirect {
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
    }

    // 4. Add rule dport 53 table (if dns_hijack is enabled)
    if tun_cfg.dns_hijack.is_enabled() && !tun_cfg.auto_redirect {
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
        add_rule_strict_blackhole(&handle, rule_index, AddressFamily::Inet, mark_mask).await?;
        if enable_v6 {
            add_rule_strict_blackhole(&handle, rule_index, AddressFamily::Inet6, mark_mask)
                .await?;
        }
    }

    Ok(())
}

pub fn setup_policy_routing(
    tun_cfg: &TunConfig,
    via: &OutboundInterface,
) -> std::io::Result<()> {
    info!("setting up policy routing via netlink for {}", via.name);
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
    mark_mask: Option<u32>,
) -> std::io::Result<()> {
    let auto_redirect = mark_mask.is_some();
    let mut rules_stream = handle.rule().get(family).execute();
    let mut to_delete = Vec::new();

    while let Some(msg) = rules_stream.try_next().await.map_err(new_io_error)? {
        let is_invert = msg.header.flags.contains(FIB_RULE_INVERT);
        let mut table = None;
        let mut fwmark = None;
        let mut fwmask = None;
        let mut suppress_prefixlen = None;
        let mut dport_range = None;
        let mut priority = None;

        for nla in &msg.attributes {
            match nla {
                RuleAttribute::Table(t) => table = Some(*t),
                RuleAttribute::FwMark(m) => fwmark = Some(*m),
                RuleAttribute::FwMask(m) => fwmask = Some(*m),
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

        let is_our_not_fwmark = is_invert != auto_redirect
            && fwmark == Some(so_mark)
            && (!auto_redirect || fwmask == mark_mask)
            && table == Some(table_id)
            && priority == Some(rule_index);

        let is_our_suppress = !auto_redirect && suppress_prefixlen == Some(0)
            && (table == Some(254) || msg.header.table == 254)
            && priority == Some(rule_index.saturating_sub(1));

        let is_our_dport = has_dns_hijack
            && dport_range == Some((53, 53))
            && table == Some(table_id)
            && priority == Some(rule_index.saturating_sub(2));

        let is_our_blackhole = strict_route
            && (!auto_redirect || (fwmark == Some(AUTO_REDIRECT_MARK)
                && fwmask == mark_mask))
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
    match parse_device_id(device_id) {
        Ok(TunDevice::Interface { name, .. }) => name,
        _ => device_id.to_owned(),
    }
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
    let so_mark = if tun_cfg.auto_redirect { AUTO_REDIRECT_MARK }
        else { tun_cfg.so_mark.unwrap_or(DEFAULT_SO_MARK) };
    let enable_v6 = tun_cfg.gateway_v6.is_some();
    let mark_mask = auto_redirect_rule_mask(tun_cfg);
    let has_dns_hijack = tun_cfg.dns_hijack.is_enabled() && !tun_cfg.auto_redirect;
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
        mark_mask,
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
            mark_mask,
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

    info!("cleaning up policy routing via netlink");
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

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;
    use crate::app::net::get_interface_by_name;

    #[test]
    fn auto_redirect_routing_mask_combines_active_marks() {
        let mut cfg = TunConfig { auto_redirect: true, ..Default::default() };
        assert_eq!(auto_redirect_rule_mask(&cfg), Some(0x167));
        cfg.so_mark = Some(0x80000);
        assert_eq!(auto_redirect_rule_mask(&cfg), Some(0x80167));
        cfg.auto_redirect = false;
        assert_eq!(auto_redirect_rule_mask(&cfg), None);
    }

    // Must run in a fresh user/network namespace, separate from the host routes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires an isolated network namespace"]
    async fn auto_redirect_policy_routing_and_cleanup() {
        fn ip(args: &[&str]) -> String {
            let output = Command::new("ip").args(args).output().unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
            String::from_utf8(output.stdout).unwrap()
        }
        ip(&["link", "set", "lo", "up"]);
        ip(&["link", "add", "tun-test", "type", "dummy"]);
        ip(&["addr", "add", "198.18.0.1/30", "dev", "tun-test"]);
        ip(&["link", "set", "tun-test", "up"]);
        ip(&["route", "add", "default", "dev", "lo"]);
        let cfg = TunConfig { enable: true, auto_redirect: true, route_all: true,
            strict_route: true, device_id: "tun-test".into(), route_table: 2022,
            ..Default::default() };
        let interface = get_interface_by_name("tun-test").unwrap();
        setup_policy_routing(&cfg, &interface).unwrap();
        assert!(ip(&["route", "get", "203.0.113.1", "mark", "0x163"])
            .contains("dev tun-test"));
        assert!(ip(&["route", "get", "203.0.113.1", "mark", "0x80000163"])
            .contains("dev tun-test"));
        assert!(ip(&["route", "get", "203.0.113.1", "mark", "0x164"])
            .contains("dev lo"));
        assert!(ip(&["rule", "show"]).contains("0x163/0x167"));
        assert!(ip(&["route", "get", "203.0.113.1"]).contains("dev lo"));
        maybe_routes_clean_up(&cfg).unwrap();
        assert!(!ip(&["rule", "show"]).contains("9000:"));
        assert!(!ip(&["rule", "show"]).contains("9001:"));
        assert!(ip(&["route", "show", "table", "2022"]).is_empty());
    }
}
