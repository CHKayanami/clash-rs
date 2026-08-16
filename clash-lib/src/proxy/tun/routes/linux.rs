use std::net::{Ipv4Addr, Ipv6Addr};

use futures::stream::TryStreamExt;
use ipnet::IpNet;
use netlink_packet_route::{
    AddressFamily,
    route::RouteAttribute,
    rule::{RuleAction, RuleAttribute, RuleFlags, RulePortRange},
};
use rtnetlink::{IpVersion, RouteMessageBuilder, new_connection};
use tracing::warn;

use crate::{
    app::net::OutboundInterface, common::errors::new_io_error,
    config::internal::config::TunConfig,
};

const FIB_RULE_INVERT: RuleFlags = RuleFlags::from_bits_retain(0x02);

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

async fn add_route_internal(via: &OutboundInterface, dest: &IpNet) -> std::io::Result<()> {
    let handle = get_rtnetlink_handle().await?;
    match dest {
        IpNet::V4(v4) => {
            let route = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(v4.addr(), v4.prefix_len())
                .output_interface(via.index)
                .build();
            handle
                .route()
                .add(route)
                .execute()
                .await
                .map_err(new_io_error)?;
        }
        IpNet::V6(v6) => {
            let route = RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(v6.addr(), v6.prefix_len())
                .output_interface(via.index)
                .build();
            handle
                .route()
                .add(route)
                .execute()
                .await
                .map_err(new_io_error)?;
        }
    }
    Ok(())
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
        handle
            .route()
            .add(route)
            .execute()
            .await
            .map_err(new_io_error)?;
    } else {
        let route = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
            .output_interface(ifindex)
            .table_id(table_id)
            .build();
        handle
            .route()
            .add(route)
            .execute()
            .await
            .map_err(new_io_error)?;
    }
    Ok(())
}

async fn add_rule_not_fwmark(
    handle: &rtnetlink::Handle,
    table_id: u32,
    so_mark: u32,
    rule_index: Option<u32>,
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
            if let Some(pref) = rule_index {
                msg.attributes.push(RuleAttribute::Priority(pref));
            }
            req.execute().await.map_err(new_io_error)?;
        }
        AddressFamily::Inet6 => {
            let mut req = handle.rule().add().v6();
            let msg = req.message_mut();
            msg.header.flags |= FIB_RULE_INVERT;
            msg.header.action = RuleAction::ToTable;
            msg.attributes.push(RuleAttribute::FwMark(so_mark));
            msg.attributes.push(RuleAttribute::Table(table_id));
            if let Some(pref) = rule_index {
                msg.attributes.push(RuleAttribute::Priority(pref));
            }
            req.execute().await.map_err(new_io_error)?;
        }
        _ => {}
    }
    Ok(())
}

async fn add_rule_suppress_prefixlength_main(
    handle: &rtnetlink::Handle,
    rule_index: Option<u32>,
    family: AddressFamily,
) -> std::io::Result<()> {
    match family {
        AddressFamily::Inet => {
            let mut req = handle.rule().add().v4();
            let msg = req.message_mut();
            msg.header.action = RuleAction::ToTable;
            msg.attributes.push(RuleAttribute::Table(254));
            msg.attributes.push(RuleAttribute::SuppressPrefixLen(0));
            if let Some(pref) = rule_index {
                msg.attributes.push(RuleAttribute::Priority(pref.saturating_sub(1)));
            }
            req.execute().await.map_err(new_io_error)?;
        }
        AddressFamily::Inet6 => {
            let mut req = handle.rule().add().v6();
            let msg = req.message_mut();
            msg.header.action = RuleAction::ToTable;
            msg.attributes.push(RuleAttribute::Table(254));
            msg.attributes.push(RuleAttribute::SuppressPrefixLen(0));
            if let Some(pref) = rule_index {
                msg.attributes.push(RuleAttribute::Priority(pref.saturating_sub(1)));
            }
            req.execute().await.map_err(new_io_error)?;
        }
        _ => {}
    }
    Ok(())
}

async fn add_rule_dport(
    handle: &rtnetlink::Handle,
    table_id: u32,
    port: u16,
    rule_index: Option<u32>,
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
            if let Some(pref) = rule_index {
                msg.attributes.push(RuleAttribute::Priority(pref.saturating_sub(2)));
            }
            req.execute().await.map_err(new_io_error)?;
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
            if let Some(pref) = rule_index {
                msg.attributes.push(RuleAttribute::Priority(pref.saturating_sub(2)));
            }
            req.execute().await.map_err(new_io_error)?;
        }
        _ => {}
    }
    Ok(())
}

async fn add_rule_strict_blackhole(
    handle: &rtnetlink::Handle,
    rule_index: Option<u32>,
    family: AddressFamily,
) -> std::io::Result<()> {
    match family {
        AddressFamily::Inet => {
            let mut req = handle.rule().add().v4();
            let msg = req.message_mut();
            msg.header.action = RuleAction::Blackhole;
            if let Some(pref) = rule_index {
                msg.attributes.push(RuleAttribute::Priority(pref.saturating_add(1)));
            }
            req.execute().await.map_err(new_io_error)?;
        }
        AddressFamily::Inet6 => {
            let mut req = handle.rule().add().v6();
            let msg = req.message_mut();
            msg.header.action = RuleAction::Blackhole;
            if let Some(pref) = rule_index {
                msg.attributes.push(RuleAttribute::Priority(pref.saturating_add(1)));
            }
            req.execute().await.map_err(new_io_error)?;
        }
        _ => {}
    }
    Ok(())
}

async fn setup_policy_routing_async(
    tun_cfg: &TunConfig,
    via: &OutboundInterface,
) -> std::io::Result<()> {
    let handle = get_rtnetlink_handle().await?;
    let table = tun_cfg.route_table;
    let rule_index = tun_cfg.iproute2_rule_index;
    let enable_v6 = tun_cfg.gateway_v6.is_some();

    // 1. Add default route in table
    add_default_route_to_table(&handle, table, via.index, false).await?;
    if enable_v6 {
        add_default_route_to_table(&handle, table, via.index, true).await?;
    }

    // 2. Add rule not fwmark table
    if let Some(so_mark) = tun_cfg.so_mark {
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
    so_mark: Option<u32>,
    has_dns_hijack: bool,
) -> std::io::Result<()> {
    let mut rules_stream = handle.rule().get(family).execute();
    let mut to_delete = Vec::new();

    while let Some(msg) = rules_stream.try_next().await.map_err(new_io_error)? {
        let is_invert = msg.header.flags.contains(FIB_RULE_INVERT);
        let mut table = None;
        let mut fwmark = None;
        let mut suppress_prefixlen = None;
        let mut dport_range = None;

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
                _ => {}
            }
        }

        let is_our_not_fwmark = so_mark.is_some()
            && is_invert
            && fwmark == so_mark
            && table == Some(table_id);

        let is_our_suppress = suppress_prefixlen == Some(0)
            && (table == Some(254) || msg.header.table == 254);

        let is_our_dport = has_dns_hijack
            && dport_range == Some((53, 53))
            && table == Some(table_id);

        let is_blackhole = msg.header.action == RuleAction::Blackhole;

        if is_our_not_fwmark || is_our_suppress || is_our_dport || is_blackhole {
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

async fn cleanup_routes_for_table(
    handle: &rtnetlink::Handle,
    table_id: u32,
    family: IpVersion,
) -> std::io::Result<()> {
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
        for nla in &msg.attributes {
            if let RouteAttribute::Table(t) = nla {
                table = Some(*t);
            }
        }
        if table == Some(table_id)
            || (table.is_none() && msg.header.table as u32 == table_id)
        {
            to_delete.push(msg);
        }
    }

    for msg in to_delete {
        if let Err(e) = handle.route().del(msg).execute().await {
            warn!("failed to delete route in table {}: {}", table_id, e);
        }
    }

    Ok(())
}

async fn routes_clean_up_async(tun_cfg: &TunConfig) -> std::io::Result<()> {
    let handle = get_rtnetlink_handle().await?;
    let table = tun_cfg.route_table;
    let enable_v6 = tun_cfg.gateway_v6.is_some();
    let has_dns_hijack = tun_cfg.dns_hijack.is_enabled();

    // Clean up rules
    cleanup_rules_for_family(
        &handle,
        IpVersion::V4,
        table,
        tun_cfg.so_mark,
        has_dns_hijack,
    )
    .await?;

    if enable_v6 {
        cleanup_rules_for_family(
            &handle,
            IpVersion::V6,
            table,
            tun_cfg.so_mark,
            has_dns_hijack,
        )
        .await?;
    }

    // Clean up routes in table
    cleanup_routes_for_table(&handle, table, IpVersion::V4).await?;
    if enable_v6 {
        cleanup_routes_for_table(&handle, table, IpVersion::V6).await?;
    }

    Ok(())
}

pub fn maybe_routes_clean_up(tun_cfg: &TunConfig) -> std::io::Result<()> {
    if !(tun_cfg.enable && tun_cfg.route_all) {
        return Ok(());
    }

    warn!("cleaning up policy routing via netlink");
    run_netlink_async(routes_clean_up_async(tun_cfg))
}
