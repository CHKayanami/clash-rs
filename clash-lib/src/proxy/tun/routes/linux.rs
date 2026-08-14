use std::net::{Ipv4Addr, Ipv6Addr};

use futures::stream::TryStreamExt;
use ipnet::IpNet;
use netlink_packet_route::{
    AddressFamily,
    route::RouteAttribute,
    rule::{RuleAction, RuleAttribute, RulePortRange, FIB_RULE_INVERT},
};
use rtnetlink::new_connection;
use tracing::warn;

use crate::{
    app::net::OutboundInterface, common::errors::new_io_error,
    config::internal::config::TunConfig,
};

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
            handle
                .route()
                .add()
                .v4()
                .destination_prefix(v4.addr(), v4.prefix_len())
                .output_interface(via.index)
                .execute()
                .await
                .map_err(new_io_error)?;
        }
        IpNet::V6(v6) => {
            handle
                .route()
                .add()
                .v6()
                .destination_prefix(v6.addr(), v6.prefix_len())
                .output_interface(via.index)
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
        handle
            .route()
            .add()
            .v4()
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .output_interface(ifindex)
            .table_id(table_id)
            .execute()
            .await
            .map_err(new_io_error)?;
    } else {
        handle
            .route()
            .add()
            .v6()
            .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
            .output_interface(ifindex)
            .table_id(table_id)
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
    family: AddressFamily,
) -> std::io::Result<()> {
    let mut req = handle.rule().add();
    if family == AddressFamily::Inet {
        req = req.v4();
    } else {
        req = req.v6();
    }
    let msg = req.message_mut();
    msg.header.flags |= FIB_RULE_INVERT;
    msg.header.action = RuleAction::ToTbl;
    msg.nlas.push(RuleAttribute::FwMark(so_mark));
    msg.nlas.push(RuleAttribute::Table(table_id));
    req.execute().await.map_err(new_io_error)?;
    Ok(())
}

async fn add_rule_suppress_prefixlength_main(
    handle: &rtnetlink::Handle,
    family: AddressFamily,
) -> std::io::Result<()> {
    let mut req = handle.rule().add();
    if family == AddressFamily::Inet {
        req = req.v4();
    } else {
        req = req.v6();
    }
    let msg = req.message_mut();
    msg.header.action = RuleAction::ToTbl;
    msg.nlas.push(RuleAttribute::Table(254));
    msg.nlas.push(RuleAttribute::SuppressPrefixLen(0));
    req.execute().await.map_err(new_io_error)?;
    Ok(())
}

async fn add_rule_dport(
    handle: &rtnetlink::Handle,
    table_id: u32,
    port: u16,
    family: AddressFamily,
) -> std::io::Result<()> {
    let mut req = handle.rule().add();
    if family == AddressFamily::Inet {
        req = req.v4();
    } else {
        req = req.v6();
    }
    let msg = req.message_mut();
    msg.header.action = RuleAction::ToTbl;
    msg.nlas.push(RuleAttribute::Table(table_id));
    msg.nlas
        .push(RuleAttribute::DestinationPortRange(RulePortRange {
            start: port,
            end: port,
        }));
    req.execute().await.map_err(new_io_error)?;
    Ok(())
}

async fn setup_policy_routing_async(
    tun_cfg: &TunConfig,
    via: &OutboundInterface,
) -> std::io::Result<()> {
    let handle = get_rtnetlink_handle().await?;
    let table = tun_cfg.route_table;
    let enable_v6 = tun_cfg.gateway_v6.is_some();

    // 1. Add default route in table
    add_default_route_to_table(&handle, table, via.index, false).await?;
    if enable_v6 {
        add_default_route_to_table(&handle, table, via.index, true).await?;
    }

    // 2. Add rule not fwmark table
    if let Some(so_mark) = tun_cfg.so_mark {
        add_rule_not_fwmark(&handle, table, so_mark, AddressFamily::Inet).await?;
        if enable_v6 {
            add_rule_not_fwmark(&handle, table, so_mark, AddressFamily::Inet6)
                .await?;
        }
    }

    // 3. Add rule suppress_prefixlength 0 table main
    add_rule_suppress_prefixlength_main(&handle, AddressFamily::Inet).await?;
    if enable_v6 {
        add_rule_suppress_prefixlength_main(&handle, AddressFamily::Inet6).await?;
    }

    // 4. Add rule dport 53 table (if dns_hijack is enabled)
    if tun_cfg.dns_hijack.is_enabled() {
        add_rule_dport(&handle, table, 53, AddressFamily::Inet).await?;
        if enable_v6 {
            add_rule_dport(&handle, table, 53, AddressFamily::Inet6).await?;
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
    family: AddressFamily,
    table_id: u32,
    so_mark: Option<u32>,
    has_dns_hijack: bool,
) -> std::io::Result<()> {
    let mut rules_stream = handle.rule().get(family).execute();
    let mut to_delete = Vec::new();

    while let Some(msg) = rules_stream.try_next().await.map_err(new_io_error)? {
        let is_invert = (msg.header.flags & FIB_RULE_INVERT) != 0;
        let mut table = None;
        let mut fwmark = None;
        let mut suppress_prefixlen = None;
        let mut dport_range = None;

        for nla in &msg.nlas {
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

        if is_our_not_fwmark || is_our_suppress || is_our_dport {
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
    family: AddressFamily,
) -> std::io::Result<()> {
    let route_family = if family == AddressFamily::Inet {
        rtnetlink::RouteAddressFamily::V4
    } else {
        rtnetlink::RouteAddressFamily::V6
    };

    let mut routes_stream = handle.route().get(route_family).execute();
    let mut to_delete = Vec::new();

    while let Some(msg) = routes_stream.try_next().await.map_err(new_io_error)? {
        let mut table = None;
        for nla in &msg.nlas {
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
        AddressFamily::Inet,
        table,
        tun_cfg.so_mark,
        has_dns_hijack,
    )
    .await?;

    if enable_v6 {
        cleanup_rules_for_family(
            &handle,
            AddressFamily::Inet6,
            table,
            tun_cfg.so_mark,
            has_dns_hijack,
        )
        .await?;
    }

    // Clean up routes in table
    cleanup_routes_for_table(&handle, table, AddressFamily::Inet).await?;
    if enable_v6 {
        cleanup_routes_for_table(&handle, table, AddressFamily::Inet6).await?;
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
