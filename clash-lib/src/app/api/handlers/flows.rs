use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{Query, State, WebSocketUpgrade, ws::Message},
    response::IntoResponse,
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::{
    app::{
        api::AppState,
        dispatcher::StatisticsManager,
    },
    session::Network,
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct FlowState {
    pub statistics_manager: Arc<StatisticsManager>,
}

pub fn routes(statistics_manager: Arc<StatisticsManager>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(handle))
        .with_state(FlowState { statistics_manager })
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct FlowQuery {
    /// Maximum number of flow records to return (default 20).
    pub top: Option<usize>,
    /// Field to group by (currently only "dst_host" is supported, kept for
    /// forward compatibility).
    #[allow(dead_code)]
    pub group_by: Option<String>,
    /// Whether to include recently-closed connections (default true).
    pub include_closed: Option<bool>,
    /// WebSocket polling interval in seconds (default 5, min 1).
    #[allow(dead_code)]
    pub interval: Option<u64>,
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FlowRecord {
    pub dst_host: String,
    pub dst_port: u16,
    pub protocol: String,
    pub src_ips: Vec<String>,
    pub conn_count: usize,
    pub active_count: usize,
    pub closed_count: usize,
    pub upload_total: u64,
    pub download_total: u64,
    pub bytes_total: u64,
    pub rule: String,
    pub rule_payload: String,
    pub chains: Vec<String>,
    /// ISO 3166-1 alpha-2 country code from country mmdb.
    pub country: Option<String>,
    /// ASN org name from ASN mmdb.
    pub asn: Option<String>,
    pub last_seen: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Aggregation key (owned — necessary because SocksAddr::Ip produces Cow::Owned)
// ---------------------------------------------------------------------------

use std::net::IpAddr;

#[derive(Hash, PartialEq, Eq)]
struct FlowKey {
    dst_host: String,
    dst_port: u16,
    is_tcp: bool,
}

// ---------------------------------------------------------------------------
// Per-key accumulator — borrows strings from Arc<TrackerInfo> which outlive
// the map, but owns only what it must (src_ips as stack-cheap IpAddr, chains
// cloned lazily at most once per unique flow key).
// ---------------------------------------------------------------------------

struct Acc<'a> {
    src_ips: Vec<IpAddr>,
    conn_count: usize,
    active_count: usize,
    closed_count: usize,
    upload_total: u64,
    download_total: u64,
    rule: Option<&'a str>,
    rule_payload: Option<&'a str>,
    chains: Option<Vec<String>>,
    country: Option<&'a str>,
    asn: Option<&'a str>,
    last_seen: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Core aggregation logic
// ---------------------------------------------------------------------------

async fn build_flow_records(
    mgr: &StatisticsManager,
    top: usize,
    include_closed: bool,
) -> Vec<FlowRecord> {
    use std::sync::atomic::Ordering;

    let active = mgr.active_connections_snapshot();
    let closed = if include_closed {
        mgr.closed_flows_snapshot().await
    } else {
        Vec::new()
    };

    let total_hint = active.len() + closed.len();
    let mut map: HashMap<FlowKey, Acc<'_>> =
        HashMap::with_capacity(total_hint.min(64));

    // Process TrackerInfo into the aggregation map.
    for (info, is_active) in active
        .iter()
        .map(|i| (i, true))
        .chain(closed.iter().map(|i| (i, false)))
    {
        let dst_host = info.session_holder.destination.host();
        let dst_port = info.session_holder.destination.port();
        let is_tcp = matches!(info.session_holder.network, Network::Tcp);

        let upload = info.upload_total.load(Ordering::Relaxed);
        let download = info.download_total.load(Ordering::Relaxed);
        let src_ip = info.session_holder.source.ip();

        let key = FlowKey {
            dst_host,
            dst_port,
            is_tcp,
        };

        if let Some(acc) = map.get_mut(&key) {
            acc.conn_count += 1;
            if is_active {
                acc.active_count += 1;
            } else {
                acc.closed_count += 1;
            }
            acc.upload_total += upload;
            acc.download_total += download;
            if !acc.src_ips.contains(&src_ip) {
                acc.src_ips.push(src_ip);
            }
            if info.start_time > acc.last_seen {
                acc.last_seen = info.start_time;
            }
            if acc.rule.is_none() && !info.rule.is_empty() {
                acc.rule = Some(&info.rule);
            }
            if acc.rule_payload.is_none() && !info.rule_payload.is_empty() {
                acc.rule_payload = Some(&info.rule_payload);
            }
            if acc.chains.is_none() {
                let c = info.proxy_chain_holder.snapshot();
                if !c.is_empty() {
                    acc.chains = Some(c);
                }
            }
            if acc.country.is_none() {
                acc.country = info.session_holder.country.as_deref();
            }
            if acc.asn.is_none() {
                acc.asn = info.session_holder.asn.as_deref();
            }
        } else {
            let chains = info.proxy_chain_holder.snapshot();
            map.insert(
                key,
                Acc {
                    src_ips: vec![src_ip],
                    conn_count: 1,
                    active_count: if is_active { 1 } else { 0 },
                    closed_count: if is_active { 0 } else { 1 },
                    upload_total: upload,
                    download_total: download,
                    rule: if info.rule.is_empty() {
                        None
                    } else {
                        Some(&info.rule)
                    },
                    rule_payload: if info.rule_payload.is_empty() {
                        None
                    } else {
                        Some(&info.rule_payload)
                    },
                    chains: if chains.is_empty() {
                        None
                    } else {
                        Some(chains)
                    },
                    country: info.session_holder.country.as_deref(),
                    asn: info.session_holder.asn.as_deref(),
                    last_seen: info.start_time,
                },
            );
        }
    }

    // Convert accumulator map → sorted FlowRecord list.
    let mut records: Vec<FlowRecord> = map
        .into_iter()
        .map(|(key, acc)| {
            let bytes_total = acc.upload_total + acc.download_total;
            FlowRecord {
                dst_host: key.dst_host,
                dst_port: key.dst_port,
                protocol: if key.is_tcp {
                    "tcp".to_string()
                } else {
                    "udp".to_string()
                },
                src_ips: acc.src_ips.into_iter().map(|ip| ip.to_string()).collect(),
                conn_count: acc.conn_count,
                active_count: acc.active_count,
                closed_count: acc.closed_count,
                upload_total: acc.upload_total,
                download_total: acc.download_total,
                bytes_total,
                rule: acc.rule.unwrap_or_default().to_string(),
                rule_payload: acc.rule_payload.unwrap_or_default().to_string(),
                chains: acc.chains.unwrap_or_default(),
                country: acc.country.map(|s| s.to_string()),
                asn: acc.asn.map(|s| s.to_string()),
                last_seen: acc.last_seen,
            }
        })
        .collect();

    records.sort_by_key(|r| std::cmp::Reverse(r.bytes_total));
    records.truncate(top);
    records
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

pub async fn handle(
    State(state): State<FlowState>,
    Query(q): Query<FlowQuery>,
) -> impl IntoResponse {
    let top = q.top.unwrap_or(20).clamp(1, 500);
    let include_closed = q.include_closed.unwrap_or(true);

    let records =
        build_flow_records(&state.statistics_manager, top, include_closed).await;
    Json(records).into_response()
}

// ---------------------------------------------------------------------------
// WebSocket handler (used from websocket.rs via AppState)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct WsFlowQuery {
    pub interval: Option<u64>,
    pub top: Option<usize>,
    pub include_closed: Option<bool>,
}

pub async fn ws_handle(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Query(q): Query<WsFlowQuery>,
) -> impl IntoResponse {
    let top = q.top.unwrap_or(20).clamp(1, 500);
    let include_closed = q.include_closed.unwrap_or(true);
    let interval_secs = q.interval.unwrap_or(5).max(1);

    let callback = async move |mut socket: axum::extract::ws::WebSocket| {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut buf = Vec::with_capacity(4096);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let records =
                        build_flow_records(&state.statistics_manager, top, include_closed)
                            .await;
                    buf.clear();
                    if let Err(e) = serde_json::to_writer(&mut buf, &records) {
                        warn!("failed to serialize flow records: {}", e);
                        break;
                    }
                    let Ok(body) = std::str::from_utf8(&buf) else {
                        break;
                    };
                    if let Err(e) = socket.send(Message::Text(body.into())).await {
                        debug!("ws/flows send error: {}", e);
                        break;
                    }
                }
                msg = socket.recv() => {
                    match msg {
                        Some(Ok(Message::Close(_))) | None => {
                            debug!("ws/flows client disconnected");
                            break;
                        }
                        Some(Err(e)) => {
                            debug!("ws/flows receive error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
    };

    ws.on_failed_upgrade(|e| warn!("ws/flows upgrade error: {}", e))
        .on_upgrade(async move |socket| {
            callback(socket).await;
        })
}
