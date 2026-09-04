use std::{collections::HashMap, sync::Arc};

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
        dispatcher::{FlowKey, StatisticsManager},
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

use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Per-key accumulator
// ---------------------------------------------------------------------------

struct Acc {
    src_ips: Vec<IpAddr>,
    conn_count: usize,
    active_count: usize,
    closed_count: usize,
    upload_total: u64,
    download_total: u64,
    bytes_total: u64,
    rule: String,
    rule_payload: String,
    chains: Vec<String>,
    country: Option<String>,
    asn: Option<String>,
    last_seen: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Core aggregation logic
// ---------------------------------------------------------------------------

pub(crate) async fn build_flow_records(
    mgr: &StatisticsManager,
    top: usize,
    include_closed: bool,
) -> Vec<FlowRecord> {
    use std::sync::atomic::Ordering;

    let active = mgr.active_connections_snapshot();
    let closed = if include_closed {
        mgr.closed_flows_snapshot().await
    } else {
        HashMap::new()
    };

    let mut map: HashMap<FlowKey, Acc> =
        HashMap::with_capacity(active.len() + closed.len());

    // 1. Initialize map from pre-aggregated closed flows
    for (key, closed_entry) in closed.into_iter() {
        let bytes_total = closed_entry.upload_total + closed_entry.download_total;
        map.insert(
            key,
            Acc {
                src_ips: closed_entry.src_ips,
                conn_count: closed_entry.conn_count,
                active_count: 0,
                closed_count: closed_entry.conn_count,
                upload_total: closed_entry.upload_total,
                download_total: closed_entry.download_total,
                bytes_total,
                rule: closed_entry.rule,
                rule_payload: closed_entry.rule_payload,
                chains: closed_entry.chains,
                country: closed_entry.country,
                asn: closed_entry.asn,
                last_seen: closed_entry.last_seen,
            },
        );
    }

    const MAX_SRC_IPS: usize = 32;

    // 2. Aggregate active connections
    for info in active.iter() {
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
            acc.active_count += 1;
            acc.upload_total += upload;
            acc.download_total += download;
            acc.bytes_total += upload + download;
            if acc.src_ips.len() < MAX_SRC_IPS && !acc.src_ips.contains(&src_ip) {
                acc.src_ips.push(src_ip);
            }
            if info.start_time > acc.last_seen {
                acc.last_seen = info.start_time;
            }
            if acc.rule.is_empty() && !info.rule.is_empty() {
                acc.rule = info.rule.clone();
            }
            if acc.rule_payload.is_empty() && !info.rule_payload.is_empty() {
                acc.rule_payload = info.rule_payload.clone();
            }
            if acc.chains.is_empty() {
                let c = info.proxy_chain_holder.snapshot();
                if !c.is_empty() {
                    acc.chains = c;
                }
            }
            if acc.country.is_none() {
                acc.country = info.session_holder.country.clone();
            }
            if acc.asn.is_none() {
                acc.asn = info.session_holder.asn.clone();
            }
        } else {
            let chains = info.proxy_chain_holder.snapshot();
            let bytes_total = upload + download;
            map.insert(
                key,
                Acc {
                    src_ips: vec![src_ip],
                    conn_count: 1,
                    active_count: 1,
                    closed_count: 0,
                    upload_total: upload,
                    download_total: download,
                    bytes_total,
                    rule: info.rule.clone(),
                    rule_payload: info.rule_payload.clone(),
                    chains,
                    country: info.session_holder.country.clone(),
                    asn: info.session_holder.asn.clone(),
                    last_seen: info.start_time,
                },
            );
        }
    }

    if top == 0 {
        return Vec::new();
    }

    // Convert accumulator map → sorted (FlowKey, Acc) list.
    let mut entries: Vec<(FlowKey, Acc)> = map.into_iter().collect();

    // Sort and truncate at (FlowKey, Acc) level to avoid formatting records that will be discarded.
    if entries.len() > top {
        entries.select_nth_unstable_by_key(top, |(_, acc)| {
            std::cmp::Reverse(acc.bytes_total)
        });
        entries.truncate(top);
    }
    entries.sort_by_key(|(_, acc)| {
        std::cmp::Reverse(acc.bytes_total)
    });

    // Only format and allocate Strings for the final top records.
    entries
        .into_iter()
        .map(|(key, acc)| {
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
                bytes_total: acc.bytes_total,
                rule: acc.rule,
                rule_payload: acc.rule_payload,
                chains: acc.chains,
                country: acc.country,
                asn: acc.asn,
                last_seen: acc.last_seen,
            }
        })
        .collect()
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
    /// Legacy parameter: The flow streaming interval is now fixed globally to 5s
    /// (see `FLOW_SAMPLER_INTERVAL`) for efficient broadcast deduplication.
    /// This field is kept for API backwards-compatibility with existing dashboard clients.
    #[allow(dead_code)]
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
    let mut frames = state.samplers.subscribe_flows(
        state.statistics_manager.clone(),
        top,
        include_closed,
    );

    ws.on_failed_upgrade(|e| warn!("ws/flows upgrade error: {}", e))
        .on_upgrade(move |mut socket: axum::extract::ws::WebSocket| async move {
            loop {
                tokio::select! {
                    res = frames.recv() => {
                        match res {
                            Ok(frame) => {
                                if let Err(e) = socket.send(Message::Text(frame)).await {
                                    debug!("ws/flows send error: {}", e);
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
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
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::api::StreamSamplers;
    use crate::app::dispatcher::Manager;

    #[tokio::test]
    async fn test_subscribe_flows_broadcast() {
        let mgr = Manager::new();
        let samplers = Arc::new(StreamSamplers::new());
        let mut sub1 = samplers.subscribe_flows(mgr.clone(), 20, true);
        let mut sub2 = samplers.subscribe_flows(mgr.clone(), 20, true);

        // Same top and include_closed should share 1 sampler
        assert_eq!(samplers.active_flow_samplers_count(), 1);

        // First tick happens immediately in tokio interval
        let frame1 = tokio::time::timeout(std::time::Duration::from_millis(300), sub1.recv())
            .await
            .expect("sub1 timed out")
            .expect("sub1 recv error");

        let frame2 = tokio::time::timeout(std::time::Duration::from_millis(300), sub2.recv())
            .await
            .expect("sub2 timed out")
            .expect("sub2 recv error");

        assert_eq!(frame1, frame2);
        assert!(frame1.as_str().starts_with('[') && frame1.as_str().ends_with(']'));

        // Different params should create another sampler
        let mut sub3 = samplers.subscribe_flows(mgr.clone(), 50, false);
        assert_eq!(samplers.active_flow_samplers_count(), 2);
        let frame3 = tokio::time::timeout(std::time::Duration::from_millis(300), sub3.recv())
            .await
            .expect("sub3 timed out")
            .expect("sub3 recv error");
        assert!(frame3.as_str().starts_with('[') && frame3.as_str().ends_with(']'));

        drop(sub1);
        drop(sub2);
        drop(sub3);
    }
}


