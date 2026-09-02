use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, State, WebSocketUpgrade, ws::Message},
    response::IntoResponse,
};

use serde::Serialize;
use tracing::{debug, warn};

use crate::app::api::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TrafficResponse {
    up: u64,
    down: u64,
    upload_total: u64,
    download_total: u64,
    conn_count: usize,
}
pub async fn handle(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_failed_upgrade(move |e| {
        warn!("ws upgrade error: {} with {}", e, addr);
    })
    .on_upgrade(move |mut socket| async move {
        let mgr = state.statistics_manager.clone();
        let mut buf = Vec::with_capacity(128);
        loop {
            let (up, down, upload_total, download_total, conn_count) =
                mgr.traffic_summary();
            let res = TrafficResponse {
                up,
                down,
                upload_total,
                download_total,
                conn_count,
            };
            buf.clear();
            if let Err(e) = serde_json::to_writer(&mut buf, &res) {
                warn!("Failed to serialize traffic stats: {}", e);
                continue;
            }

            let Ok(j_str) = std::str::from_utf8(&buf) else {
                continue;
            };

            if let Err(e) = socket.send(Message::Text(j_str.into())).await {
                debug!("ws send error: {}", e);
                break;
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    })
}
