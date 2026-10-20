use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::task::spawn_blocking;

use crate::app::{api::AppState, memory::memory_details};

#[derive(Deserialize)]
pub struct GetMemoryQuery {
    pub interval: Option<u64>,
}

#[derive(Serialize)]
pub struct GetMemoryResponse {
    pub inuse: usize,
    pub oslimit: usize,
}

pub async fn handle(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mgr = state.statistics_manager.clone();
    let snapshot = GetMemoryResponse {
        inuse: mgr.memory_usage(),
        oslimit: 0,
    };
    Json(snapshot).into_response()
}

pub async fn details() -> impl IntoResponse {
    // /proc reads and allocator epoch refreshes must not block Tokio workers.
    match spawn_blocking(memory_details).await {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": error.to_string() })),
        ).into_response(),
    }
}
