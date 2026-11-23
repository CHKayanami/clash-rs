use std::net::IpAddr;
use std::sync::Arc;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
use std::sync::RwLock;

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::app::api::AppState;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
use crate::proxy::ebpf::offloader::{DirectOffloader, OffloadQueryError};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OffloadStatusCounts {
    pub domain_owners: usize,
    pub direct_ip_owners: usize,
    pub max_domain_owners: usize,
    pub max_direct_ip_owners: usize,
    pub tracked_v4: usize,
    pub tracked_v6: usize,
    pub max_v4_ips: usize,
    pub max_v6_ips: usize,
    pub desired: usize,
    pub applied: usize,
    pub dirty: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EbpfStatusResponse {
    pub enabled: bool,
    pub auto_direct_offload: bool,
    pub ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts: Option<OffloadStatusCounts>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DomainIpStatus {
    pub ip: IpAddr,
    pub family: &'static str,
    pub direct_count: u16,
    pub proxy_count: u16,
    pub desired: bool,
    pub applied: bool,
    pub dirty: bool,
    pub status: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DomainOwnerDetail {
    pub action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
    pub rule_offloadable: bool,
    pub last_seen: u64,
    pub ips: Vec<DomainIpStatus>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DomainQueryResponse {
    pub query: String,
    pub normalized: String,
    pub found: bool,
    pub active_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<DomainOwnerDetail>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DirectIpOwnerDetail {
    pub action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
    pub rule_offloadable: bool,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IpActionCountsDetail {
    pub direct: u16,
    pub proxy: u16,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IpQueryResponse {
    pub ip: IpAddr,
    pub family: &'static str,
    pub active_mode: String,
    pub static_match: &'static str,
    pub effective_status: &'static str,
    pub desired: bool,
    pub applied: bool,
    pub dirty: bool,
    pub counts: IpActionCountsDetail,
    pub domain_owner_count: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_ip_owner: Option<DirectIpOwnerDetail>,
}

#[derive(Clone)]
pub struct EbpfInspectHandle {
    enabled: bool,
    auto_direct_offload: bool,
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    offloader: Arc<RwLock<Option<DirectOffloader>>>,
}

impl EbpfInspectHandle {
    pub fn disabled() -> Self {
        Self::new(false, false)
    }

    pub fn new(enabled: bool, auto_direct_offload: bool) -> Self {
        Self {
            enabled,
            auto_direct_offload: enabled && auto_direct_offload,
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            offloader: Arc::new(RwLock::new(None)),
        }
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub fn set_offloader(&self, offloader: Option<DirectOffloader>) {
        if let Ok(mut guard) = self.offloader.write() {
            *guard = offloader;
        }
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub fn clear_offloader(&self) {
        self.set_offloader(None);
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    fn get_offloader(&self) -> Option<DirectOffloader> {
        self.offloader.read().ok().and_then(|guard| guard.clone())
    }

    async fn status(&self) -> Result<EbpfStatusResponse, (StatusCode, &'static str)> {
        if !self.enabled {
            return Ok(EbpfStatusResponse {
                enabled: false,
                auto_direct_offload: false,
                ready: false,
                active_mode: None,
                counts: None,
            });
        }
        if !self.auto_direct_offload {
            return Ok(EbpfStatusResponse {
                enabled: true,
                auto_direct_offload: false,
                ready: false,
                active_mode: None,
                counts: None,
            });
        }

        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        if let Some(offloader) = self.get_offloader() {
            return match offloader.status().await {
                Ok((mode, counts)) => Ok(EbpfStatusResponse {
                    enabled: true,
                    auto_direct_offload: true,
                    ready: true,
                    active_mode: Some(mode.to_owned()),
                    counts: Some(counts),
                }),
                Err(OffloadQueryError::NotReady) => Ok(EbpfStatusResponse {
                    enabled: true,
                    auto_direct_offload: true,
                    ready: false,
                    active_mode: None,
                    counts: None,
                }),
                Err(err) => Err(map_query_error(err)),
            };
        }

        Ok(EbpfStatusResponse {
            enabled: true,
            auto_direct_offload: true,
            ready: false,
            active_mode: None,
            counts: None,
        })
    }

    async fn query_domain(&self, name: &str) -> Result<DomainQueryResponse, (StatusCode, &'static str)> {
        if !self.enabled {
            return Err((StatusCode::BAD_REQUEST, "eBPF is not enabled"));
        }
        if !self.auto_direct_offload {
            return Err((StatusCode::BAD_REQUEST, "eBPF auto direct offload is not enabled"));
        }

        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            let Some(offloader) = self.get_offloader() else {
                return Err((StatusCode::SERVICE_UNAVAILABLE, "eBPF offloader is not ready"));
            };
            offloader.query_domain(name).await.map_err(map_query_error)
        }

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            let _ = name;
            Err((StatusCode::BAD_REQUEST, "eBPF is not supported on this platform"))
        }
    }

    async fn query_ip(&self, raw_ip: &str) -> Result<IpQueryResponse, (StatusCode, &'static str)> {
        if !self.enabled {
            return Err((StatusCode::BAD_REQUEST, "eBPF is not enabled"));
        }
        if !self.auto_direct_offload {
            return Err((StatusCode::BAD_REQUEST, "eBPF auto direct offload is not enabled"));
        }

        let ip: IpAddr = raw_ip
            .trim()
            .parse()
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid IP address"))?;

        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            let Some(offloader) = self.get_offloader() else {
                return Err((StatusCode::SERVICE_UNAVAILABLE, "eBPF offloader is not ready"));
            };
            offloader.query_ip(ip).await.map_err(map_query_error)
        }

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            let _ = ip;
            Err((StatusCode::BAD_REQUEST, "eBPF is not supported on this platform"))
        }
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn map_query_error(err: OffloadQueryError) -> (StatusCode, &'static str) {
    match err {
        OffloadQueryError::InvalidDomain => (StatusCode::BAD_REQUEST, "Invalid domain name"),
        OffloadQueryError::QueueBusy => {
            (StatusCode::SERVICE_UNAVAILABLE, "eBPF offloader query queue is busy")
        }
        OffloadQueryError::TimedOut => {
            (StatusCode::GATEWAY_TIMEOUT, "eBPF offloader query timed out")
        }
        OffloadQueryError::NotReady => {
            (StatusCode::SERVICE_UNAVAILABLE, "eBPF offloader is not ready")
        }
    }
}

pub fn routes(handle: EbpfInspectHandle) -> Router<Arc<AppState>> {
    Router::new()
        .route("/status", get(get_status))
        .route("/offload/domain", get(query_domain))
        .route("/offload/ip", get(query_ip))
        .with_state(handle)
}

#[derive(Deserialize)]
struct DomainQueryParams {
    name: String,
}

#[derive(Deserialize)]
struct IpQueryParams {
    ip: String,
}

async fn get_status(State(handle): State<EbpfInspectHandle>) -> impl IntoResponse {
    match handle.status().await {
        Ok(resp) => Json(resp).into_response(),
        Err((status, msg)) => (status, msg).into_response(),
    }
}

async fn query_domain(
    State(handle): State<EbpfInspectHandle>,
    Query(params): Query<DomainQueryParams>,
) -> impl IntoResponse {
    match handle.query_domain(&params.name).await {
        Ok(resp) => Json(resp).into_response(),
        Err((status, msg)) => (status, msg).into_response(),
    }
}

async fn query_ip(
    State(handle): State<EbpfInspectHandle>,
    Query(params): Query<IpQueryParams>,
) -> impl IntoResponse {
    match handle.query_ip(&params.ip).await {
        Ok(resp) => Json(resp).into_response(),
        Err((status, msg)) => (status, msg).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_handle_reports_disabled_and_rejects_queries() {
        let handle = EbpfInspectHandle::disabled();
        let status = handle.status().await.unwrap();
        assert!(!status.enabled);
        assert!(!status.auto_direct_offload);
        assert!(!status.ready);
        assert!(status.counts.is_none());

        let dom_err = handle.query_domain("example.com").await.unwrap_err();
        assert_eq!(dom_err.0, StatusCode::BAD_REQUEST);

        let ip_err = handle.query_ip("1.1.1.1").await.unwrap_err();
        assert_eq!(ip_err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn enabled_without_auto_offload_rejects_queries() {
        let handle = EbpfInspectHandle::new(true, false);
        let status = handle.status().await.unwrap();
        assert!(status.enabled);
        assert!(!status.auto_direct_offload);
        assert!(!status.ready);

        let ip_err = handle.query_ip("1.1.1.1").await.unwrap_err();
        assert_eq!(ip_err.0, StatusCode::BAD_REQUEST);
    }
}
