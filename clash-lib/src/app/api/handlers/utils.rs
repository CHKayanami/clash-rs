use std::{io, time::Duration};

use http::{HeaderMap, header};
use serde::Deserialize;

use crate::{
    app::outbound::manager::ThreadSafeOutboundManager, proxy::OutboundNode,
};

/// Shared query-string parameters for all latency-test endpoints.
#[derive(Deserialize)]
pub struct DelayRequest {
    pub url: String,
    pub timeout: u16,
}

/// Test all members before testing the group so automatic selection uses the
/// fresh results. The returned latency and group history describe the same
/// request through the group.
pub async fn group_url_test(
    outbound_manager: &ThreadSafeOutboundManager,
    proxy: OutboundNode,
    fallback_url: &str,
    timeout: Duration,
) -> io::Result<(Duration, Duration)> {
    let group = proxy.as_group().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "proxy is not a group")
    })?;
    let latency_test_url = group.get_latency_test_url();
    let url = latency_test_url.as_deref().unwrap_or(fallback_url);
    let members = group.get_proxies().await;

    outbound_manager.url_test(&members, url, timeout).await;
    let results = outbound_manager.url_test(&vec![proxy], url, timeout).await;
    match results.into_iter().next() {
        Some(result) => result,
        None => Err(io::Error::other("missing latency result for group")),
    }
}

pub fn is_request_websocket(header: &HeaderMap) -> bool {
    header
        .get(header::CONNECTION)
        .and_then(|x| x.to_str().ok().map(|x| x.to_ascii_lowercase()))
        // Firefox sends "Connection: keep-alive, Upgrade"
        .is_some_and(|x| x.contains(&"upgrade".to_ascii_lowercase()))
        && header
            .get(header::UPGRADE)
            .and_then(|x| x.to_str().ok().map(|x| x.to_ascii_lowercase()))
            == Some("websocket".to_ascii_lowercase())
}
