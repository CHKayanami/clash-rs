use std::{io, time::Duration};

use futures::future::join_all;
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
    let batches = group.member_probe_batches(fallback_url);

    join_all(
        batches
            .iter()
            .map(|(batch_url, members)| outbound_manager.url_test(members, batch_url, timeout)),
    )
    .await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::{
            outbound::manager::OutboundManager,
            remote_content_manager::{
                ProxyManager,
                healthcheck::HealthCheck,
                providers::proxy_provider::PlainProvider,
            },
        },
        proxy::{
            AnyStream, HandlerCommonOptions,
            group::{GroupProxyAPIResponse, urltest},
            mocks::MockDummyOutboundHandler,
            utils::test_utils::noop::NoopResolver,
        },
    };
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn group_url_test_updates_provider_healthcheck_url_used_by_group_selection() {
        let pm = ProxyManager::new(Arc::new(NoopResolver), None);
        let primary_alive = Arc::new(AtomicBool::new(true));
        let backup_hit_on_group_url = Arc::new(AtomicBool::new(false));

        let mut primary_mock = MockDummyOutboundHandler::new();
        primary_mock.expect_name().return_const("primary".to_owned());
        {
            let primary_alive = primary_alive.clone();
            primary_mock.expect_connect_stream().returning(move |_, _| {
                if !primary_alive.load(Ordering::SeqCst) {
                    return Err(io::Error::other("primary is now dead"));
                }
                let (client, mut server) = duplex(1024);
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = server.read(&mut buf).await;
                    let _ = server
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = server.shutdown().await;
                });
                Ok(AnyStream::new(client))
            });
        }
        let primary = OutboundNode::protocol(Arc::new(primary_mock));

        let mut backup_mock = MockDummyOutboundHandler::new();
        backup_mock.expect_name().return_const("backup".to_owned());
        {
            let backup_hit_on_group_url = backup_hit_on_group_url.clone();
            backup_mock.expect_connect_stream().returning(move |sess, _| {
                if sess.destination.host() == "group-url.example" {
                    backup_hit_on_group_url.store(true, Ordering::SeqCst);
                }
                let (client, mut server) = duplex(1024);
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = server.read(&mut buf).await;
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    let _ = server
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = server.shutdown().await;
                });
                Ok(AnyStream::new(client))
            });
        }
        let backup = OutboundNode::protocol(Arc::new(backup_mock));

        let provider_url = "http://provider-url.example/generate_204";
        let group_url = "http://group-url.example/generate_204";
        let provider = Arc::new(
            PlainProvider::new(
                "prov".to_owned(),
                vec![primary.clone(), backup.clone()],
                HealthCheck::new(
                    vec![primary.clone(), backup.clone()],
                    provider_url.to_owned(),
                    0,
                    true,
                    pm.clone(),
                ),
            )
            .unwrap(),
        );

        let group = Arc::new(urltest::Handler::new(
            urltest::HandlerOptions {
                name: "AUTO".to_owned(),
                common_opts: HandlerCommonOptions {
                    url: Some(group_url.to_owned()),
                    ..Default::default()
                },
                ..Default::default()
            },
            0,
            vec![provider],
            pm.clone(),
        ));
        let group_node = OutboundNode::group(group.clone());

        // Initial baseline: primary is faster than backup under provider_url.
        pm.check(
            &vec![primary.clone(), backup.clone()],
            provider_url,
            Some(Duration::from_secs(2)),
        )
        .await;
        assert_eq!(group.get_active_proxy().await.unwrap().name(), "primary");

        // Now primary dies. Running manual `group_url_test` must probe members
        // with the same provider_url that group selection reads, so the
        // subsequent group test switches away from dead primary to backup.
        primary_alive.store(false, Ordering::SeqCst);

        let outbound_manager = Arc::new(OutboundManager::new_for_test_with_proxy_manager(
            HashMap::from([("AUTO".to_owned(), group_node.clone())]),
            pm.clone(),
        ));
        let res = group_url_test(
            &outbound_manager,
            group_node,
            "http://fallback.example/generate_204",
            Duration::from_secs(2),
        )
        .await;
        assert!(
            res.is_ok(),
            "group_url_test must pick newly healthy backup after member probes, got {res:?}"
        );
        assert!(
            !pm.alive_for(&primary, Some(provider_url)),
            "member probe must update the provider healthcheck URL state"
        );
        assert!(
            backup_hit_on_group_url.load(Ordering::SeqCst),
            "group test must route through backup after primary failed"
        );
        assert_eq!(group.get_active_proxy().await.unwrap().name(), "backup");
    }

    #[tokio::test]
    async fn selector_group_url_test_probes_members_by_provider_healthcheck_url() {
        use crate::proxy::group::selector;

        let pm = ProxyManager::new(Arc::new(NoopResolver), None);
        let mut mock = MockDummyOutboundHandler::new();
        mock.expect_name().return_const("hk-1".to_owned());
        mock.expect_connect_stream().returning(|_, _| {
            let (client, mut server) = duplex(1024);
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let _ = server.read(&mut buf).await;
                let _ = server
                    .write_all(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let _ = server.shutdown().await;
            });
            Ok(AnyStream::new(client))
        });
        let node = OutboundNode::protocol(Arc::new(mock));

        let provider_url = "http://provider-hc.example/generate_204";
        let provider = Arc::new(
            PlainProvider::new(
                "remote-prov".to_owned(),
                vec![node.clone()],
                HealthCheck::new(
                    vec![node.clone()],
                    provider_url.to_owned(),
                    0,
                    true,
                    pm.clone(),
                ),
            )
            .unwrap(),
        );
        let sel = Arc::new(
            selector::Handler::new(
                selector::HandlerOptions {
                    name: "GLOBAL".to_owned(),
                    ..Default::default()
                },
                vec![provider],
                Some("hk-1".to_owned()),
            )
            .await,
        );
        let sel_node = OutboundNode::group(sel);

        let outbound_manager = Arc::new(OutboundManager::new_for_test_with_proxy_manager(
            HashMap::from([("GLOBAL".to_owned(), sel_node.clone())]),
            pm.clone(),
        ));

        group_url_test(
            &outbound_manager,
            sel_node,
            "http://fallback.example/generate_204",
            Duration::from_secs(2),
        )
        .await
        .unwrap();

        let (alive, delay) = pm.alive_and_last_delay_for(&node, Some(provider_url));
        assert!(alive);
        assert!(
            delay.is_some(),
            "selector group_url_test must refresh members under their provider's healthcheck_url"
        );
    }
}
