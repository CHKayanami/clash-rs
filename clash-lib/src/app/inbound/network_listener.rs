use crate::{
    common::auth::ThreadSafeAuthenticator,
    config::listener::{InboundOpts, InboundUser},
    proxy::{
        anytls::inbound::{AnytlsInbound, InboundOptions as AnytlsInboundOptions},
        http::HttpInbound,
        inbound::InboundHandlerTrait,
        mixed::MixedInbound,
        socks::inbound::SocksInbound,
        tunnel::TunnelInbound,
    },
};

#[cfg(all(target_os = "linux", feature = "redir"))]
use crate::proxy::redir::RedirInbound;
#[cfg(all(target_os = "linux", feature = "tproxy"))]
use crate::proxy::tproxy::TproxyInbound;

use crate::{
    Dispatcher, Error, Result,
    runner::prepare_service,
};
use futures::future::BoxFuture;
use tracing::{error, info, warn};

#[cfg(feature = "shadowsocks")]
use crate::proxy::shadowsocks::inbound::{InboundOptions, ShadowsocksInbound};
use std::sync::Arc;

const REBIND_ATTEMPTS: usize = 4;
const REBIND_DELAY: std::time::Duration = std::time::Duration::from_millis(10);

#[derive(Clone, Copy)]
enum ListenerTransport {
    Tcp,
    Udp,
}

async fn listen_with_rebind_retry(
    handler: Arc<dyn InboundHandlerTrait>,
    transport: ListenerTransport,
    name: &str,
) -> Result<BoxFuture<'static, Result<()>>> {
    for attempt in 0..REBIND_ATTEMPTS {
        let handler = handler.clone();
        let result = prepare_service(move |ready| async move {
            match transport {
                ListenerTransport::Tcp => handler.listen_tcp(ready).await,
                ListenerTransport::Udp => handler.listen_udp(ready).await,
            }.map_err(Error::from)
        }).await;

        match result {
            Err(Error::Io(e))
                if e.kind() == std::io::ErrorKind::AddrInUse
                    && attempt + 1 < REBIND_ATTEMPTS =>
            {
                let delay = REBIND_DELAY * 2u32.pow(attempt as u32);
                warn!(
                    "handler {} address is still in use; retrying bind in {:?}",
                    name, delay
                );
                tokio::time::sleep(delay).await;
            }
            result => return result,
        }
    }

    unreachable!("rebind loop always returns on its final attempt")
}

pub(crate) async fn build_network_listeners(
    inbound_opts: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    users_rx: Option<tokio::sync::watch::Receiver<Vec<InboundUser>>>,
) -> Result<Vec<BoxFuture<'static, Result<()>>>> {
    let name = &inbound_opts.common_opts().name;
    let addr = inbound_opts.common_opts().listen.0;
    let port = inbound_opts.common_opts().port;
    let handler = build_handler(
        inbound_opts, dispatcher, authenticator, users_rx,
    ).ok_or_else(|| Error::InvalidConfig(format!(
        "could not initialize inbound {name}"
    )))?;
    let mut runners = Vec::new();
    for (enabled, transport, label) in [
        (handler.handle_tcp(), ListenerTransport::Tcp, "TCP"),
        (handler.handle_udp(), ListenerTransport::Udp, "UDP"),
    ] {
        if enabled {
            let runner = listen_with_rebind_retry(
                handler.clone(), transport, name,
            ).await.inspect_err(|e| {
                error!("handler {} {} listen failed: {}", name, label, e);
            })?;
            info!("{} {} listening at: {}:{}", name, label, addr, port);
            runners.push(runner);
        }
    }
    if runners.is_empty() {
        return Err(Error::InvalidConfig(format!("no listener for {name}")));
    }
    Ok(runners)
}

fn build_handler(
    listener: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    #[allow(unused)] users_rx: Option<
        tokio::sync::watch::Receiver<Vec<InboundUser>>,
    >,
) -> Option<Arc<dyn InboundHandlerTrait>> {
    let fw_mark = listener.common_opts().fw_mark;
    match listener {
        InboundOpts::Http { common_opts, .. } => Some(Arc::new(HttpInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),

        InboundOpts::Socks { common_opts, .. } => Some(Arc::new(SocksInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),
        InboundOpts::Mixed { common_opts, .. } => Some(Arc::new(MixedInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),
        #[cfg(feature = "tproxy")]
        InboundOpts::TProxy {
            #[cfg(target_os = "linux")]
            common_opts,
            #[cfg(target_os = "linux")]
            udp,
            ..
        } => {
            #[cfg(target_os = "linux")]
            {
                Some(Arc::new(TproxyInbound::new(
                    (common_opts.listen.0, common_opts.port).into(),
                    common_opts.allow_lan,
                    *udp,
                    dispatcher,
                    fw_mark,
                )))
            }

            #[cfg(not(target_os = "linux"))]
            {
                warn!("tproxy is not supported on this platform");
                None
            }
        }
        #[cfg(feature = "redir")]
        InboundOpts::Redir {
            #[cfg(target_os = "linux")]
            common_opts,
            ..
        } => {
            #[cfg(target_os = "linux")]
            {
                Some(Arc::new(RedirInbound::new(
                    (common_opts.listen.0, common_opts.port).into(),
                    common_opts.allow_lan,
                    dispatcher,
                    fw_mark,
                )))
            }
            #[cfg(not(target_os = "linux"))]
            {
                warn!("redir is not supported on this platform");
                None
            }
        }
        InboundOpts::Tunnel {
            common_opts,
            network,
            target,
        } => TunnelInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            network.clone(),
            target.clone(),
            fw_mark,
        )
        .inspect_err(|x| {
            warn!("tunnel inbound handler failed to create: {x}");
        })
        .map(|x| Arc::new(x) as _)
        .ok(),
        #[cfg(feature = "shadowsocks")]
        InboundOpts::Shadowsocks {
            common_opts,
            udp,
            cipher,
            password,
            users,
        } => {
            // Use the provided watch receiver, or create a static one for
            // non-provider (static config) inbounds whose user list never changes.
            let rx = users_rx
                .unwrap_or_else(|| tokio::sync::watch::channel(users.clone()).1);
            Some(Arc::new(ShadowsocksInbound::new(InboundOptions {
                addr: (common_opts.listen.0, common_opts.port).into(),
                password: password.clone(),
                udp: *udp,
                cipher: cipher.clone(),
                allow_lan: common_opts.allow_lan,
                dispatcher,
                authenticator,
                fw_mark: common_opts.fw_mark,
                users_rx: rx,
            })))
        }
        InboundOpts::Anytls {
            common_opts,
            password,
            certificate,
            private_key,
            fallback,
            users,
        } => {
            let rx = users_rx
                .unwrap_or_else(|| tokio::sync::watch::channel(users.clone()).1);
            match AnytlsInbound::new(AnytlsInboundOptions {
                addr: (common_opts.listen.0, common_opts.port).into(),
                password: password.clone(),
                certificate: certificate.clone(),
                private_key: private_key.clone(),
                fallback: fallback.clone(),
                allow_lan: common_opts.allow_lan,
                dispatcher,
                fw_mark: common_opts.fw_mark,
                users_rx: rx,
            }) {
                Ok(h) => Some(Arc::new(h)),
                Err(e) => {
                    warn!("anytls inbound failed to init: {e}");
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use std::future::pending;
    use async_trait::async_trait;
    use crate::runner::ListenerReady;

    use super::*;

    struct RebindTestHandler {
        attempts: AtomicUsize,
        failures_before_success: usize,
        error_kind: std::io::ErrorKind,
    }

    #[async_trait]
    impl InboundHandlerTrait for RebindTestHandler {
        fn handle_tcp(&self) -> bool {
            true
        }

        fn handle_udp(&self) -> bool {
            false
        }

        async fn listen_tcp(&self, ready: ListenerReady) -> std::io::Result<()> {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
            if attempt < self.failures_before_success {
                Err(std::io::Error::from(self.error_kind))
            } else {
                ready.notify();
                pending().await
            }
        }

        async fn listen_udp(&self, _ready: ListenerReady) -> std::io::Result<()> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn retries_transient_address_in_use() {
        let handler = Arc::new(RebindTestHandler {
            attempts: AtomicUsize::new(0),
            failures_before_success: 2,
            error_kind: std::io::ErrorKind::AddrInUse,
        });

        let _listener = listen_with_rebind_retry(
            handler.clone(), ListenerTransport::Tcp, "test",
        )
            .await
            .unwrap_or_else(|e| panic!("transient address-in-use: {e}"));

        assert_eq!(handler.attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn does_not_retry_other_bind_errors() {
        let handler = Arc::new(RebindTestHandler {
            attempts: AtomicUsize::new(0),
            failures_before_success: usize::MAX,
            error_kind: std::io::ErrorKind::PermissionDenied,
        });

        let result = listen_with_rebind_retry(
            handler.clone(),
            ListenerTransport::Tcp,
            "test",
        )
        .await;

        assert!(matches!(result, Err(Error::Io(e))
            if e.kind() == std::io::ErrorKind::PermissionDenied));
        assert_eq!(handler.attempts.load(Ordering::SeqCst), 1);
    }
}
