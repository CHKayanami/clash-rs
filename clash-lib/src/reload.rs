use std::{path::PathBuf, sync::Arc};

use tokio::sync::{Mutex, broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Error, GlobalState, Result, RuntimeComponents, create_components,
    app::{api::{ApiRunner, RuntimeContext}, logging::LogEvent, net::NetworkConfig},
    config::{InternalConfig, config::Controller},
    runner::{AsyncService, ServiceContext},
};

pub(super) struct RuntimeState {
    pub components: RuntimeComponents,
    pub api_listener: Arc<ApiRunner>,
    pub api_service_context: ServiceContext,
    pub active_config: InternalConfig,
    pub global_state: Arc<Mutex<GlobalState>>,
    pub log_tx: broadcast::Sender<LogEvent>,
    pub shutdown_token: CancellationToken,
    pub fatal_tx: mpsc::Sender<Error>,
    pub dns_collect_file: Option<String>,
}

impl RuntimeState {
    fn api_for(
        &self,
        components: &RuntimeComponents,
        controller: Controller,
    ) -> (Arc<ApiRunner>, ServiceContext) {
        let context = RuntimeContext::new(
            components.inbound_manager.clone(),
            components.dispatcher.clone(),
            self.global_state.clone(),
            components.dns_resolver.clone(),
            components.outbound_manager.clone(),
            components.statistics_manager.clone(),
            components.cache_store.clone(),
            components.router.clone(),
            components.cwd.clone(),
            components.dns_listen.clone(),
            components.dns_enabled,
        );
        let api = Arc::new(ApiRunner::from_context(
            controller, self.log_tx.clone(), context,
            Some(self.shutdown_token.child_token()),
        ));
        let service_context = ServiceContext::with_fatal_tx(
            self.shutdown_token.child_token(), self.fatal_tx.clone(),
        );
        (api, service_context)
    }

    async fn stop_api(&self) {
        let _ = self.api_listener.stop().await;
        self.api_service_context.tracker().close();
        self.api_service_context.tracker().wait().await;
    }

    async fn publish(&self, components: &RuntimeComponents, config: &InternalConfig) {
        let mut global = self.global_state.lock().await;
        global.log_level = config.general.log_level;
        #[cfg(feature = "tun")]
        {
            global.tunnel_runner = components.tun_runner.clone();
        }
        global.dns_listener = components.dns_listener.clone();
    }

    async fn restore(&mut self, network: NetworkConfig) -> Result<()> {
        network.apply();
        let restored = create_components(
            PathBuf::from(&self.components.cwd),
            self.active_config.clone(), Some(&self.components),
            self.dns_collect_file.clone(), Some(self.fatal_tx.clone()),
        ).await?;
        if let Err(e) = restored.start_all().await {
            restored.stop_all().await;
            return Err(e);
        }
        self.stop_api().await;
        let (api, context) = self.api_for(
            &restored, self.api_listener.controller_config().clone(),
        );
        if let Err(e) = api.start(&context).await {
            restored.stop_all().await;
            return Err(e);
        }
        self.publish(&restored, &self.active_config).await;
        self.components = restored;
        self.api_listener = api;
        self.api_service_context = context;
        Ok(())
    }

    pub async fn reload(&mut self, config: InternalConfig) -> Result<()> {
        // Preparation shares persistent resources and leaves the old listeners
        // and global network defaults untouched.
        let next = create_components(
            PathBuf::from(&self.components.cwd), config.clone(),
            Some(&self.components), self.dns_collect_file.clone(),
            Some(self.fatal_tx.clone()),
        ).await?;
        let previous_network = NetworkConfig::capture();
        self.components.stop_all().await;
        next.network_config.apply();

        let result = async {
            next.start_all().await?;
            self.stop_api().await;
            let (api, context) = self.api_for(
                &next, config.general.controller.clone(),
            );
            api.start(&context).await?;
            Ok::<_, Error>((api, context))
        }.await;

        match result {
            Ok((api, context)) => {
                self.publish(&next, &config).await;
                self.components = next;
                self.api_listener = api;
                self.api_service_context = context;
                self.active_config = config;
                info!("configuration reload completed");
                Ok(())
            }
            Err(error) => {
                next.stop_all().await;
                if let Err(restore_error) = self.restore(previous_network).await {
                    let message = format!(
                        "reload failed: {error}; rollback failed: {restore_error}"
                    );
                    let _ = self.fatal_tx.try_send(Error::Operation(message.clone()));
                    self.shutdown_token.cancel();
                    return Err(Error::Operation(message));
                }
                Err(error)
            }
        }
    }

    pub async fn stop(&self) {
        self.components.stop_all().await;
        self.stop_api().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, setup_default_crypto_provider};
    use crate::config::def::LogLevel;
    use crate::app::net::{get_default_outbound_interface, get_tun_somark};
    use serial_test::serial;
    use tokio::net::TcpListener;
    use std::{io::ErrorKind, path::Path};
    use watfaq_dns::DNSError as ServerDNSError;

    struct RestoreNetwork(NetworkConfig);

    impl Drop for RestoreNetwork {
        fn drop(&mut self) {
            self.0.apply();
        }
    }

    async fn runtime(
        dir: &Path,
    ) -> (RuntimeState, mpsc::Receiver<Error>) {
        setup_default_crypto_provider();
        let config = Config::Str("mode: direct\ntun:\n  enable: false\n".into())
            .try_parse().unwrap();
        runtime_for_config(dir, config).await
    }

    async fn runtime_for_config(
        dir: &Path, config: InternalConfig,
    ) -> (RuntimeState, mpsc::Receiver<Error>) {
        setup_default_crypto_provider();
        let (fatal_tx, fatal_rx) = mpsc::channel(16);
        let components = create_components(
            dir.to_path_buf(), config.clone(), None, None, Some(fatal_tx.clone()),
        ).await.unwrap();
        let (reload_tx, _) = mpsc::channel(1);
        let global_state = Arc::new(Mutex::new(GlobalState {
            log_level: config.general.log_level,
            #[cfg(feature = "tun")]
            tunnel_runner: components.tun_runner.clone(),
            dns_listener: components.dns_listener.clone(),
            reload_tx,
            cwd: components.cwd.clone(),
            config_path: None,
        }));
        let context = RuntimeContext::new(
            components.inbound_manager.clone(), components.dispatcher.clone(),
            global_state.clone(), components.dns_resolver.clone(),
            components.outbound_manager.clone(), components.statistics_manager.clone(),
            components.cache_store.clone(), components.router.clone(),
            components.cwd.clone(), components.dns_listen.clone(), components.dns_enabled,
        );
        let shutdown_token = CancellationToken::new();
        let (log_tx, _) = broadcast::channel(16);
        let api_listener = Arc::new(ApiRunner::from_context(
            config.general.controller.clone(), log_tx.clone(), context,
            Some(shutdown_token.child_token()),
        ));
        let api_service_context = ServiceContext::with_fatal_tx(
            shutdown_token.child_token(), fatal_tx.clone(),
        );
        components.start_all().await.unwrap();
        api_listener.start(&api_service_context).await.unwrap();
        (RuntimeState {
            components, api_listener, api_service_context,
            active_config: config, global_state, log_tx, shutdown_token,
            fatal_tx, dns_collect_file: None,
        }, fatal_rx)
    }

    #[tokio::test]
    #[serial]
    async fn reload_releases_previous_generation() {
        let _restore = RestoreNetwork(NetworkConfig::capture());
        for (respect_rules, dns2, bind_provider) in [
            (false, false, false), (true, false, false),
            (false, true, false), (false, false, true),
            (true, false, true), (false, true, true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let rules = dir.path().join("rules.yaml");
            std::fs::write(&rules, "payload: [example.test]\n").unwrap();
            let provider = if bind_provider {
                format!(
                    "rule-providers:\n  local:\n    type: http\n    url: http://127.0.0.1:9/rules\n    path: {}\n    proxy: DIRECT\n    interval: 0\n    behavior: domain\n",
                    serde_json::to_string(rules.to_str().unwrap()).unwrap(),
                )
            } else { String::new() };
            let dns_config = if dns2 {
                "dns2:\n  enable: true\n  upstreams:\n    - tag: local\n      type: local\n      servers: [udp://127.0.0.1:9]\n  routing:\n    request:\n      - rule-set: [local]\n        upstream: local\n      - fallback: local\n".to_string()
            } else {
                format!(
                    "dns:\n  enable: true\n  respect-rules: {respect_rules}\n  nameserver: [udp://127.0.0.1:9]\n  nameserver-policy:\n    rule-set:local: udp://127.0.0.1:9\n",
                )
            };
            let config = Config::Str(format!(
                "mode: direct\ntun:\n  enable: false\n{dns_config}{provider}",
            )).try_parse().unwrap();
            let (mut runtime, _) = runtime_for_config(dir.path(), config).await;
            for _ in 0..3 {
                let dns = Arc::downgrade(&runtime.components.dns_resolver);
                let router = Arc::downgrade(&runtime.components.router);
                let outbound = Arc::downgrade(&runtime.components.outbound_manager);
                let dispatcher = Arc::downgrade(&runtime.components.dispatcher);
                let inbound = Arc::downgrade(&runtime.components.inbound_manager);
                let statistics = Arc::downgrade(&runtime.components.statistics_manager);
                runtime.reload(runtime.active_config.clone()).await.unwrap();
                let released = tokio::time::timeout(
                    std::time::Duration::from_secs(1), async {
                        while dns.strong_count() != 0 || router.strong_count() != 0
                            || outbound.strong_count() != 0
                            || dispatcher.strong_count() != 0
                            || inbound.strong_count() != 0
                            || statistics.strong_count() != 0
                        {
                            tokio::task::yield_now().await;
                        }
                    },
                ).await;
                assert!(released.is_ok(),
                    "respect-rules={respect_rules}, dns2={dns2}, provider={bind_provider}: old generation retained: dns={}, router={}, outbound={}, dispatcher={}, inbound={}, statistics={}",
                    dns.strong_count(), router.strong_count(), outbound.strong_count(),
                    dispatcher.strong_count(), inbound.strong_count(), statistics.strong_count());
            }
            runtime.stop().await;
        }
    }

    #[tokio::test]
    #[serial]
    async fn preparation_failure_preserves_network_defaults() {
        let _restore = RestoreNetwork(NetworkConfig::capture());
        NetworkConfig::resolve(Some("lo0"), true, Some(42)).apply();
        let previous_interface = get_default_outbound_interface().map(|i| i.name.clone());
        let dir = tempfile::tempdir().unwrap();
        let (mut runtime, mut fatal_rx) = runtime(dir.path()).await;
        let mut next = runtime.active_config.clone();
        next.tun.enable = true;
        next.tun.so_mark = Some(99);
        next.general.mmdb = Some("missing.mmdb".into());
        next.general.mmdb_download_url = Some("http://[".into());

        assert!(runtime.reload(next).await.is_err());
        assert_eq!(get_tun_somark(), Some(42));
        assert_eq!(get_default_outbound_interface().map(|i| i.name.clone()), previous_interface);
        assert!(!runtime.shutdown_token.is_cancelled());
        assert!(fatal_rx.try_recv().is_err());
        runtime.stop().await;
    }

    #[tokio::test]
    #[serial]
    async fn failed_start_restores_network_and_can_reload_again() {
        let _restore = RestoreNetwork(NetworkConfig::capture());
        NetworkConfig::resolve(Some("lo0"), true, Some(42)).apply();
        let previous_interface = get_default_outbound_interface().map(|i| i.name.clone());
        let dir = tempfile::tempdir().unwrap();
        let (mut runtime, mut fatal_rx) = runtime(dir.path()).await;
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let previous_log_level = runtime.global_state.lock().await.log_level;
        let next = Config::Str(format!(
            "mode: direct\nlog-level: debug\ntun:\n  enable: false\ndns:\n  enable: true\n  listen:\n    udp: {address}\n    tcp: {address}\n  nameserver: [udp://127.0.0.1:9]\n",
            address = occupied.local_addr().unwrap(),
        )).try_parse().unwrap();

        let error = runtime.reload(next).await.unwrap_err();
        assert!(matches!(error, Error::DNSServerError(ServerDNSError::Io(e))
            if e.kind() == ErrorKind::AddrInUse));
        assert_eq!(get_tun_somark(), Some(42));
        assert_eq!(get_default_outbound_interface().map(|i| i.name.clone()), previous_interface);
        assert!(!runtime.active_config.dns.enable);
        assert_eq!(runtime.global_state.lock().await.log_level, previous_log_level);
        assert!(!runtime.shutdown_token.is_cancelled());
        assert!(fatal_rx.try_recv().is_err());

        let mut next = runtime.active_config.clone();
        next.general.log_level = LogLevel::Debug;
        runtime.reload(next).await.unwrap();
        assert_eq!(runtime.global_state.lock().await.log_level, LogLevel::Debug);
        assert_eq!(get_tun_somark(), None);
        assert!(get_default_outbound_interface().is_none());
        runtime.stop().await;
    }

    #[cfg(feature = "tun")]
    #[tokio::test]
    #[serial]
    async fn failed_tun_start_restores_network_defaults() {
        let _restore = RestoreNetwork(NetworkConfig::capture());
        NetworkConfig::resolve(Some("lo0"), true, Some(42)).apply();
        let previous_interface = get_default_outbound_interface().map(|i| i.name.clone());
        let dir = tempfile::tempdir().unwrap();
        let (mut runtime, mut fatal_rx) = runtime(dir.path()).await;
        let mut next = runtime.active_config.clone();
        next.tun.enable = true;
        next.tun.so_mark = Some(99);
        // Rejected before creating a device or modifying OS routes.
        next.tun.device_id = "unsupported://device".into();

        let error = runtime.reload(next).await.unwrap_err();
        assert!(matches!(error, Error::InvalidConfig(message)
            if message.contains("invalid device id")));
        assert_eq!(get_tun_somark(), Some(42));
        assert_eq!(get_default_outbound_interface().map(|i| i.name.clone()), previous_interface);
        assert!(!runtime.shutdown_token.is_cancelled());
        assert!(fatal_rx.try_recv().is_err());
        runtime.stop().await;
    }


    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[tokio::test]
    #[serial]
    async fn failed_ebpf_start_restores_network_defaults() {
        use crate::config::def::EbpfConfig;

        let _restore = RestoreNetwork(NetworkConfig::capture());
        NetworkConfig::resolve(None, false, Some(42)).apply();
        let dir = tempfile::tempdir().unwrap();
        let (mut runtime, mut fatal_rx) = runtime(dir.path()).await;
        let mut next = runtime.active_config.clone();
        let mut ebpf = EbpfConfig::default();
        ebpf.enable = true;
        ebpf.routing_mark = Some(99);
        // Exercise the initializer's error path before touching host networking.
        ebpf.lan.proxy_src_macs.push("invalid-mac".into());
        next.ebpf = Some(ebpf);

        let error = runtime.reload(next).await.unwrap_err();
        assert!(matches!(error, Error::Operation(message)
            if message.contains("failed to init ebpf inbound")
                && message.contains("invalid MAC address")));
        assert_eq!(get_tun_somark(), Some(42));
        assert!(!runtime.shutdown_token.is_cancelled());
        assert!(fatal_rx.try_recv().is_err());
        runtime.reload(runtime.active_config.clone()).await.unwrap();
        assert_eq!(get_tun_somark(), None);
        runtime.stop().await;
    }

}
