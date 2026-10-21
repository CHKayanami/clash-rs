use std::{path::PathBuf, sync::Arc};

use tokio::sync::{Mutex, broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Error, GlobalState, Result, RuntimeComponents, create_components,
    app::{
        api::{ApiRunner, RuntimeContext},
        logging::{LogEvent, set_log_level},
        net::NetworkConfig,
    },
    config::{InternalConfig, config::Controller, def::LogLevel},
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

    async fn stop_api_instance(api: &ApiRunner, context: &ServiceContext) {
        let _ = api.stop().await;
        context.tracker().close();
        context.tracker().wait().await;
    }

    async fn stop_api(&self) {
        Self::stop_api_instance(&self.api_listener, &self.api_service_context).await;
    }

    async fn start_api_and_publish(
        &self, components: &RuntimeComponents, config: &InternalConfig,
        update_log_level: &mut impl FnMut(LogLevel) -> anyhow::Result<()>,
    ) -> Result<(Arc<ApiRunner>, ServiceContext)> {
        let (api, context) = self.api_for(components, config.general.controller.clone());
        let result = async {
            api.start(&context).await?;
            self.publish(components, config, update_log_level).await
        }.await;
        if let Err(error) = result {
            // This generation is not owned by RuntimeState until publication succeeds.
            // Release its listener before rollback attempts to bind the old API.
            Self::stop_api_instance(&api, &context).await;
            return Err(error);
        }
        Ok((api, context))
    }

    async fn publish(
        &self, components: &RuntimeComponents, config: &InternalConfig,
        update_log_level: &mut impl FnMut(LogLevel) -> anyhow::Result<()>,
    ) -> Result<()> {
        let mut global = self.global_state.lock().await;
        update_log_level(config.general.log_level)?;
        global.log_level = config.general.log_level;
        #[cfg(feature = "tun")]
        {
            global.tunnel_runner = components.tun_runner.clone();
        }
        global.dns_listener = components.dns_listener.clone();
        Ok(())
    }

    async fn restore(
        &mut self, network: NetworkConfig,
        update_log_level: &mut impl FnMut(LogLevel) -> anyhow::Result<()>,
    ) -> Result<()> {
        network.apply();
        let restored = create_components(
            PathBuf::from(&self.components.cwd),
            self.active_config.clone(), Some(&self.components),
            Some(self.fatal_tx.clone()),
            Some(self.components.dns_prepared.clone()),
        ).await?;
        if let Err(e) = restored.start_all().await {
            restored.stop_all().await;
            return Err(e);
        }
        self.stop_api().await;
        let (api, context) = match self.start_api_and_publish(
            &restored, &self.active_config, update_log_level,
        ).await {
            Ok(api) => api,
            Err(error) => {
                restored.stop_all().await;
                return Err(error);
            }
        };
        self.components = restored;
        self.api_listener = api;
        self.api_service_context = context;
        Ok(())
    }

    pub async fn reload(&mut self, config: InternalConfig) -> Result<()> {
        self.reload_with_log_level(config, set_log_level).await
    }

    async fn reload_with_log_level(
        &mut self, config: InternalConfig,
        mut update_log_level: impl FnMut(LogLevel) -> anyhow::Result<()>,
    ) -> Result<()> {
        // Preparation shares persistent resources and leaves the old listeners
        // and global network defaults untouched.
        let next = create_components(
            PathBuf::from(&self.components.cwd), config.clone(),
            Some(&self.components),
            Some(self.fatal_tx.clone()), None,
        ).await?;
        let previous_network = NetworkConfig::capture();
        self.components.stop_all().await;
        next.network_config.apply();

        let result = async {
            next.start_all().await?;
            self.stop_api().await;
            self.start_api_and_publish(&next, &config, &mut update_log_level).await
        }.await;

        match result {
            Ok((api, context)) => {
                self.components = next;
                self.api_listener = api;
                self.api_service_context = context;
                self.active_config = config;
                info!("configuration reload completed");
                Ok(())
            }
            Err(error) => {
                next.stop_all().await;
                if let Err(restore_error) = self.restore(
                    previous_network, &mut update_log_level,
                ).await {
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
    use crate::app::net::{get_default_outbound_interface, get_tun_somark};
    use serial_test::serial;
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::time::{Duration, timeout};
    use std::net::IpAddr;
    use crate::app::dns::query::{DnsName, QType, QueryContext};
    use crate::app::dns::response::ResponseTemplate;
    use crate::app::dns::resolver::router::config::RequestAction;
    use std::{io::ErrorKind, path::Path};
    use clash_dns::DNSError as ServerDNSError;

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
            dir.to_path_buf(), config.clone(), None, Some(fatal_tx.clone()), None,
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
            fatal_tx,
        }, fatal_rx)
    }

    #[tokio::test]
    #[serial]
    async fn dns2_listener_starts_and_reloads_without_legacy_dns() {
        let _restore = RestoreNetwork(NetworkConfig::capture());
        let dir = tempfile::tempdir().unwrap();
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let config = Config::Str(format!(r#"
mode: direct
tun:
  enable: false
dns2:
  enable: true
  listen:
    udp: {address}
    tcp: {address}
  hosts:
    dns2.example: 192.0.2.42
"#)).try_parse().unwrap();
        let (mut runtime, mut fatal_rx) = runtime_for_config(dir.path(), config).await;
        let query = QueryContext::new(
            DnsName::from_domain("dns2.example").unwrap(), QType::A,
        );
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for attempt in 0..2 {
            if attempt != 0 {
                runtime.reload(runtime.active_config.clone()).await.unwrap();
            }
            assert!(runtime.components.dns_enabled);
            assert_eq!(runtime.components.dns_listen.udp, Some(address));
            drop(TcpStream::connect(address).await.unwrap());
            socket.send_to(query.wire(), address).await.unwrap();
            let mut response = [0u8; 512];
            let (length, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut response))
                .await.unwrap().unwrap();
            let response = ResponseTemplate::validate(&query, &response[..length]).unwrap();
            assert_eq!(response.answer_ips().as_ref(), &["192.0.2.42".parse::<IpAddr>().unwrap()]);
            assert!(fatal_rx.try_recv().is_err());
        }

        let previous = runtime.components.dns_resolver.clone();
        let mut invalid = runtime.active_config.clone();
        invalid.dns.dns2.as_mut().unwrap().request_fallback =
            RequestAction::Route("missing".into());
        let error = runtime.reload(invalid).await.unwrap_err();
        assert!(error.to_string().contains("unknown dns2 upstream 'missing'"));
        assert!(Arc::ptr_eq(&previous, &runtime.components.dns_resolver));
        drop(TcpStream::connect(address).await.unwrap());
        assert!(fatal_rx.try_recv().is_err());
        drop(previous);

        let internal_only = Config::Str(
            "mode: direct\ntun:\n  enable: false\ndns2:\n  enable: true\n".into(),
        ).try_parse().unwrap();
        runtime.reload(internal_only).await.unwrap();
        tokio::task::yield_now().await;
        assert!(runtime.components.dns_enabled);
        assert!(runtime.components.dns_listen.udp.is_none());
        assert!(fatal_rx.try_recv().is_err());
        drop(TcpListener::bind(address).await.unwrap());
        drop(UdpSocket::bind(address).await.unwrap());
        runtime.stop().await;
    }

    #[tokio::test]
    #[serial]
    async fn encrypted_dns2_reload_resolves_relative_certificates_and_restores_on_failure() {
        use rcgen::generate_simple_self_signed;
        use std::fs;
        use anyhow::anyhow;
        use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::TlsConnector;

        let _restore = RestoreNetwork(NetworkConfig::capture());
        setup_default_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        fs::write(dir.path().join("dns.crt"), cert.cert.pem()).unwrap();
        fs::write(dir.path().join("dns.key"), cert.signing_key.serialize_pem()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let client = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client));
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let config = Config::Str(format!(r#"
mode: direct
tun:
  enable: false
dns2:
  enable: true
  listen:
    dot:
      addr: {address}
      ca-cert: dns.crt
      ca-key: dns.key
  hosts:
    dns2.example: 192.0.2.42
"#)).try_parse().unwrap();
        let (mut runtime, mut fatal_rx) = runtime_for_config(dir.path(), config).await;
        let query = QueryContext::new(DnsName::from_domain("dns2.example").unwrap(), QType::A);
        for attempt in 0..5 {
            if attempt == 1 {
                runtime.reload(runtime.active_config.clone()).await.unwrap();
            } else if attempt == 2 {
                let mut invalid = runtime.active_config.clone();
                invalid.dns.listen.dot.as_mut().unwrap().ca_key = Some("missing.key".into());
                assert!(runtime.reload(invalid).await.is_err());
            } else if attempt == 3 {
                // A failed in-place rotation must leave the active listener
                // untouched, including existing TLS material.
                fs::write(dir.path().join("dns.key"), b"invalid key").unwrap();
                let resolver = runtime.components.dns_resolver.clone();
                assert!(runtime.reload(runtime.active_config.clone()).await.is_err());
                assert!(Arc::ptr_eq(&resolver, &runtime.components.dns_resolver));
            } else if attempt == 4 {
                // Fail after the new listeners have started and invalidate
                // the file during publication: rollback must use the snapshot.
                fs::write(dir.path().join("dns.key"), cert.signing_key.serialize_pem()).unwrap();
                let mut fail_once = true;
                let result = runtime.reload_with_log_level(runtime.active_config.clone(), |_| {
                    if fail_once {
                        fail_once = false;
                        fs::write(dir.path().join("dns.key"), b"invalid key").unwrap();
                        Err(anyhow!("publication failed after certificate preparation"))
                    } else { Ok(()) }
                }).await;
                assert!(result.unwrap_err().to_string().contains("publication failed"));
            }
            let mut stream = connector.connect(ServerName::try_from("localhost").unwrap(),
                TcpStream::connect(address).await.unwrap()).await.unwrap();
            stream.write_u16(query.wire().len() as u16).await.unwrap();
            stream.write_all(query.wire()).await.unwrap();
            let length = timeout(Duration::from_secs(2), stream.read_u16()).await.unwrap().unwrap();
            let mut answer = vec![0; length as usize];
            stream.read_exact(&mut answer).await.unwrap();
            let answer = ResponseTemplate::validate(&query, &answer).unwrap();
            assert_eq!(answer.answer_ips().as_ref(), &["192.0.2.42".parse::<IpAddr>().unwrap()]);
            assert!(fatal_rx.try_recv().is_err());
        }
        runtime.stop().await;
        let _rebound = TcpListener::bind(address).await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn publish_failure_releases_new_api_before_rollback() {
        let _restore = RestoreNetwork(NetworkConfig::capture());
        for fail_rollback in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = reservation.local_addr().unwrap();
            drop(reservation);
            let config = Config::Str(format!(
                "mode: direct\nexternal-controller: {address}\nsecret: test-secret\ntun:\n  enable: false\n",
            )).try_parse().unwrap();
            let (mut runtime, mut fatal_rx) = runtime_for_config(dir.path(), config).await;
            let previous_level = runtime.active_config.general.log_level;
            let mut next = runtime.active_config.clone();
            next.general.log_level = LogLevel::Debug;
            let mut attempts = 0;
            let error = runtime.reload_with_log_level(next, |_| {
                attempts += 1;
                if attempts == 1 || fail_rollback {
                    Err(anyhow::anyhow!("injected log filter failure"))
                } else {
                    Ok(())
                }
            }).await.unwrap_err();

            // Both publications were reached after successfully binding the same port.
            assert_eq!(attempts, 2);
            assert!(error.to_string().contains("injected log filter failure"));
            assert_eq!(runtime.active_config.general.log_level, previous_level);
            assert_eq!(runtime.global_state.lock().await.log_level, previous_level);
            if fail_rollback {
                assert!(runtime.shutdown_token.is_cancelled());
                assert!(fatal_rx.try_recv().is_ok());
            } else {
                assert!(!runtime.shutdown_token.is_cancelled());
                assert!(fatal_rx.try_recv().is_err());
                drop(TcpStream::connect(address).await.unwrap());
                runtime.reload(runtime.active_config.clone()).await.unwrap();
                drop(TcpStream::connect(address).await.unwrap());
            }
            runtime.stop().await;
            // Neither failed generation may leave a listener behind.
            drop(TcpListener::bind(address).await.unwrap());
        }
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
