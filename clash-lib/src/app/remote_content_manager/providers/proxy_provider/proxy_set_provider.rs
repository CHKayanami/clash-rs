
use super::ProxyProvider;
use crate::{
    Error,
    app::{
        outbound::manager::OutboundManager,
        remote_content_manager::{
            healthcheck::HealthCheck,
            providers::{
                Provider, ProviderType, ProviderVehicleType,
                ThreadSafeProviderVehicle, fetcher::Fetcher,
            },
        },
    },
    common::errors::map_io_error,
    config::internal::proxy::OutboundProxyProtocol,
    proxy::{OutboundNode, RouteChange, utils::{OutboundNodeRegistry, ProviderRegistry, ProviderSnapshot}},
};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use erased_serde::Serialize as ESerialize;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use yaml_serde::Value;
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
    time::Duration,
};
use tracing::{debug, warn};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProviderScheme {
    #[serde(rename = "proxies")]
    proxies: Option<Vec<HashMap<String, Value>>>,
}

type ProxyUpdater = Box<
    dyn Fn(Vec<OutboundNode>) -> BoxFuture<'static, ()>
        + Send
        + Sync
        + 'static,
>;
type ProxyParser = Box<
    dyn Fn(&[u8]) -> anyhow::Result<Vec<OutboundNode>> + Send + Sync + 'static,
>;

pub struct ProxySetProvider {
    fetcher: Fetcher<ProxyUpdater, ProxyParser>,
    hc: Arc<HealthCheck>,
    proxies: ProviderRegistry,
    changes: RouteChange,
}

impl ProxySetProvider {
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        hc: HealthCheck,
        registry: Option<OutboundNodeRegistry>,
    ) -> anyhow::Result<Self> {
        let hc = Arc::new(hc);

        if hc.auto() {
            let hc = hc.clone();
            debug!("kicking off healthcheck for: {}", &name);
            tokio::spawn(async move {
                hc.kick_off().await;
            });
        }

        let proxies = Arc::new(ArcSwap::from_pointee(ProviderSnapshot::default()));
        let proxies_clone = proxies.clone();
        let changes = RouteChange::default();
        let change_updater = changes.clone();

        let n = name.clone();
        let hc_updater = hc.clone();
        let updater: ProxyUpdater = Box::new(
            move |input: Vec<OutboundNode>| -> BoxFuture<'static, ()> {
                let hc = hc_updater.clone();
                let n = n.clone();
                let proxies = proxies_clone.clone();
                let changes = change_updater.clone();
                Box::pin(async move {
                    debug!("updating {} proxies for: {}", n, input.len());
                    proxies.store(Arc::new(ProviderSnapshot::new(input.clone())));
                    changes.notify();
                    hc.update(input).await;
                    tokio::spawn(async move {
                        hc.check().await;
                    });
                })
            },
        );

        // Parsing constructs candidates; only the updater publishes a generation.
        let parser_registry = proxies.clone();
        let fallback_registry = Arc::new(ArcSwap::from_pointee(HashMap::new()));
        let global_registry = registry.as_ref().map(Arc::downgrade);
        let n = name.clone();
        let parser: ProxyParser = Box::new(
            move |input: &[u8]| -> anyhow::Result<Vec<OutboundNode>> {
                let mut val: Value =
                    yaml_serde::from_slice(input).map_err(|x| {
                        Error::InvalidConfig(format!(
                            "proxy provider parse error {n}: {x}"
                        ))
                    })?;
                val.apply_merge().map_err(|x| {
                    Error::InvalidConfig(format!(
                        "proxy provider anchor merge error {n}: {x}"
                    ))
                })?;
                let scheme: ProviderScheme =
                    yaml_serde::from_value(val).map_err(|x| {
                        Error::InvalidConfig(format!(
                            "proxy provider parse error {n}: {x}"
                        ))
                    })?;
                let proxies = scheme.proxies;
                match proxies {
                    Some(proxies) => {
                        let proxies = proxies
                            .into_iter()
                            .filter_map(|x| {
                                match OutboundProxyProtocol::try_from(x) {
                                    Ok(p) => Some(p),
                                    Err(e) => {
                                        warn!(
                                            provider = n.as_str(),
                                            "skipping proxy due to parse error: {e}"
                                        );
                                        None
                                    }
                                }
                            })
                            .collect::<Vec<_>>();
                        let global = global_registry.as_ref()
                            .and_then(Weak::upgrade)
                            .unwrap_or_else(|| fallback_registry.clone());
                        let proxies = OutboundManager::load_provider_outbounds(
                            proxies, &global, Some(&parser_registry),
                        );
                        match proxies {
                            Ok(proxies) => Ok(proxies),
                            Err(e) => {
                                warn!(
                                    provider = n.as_str(),
                                    "proxy provider failed to construct handler: \
                                     {e}"
                                );
                                Err(e.into())
                            }
                        }
                    }
                    _ => Err(Error::InvalidConfig(format!("{n}: proxies is empty"))
                        .into()),
                }
            },
        );

        let fetcher = Fetcher::new(name, interval, vehicle, parser, Some(updater));
        Ok(Self {
            fetcher,
            hc,
            proxies,
            changes,
        })
    }
}

#[async_trait]
impl Provider for ProxySetProvider {
    fn name(&self) -> &str {
        self.fetcher.name()
    }

    fn vehicle_type(&self) -> ProviderVehicleType {
        self.fetcher.vehicle_type()
    }

    fn typ(&self) -> ProviderType {
        ProviderType::Proxy
    }

    async fn initialize(&self) -> std::io::Result<()> {
        let ele = self.fetcher.initial().await.map_err(map_io_error)?;
        debug!("{} initialized with {} proxies", self.name(), ele.len());
        if let Some(updater) = self.fetcher.on_update.as_ref() {
            updater(ele).await;
        }
        Ok(())
    }

    async fn update(&self) -> std::io::Result<()> {
        let (ele, same) = self.fetcher.update().await.map_err(map_io_error)?;
        debug!(
            "{} updated with {} proxies, same? {}",
            self.name(),
            ele.len(),
            same
        );
        if !same && let Some(updater) = self.fetcher.on_update.as_ref() {
            updater(ele).await;
        }
        Ok(())
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn ESerialize + Send>> {
        let mut m: HashMap<String, Box<dyn ESerialize + Send>> = HashMap::new();

        m.insert("name".to_owned(), Box::new(self.name().to_string()));
        m.insert("type".to_owned(), Box::new(self.typ().to_string()));
        m.insert(
            "vehicleType".to_owned(),
            Box::new(self.vehicle_type().to_string()),
        );

        m.insert(
            "updatedAt".to_owned(),
            Box::new(self.fetcher.updated_at().await),
        );

        m
    }
}

#[async_trait]
impl ProxyProvider for ProxySetProvider {
    fn route_changes(&self) -> Option<RouteChange> {
        Some(self.changes.clone())
    }

    fn proxies(&self) -> Arc<Vec<OutboundNode>> {
        self.proxies.load().proxies.clone()
    }

    fn touch(&self) {
        self.hc.touch();
    }

    async fn healthcheck(&self) {
        self.hc.check().await;
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::time::sleep;

    use crate::app::{
        dns::MockClashResolver,
        remote_content_manager::{
            ProxyManager,
            healthcheck::HealthCheck,
            providers::{
                MockProviderVehicle, Provider, ProviderVehicleType,
                proxy_provider::{
                    ProxyProvider, proxy_set_provider::ProxySetProvider,
                },
            },
        },
    };

    #[tokio::test]
    async fn dialer_snapshot_changes_only_after_successful_commit() {
        use std::fs;
        use parking_lot::Mutex;
        use tempfile::tempdir;
        use crate::proxy::utils::test_utils::noop::NoopResolver;

        let directory = tempdir().unwrap();
        let path = directory.path().join("provider.yaml");
        let config = |port| format!("proxies:\n  - type: direct\n    name: local-entry\n  - type: socks5\n    name: exit\n    server: 127.0.0.1\n    port: {port}\n    dialer-proxy: local-entry\n").into_bytes();
        let content = Arc::new(Mutex::new(config(1080)));
        let source = content.clone();
        let mut vehicle = MockProviderVehicle::new();
        vehicle.expect_read().returning(move || Ok(source.lock().clone()));
        vehicle.expect_path().return_const(path.to_string_lossy().into_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);
        let manager = ProxyManager::new(Arc::new(NoopResolver), None);
        let hc = HealthCheck::new(vec![], "invalid-url".to_owned(), 0, true, manager);
        let provider = ProxySetProvider::new("snapshot".to_owned(), Duration::ZERO, Arc::new(vehicle), hc, None).unwrap();
        provider.initialize().await.unwrap();
        let mut changes = provider.route_changes().unwrap().subscribe();
        let original = provider.proxies();
        let entry = original[0].clone();
        let exit = original[1].clone();
        assert!(exit.dialer_dependency().unwrap().ptr_eq(&entry));

        provider.update().await.unwrap();
        assert!(!changes.has_changed().unwrap());
        assert!(Arc::ptr_eq(&original, &provider.proxies()));
        assert!(exit.dialer_dependency().unwrap().ptr_eq(&entry));

        *content.lock() = config(1081);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(provider.update().await.is_err());
        assert!(!changes.has_changed().unwrap());
        assert!(Arc::ptr_eq(&original, &provider.proxies()));
        assert!(exit.dialer_dependency().unwrap().ptr_eq(&entry));

        fs::remove_dir(&path).unwrap();
        provider.update().await.unwrap();
        assert!(changes.has_changed().unwrap());
        changes.borrow_and_update();
        let committed = provider.proxies();
        assert!(!Arc::ptr_eq(&original, &committed));
        assert!(!committed[0].ptr_eq(&entry));
        assert!(committed[1].dialer_dependency().unwrap().ptr_eq(&committed[0]));
        assert!(exit.dialer_dependency().unwrap().ptr_eq(&committed[0]));
    }

    #[tokio::test]
    async fn test_proxy_set_provider() {
        let mut mock_vehicle = MockProviderVehicle::new();

        mock_vehicle.expect_read().returning(|| {
            Ok(r#"
proxies:
  - name: "socks5"
    type: socks5
    server: localhost
    port: 1080
    udp: true
"#
            .as_bytes()
            .to_vec())
        });
        mock_vehicle
            .expect_path()
            .return_const("/tmp/test_proxy_set_provider".to_owned());
        mock_vehicle
            .expect_typ()
            .return_const(ProviderVehicleType::File);

        let vehicle = Arc::new(mock_vehicle);

        let mock_resolver = MockClashResolver::new();

        let latency_manager = ProxyManager::new(Arc::new(mock_resolver), None);
        let hc = HealthCheck::new(
            vec![],
            "http://www.google.com".to_owned(),
            0,
            true,
            latency_manager.clone(),
        );

        let provider = ProxySetProvider::new(
            "test".to_owned(),
            Duration::from_secs(1),
            vehicle,
            hc,
            None,
        )
        .unwrap();

        assert_eq!(provider.proxies().len(), 0);

        provider.initialize().await.unwrap();

        sleep(Duration::from_secs_f64(1.5)).await;

        assert_eq!(provider.proxies().len(), 1);
    }

    #[tokio::test]
    async fn test_proxy_set_provider_with_anchor() {
        let mut mock_vehicle = MockProviderVehicle::new();

        mock_vehicle.expect_read().returning(|| {
            Ok(r#"
node_base: &node_base
  type: socks5
  server: localhost
  port: 1080
  udp: true

proxies:
  - name: "socks5"
    <<: *node_base
"#
            .as_bytes()
            .to_vec())
        });
        mock_vehicle
            .expect_path()
            .return_const("/tmp/test_proxy_set_provider_anchor".to_owned());
        mock_vehicle
            .expect_typ()
            .return_const(ProviderVehicleType::File);

        let vehicle = Arc::new(mock_vehicle);

        let mock_resolver = MockClashResolver::new();

        let latency_manager = ProxyManager::new(Arc::new(mock_resolver), None);
        let hc = HealthCheck::new(
            vec![],
            "http://www.google.com".to_owned(),
            0,
            true,
            latency_manager.clone(),
        );

        let provider = ProxySetProvider::new(
            "test_anchor".to_owned(),
            Duration::from_secs(1),
            vehicle,
            hc,
            None,
        )
        .unwrap();

        assert_eq!(provider.proxies().len(), 0);

        provider.initialize().await.unwrap();

        sleep(Duration::from_secs_f64(1.5)).await;

        assert_eq!(provider.proxies().len(), 1);
    }
}
