use std::{
    fs::{self, metadata},
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime},
};

use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use tokio::sync::RwLock;
use tracing::{info, trace, warn};

use crate::common::utils;

use super::{ProviderVehicleType, ThreadSafeProviderVehicle};

struct Inner {
    updated_at: SystemTime,
    hash: [u8; 16],

    thread_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(handle) = self.thread_handle.take() {
            handle.abort();
        }
    }
}

pub struct Fetcher<U, P> {
    name: String,
    interval: Duration,
    vehicle: ThreadSafeProviderVehicle,
    ticker_interval: Duration,
    inner: Arc<RwLock<Inner>>,
    parser: Arc<P>,
    pub on_update: Option<Arc<U>>,
    cancellation_token: tokio_util::sync::CancellationToken,
}

impl<T, U, P> Fetcher<U, P>
where
    T: Send + Sync + 'static,
    U: Fn(T) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    P: Fn(&[u8]) -> anyhow::Result<T> + Send + Sync + 'static,
{
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        parser: P,
        on_update: Option<U>,
    ) -> Self {
        Self {
            name,
            interval,
            vehicle,
            ticker_interval: interval,
            inner: Arc::new(tokio::sync::RwLock::new(Inner {
                updated_at: SystemTime::UNIX_EPOCH,
                hash: [0; 16],
                thread_handle: None,
            })),
            parser: Arc::new(parser),
            on_update: on_update.map(Arc::new),
            cancellation_token: tokio_util::sync::CancellationToken::new(),
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn vehicle_type(&self) -> ProviderVehicleType {
        self.vehicle.typ()
    }

    pub async fn updated_at(&self) -> DateTime<Utc> {
        self.inner.read().await.updated_at.into()
    }

    pub async fn initial(&self) -> anyhow::Result<T> {
        let mut is_local = false;
        let mut immediately_update = false;
        let mut should_save_cache = false;

        let vehicle_path = self.vehicle.path().to_owned();

        let mut inner = self.inner.write().await;

        let mut content = match metadata(&vehicle_path) {
            Ok(meta) if meta.is_file() => {
                let content = fs::read(&vehicle_path)?;
                is_local = true;
                inner.updated_at = meta.modified()?;
                immediately_update = SystemTime::now()
                    .duration_since(inner.updated_at)
                    .map(|d| d > self.interval)
                    .unwrap_or(true);
                content
            }
            _ => {
                should_save_cache = true;
                inner.updated_at = SystemTime::now();
                self.vehicle.read().await?
            }
        };

        let parser_guard = &self.parser;

        let items = match (parser_guard)(&content) {
            Ok(proxies) => proxies,
            Err(e) => {
                if !is_local {
                    return Err(e);
                }
                warn!(
                    "failed to parse local cache for {}, falling back to remote: {}",
                    self.name, e
                );
                let fetched = self.vehicle.read().await?;
                let proxies = (parser_guard)(&fetched)?;
                content = fetched;
                should_save_cache = true;
                inner.updated_at = SystemTime::now();
                proxies
            }
        };

        if self.vehicle_type() != ProviderVehicleType::File && should_save_cache {
            let p = self.vehicle.path().to_owned();
            let path = Path::new(p.as_str());
            if let Some(prefix) = path.parent() {
                if !prefix.as_os_str().is_empty() && !prefix.exists() {
                    fs::create_dir_all(prefix)?;
                }
            }
            fs::write(self.vehicle.path(), &content)?;
        }

        inner.hash = utils::md5(&content)[..16]
            .try_into()
            .expect("md5 must be 16 bytes");

        drop(inner);

        if !self.ticker_interval.is_zero() {
            self.pull_loop(
                immediately_update,
                tokio::time::interval(self.ticker_interval),
            )
            .await;
        }

        Ok(items)
    }

    pub async fn update(&self) -> anyhow::Result<(T, bool)> {
        Fetcher::<U, P>::update_inner(
            self.inner.clone(),
            self.vehicle.clone(),
            self.parser.clone(),
        )
        .await
    }

    async fn update_inner(
        inner: Arc<RwLock<Inner>>,
        vehicle: ThreadSafeProviderVehicle,
        parser: Arc<P>,
    ) -> anyhow::Result<(T, bool)> {
        let mut this = inner.write().await;
        let content = vehicle.read().await?;
        let proxies = parser(&content)?;

        let now = SystemTime::now();
        let hash = utils::md5(&content)[..16]
            .try_into()
            .expect("md5 must be 16 bytes");

        if hash == this.hash {
            this.updated_at = now;
            filetime::set_file_times(vehicle.path(), now.into(), now.into())?;
            return Ok((proxies, true));
        }

        if vehicle.typ() != ProviderVehicleType::File {
            let p = vehicle.path().to_owned();
            let path = Path::new(p.as_str());
            if let Some(prefix) = path.parent() {
                if !prefix.as_os_str().is_empty() && !prefix.exists() {
                    fs::create_dir_all(prefix)?;
                }
            }

            fs::write(vehicle.path(), &content)?;
        }

        this.hash = hash;
        this.updated_at = now;

        Ok((proxies, false))
    }

    #[cfg(test)]
    pub async fn destroy(&mut self) {
        if let Some(handle) = self.inner.write().await.thread_handle.take() {
            handle.abort();
        }
    }

    pub async fn stop(&self) {
        self.cancellation_token.cancel();
        if let Some(handle) = self.inner.write().await.thread_handle.take() {
            handle.abort();
        }
    }

    async fn pull_loop(
        &self,
        immediately_update: bool,
        mut ticker: tokio::time::Interval,
    ) {
        let weak_inner = Arc::downgrade(&self.inner);
        let vehicle = self.vehicle.clone();
        let parser = self.parser.clone();
        let on_update = self.on_update.clone();
        let name = self.name.clone();
        let fire_immediately = immediately_update;
        let cancel = self.cancellation_token.clone();

        let thread_handle = Some(tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                let Some(inner) = weak_inner.upgrade() else {
                    break;
                };
                let vehicle = vehicle.clone();
                let parser = parser.clone();
                let name = name.clone();
                let on_update = on_update.clone();
                trace!("fetcher {} tick", &name);

                let update = || async move {
                    let (elm, same) =
                        match Fetcher::<U, P>::update_inner(inner, vehicle, parser)
                            .await
                        {
                            Ok((elm, same)) => (elm, same),
                            Err(e) => {
                                warn!("{} update failed: {}", &name, e);
                                return;
                            }
                        };

                    if same {
                        trace!("fetcher {} no update", &name);
                        return;
                    }

                    if let Some(on_update) = on_update {
                        info!("fetcher {} updated", &name);
                        on_update(elm).await;
                    }
                };

                if fire_immediately {
                    update().await;
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = ticker.tick() => {}
                    }
                } else {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = ticker.tick() => {}
                    }
                    update().await;
                }
            }
        }));

        let mut inner_guard = self.inner.write().await;
        if let Some(old_handle) = inner_guard.thread_handle.take() {
            old_handle.abort();
        }
        inner_guard.thread_handle = thread_handle;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::Path,
        sync::Arc,
        time::{Duration, SystemTime},
    };

    use futures::future::BoxFuture;
    use tokio::time::sleep;

    use crate::{
        app::remote_content_manager::providers::{MockProviderVehicle, ProviderVehicleType},
        common::utils,
    };

    use super::Fetcher;

    #[tokio::test]
    async fn test_fetcher() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(32);
        let tx1 = tx.clone();

        let mut mock_vehicle = MockProviderVehicle::new();
        let mock_file = std::env::temp_dir().join(format!(
            "{}-{}",
            "mock_provider_vehicle",
            uuid::Uuid::new_v4()
        ));
        if Path::new(mock_file.to_str().unwrap()).exists() {
            std::fs::remove_file(&mock_file).unwrap();
        }
        std::fs::write(&mock_file, vec![1, 2, 3]).unwrap();

        mock_vehicle
            .expect_path()
            .return_const(mock_file.to_str().unwrap().to_owned());
        mock_vehicle.expect_read().returning(|| Ok(vec![4, 5, 6]));
        mock_vehicle
            .expect_typ()
            .return_const(ProviderVehicleType::File);

        let parser = move |i: &[u8]| -> anyhow::Result<String> {
            let copy = i.to_owned();
            tx1.try_send(copy).unwrap();
            Ok("parsed".to_owned())
        };

        let updater = move |input: String| -> BoxFuture<'static, ()> {
            Box::pin(async move {
                assert_eq!(input, "parsed".to_owned());
            })
        };

        let mut f = Fetcher::new(
            "test_fetcher".to_string(),
            Duration::from_secs(1),
            Arc::new(mock_vehicle),
            parser,
            Some(updater),
        );

        let _ = f.initial().await;

        sleep(Duration::from_secs_f64(5.5)).await;
        f.destroy().await;

        drop(tx);
        drop(f);

        let mut parsed = vec![];

        while let Some(message) = rx.recv().await {
            parsed.push(message);
        }

        assert!(parsed.len() > 5);
        assert_eq!(parsed[0], vec![1, 2, 3]);
        assert_eq!(parsed[1], vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn test_fetcher_corrupt_cache_repaired_and_hash_updated() {
        let mut mock_vehicle = MockProviderVehicle::new();
        let mock_file = std::env::temp_dir().join(format!(
            "{}-{}",
            "mock_corrupt_cache",
            uuid::Uuid::new_v4()
        ));
        let mock_path_str = mock_file.to_str().unwrap().to_owned();

        // Write corrupt bytes to cache file
        std::fs::write(&mock_file, b"corrupted").unwrap();

        mock_vehicle.expect_path().return_const(mock_path_str.clone());
        mock_vehicle
            .expect_read()
            .returning(|| Ok(b"repaired content".to_vec()));
        mock_vehicle
            .expect_typ()
            .return_const(ProviderVehicleType::Http);

        let parser = |i: &[u8]| -> anyhow::Result<String> {
            if i == b"corrupted" {
                anyhow::bail!("corrupted local cache");
            }
            Ok(String::from_utf8_lossy(i).to_string())
        };

        let mut f = Fetcher::new(
            "test_corrupt_cache".to_string(),
            Duration::from_secs(60),
            Arc::new(mock_vehicle),
            parser,
            None::<fn(String) -> BoxFuture<'static, ()>>,
        );

        let res = f.initial().await;
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "repaired content");

        // Verify the cache file on disk has been repaired
        let disk_content = std::fs::read(&mock_file).unwrap();
        assert_eq!(disk_content, b"repaired content");

        // Verify the hash in inner matches the repaired content
        let expected_hash: [u8; 16] = utils::md5(b"repaired content")[..16]
            .try_into()
            .unwrap();
        assert_eq!(f.inner.read().await.hash, expected_hash);

        f.destroy().await;
        let _ = std::fs::remove_file(&mock_file);
    }

    #[tokio::test]
    async fn test_fetcher_future_timestamp_does_not_panic() {
        let mut mock_vehicle = MockProviderVehicle::new();
        let mock_file = std::env::temp_dir().join(format!(
            "{}-{}",
            "mock_future_ts",
            uuid::Uuid::new_v4()
        ));
        let mock_path_str = mock_file.to_str().unwrap().to_owned();

        std::fs::write(&mock_file, b"valid content").unwrap();

        // Set modification time 1 hour into the future
        let future_time = SystemTime::now() + Duration::from_secs(3600);
        filetime::set_file_times(&mock_file, future_time.into(), future_time.into())
            .unwrap();

        mock_vehicle.expect_path().return_const(mock_path_str.clone());
        mock_vehicle
            .expect_read()
            .returning(|| Ok(b"remote content".to_vec()));
        mock_vehicle
            .expect_typ()
            .return_const(ProviderVehicleType::Http);

        let parser = |i: &[u8]| -> anyhow::Result<String> {
            Ok(String::from_utf8_lossy(i).to_string())
        };

        let mut f = Fetcher::new(
            "test_future_ts".to_string(),
            Duration::from_secs(60),
            Arc::new(mock_vehicle),
            parser,
            None::<fn(String) -> BoxFuture<'static, ()>>,
        );

        // initial() should succeed without panicking on duration_since
        let res = f.initial().await;
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "valid content");

        f.destroy().await;
        let _ = std::fs::remove_file(&mock_file);
    }
}
