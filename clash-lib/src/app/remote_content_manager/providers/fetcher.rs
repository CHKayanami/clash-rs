use std::{
    fs::{self, metadata},
    path::Path,
    sync::{Arc, atomic::{AtomicBool, Ordering}},
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
    update_retry: Option<Arc<AtomicBool>>,
}

impl<U, P> Drop for Fetcher<U, P> {
    fn drop(&mut self) {
        // A sleeping pull loop may still hold Inner, so Inner::drop alone
        // cannot promptly release its vehicle, parser and update callback.
        self.cancellation_token.cancel();
    }
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
            update_retry: None,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub(crate) fn with_update_retry(mut self, retry: Arc<AtomicBool>) -> Self {
        self.update_retry = Some(retry);
        self
    }

    pub fn vehicle_type(&self) -> ProviderVehicleType {
        self.vehicle.typ()
    }

    pub async fn updated_at(&self) -> DateTime<Utc> {
        self.inner.read().await.updated_at.into()
    }

    /// Finish an in-flight update before stopping, so its listener handles
    /// remain available for the inbound manager to clean up.
    pub async fn stop_and_wait(&self) {
        self.cancellation_token.cancel();
        let handle = self.inner.write().await.thread_handle.take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
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
        let update_retry = self.update_retry.clone();

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
                let update_retry = update_retry.clone();
                trace!("fetcher {} tick", &name);

                let update_cancel = cancel.clone();
                let update = || async move {
                    // Cancelling fetch/parse is safe before the listener update
                    // callback starts. Once started, let that transaction finish.
                    let result = tokio::select! {
                        biased;
                        _ = update_cancel.cancelled() => return,
                        result = Fetcher::<U, P>::update_inner(inner, vehicle, parser) => result,
                    };
                    let (elm, same) = match result {
                        Ok(result) => result,
                        Err(e) => {
                            warn!("{} update failed: {}", &name, e);
                            return;
                        }
                    };

                    if same && !update_retry.as_ref()
                        .is_some_and(|retry| retry.load(Ordering::Acquire))
                    {
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
    use super::super::ProviderVehicle;

    struct BlockingVehicle {
        started: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl ProviderVehicle for BlockingVehicle {
        async fn read(&self) -> std::io::Result<Vec<u8>> {
            self.started.notify_one();
            futures::future::pending().await
        }

        fn path(&self) -> &str { "unused" }
        fn typ(&self) -> ProviderVehicleType { ProviderVehicleType::Http }
    }

    #[tokio::test]
    async fn stopping_fetcher_cancels_in_flight_download() {
        let vehicle = Arc::new(BlockingVehicle {
            started: tokio::sync::Notify::new(),
        });
        let fetcher = Fetcher::new(
            "cancel-test".into(), Duration::from_secs(3600), vehicle.clone(),
            |input: &[u8]| -> anyhow::Result<Vec<u8>> { Ok(input.to_vec()) },
            Some(|_: Vec<u8>| -> BoxFuture<'static, ()> {
                Box::pin(async { panic!("cancelled download reached callback") })
            }),
        );
        fetcher.pull_loop(true, tokio::time::interval(Duration::from_secs(3600))).await;
        vehicle.started.notified().await;
        tokio::time::timeout(Duration::from_secs(1), fetcher.stop_and_wait())
            .await.expect("stop waited for the blocked download");
    }

    #[tokio::test]
    async fn stopping_fetcher_finishes_in_flight_callback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.yaml");
        std::fs::write(&path, b"updated").unwrap();
        let mut vehicle = MockProviderVehicle::new();
        vehicle.expect_path().return_const(path.to_str().unwrap().to_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::File);
        vehicle.expect_read().returning(|| Ok(b"updated".to_vec()));
        let started = Arc::new(tokio::sync::Notify::new());
        let finish = Arc::new(tokio::sync::Notify::new());
        let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
        let committed = Arc::new(std::sync::Mutex::new(Some(committed_tx)));
        let callback_started = started.clone();
        let callback_finish = finish.clone();
        let fetcher = Arc::new(Fetcher::new(
            "transaction-test".into(), Duration::from_secs(3600), Arc::new(vehicle),
            |input: &[u8]| -> anyhow::Result<Vec<u8>> { Ok(input.to_vec()) },
            Some(move |_: Vec<u8>| -> BoxFuture<'static, ()> {
                let started = callback_started.clone();
                let finish = callback_finish.clone();
                let committed = committed.clone();
                Box::pin(async move {
                    started.notify_one();
                    finish.notified().await;
                    committed.lock().unwrap().take().unwrap().send(()).unwrap();
                })
            }),
        ));
        fetcher.pull_loop(true, tokio::time::interval(Duration::from_secs(3600))).await;
        started.notified().await;
        let stopping_fetcher = fetcher.clone();
        let stop = tokio::spawn(async move { stopping_fetcher.stop_and_wait().await });
        fetcher.cancellation_token.cancelled().await;
        assert!(!stop.is_finished());
        finish.notify_one();
        tokio::time::timeout(Duration::from_secs(1), stop).await.unwrap().unwrap();
        committed_rx.await.expect("stop interrupted the update transaction");
    }

    #[tokio::test]
    async fn dropping_fetcher_releases_sleeping_update_resources() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.yaml");
        std::fs::write(&path, b"unchanged").unwrap();
        let ticked = Arc::new(tokio::sync::Notify::new());
        let notify_tick = ticked.clone();
        let mut vehicle = MockProviderVehicle::new();
        vehicle.expect_path().return_const(path.to_str().unwrap().to_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::File);
        vehicle.expect_read().returning(move || {
            notify_tick.notify_one();
            Ok(b"unchanged".to_vec())
        });
        let resource = Arc::new(());
        let weak = Arc::downgrade(&resource);
        let parser = move |input: &[u8]| -> anyhow::Result<Vec<u8>> {
            assert!(Arc::strong_count(&resource) > 0);
            Ok(input.to_vec())
        };
        let fetcher = Fetcher::new(
            "drop-test".into(), Duration::from_secs(3600), Arc::new(vehicle),
            parser, None::<fn(Vec<u8>) -> BoxFuture<'static, ()>>,
        );
        fetcher.initial().await.unwrap();
        ticked.notified().await;
        tokio::task::yield_now().await;
        drop(fetcher);
        tokio::time::timeout(Duration::from_secs(1), async {
            while weak.strong_count() != 0 {
                tokio::task::yield_now().await;
            }
        }).await.expect("sleeping provider retained its parser after drop");
    }

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
