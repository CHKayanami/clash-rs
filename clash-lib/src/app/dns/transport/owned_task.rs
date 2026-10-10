use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::task::JoinHandle;
use tokio_util::task::AbortOnDropHandle;

pub struct OwnedTask {
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl OwnedTask {
    pub fn spawn<F>(future: F, active: Arc<AtomicUsize>) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        active.fetch_add(1, Ordering::SeqCst);
        let guard = ActiveTaskGuard(active);
        let handle = tokio::spawn(async move {
            let _guard = guard;
            future.await;
        });
        Self {
            handle: Mutex::new(Some(handle)),
        }
    }

    pub async fn shutdown(&self, timeout: Duration) {
        let Some(handle) = self.handle.lock().take() else {
            return;
        };
        let mut handle = AbortOnDropHandle::new(handle);
        if tokio::time::timeout(timeout, &mut handle).await.is_err() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

impl Drop for OwnedTask {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.get_mut().take() {
            handle.abort();
        }
    }
}

struct ActiveTaskGuard(Arc<AtomicUsize>);

impl Drop for ActiveTaskGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;

    #[tokio::test]
    async fn abort_before_first_poll_releases_task_count() {
        let active = Arc::new(AtomicUsize::new(0));
        let task = OwnedTask::spawn(pending(), active.clone());
        drop(task);
        tokio::time::timeout(Duration::from_secs(1), async {
            while active.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_shutdown_aborts_worker() {
        let active = Arc::new(AtomicUsize::new(0));
        let task = OwnedTask::spawn(pending(), active.clone());
        let mut shutdown = Box::pin(task.shutdown(Duration::from_secs(60)));
        tokio::select! {
            biased;
            _ = &mut shutdown => panic!("pending worker exited"),
            _ = tokio::task::yield_now() => {}
        }
        drop(shutdown);
        tokio::time::timeout(Duration::from_secs(1), async {
            while active.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
    }
}
