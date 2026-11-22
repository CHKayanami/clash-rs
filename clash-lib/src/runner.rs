use std::{borrow::Cow, future::Future, sync::Arc};

use crate::{Error, Result as ClashResult};

use async_trait::async_trait;
use futures::future::BoxFuture;
use tokio::sync::oneshot;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

/// Sent only after all fallible listener initialization has completed.
#[derive(Default)]
pub(crate) struct ListenerReady(Option<oneshot::Sender<()>>);

impl ListenerReady {
    pub fn notify(self) {
        if let Some(tx) = self.0 {
            let _ = tx.send(());
        }
    }
}

/// Drive initialization before transferring the listener to a supervised task.
/// On failure, dropping the future releases any partially initialized resources.
pub(crate) async fn prepare_service<F>(
    service: impl FnOnce(ListenerReady) -> F,
) -> ClashResult<BoxFuture<'static, ClashResult<()>>>
where
    F: Future<Output = ClashResult<()>> + Send + 'static,
{
    let (tx, rx) = oneshot::channel();
    let mut future: BoxFuture<'static, ClashResult<()>> =
        Box::pin(service(ListenerReady(Some(tx))));
    tokio::select! {
        result = &mut future => {
            result?;
            Err(Error::Operation(
                "listener exited during initialization".to_string(),
            ))
        }
        result = rx => {
            result.map_err(|_| Error::Operation(
                "listener did not report readiness".to_string(),
            ))?;
            Ok(future)
        }
    }
}

/// Guard that triggers a fatal error if a critical background task exits unexpectedly.
///
/// If the task is cleanly cancelled via the associated [`CancellationToken`],
/// the guard drops silently. Otherwise (panic, early return, unhandled error),
/// it dispatches an error to the fatal channel to initiate process-level shutdown
/// and prevent the system from becoming a deaf "zombie process".
pub struct CriticalTaskGuard {
    name: Cow<'static, str>,
    lifecycle_token: CancellationToken,
    fatal_tx: tokio::sync::mpsc::Sender<crate::Error>,
}

impl CriticalTaskGuard {
    pub fn new(
        name: impl Into<Cow<'static, str>>,
        lifecycle_token: CancellationToken,
        fatal_tx: tokio::sync::mpsc::Sender<crate::Error>,
    ) -> Self {
        Self {
            name: name.into(),
            lifecycle_token,
            fatal_tx,
        }
    }
}

impl Drop for CriticalTaskGuard {
    fn drop(&mut self) {
        if !self.lifecycle_token.is_cancelled() {
            let err = crate::Error::Operation(format!(
                "critical background task '{}' exited unexpectedly",
                self.name
            ));
            let _ = self.fatal_tx.try_send(err);
        }
    }
}

/// Shared execution context passed to an [`AsyncService`].
///
/// It combines a [`CancellationToken`] for cooperative shutdown signalling,
/// a [`TaskTracker`] for tracking background tasks, and an optional fatal channel
/// for critical task supervisory alerting.
#[derive(Clone)]
pub struct ServiceContext {
    cancellation_token: CancellationToken,
    tracker: TaskTracker,
    fatal_tx: Option<tokio::sync::mpsc::Sender<crate::Error>>,
}

impl ServiceContext {
    pub fn new(cancellation_token: CancellationToken) -> Self {
        Self {
            cancellation_token,
            tracker: TaskTracker::new(),
            fatal_tx: None,
        }
    }

    pub fn with_fatal_tx(
        cancellation_token: CancellationToken,
        fatal_tx: tokio::sync::mpsc::Sender<crate::Error>,
    ) -> Self {
        Self {
            cancellation_token,
            tracker: TaskTracker::new(),
            fatal_tx: Some(fatal_tx),
        }
    }

    #[inline]
    pub fn cancellation_token(&self) -> &CancellationToken {
        &self.cancellation_token
    }

    #[inline]
    pub fn tracker(&self) -> &TaskTracker {
        &self.tracker
    }

    pub(crate) fn report_fatal(&self, message: String) {
        if let Some(tx) = &self.fatal_tx {
            let _ = tx.try_send(Error::Operation(message));
        }
        self.cancellation_token.cancel();
    }

    /// Spawns a background task tracked by the service context's [`TaskTracker`].
    pub fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.tracker.spawn(future)
    }

    /// Spawns a critical task tied to the service context's cancellation token.
    pub fn spawn_critical<F>(
        &self,
        name: impl Into<Cow<'static, str>>,
        future: F,
    ) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.spawn_critical_with_token(name, self.cancellation_token.clone(), future)
    }

    /// Spawns a critical task whose planned shutdown is controlled by
    /// `lifecycle_token` (e.g. a per-listener stop token).
    pub fn spawn_critical_with_token<F>(
        &self,
        name: impl Into<Cow<'static, str>>,
        lifecycle_token: CancellationToken,
        future: F,
    ) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let name = name.into();
        let guard = self.fatal_tx.as_ref().map(|tx| {
            CriticalTaskGuard::new(name, lifecycle_token, tx.clone())
        });

        self.spawn(async move {
            let _guard = guard;
            future.await
        })
    }
}

/// A service with structured, asynchronous lifecycle.
#[async_trait]
pub trait AsyncService: Send + Sync {
    /// Start the service asynchronously. Any background tasks should be spawned
    /// via `ctx.spawn(...)` so they are properly tracked by the [`TaskTracker`].
    async fn start(&self, ctx: &ServiceContext) -> Result<(), crate::Error>;

    /// Signal the service to stop and clean up any external resources (e.g. routes, interfaces).
    async fn stop(&self) -> Result<(), crate::Error> {
        Ok(())
    }
}

pub type ArcService = Arc<dyn AsyncService>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_critical_task_fires_on_unexpected_exit() {
        let token = CancellationToken::new();
        let (fatal_tx, mut fatal_rx) = mpsc::channel(1);
        let ctx = ServiceContext::with_fatal_tx(token, fatal_tx);

        ctx.spawn_critical_with_token(
            "test_critical",
            ctx.cancellation_token().clone(),
            async {
                // Task exits immediately without cancellation
            },
        );

        let err = tokio::time::timeout(Duration::from_millis(500), fatal_rx.recv())
            .await
            .expect("should receive fatal alert before timeout")
            .expect("fatal channel should have a message");

        assert!(err.to_string().contains("test_critical"));
    }

    #[tokio::test]
    async fn test_critical_task_silent_on_clean_cancel() {
        let token = CancellationToken::new();
        let (fatal_tx, mut fatal_rx) = mpsc::channel(1);
        let ctx = ServiceContext::with_fatal_tx(token.clone(), fatal_tx);

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let barrier_clone = barrier.clone();

        ctx.spawn_critical_with_token("test_clean", token.clone(), async move {
            barrier_clone.wait().await;
        });

        token.cancel();
        barrier.wait().await;

        ctx.tracker().close();
        ctx.tracker().wait().await;

        assert!(
            fatal_rx.try_recv().is_err(),
            "should not fire fatal error on clean cancel"
        );
    }

    #[tokio::test]
    async fn test_critical_task_silent_on_service_cancel() {
        let context_token = CancellationToken::new();
        let service_token = CancellationToken::new();
        let (fatal_tx, mut fatal_rx) = mpsc::channel(1);
        let ctx = ServiceContext::with_fatal_tx(context_token, fatal_tx);

        let task_token = service_token.clone();
        ctx.spawn_critical_with_token(
            "test_service",
            service_token.clone(),
            async move {
                task_token.cancelled().await;
            },
        );

        service_token.cancel();
        ctx.tracker().close();
        ctx.tracker().wait().await;

        assert!(
            fatal_rx.try_recv().is_err(),
            "planned service stop must not be fatal"
        );
    }
}
