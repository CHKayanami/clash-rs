use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arc_swap::ArcSwapOption;
use parking_lot::Mutex;
use tokio::sync::Notify;

mod guards {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use super::{BuildFailure, LifecycleSlot, SlotState};

    pub struct CloseGuard<'a, T> {
        slot: &'a LifecycleSlot<T>,
        armed: bool,
    }

    impl<'a, T> CloseGuard<'a, T> {
        pub fn new(slot: &'a LifecycleSlot<T>) -> Self {
            Self { slot, armed: true }
        }

        pub fn complete(mut self) {
            self.slot.active.store(None);
            {
                let mut inner = self.slot.inner.lock();
                inner.state = SlotState::Closed;
            }
            self.slot.close_count.fetch_add(1, Ordering::SeqCst);
            self.armed = false;
            self.slot.changed.notify_waiters();
        }
    }

    impl<T> Drop for CloseGuard<'_, T> {
        fn drop(&mut self) {
            if !self.armed {
                return;
            }
            self.slot.active.store(None);
            {
                let mut inner = self.slot.inner.lock();
                if let SlotState::Closing { owner, .. } = &mut inner.state {
                    *owner = false;
                }
            }
            self.slot.changed.notify_waiters();
        }
    }

    pub struct BuildGuard<'a, T> {
        slot: &'a LifecycleSlot<T>,
        generation: u64,
        armed: bool,
    }

    impl<'a, T> BuildGuard<'a, T> {
        pub fn new(slot: &'a LifecycleSlot<T>, generation: u64) -> Self {
            Self {
                slot,
                generation,
                armed: true,
            }
        }

        pub fn publish(mut self, value: T) -> Arc<T> {
            let value = Arc::new(value);
            {
                let mut inner = self.slot.inner.lock();
                inner.state = SlotState::Ready(Arc::clone(&value));
            }
            self.slot.active.store(Some(Arc::clone(&value)));
            self.armed = false;
            self.slot.changed.notify_waiters();
            value
        }

        pub fn fail(mut self, message: Arc<str>) {
            self.record_failure(message);
            self.armed = false;
        }

        fn record_failure(&self, message: Arc<str>) {
            self.slot.active.store(None);
            {
                let mut inner = self.slot.inner.lock();
                if matches!(
                    inner.state,
                    SlotState::Building { generation } if generation == self.generation
                ) {
                    inner.state = SlotState::Closed;
                    inner.last_failure = Some(BuildFailure {
                        generation: self.generation,
                        message,
                    });
                }
            }
            self.slot.changed.notify_waiters();
        }
    }

    impl<T> Drop for BuildGuard<'_, T> {
        fn drop(&mut self) {
            if self.armed {
                self.record_failure(Arc::from("transport initialization cancelled"));
            }
        }
    }
}

use guards::{BuildGuard, CloseGuard};

struct BuildFailure {
    generation: u64,
    message: Arc<str>,
}

enum SlotState<T> {
    Building { generation: u64 },
    Ready(Arc<T>),
    Closing { value: Arc<T>, owner: bool },
    Closed,
}

struct SlotInner<T> {
    state: SlotState<T>,
    generation: u64,
    last_failure: Option<BuildFailure>,
}

pub struct LifecycleSlot<T> {
    active: ArcSwapOption<T>,
    inner: Mutex<SlotInner<T>>,
    changed: Notify,
    init_count: AtomicUsize,
    close_count: AtomicUsize,
}

impl<T> Default for LifecycleSlot<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> LifecycleSlot<T> {
    pub fn new() -> Self {
        Self {
            active: ArcSwapOption::new(None),
            inner: Mutex::new(SlotInner {
                state: SlotState::Closed,
                generation: 0,
                last_failure: None,
            }),
            changed: Notify::new(),
            init_count: AtomicUsize::new(0),
            close_count: AtomicUsize::new(0),
        }
    }

    pub fn init_count(&self) -> usize {
        self.init_count.load(Ordering::SeqCst)
    }

    pub fn close_count(&self) -> usize {
        self.close_count.load(Ordering::SeqCst)
    }

    pub async fn acquire<F, Fut>(&self, build: F) -> anyhow::Result<Arc<T>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<T>>,
    {
        if let Some(ready) = self.active.load_full() {
            return Ok(ready);
        }

        let mut build = Some(build);
        let mut waited_generation = None;
        loop {
            let notified = self.changed.notified();
            let action = {
                let mut inner = self.inner.lock();
                if let Some(generation) = waited_generation
                    && let Some(failure) = &inner.last_failure
                    && failure.generation == generation
                {
                    return Err(anyhow::anyhow!("{}", failure.message));
                }
                match &inner.state {
                    SlotState::Ready(value) => {
                        let value = Arc::clone(value);
                        self.active.store(Some(Arc::clone(&value)));
                        return Ok(value);
                    }
                    SlotState::Building { generation } => {
                        waited_generation = Some(*generation);
                        None
                    }
                    SlotState::Closing { .. } => None,
                    SlotState::Closed => {
                        inner.generation = inner.generation.wrapping_add(1);
                        let generation = inner.generation;
                        inner.state = SlotState::Building { generation };
                        self.init_count.fetch_add(1, Ordering::SeqCst);
                        tracing::debug!(phase = "start", "DNS transport initialization");
                        Some(generation)
                    }
                }
            };

            let Some(generation) = action else {
                notified.await;
                continue;
            };
            let guard = BuildGuard::new(self, generation);
            let initializer = build
                .take()
                .ok_or_else(|| anyhow::anyhow!("initializer was already consumed"))?;
            match initializer().await {
                Ok(value) => return Ok(guard.publish(value)),
                Err(error) => {
                    let message: Arc<str> = Arc::from(error.to_string());
                    guard.fail(Arc::clone(&message));
                    return Err(anyhow::anyhow!("{}", message));
                }
            }
        }
    }

    pub async fn close<F, Fut>(&self, close: F)
    where
        F: FnOnce(Arc<T>) -> Fut,
        Fut: Future<Output = ()>,
    {
        self.active.store(None);
        let mut close = Some(close);
        loop {
            let notified = self.changed.notified();
            let resource = {
                let mut inner = self.inner.lock();
                match &mut inner.state {
                    SlotState::Ready(value) => {
                        let value = Arc::clone(value);
                        inner.state = SlotState::Closing {
                            value: Arc::clone(&value),
                            owner: true,
                        };
                        Some(value)
                    }
                    SlotState::Closing { value, owner } if !*owner => {
                        *owner = true;
                        Some(Arc::clone(value))
                    }
                    SlotState::Building { .. } | SlotState::Closing { .. } => None,
                    SlotState::Closed => return,
                }
            };
            let Some(resource) = resource else {
                notified.await;
                continue;
            };
            let guard = CloseGuard::new(self);
            let close_resource = close
                .take()
                .ok_or_else(|| anyhow::anyhow!("close operation was already consumed"));
            if let Ok(close_resource) = close_resource {
                close_resource(resource).await;
            }
            guard.complete();
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::LifecycleSlot;

    #[tokio::test]
    async fn test_lifecycle_slot_fast_path_and_deduplication() {
        let slot = Arc::new(LifecycleSlot::<String>::new());
        let build_count = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..10 {
            let slot = Arc::clone(&slot);
            let build_count = Arc::clone(&build_count);
            handles.push(tokio::spawn(async move {
                slot.acquire(|| async {
                    build_count.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    Ok("connected".to_string())
                })
                .await
            }));
        }

        for h in handles {
            let res = h.await.unwrap().unwrap();
            assert_eq!(*res, "connected");
        }

        // Only 1 build should have occurred (Singleflight)
        assert_eq!(build_count.load(Ordering::SeqCst), 1);
        assert_eq!(slot.init_count(), 1);

        // Fast-path test: acquiring again should return immediately without calling initializer
        let res = slot
            .acquire(|| async { panic!("Should hit fast-path!") })
            .await
            .unwrap();
        assert_eq!(*res, "connected");

        // Close test
        let closed = Arc::new(AtomicUsize::new(0));
        let closed_clone = Arc::clone(&closed);
        slot.close(|val| async move {
            assert_eq!(*val, "connected");
            closed_clone.fetch_add(1, Ordering::SeqCst);
        })
        .await;

        assert_eq!(closed.load(Ordering::SeqCst), 1);
        assert_eq!(slot.close_count(), 1);

        // Next acquire should trigger re-initialization
        let res = slot
            .acquire(|| async {
                build_count.fetch_add(1, Ordering::SeqCst);
                Ok("reconnected".to_string())
            })
            .await
            .unwrap();
        assert_eq!(*res, "reconnected");
        assert_eq!(build_count.load(Ordering::SeqCst), 2);
    }
}
