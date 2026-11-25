use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use parking_lot::RwLock;
use tokio::{
    runtime::Handle,
    task::JoinHandle,
    time::{Instant, interval},
};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::proxy::OutboundNode;

use super::ProxyManager;

const STATE_IDLE: u8 = 0;
const STATE_RUNNING: u8 = 1;
const STATE_RUNNING_PENDING: u8 = 2;

/// Small jitter margin so a timer waking a few milliseconds early does not
/// skip a scheduled periodic probe.
const PERIODIC_TIMER_JITTER: Duration = Duration::from_millis(50);

struct CheckingGuard<'a> {
    proxy_manager: &'a ProxyManager,
    inner: &'a Arc<RwLock<HealthCheckInner>>,
    state: &'a Arc<AtomicU8>,
    url: &'a str,
    cancel: &'a CancellationToken,
    armed: bool,
}

impl<'a> CheckingGuard<'a> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CheckingGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.cancel.is_cancelled() {
            self.state.store(STATE_IDLE, Ordering::Release);
            return;
        }
        if HealthCheck::finish_or_continue(self.state) {
            // A forced/refresh check was queued while this future was cancelled.
            // Spawn a follow-up runner to probe the latest node set.
            if let Ok(handle) = Handle::try_current() {
                let pm = self.proxy_manager.clone();
                let inner = self.inner.clone();
                let state = self.state.clone();
                let url = self.url.to_owned();
                let cancel = self.cancel.clone();
                handle.spawn(async move {
                    HealthCheck::run_check_loop(&pm, &inner, &state, &url, &cancel, None)
                        .await;
                });
            } else {
                self.state.store(STATE_IDLE, Ordering::Release);
            }
        }
    }
}

struct HealthCheckInner {
    last_check: Instant,
    proxies: Vec<OutboundNode>,
    /// Per-instance probe start timestamps owned by this `HealthCheck` so
    /// independent groups (different URLs/intervals) or same-named nodes from
    /// distinct providers never suppress each other's periodic schedules.
    last_probe_started: HashMap<usize, Instant>,
    task_handle: Option<JoinHandle<()>>,
}

impl Drop for HealthCheckInner {
    fn drop(&mut self) {
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
        }
    }
}

pub struct HealthCheck {
    url: String,
    interval: u64,
    lazy: bool,
    proxy_manager: ProxyManager,
    inner: Arc<RwLock<HealthCheckInner>>,
    state: Arc<AtomicU8>,
    cancellation_token: CancellationToken,
}

impl HealthCheck {
    pub fn new(
        proxies: Vec<OutboundNode>,
        url: String,
        interval: u64,
        lazy: bool,
        proxy_manager: ProxyManager,
    ) -> Self {
        proxy_manager.register_probe_url(&url);
        Self {
            url,
            interval,
            lazy,
            proxy_manager,
            inner: Arc::new(RwLock::new(HealthCheckInner {
                last_check: Instant::now(),
                proxies,
                last_probe_started: HashMap::new(),
                task_handle: None,
            })),
            state: Arc::new(AtomicU8::new(STATE_IDLE)),
            cancellation_token: CancellationToken::new(),
        }
    }

    pub fn stop(&self) {
        self.cancellation_token.cancel();
        if let Some(handle) = self.inner.write().task_handle.take() {
            handle.abort();
        }
    }

    /// Atomically acquire the runner slot or, for forced/refresh checks,
    /// record a pending follow-up on the same state word as loop exit.
    fn try_enter_or_queue(state: &AtomicU8, force: bool) -> bool {
        let mut cur = state.load(Ordering::Acquire);
        loop {
            match cur {
                STATE_IDLE => {
                    match state.compare_exchange_weak(
                        STATE_IDLE,
                        STATE_RUNNING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return true,
                        Err(actual) => cur = actual,
                    }
                }
                STATE_RUNNING if force => {
                    match state.compare_exchange_weak(
                        STATE_RUNNING,
                        STATE_RUNNING_PENDING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return false,
                        Err(actual) => cur = actual,
                    }
                }
                _ => return false,
            }
        }
    }

    /// Atomically transition out of the running state or consume a queued
    /// follow-up check. Returns `true` if another forced pass must run.
    fn finish_or_continue(state: &AtomicU8) -> bool {
        let mut cur = state.load(Ordering::Acquire);
        loop {
            match cur {
                STATE_RUNNING => {
                    match state.compare_exchange_weak(
                        STATE_RUNNING,
                        STATE_IDLE,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return false,
                        Err(actual) => cur = actual,
                    }
                }
                STATE_RUNNING_PENDING => {
                    match state.compare_exchange_weak(
                        STATE_RUNNING_PENDING,
                        STATE_RUNNING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return true,
                        Err(actual) => cur = actual,
                    }
                }
                _ => return false,
            }
        }
    }

    fn is_due_for_periodic_probe(
        last_started: Option<Instant>,
        now: Instant,
        interval_secs: u64,
    ) -> bool {
        let Some(last_started) = last_started else {
            return true;
        };
        let min_elapsed = Duration::from_secs(interval_secs)
            .saturating_sub(PERIODIC_TIMER_JITTER);
        now.saturating_duration_since(last_started) >= min_elapsed
    }

    async fn run_check(
        proxy_manager: &ProxyManager,
        inner: &Arc<RwLock<HealthCheckInner>>,
        state: &Arc<AtomicU8>,
        url: &str,
        cancel: &CancellationToken,
        periodic_interval: Option<u64>,
    ) -> bool {
        if !Self::try_enter_or_queue(state, periodic_interval.is_none()) {
            debug!("healthcheck already in progress for {}, deferring", url);
            return false;
        }
        Self::run_check_loop(proxy_manager, inner, state, url, cancel, periodic_interval)
            .await;
        true
    }

    async fn run_check_loop(
        proxy_manager: &ProxyManager,
        inner: &Arc<RwLock<HealthCheckInner>>,
        state: &Arc<AtomicU8>,
        url: &str,
        cancel: &CancellationToken,
        periodic_interval: Option<u64>,
    ) {
        let mut guard = CheckingGuard {
            proxy_manager,
            inner,
            state,
            url,
            cancel,
            armed: true,
        };

        let mut current_interval = periodic_interval;
        loop {
            let now = Instant::now();
            let targets: Vec<OutboundNode> = {
                let mut inner_guard = inner.write();
                let live_ids: HashSet<usize> = inner_guard
                    .proxies
                    .iter()
                    .map(OutboundNode::identity)
                    .collect();
                inner_guard
                    .last_probe_started
                    .retain(|id, _| live_ids.contains(id));

                let selected: Vec<OutboundNode> =
                    if let Some(interval_secs) = current_interval
                        && interval_secs > 0
                    {
                        inner_guard
                            .proxies
                            .iter()
                            .filter(|proxy| {
                                Self::is_due_for_periodic_probe(
                                    inner_guard
                                        .last_probe_started
                                        .get(&proxy.identity())
                                        .copied(),
                                    now,
                                    interval_secs,
                                )
                            })
                            .cloned()
                            .collect()
                    } else {
                        inner_guard.proxies.clone()
                    };

                for proxy in &selected {
                    inner_guard.last_probe_started.insert(proxy.identity(), now);
                }
                selected
            };

            if !targets.is_empty() {
                proxy_manager.check(&targets, url, None).await;
            }

            if cancel.is_cancelled() {
                state.store(STATE_IDLE, Ordering::Release);
                guard.disarm();
                break;
            }

            if Self::finish_or_continue(state) {
                current_interval = None;
                continue;
            }
            // State is already back to STATE_IDLE via CAS; disarm guard without
            // clobbering a concurrent entrant that may have already started.
            guard.disarm();
            break;
        }
    }

    pub async fn kick_off(&self) {
        if self.interval == 0 {
            return;
        }
        let proxy_manager = self.proxy_manager.clone();
        let interval_secs = self.interval;
        let lazy = self.lazy;
        let url = self.url.clone();
        let pm = proxy_manager.clone();
        let inner = self.inner.clone();
        let state = self.state.clone();
        let cancel_init = self.cancellation_token.clone();
        tokio::spawn(async move {
            Self::run_check(&pm, &inner, &state, &url, &cancel_init, None).await;
        });

        let weak_inner = Arc::downgrade(&self.inner);
        let proxy_manager = self.proxy_manager.clone();
        let url = self.url.clone();
        let cancel = self.cancellation_token.clone();
        let state = self.state.clone();
        let task_handle = tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(interval_secs));
            // Skip immediate first tick since initial check was already spawned above.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        let Some(inner) = weak_inner.upgrade() else { break; };
                        debug!("healthcheck ticking: {}, lazy: {}", url, lazy);
                        let now = Instant::now();
                        let last_check = inner.read().last_check;
                        if !lazy || now.duration_since(last_check).as_secs() >= interval_secs {
                            let ran = Self::run_check(
                                &proxy_manager,
                                &inner,
                                &state,
                                &url,
                                &cancel,
                                Some(interval_secs),
                            )
                            .await;
                            if ran {
                                inner.write().last_check = now;
                            }
                        }
                    },
                }
            }
        });

        let mut inner_guard = self.inner.write();
        if let Some(old_handle) = inner_guard.task_handle.take() {
            old_handle.abort();
        }
        inner_guard.task_handle = Some(task_handle);
    }

    pub fn touch(&self) {
        self.inner.write().last_check = Instant::now();
    }

    pub async fn check(&self) {
        Self::run_check(
            &self.proxy_manager,
            &self.inner,
            &self.state,
            &self.url,
            &self.cancellation_token,
            None,
        )
        .await;
    }

    pub async fn update(&self, proxies: Vec<OutboundNode>) {
        let mut inner = self.inner.write();
        let live_ids: HashSet<usize> =
            proxies.iter().map(OutboundNode::identity).collect();
        inner.last_probe_started.retain(|id, _| live_ids.contains(id));
        inner.proxies = proxies;
    }

    pub fn auto(&self) -> bool {
        self.interval != 0
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{
        AnyStream, mocks::MockDummyOutboundHandler,
        utils::test_utils::noop::NoopResolver,
    };
    use std::sync::atomic::AtomicUsize;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, duplex},
        sync::Notify,
    };

    #[tokio::test(start_paused = true)]
    async fn periodic_probe_uses_start_time_for_short_and_long_intervals() {
        let started = Instant::now();

        // Even for a 1-second interval, advancing by 1s makes the node due.
        assert!(!HealthCheck::is_due_for_periodic_probe(
            Some(started),
            started,
            1
        ));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(HealthCheck::is_due_for_periodic_probe(
            Some(started),
            Instant::now(),
            1
        ));

        // Even if a batch took 15s to finish on a 60s interval, `started` is
        // recorded at batch start so the 60s tick is never skipped.
        let batch_start = Instant::now();
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(!HealthCheck::is_due_for_periodic_probe(
            Some(batch_start),
            Instant::now(),
            60
        ));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(HealthCheck::is_due_for_periodic_probe(
            Some(batch_start),
            Instant::now(),
            60
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn independent_healthchecks_with_different_urls_do_not_suppress_each_other() {
        let pm = ProxyManager::new(Arc::new(NoopResolver), None);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut mock = MockDummyOutboundHandler::new();
        mock.expect_name().return_const("shared".to_owned());
        {
            let calls = calls.clone();
            mock.expect_connect_stream().returning(move |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
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
        let shared_node = OutboundNode::protocol(Arc::new(mock));

        let hc_fast = HealthCheck::new(
            vec![shared_node.clone()],
            "http://fast.example/generate_204".to_owned(),
            30,
            false,
            pm.clone(),
        );
        let hc_slow = HealthCheck::new(
            vec![shared_node],
            "http://slow.example/generate_204".to_owned(),
            300,
            false,
            pm,
        );

        // Initial check for both healthchecks.
        hc_fast.check().await;
        hc_slow.check().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // Fast 30s healthcheck runs repeatedly up to t=290s; at t=300s the
        // slow 300s healthcheck must still be due and MUST NOT be skipped.
        tokio::time::advance(Duration::from_secs(290)).await;
        HealthCheck::run_check(
            &hc_fast.proxy_manager,
            &hc_fast.inner,
            &hc_fast.state,
            &hc_fast.url,
            &hc_fast.cancellation_token,
            Some(30),
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        tokio::time::advance(Duration::from_secs(10)).await;
        HealthCheck::run_check(
            &hc_slow.proxy_manager,
            &hc_slow.inner,
            &hc_slow.state,
            &hc_slow.url,
            &hc_slow.cancellation_token,
            Some(300),
        )
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            4,
            "30s group's probe must not suppress 300s group's periodic schedule"
        );
    }

    #[test]
    fn state_machine_atomic_queue_and_exit() {
        let state = AtomicU8::new(STATE_IDLE);
        assert!(HealthCheck::try_enter_or_queue(&state, false));
        assert_eq!(state.load(Ordering::Acquire), STATE_RUNNING);

        // Non-forced periodic call while running does not queue a follow-up.
        assert!(!HealthCheck::try_enter_or_queue(&state, false));
        assert_eq!(state.load(Ordering::Acquire), STATE_RUNNING);

        // Forced/refresh call while running transitions atomically to pending.
        assert!(!HealthCheck::try_enter_or_queue(&state, true));
        assert_eq!(state.load(Ordering::Acquire), STATE_RUNNING_PENDING);

        // Finishing consumes pending and keeps running.
        assert!(HealthCheck::finish_or_continue(&state));
        assert_eq!(state.load(Ordering::Acquire), STATE_RUNNING);

        // Next finish returns to idle cleanly.
        assert!(!HealthCheck::finish_or_continue(&state));
        assert_eq!(state.load(Ordering::Acquire), STATE_IDLE);
    }

    #[tokio::test]
    async fn refresh_check_during_inflight_batch_runs_followup() {
        let pm = ProxyManager::new(Arc::new(NoopResolver), None);
        let first_started = Arc::new(Notify::new());
        let allow_first_finish = Arc::new(Notify::new());
        let second_calls = Arc::new(AtomicUsize::new(0));

        let mut old_mock = MockDummyOutboundHandler::new();
        old_mock.expect_name().return_const("old-node".to_owned());
        {
            let first_started = first_started.clone();
            let allow_first_finish = allow_first_finish.clone();
            old_mock.expect_connect_stream().returning(move |_, _| {
                let (client, mut server) = duplex(1024);
                let first_started = first_started.clone();
                let allow_first_finish = allow_first_finish.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = server.read(&mut buf).await;
                    first_started.notify_one();
                    allow_first_finish.notified().await;
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

        let mut new_mock = MockDummyOutboundHandler::new();
        new_mock.expect_name().return_const("new-node".to_owned());
        {
            let second_calls = second_calls.clone();
            new_mock.expect_connect_stream().returning(move |_, _| {
                second_calls.fetch_add(1, Ordering::SeqCst);
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

        let hc = Arc::new(HealthCheck::new(
            vec![OutboundNode::protocol(Arc::new(old_mock))],
            "http://example.com/generate_204".to_owned(),
            0,
            false,
            pm,
        ));

        let hc_first = hc.clone();
        let first_task = tokio::spawn(async move { hc_first.check().await });

        first_started.notified().await;

        // Provider refreshes with a new node while the first check is in flight.
        hc.update(vec![OutboundNode::protocol(Arc::new(new_mock))]).await;
        hc.check().await;

        allow_first_finish.notify_one();
        first_task.await.unwrap();

        assert_eq!(second_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn normal_exit_does_not_leak_state_arc() {
        let pm = ProxyManager::new(Arc::new(NoopResolver), None);
        let hc = HealthCheck::new(
            Vec::new(),
            "http://example.com/generate_204".to_owned(),
            0,
            false,
            pm,
        );
        let initial_strong = Arc::strong_count(&hc.state);
        for _ in 0..5 {
            hc.check().await;
        }
        assert_eq!(Arc::strong_count(&hc.state), initial_strong);
    }

    #[tokio::test]
    async fn cancelled_check_spawns_pending_refresh() {
        let pm = ProxyManager::new(Arc::new(NoopResolver), None);
        let first_started = Arc::new(Notify::new());
        let second_done = Arc::new(Notify::new());
        let second_calls = Arc::new(AtomicUsize::new(0));

        let mut old_mock = MockDummyOutboundHandler::new();
        old_mock.expect_name().return_const("old-node".to_owned());
        {
            let first_started = first_started.clone();
            old_mock.expect_connect_stream().returning(move |_, _| {
                let (client, mut server) = duplex(1024);
                let first_started = first_started.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = server.read(&mut buf).await;
                    first_started.notify_one();
                    // Hold stream open until caller cancels the healthcheck.
                    std::future::pending::<()>().await;
                });
                Ok(AnyStream::new(client))
            });
        }

        let mut new_mock = MockDummyOutboundHandler::new();
        new_mock.expect_name().return_const("new-node".to_owned());
        {
            let second_calls = second_calls.clone();
            let second_done = second_done.clone();
            new_mock.expect_connect_stream().returning(move |_, _| {
                second_calls.fetch_add(1, Ordering::SeqCst);
                let (client, mut server) = duplex(1024);
                let second_done = second_done.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = server.read(&mut buf).await;
                    let _ = server
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = server.shutdown().await;
                    second_done.notify_one();
                });
                Ok(AnyStream::new(client))
            });
        }

        let hc = Arc::new(HealthCheck::new(
            vec![OutboundNode::protocol(Arc::new(old_mock))],
            "http://example.com/generate_204".to_owned(),
            0,
            false,
            pm,
        ));

        let hc_first = hc.clone();
        let first_task = tokio::spawn(async move { hc_first.check().await });
        first_started.notified().await;

        // Refresh updates nodes and queues STATE_RUNNING_PENDING.
        hc.update(vec![OutboundNode::protocol(Arc::new(new_mock))]).await;
        hc.check().await;
        assert_eq!(hc.state.load(Ordering::Acquire), STATE_RUNNING_PENDING);

        // Cancel the in-flight check; CheckingGuard must spawn the queued refresh.
        first_task.abort();
        let _ = first_task.await;

        tokio::time::timeout(Duration::from_secs(2), second_done.notified())
            .await
            .expect("queued refresh must run after active check is cancelled");
        assert_eq!(second_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancelled_check_aborts_inflight_probes_and_preserves_refresh_result() {
        let pm = ProxyManager::new(Arc::new(NoopResolver), None);
        let old_started = Arc::new(Notify::new());
        let old_aborted = Arc::new(Notify::new());
        let new_done = Arc::new(Notify::new());

        let mut old_mock = MockDummyOutboundHandler::new();
        old_mock.expect_name().return_const("shared-node".to_owned());
        {
            let old_started = old_started.clone();
            let old_aborted = old_aborted.clone();
            old_mock.expect_connect_stream().returning(move |_, _| {
                let (client, mut server) = duplex(1024);
                let old_started = old_started.clone();
                let old_aborted = old_aborted.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = server.read(&mut buf).await;
                    old_started.notify_one();
                    // Wait until client side closes due to task abort.
                    let _ = server.read(&mut buf).await;
                    old_aborted.notify_one();
                });
                Ok(AnyStream::new(client))
            });
        }

        let mut new_mock = MockDummyOutboundHandler::new();
        new_mock.expect_name().return_const("shared-node".to_owned());
        {
            let new_done = new_done.clone();
            new_mock.expect_connect_stream().returning(move |_, _| {
                let (client, mut server) = duplex(1024);
                let new_done = new_done.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = server.read(&mut buf).await;
                    let _ = server
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = server.shutdown().await;
                    new_done.notify_one();
                });
                Ok(AnyStream::new(client))
            });
        }

        let hc = Arc::new(HealthCheck::new(
            vec![OutboundNode::protocol(Arc::new(old_mock))],
            "http://example.com/generate_204".to_owned(),
            0,
            false,
            pm.clone(),
        ));

        let hc_first = hc.clone();
        let first_task = tokio::spawn(async move { hc_first.check().await });
        old_started.notified().await;

        hc.update(vec![OutboundNode::protocol(Arc::new(new_mock))]).await;
        hc.check().await;

        first_task.abort();
        let _ = first_task.await;

        tokio::time::timeout(Duration::from_secs(2), old_aborted.notified())
            .await
            .expect("cancelled batch must abort in-flight probe subtasks");
        tokio::time::timeout(Duration::from_secs(2), new_done.notified())
            .await
            .expect("refresh check must complete for replacement node");
        // Wait for refresh batch to finish reporting state.
        tokio::time::timeout(Duration::from_secs(2), async {
            while hc.state.load(Ordering::Acquire) != STATE_IDLE {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(pm.alive("shared-node"));
        assert!(pm.last_delay("shared-node").is_some());
    }

    #[tokio::test]
    async fn kick_off_zero_interval_is_noop_and_skipped_run_check_returns_false() {
        let pm = ProxyManager::new(Arc::new(NoopResolver), None);
        let hc_zero = HealthCheck::new(
            vec![],
            "http://example.com/generate_204".to_owned(),
            0,
            true,
            pm.clone(),
        );
        hc_zero.kick_off().await;
        assert!(
            hc_zero.inner.read().task_handle.is_none(),
            "kick_off with interval == 0 must return early without spawning a ticker"
        );

        // Simulate an already-running check: a periodic `run_check` must return
        // `false` so the ticker does not falsely advance `last_check`.
        hc_zero.state.store(STATE_RUNNING, Ordering::Release);
        let ran = HealthCheck::run_check(
            &pm,
            &hc_zero.inner,
            &hc_zero.state,
            &hc_zero.url,
            &hc_zero.cancellation_token,
            Some(30),
        )
        .await;
        assert!(!ran, "skipped periodic check must report false");
        hc_zero.state.store(STATE_IDLE, Ordering::Release);
    }
}
