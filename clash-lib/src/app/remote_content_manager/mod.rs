use crate::proxy::RouteChange;
use std::pin::pin;
use super::dns::ThreadSafeDNSResolver;
use crate::{
    app::net::get_default_outbound_interface,
    common::{
        errors::{IntoIoResultExt as _, new_io_error},
        timed_future::TimedFuture,
        tls::GLOBAL_ROOT_STORE,
        utils::serialize_duration,
    },
    proxy::{OutboundNode, WeakOutboundNode},
    session::Session,
};
use anyhow::Context;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use dashmap::{DashMap, DashSet};
use futures::{FutureExt, StreamExt, stream};
use http_body_util::Empty;
use hyper::Request;
use hyper_util::rt::TokioIo;
use moka::sync::Cache;
use parking_lot::{
    Mutex as SyncMutex, MutexGuard as SyncMutexGuard, RwLock as SyncRwLock,
};
use serde::Serialize;
use std::{
    array::from_fn,
    collections::{HashMap, VecDeque, hash_map::Entry},
    hash::{DefaultHasher, Hash, Hasher},
    io,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    spawn,
    sync::Semaphore,
    task::AbortHandle,
    time::timeout,
};
use tracing::{debug, instrument, trace, warn};

pub const DEFAULT_URL_TEST_CONCURRENCY: usize = 10;
const MAX_EPHEMERAL_TARGET_STATES: u64 = 256;
const EPHEMERAL_TARGET_STATE_TTL: Duration = Duration::from_secs(300);
const TARGET_STATE_LOCK_STRIPES: usize = 64;

pub mod healthcheck;
pub mod providers;

#[derive(Clone, Debug, Default, Serialize)]
pub struct TrafficStats {
    /// Total bytes uploaded in this session
    pub bytes_uploaded: u64,
    /// Total bytes downloaded in this session
    pub bytes_downloaded: u64,
    /// Duration of the connection
    pub connection_duration: Duration,
    /// Average throughput in bytes per second
    pub average_throughput: f64,
    /// Peak throughput observed
    pub peak_throughput: f64,
    /// Frequency of requests per second
    pub request_frequency: f64,
    /// Whether traffic flows both ways significantly
    pub is_bidirectional: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TrafficPatternType {
    /// Web browsing - moderate download, low upload, short-medium duration
    WebBrowsing,
    /// Video streaming - high download, low upload, long duration, steady
    /// throughput
    VideoStreaming,
    /// File download - very high download, minimal upload, variable duration
    FileDownload,
    /// File upload - minimal download, high upload, variable duration
    FileUpload,
    /// Gaming - low throughput, high frequency, bidirectional, low latency
    /// critical
    Gaming,
    /// Voice call - moderate bidirectional, steady throughput, medium duration
    VoiceCall,
    /// Video call - high bidirectional, steady throughput, medium-long duration
    VideoCall,
    /// Messaging - very low throughput, sporadic, bidirectional
    Messaging,
    /// Unknown pattern
    Unknown,
}

/// Result of traffic pattern analysis with confidence score
#[derive(Clone, Debug)]
pub struct TrafficPattern {
    pub pattern_type: TrafficPatternType,
    /// Confidence score from 0.0 to 1.0
    pub confidence: f64,
}

#[derive(Clone, Serialize)]
pub struct DelayHistory {
    time: DateTime<Utc>,
    #[serde(serialize_with = "serialize_duration")]
    delay: Duration,
}

const DEPENDENT_PRUNE_MIN_THRESHOLD: usize = 32;

struct DependentVersions {
    entries: HashMap<usize, Weak<AtomicU64>>,
    prune_threshold: usize,
}

impl DependentVersions {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            prune_threshold: DEPENDENT_PRUNE_MIN_THRESHOLD,
        }
    }

    fn register(&mut self, counter: Weak<AtomicU64>) {
        // `Weak` retains the `ArcInner` allocation until removed, so its pointer
        // address cannot be reused while an entry remains in `entries`.
        let key = counter.as_ptr() as usize;
        if let Entry::Vacant(slot) = self.entries.entry(key) {
            slot.insert(counter);
            if self.entries.len() >= self.prune_threshold {
                self.entries.retain(|_, weak| weak.strong_count() > 0);
                self.finish_prune();
            }
        }
    }

    fn bump_all(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        self.entries.retain(|_, weak| {
            if let Some(counter) = weak.upgrade() {
                counter.fetch_add(1, Ordering::SeqCst);
                true
            } else {
                false
            }
        });
        self.finish_prune();
    }

    fn finish_prune(&mut self) {
        self.prune_threshold = DEPENDENT_PRUNE_MIN_THRESHOLD
            .max(self.entries.len().saturating_mul(2));
        if self.entries.capacity() > self.prune_threshold.saturating_mul(2) {
            let target = if self.entries.is_empty() {
                0
            } else {
                self.prune_threshold
            };
            self.entries.shrink_to(target);
        }
    }
}

struct ProxyState {
    alive: AtomicBool,
    alive_changes: RouteChange,
    delay_changes: RouteChange,
    delay_history: SyncRwLock<VecDeque<DelayHistory>>,
    /// Per-group version counters keyed by `Weak::as_ptr()` and notified only
    /// when this specific `ProxyState` changes its liveness or latest delay.
    dependents: SyncMutex<DependentVersions>,
}

impl ProxyState {
    fn new() -> Self {
        Self {
            alive: AtomicBool::new(true),
            alive_changes: RouteChange::default(),
            delay_changes: RouteChange::default(),
            delay_history: SyncRwLock::new(VecDeque::new()),
            dependents: SyncMutex::new(DependentVersions::new()),
        }
    }

    fn register_dependent(&self, counter: Weak<AtomicU64>) {
        self.dependents.lock().register(counter);
    }

    fn bump_dependents(&self) {
        self.dependents.lock().bump_all();
    }
}

struct TargetProxyState {
    owner: WeakOutboundNode,
    state: Arc<ProxyState>,
}

/// Direct handle to a proxy's health state, allowing routing groups to read
/// liveness/latency without repeated map lookups or URL string cloning.
#[derive(Clone)]
pub(crate) struct ProxyHealthHandle {
    state: Arc<ProxyState>,
}

impl ProxyHealthHandle {
    pub(crate) fn alive_and_last_delay(&self) -> (bool, Option<Duration>) {
        ProxyManager::read_alive_and_last_delay(&self.state)
    }

    pub(crate) fn route_changes(&self, delay: bool) -> RouteChange {
        if delay {
            self.state.delay_changes.clone()
        } else {
            self.state.alive_changes.clone()
        }
    }

    pub(crate) fn register_version(&self, counter: Weak<AtomicU64>) {
        self.state.register_dependent(counter);
    }
}

type ProbeTargetKey = (usize, String);

struct FlightBucket {
    committed_gen: u64,
    active: Vec<u64>,
}

type ProbeFlightMap = SyncMutex<HashMap<ProbeTargetKey, FlightBucket>>;

struct ProbeFlightGuard {
    flights: Arc<ProbeFlightMap>,
    key: ProbeTargetKey,
    generation: u64,
    finished: bool,
}

impl ProbeFlightGuard {
    /// Marks this probe finished and returns `true` if no newer probe for the
    /// same `(node_identity, url)` has already committed a result.
    /// Cancelled probes only remove themselves from `active` without advancing
    /// `committed_gen`, so cancelling a queued/newer probe never invalidates
    /// an earlier valid in-flight probe.
    fn finish_and_check_current(&mut self) -> bool {
        if self.finished {
            return false;
        }
        self.finished = true;
        let mut map = self.flights.lock();
        let Some(bucket) = map.get_mut(&self.key) else {
            return false;
        };
        if let Some(pos) = bucket.active.iter().position(|&g| g == self.generation) {
            bucket.active.swap_remove(pos);
        }
        let is_current = self.generation > bucket.committed_gen;
        if is_current {
            bucket.committed_gen = self.generation;
        }
        if bucket.active.is_empty() {
            map.remove(&self.key);
        }
        is_current
    }
}

impl Drop for ProbeFlightGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.finished = true;
            let mut map = self.flights.lock();
            if let Some(bucket) = map.get_mut(&self.key) {
                if let Some(pos) =
                    bucket.active.iter().position(|&g| g == self.generation)
                {
                    bucket.active.swap_remove(pos);
                }
                if bucket.active.is_empty() {
                    map.remove(&self.key);
                }
            }
        }
    }
}

struct AbortTaskOnDrop(AbortHandle);

impl Drop for AbortTaskOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// ProxyManager is the latency registry.
#[derive(Clone)]
pub struct ProxyManager {
    /// Aggregated state keyed by proxy display name, retained for API
    /// reporting and name-based manual overrides/tests.
    proxy_state: Arc<DashMap<String, Arc<ProxyState>>>,
    /// Probe URLs referenced by configured healthchecks or routing groups.
    /// Only configured (or subscribed) targets are retained persistently in
    /// `target_state`.
    configured_urls: Arc<DashSet<String>>,
    /// Per-instance and per-probe-URL state used by routing groups so distinct
    /// providers with same-named nodes or groups probing different URLs never
    /// cross-contaminate selection decisions.
    target_state: Arc<DashMap<ProbeTargetKey, Arc<TargetProxyState>>>,
    /// Bounded, expiring state for ad-hoc/manual probe URLs so arbitrary API
    /// latency checks cannot grow memory unboundedly on long-lived nodes.
    ephemeral_target_state: Cache<ProbeTargetKey, Arc<TargetProxyState>>,
    /// Per-key striped locks serializing creation and ephemeral->persistent
    /// promotion so reads, probe writes, and subscriptions always converge on
    /// the exact same `TargetProxyState` instance without dropping history.
    target_state_locks: Arc<[SyncMutex<()>; TARGET_STATE_LOCK_STRIPES]>,
    /// Key-scoped striped locks serializing `(node_identity, url)` probe result
    /// commits across both target state and name-aggregated dashboard state,
    /// preserving commit order even if an ephemeral target entry is evicted and
    /// recreated between concurrent probe completions.
    probe_commit_locks: Arc<[SyncMutex<()>; TARGET_STATE_LOCK_STRIPES]>,
    dns_resolver: ThreadSafeDNSResolver,
    /// Runtime-wide concurrency budget shared across all concurrent probe batches.
    probe_semaphore: Arc<Semaphore>,
    /// Tracks active probe generations keyed by `(node_identity, url)` so
    /// probes targeting different URLs or distinct proxy instances never
    /// suppress one another, while stale probes for the same `(node, url)`
    /// cannot overwrite newer committed results.
    probe_flights: Arc<ProbeFlightMap>,
    next_probe_gen: Arc<AtomicU64>,
    /// Firewall Mark for url test
    fw_mark: Option<u32>,
}

#[derive(Clone, Default)]
pub struct SiteTuning {
    pub delay_weight: Option<f64>,
    pub packet_loss_weight: Option<f64>,
    pub rtt_weight: Option<f64>,
    pub alive_penalty: Option<f64>,
}

impl ProxyManager {
    pub fn new(dns_resolver: ThreadSafeDNSResolver, fw_mark: Option<u32>) -> Self {
        Self::with_concurrency(dns_resolver, fw_mark, DEFAULT_URL_TEST_CONCURRENCY)
    }

    pub fn with_concurrency(
        dns_resolver: ThreadSafeDNSResolver,
        fw_mark: Option<u32>,
        max_concurrency: usize,
    ) -> Self {
        let ephemeral_target_state = Cache::builder()
            .max_capacity(MAX_EPHEMERAL_TARGET_STATES)
            .time_to_idle(EPHEMERAL_TARGET_STATE_TTL)
            .build();
        Self {
            dns_resolver,
            proxy_state: Arc::new(DashMap::new()),
            configured_urls: Arc::new(DashSet::new()),
            target_state: Arc::new(DashMap::new()),
            ephemeral_target_state,
            target_state_locks: Arc::new(from_fn(|_| SyncMutex::new(()))),
            probe_commit_locks: Arc::new(from_fn(|_| SyncMutex::new(()))),
            probe_semaphore: Arc::new(Semaphore::new(max_concurrency.max(1))),
            probe_flights: Arc::new(SyncMutex::new(HashMap::new())),
            next_probe_gen: Arc::new(AtomicU64::new(0)),
            fw_mark,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_ephemeral_limits(
        mut self,
        max_capacity: u64,
        ttl: Duration,
    ) -> Self {
        self.ephemeral_target_state = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_idle(ttl)
            .build();
        self
    }

    pub(crate) fn register_probe_url(&self, url: &str) {
        if !url.is_empty() {
            self.configured_urls.insert(url.to_owned());
        }
    }

    /// Handy wrapper of `url_test` that checks multiple proxies with bounded
    /// concurrency and per-batch deduplication.
    #[instrument(skip(self))]
    pub async fn check(
        &self,
        outbounds: &Vec<OutboundNode>,
        url: &str,
        timeout_dur: Option<Duration>,
    ) -> Vec<io::Result<(Duration, Duration)>> {
        self.check_with_concurrency(
            outbounds,
            url,
            timeout_dur,
            DEFAULT_URL_TEST_CONCURRENCY,
        )
        .await
    }

    pub async fn check_with_concurrency(
        &self,
        outbounds: &[OutboundNode],
        url: &str,
        timeout_dur: Option<Duration>,
        concurrency: usize,
    ) -> Vec<io::Result<(Duration, Duration)>> {
        if outbounds.is_empty() {
            return Vec::new();
        }

        // Deduplicate by node instance identity so distinct providers with
        // same-named nodes are both probed, while repeated references to the
        // same node in one batch only probe once.
        let mut unique_indices: HashMap<usize, usize> =
            HashMap::with_capacity(outbounds.len());
        let mut unique_outbounds: Vec<OutboundNode> =
            Vec::with_capacity(outbounds.len());
        let mut index_map: Vec<usize> = Vec::with_capacity(outbounds.len());

        for outbound in outbounds {
            let id = outbound.identity();
            let idx = if let Some(&existing) = unique_indices.get(&id) {
                existing
            } else {
                let next = unique_outbounds.len();
                unique_indices.insert(id, next);
                unique_outbounds.push(outbound.clone());
                next
            };
            index_map.push(idx);
        }

        let unique_count = unique_outbounds.len();
        let batch_limit = concurrency.max(1);
        let mut unique_results: Vec<Option<io::Result<(Duration, Duration)>>> =
            (0..unique_count).map(|_| None).collect();

        let mut completed = stream::iter(unique_outbounds.into_iter().enumerate())
            .map(|(idx, outbound)| {
                let manager = self.clone();
                let url = url.to_owned();
                async move {
                    // Acquire the runtime concurrency permit BEFORE registering
                    // a probe generation so cancelling a batch while queued on
                    // the semaphore cannot interfere with active probes.
                    let Ok(_permit) = manager.probe_semaphore.acquire().await else {
                        return (idx, Err(new_io_error("url test semaphore closed")));
                    };
                    let flight = manager.begin_probe(outbound.identity(), &url);
                    let proxy_name = outbound.name().to_owned();
                    let res = manager
                        .url_test_inner(
                            outbound,
                            url.as_str(),
                            timeout_dur,
                            Some(flight),
                        )
                        .await
                        .inspect_err(|e| {
                            warn!("healthcheck {} -> {} failed: {}", proxy_name, url, e)
                        });
                    (idx, res)
                }
            })
            .buffer_unordered(batch_limit);

        while let Some((idx, res)) = completed.next().await {
            unique_results[idx] = Some(res);
        }

        let mut results = Vec::with_capacity(index_map.len());
        for idx in index_map {
            match unique_results[idx]
                .as_ref()
                .expect("every unique outbound produced a probe result")
            {
                Ok(d) => results.push(Ok(*d)),
                Err(e) => results.push(Err(io::Error::new(
                    e.kind(),
                    e.to_string(),
                ))),
            }
        }
        results
    }

    fn begin_probe(&self, node_identity: usize, url: &str) -> ProbeFlightGuard {
        let generation = self.next_probe_gen.fetch_add(1, Ordering::SeqCst) + 1;
        let key = (node_identity, url.to_owned());
        {
            let mut map = self.probe_flights.lock();
            map.entry(key.clone())
                .and_modify(|bucket| bucket.active.push(generation))
                .or_insert_with(|| FlightBucket {
                    committed_gen: 0,
                    active: vec![generation],
                });
        }
        ProbeFlightGuard {
            flights: Arc::clone(&self.probe_flights),
            key,
            generation,
            finished: false,
        }
    }

    pub(crate) fn prune_dead_targets(&self) {
        self.target_state
            .retain(|_, entry| entry.owner.upgrade().is_some());
        self.ephemeral_target_state.run_pending_tasks();
    }

    fn lock_target_key(&self, key: &ProbeTargetKey) -> SyncMutexGuard<'_, ()> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let stripe = (hasher.finish() as usize) % TARGET_STATE_LOCK_STRIPES;
        self.target_state_locks[stripe].lock()
    }

    fn lock_probe_commit(
        &self,
        node_identity: usize,
        url: &str,
    ) -> SyncMutexGuard<'_, ()> {
        let mut hasher = DefaultHasher::new();
        node_identity.hash(&mut hasher);
        url.hash(&mut hasher);
        let stripe = (hasher.finish() as usize) % TARGET_STATE_LOCK_STRIPES;
        self.probe_commit_locks[stripe].lock()
    }

    fn get_target_state(
        &self,
        node: &OutboundNode,
        url: &str,
    ) -> Option<Arc<TargetProxyState>> {
        let key = (node.identity(), url.to_owned());
        if let Some(entry) = self.target_state.get(&key) {
            return Some(entry.value().clone());
        }
        if let Some(entry) = self.ephemeral_target_state.get(&key) {
            return Some(entry);
        }
        // Promotion always inserts into `target_state` before invalidating
        // `ephemeral_target_state`, so a single re-check closes the handoff
        // gap for lock-free readers.
        self.target_state
            .get(&key)
            .map(|entry| entry.value().clone())
    }

    fn get_or_create_target_state(
        &self,
        node: &OutboundNode,
        url: &str,
        pin: bool,
    ) -> Arc<TargetProxyState> {
        let key = (node.identity(), url.to_owned());
        if let Some(entry) = self.target_state.get(&key) {
            return entry.value().clone();
        }
        // Fast path for already-present ad-hoc entries: safe even under
        // concurrent promotion because promotion moves the same `Arc` into
        // `target_state` before invalidating the ephemeral entry.
        if !pin
            && !self.configured_urls.contains(url)
            && let Some(entry) = self.ephemeral_target_state.get(&key)
        {
            return entry;
        }

        let _guard = self.lock_target_key(&key);
        if let Some(entry) = self.target_state.get(&key) {
            return entry.value().clone();
        }

        if pin || self.configured_urls.contains(url) {
            let entry = self.ephemeral_target_state.get(&key).unwrap_or_else(|| {
                Arc::new(TargetProxyState {
                    owner: node.downgrade(),
                    state: Arc::new(ProxyState::new()),
                })
            });
            // Publish into `target_state` BEFORE removing from the ephemeral
            // cache so concurrent readers and writers always observe the same
            // `TargetProxyState` without losing prior samples.
            self.target_state.insert(key.clone(), entry.clone());
            self.ephemeral_target_state.invalidate(&key);
            entry
        } else {
            self.ephemeral_target_state.get_with(key, || {
                Arc::new(TargetProxyState {
                    owner: node.downgrade(),
                    state: Arc::new(ProxyState::new()),
                })
            })
        }
    }

    /// Returns a direct health handle for `(node, url)`.
    ///
    /// When `url` is `Some`, this pins the entry in `target_state` so cached
    /// group handles cannot be silently evicted from the ephemeral cache.
    /// Callers must only pass configured group/provider probe URLs, never
    /// ad-hoc user-supplied URLs.
    pub(crate) fn health_handle_for(
        &self,
        node: &OutboundNode,
        url: Option<&str>,
    ) -> ProxyHealthHandle {
        let state = match url {
            Some(url) => self
                .get_or_create_target_state(node, url, true)
                .state
                .clone(),
            None => self
                .proxy_state
                .get(node.name())
                .map(|entry| entry.value().clone())
                .unwrap_or_else(|| {
                    self.proxy_state
                        .entry(node.name().to_owned())
                        .or_insert_with(|| Arc::new(ProxyState::new()))
                        .value()
                        .clone()
                }),
        };
        ProxyHealthHandle { state }
    }

    fn update_proxy_state_locked(
        state: &ProxyState,
        alive: bool,
        history: Option<DelayHistory>,
    ) -> (bool, bool) {
        let mut history_lock = state.delay_history.write();
        let alive_changed = state.alive.swap(alive, Ordering::Relaxed) != alive;
        let mut delay_changed = false;
        if let Some(ins) = history {
            delay_changed = history_lock.back().map(|previous| previous.delay)
                != Some(ins.delay);
            history_lock.push_back(ins);
            if history_lock.len() > 10 {
                history_lock.pop_front();
            }
        }
        (alive_changed, delay_changed)
    }

    fn apply_state_update(
        state: &ProxyState,
        alive: bool,
        history: Option<DelayHistory>,
    ) {
        let (alive_changed, delay_changed) =
            Self::update_proxy_state_locked(state, alive, history);
        if alive_changed || delay_changed {
            state.bump_dependents();
        }
        if alive_changed {
            state.alive_changes.notify();
        }
        if alive_changed || delay_changed {
            state.delay_changes.notify();
        }
    }

    fn read_alive_and_last_delay(state: &ProxyState) -> (bool, Option<Duration>) {
        let alive = state.alive.load(Ordering::Relaxed);
        let delay = state
            .delay_history
            .read()
            .back()
            .map(|history| history.delay);
        (alive, delay)
    }

    fn read_delay_metrics(state: &ProxyState) -> Option<(f64, f64)> {
        let history = state.delay_history.read();
        if history.is_empty() {
            return None;
        }
        let failed = history.iter().filter(|sample| sample.delay.is_zero()).count();
        let rtt = history
            .iter()
            .map(|sample| sample.delay.as_millis_f64())
            .sum::<f64>()
            / history.len() as f64;
        Some((failed as f64 / history.len() as f64, rtt))
    }

    pub(crate) fn route_changes(&self, name: &str, delay: bool) -> RouteChange {
        let state = self.proxy_state.entry(name.to_owned())
            .or_insert_with(|| Arc::new(ProxyState::new()));
        if delay { state.delay_changes.clone() } else { state.alive_changes.clone() }
    }

    pub(crate) fn route_changes_for(
        &self,
        node: &OutboundNode,
        url: Option<&str>,
        delay: bool,
    ) -> RouteChange {
        let Some(url) = url else {
            return self.route_changes(node.name(), delay);
        };
        let entry = self.get_or_create_target_state(node, url, true);
        if delay {
            entry.state.delay_changes.clone()
        } else {
            entry.state.alive_changes.clone()
        }
    }

    pub fn alive(&self, name: &str) -> bool {
        self.proxy_state
            .get(name)
            .map(|x| x.alive.load(Ordering::Relaxed))
            .unwrap_or(true) // if not found, assume it's alive
    }

    pub(crate) fn alive_for(&self, node: &OutboundNode, url: Option<&str>) -> bool {
        let Some(url) = url else {
            return self.alive(node.name());
        };
        self.get_target_state(node, url)
            .map(|x| x.state.alive.load(Ordering::Relaxed))
            .unwrap_or(true)
    }

    pub(crate) fn alive_and_last_delay(
        &self,
        name: &str,
    ) -> (bool, Option<Duration>) {
        self.proxy_state
            .get(name)
            .map_or((true, None), |state| Self::read_alive_and_last_delay(&state))
    }

    pub(crate) fn alive_and_last_delay_for(
        &self,
        node: &OutboundNode,
        url: Option<&str>,
    ) -> (bool, Option<Duration>) {
        let Some(url) = url else {
            return self.alive_and_last_delay(node.name());
        };
        self.get_target_state(node, url)
            .map_or((true, None), |entry| {
                Self::read_alive_and_last_delay(&entry.state)
            })
    }

    pub async fn report_alive(
        &self,
        name: &str,
        alive: bool,
        history: Option<DelayHistory>,
    ) {
        let entry = self
            .proxy_state
            .entry(name.to_owned())
            .or_insert_with(|| Arc::new(ProxyState::new()));
        Self::apply_state_update(entry.value(), alive, history);
    }

    async fn report_probe_result(
        &self,
        node: &OutboundNode,
        url: &str,
        mut flight: Option<ProbeFlightGuard>,
        alive: bool,
        history: Option<DelayHistory>,
    ) {
        // Serialize commits by `(node_identity, url)` key so target state and
        // name-aggregated dashboard state always commit in the same generation
        // order, even if an ephemeral target cache entry is evicted and
        // recreated between concurrent probe completions.
        let (
            target_entry,
            name_entry,
            target_alive_changed,
            target_delay_changed,
            name_alive_changed,
            name_delay_changed,
        ) = {
            let _commit_guard = self.lock_probe_commit(node.identity(), url);
            if let Some(guard) = flight.as_mut()
                && !guard.finish_and_check_current()
            {
                return;
            }
            let target_entry = self.get_or_create_target_state(node, url, false);
            let name_entry = self
                .proxy_state
                .get(node.name())
                .map(|entry| entry.value().clone())
                .unwrap_or_else(|| {
                    self.proxy_state
                        .entry(node.name().to_owned())
                        .or_insert_with(|| Arc::new(ProxyState::new()))
                        .value()
                        .clone()
                });
            let (target_alive_changed, target_delay_changed) =
                Self::update_proxy_state_locked(
                    &target_entry.state,
                    alive,
                    history.clone(),
                );
            let (name_alive_changed, name_delay_changed) =
                Self::update_proxy_state_locked(&name_entry, alive, history);
            (
                target_entry,
                name_entry,
                target_alive_changed,
                target_delay_changed,
                name_alive_changed,
                name_delay_changed,
            )
        };

        if target_alive_changed || target_delay_changed {
            target_entry.state.bump_dependents();
        }
        if name_alive_changed || name_delay_changed {
            name_entry.bump_dependents();
        }
        if target_alive_changed {
            target_entry.state.alive_changes.notify();
        }
        if target_alive_changed || target_delay_changed {
            target_entry.state.delay_changes.notify();
        }
        if name_alive_changed {
            name_entry.alive_changes.notify();
        }
        if name_alive_changed || name_delay_changed {
            name_entry.delay_changes.notify();
        }
    }

    #[cfg(test)]
    pub(crate) async fn report_delay(
        &self,
        name: &str,
        alive: bool,
        delay: Duration,
    ) {
        self.report_alive(
            name,
            alive,
            Some(DelayHistory {
                time: Utc::now(),
                delay,
            }),
        )
        .await;
    }

    pub async fn delay_history(&self, name: &str) -> Vec<DelayHistory> {
        self.proxy_state
            .get(name)
            .map(|x| x.delay_history.read().clone().into())
            .unwrap_or_default()
    }

    pub fn last_delay(&self, name: &str) -> Option<Duration> {
        let (alive, delay) = self.alive_and_last_delay(name);
        if alive { delay } else { None }
    }

    /// Packet loss fraction and average RTT in milliseconds from one snapshot.
    pub fn delay_metrics(&self, name: &str) -> Option<(f64, f64)> {
        let state = self.proxy_state.get(name)?;
        Self::read_delay_metrics(&state)
    }

    pub(crate) fn delay_metrics_for(
        &self,
        node: &OutboundNode,
        url: Option<&str>,
    ) -> Option<(f64, f64)> {
        let Some(url) = url else {
            return self.delay_metrics(node.name());
        };
        let entry = self.get_target_state(node, url)?;
        Self::read_delay_metrics(&entry.state)
    }

    /// This method analyzes traffic characteristics using multiple detection
    /// algorithms and applies confidence boosting based on session context.
    pub async fn analyze_traffic_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let mut patterns = Vec::new();

        // Early exit for minimal data
        if stats.bytes_uploaded + stats.bytes_downloaded < 1024 {
            return TrafficPattern {
                pattern_type: TrafficPatternType::Unknown,
                confidence: 0.1,
            };
        }

        // Run all pattern detection algorithms
        patterns.push(self.detect_streaming_pattern(stats, sess));
        patterns.push(self.detect_download_pattern(stats, sess));
        patterns.push(self.detect_upload_pattern(stats, sess));
        patterns.push(self.detect_gaming_pattern(stats, sess));
        patterns.push(self.detect_voip_pattern(stats, sess));
        patterns.push(self.detect_video_call_pattern(stats, sess));
        patterns.push(self.detect_web_browsing_pattern(stats, sess));
        patterns.push(self.detect_messaging_pattern(stats, sess));

        // Find the pattern with highest confidence
        let best_pattern = patterns
            .into_iter()
            .max_by(|a, b| {
                a.confidence
                    .partial_cmp(&b.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap_or(TrafficPattern {
                pattern_type: TrafficPatternType::Unknown,
                confidence: 0.0,
            });

        debug!(
            "Traffic pattern analysis for {}: {:?} (confidence: {:.2})",
            sess.destination.host(),
            best_pattern.pattern_type,
            best_pattern.confidence
        );

        best_pattern
    }

    fn detect_streaming_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let download_ratio = if stats.bytes_uploaded + stats.bytes_downloaded > 0 {
            stats.bytes_downloaded as f64
                / (stats.bytes_uploaded + stats.bytes_downloaded) as f64
        } else {
            0.0
        };

        let duration_secs = stats.connection_duration.as_secs();
        let mut confidence = 0.0;

        // Domain-based detection boost
        let host = sess.destination.host().to_lowercase();
        if host.contains("youtube")
            || host.contains("netflix")
            || host.contains("twitch")
            || host.contains("video")
            || host.contains("stream")
            || host.contains("hls")
        {
            confidence += 0.2;
        }

        // High download ratio (>88% download, slightly relaxed)
        if download_ratio > 0.88 {
            confidence += 0.3;
        }

        // Long duration indicates streaming
        match duration_secs {
            0..=60 => {}                      // Too short for streaming
            61..=300 => confidence += 0.1,    // Short stream
            301..=1800 => confidence += 0.25, // Medium stream
            _ => confidence += 0.3,           // Long stream
        }

        // Steady moderate to high throughput
        if stats.average_throughput > 500_000.0
            && stats.average_throughput < 100_000_000.0
        {
            confidence += 0.25;
        }

        // Consistent throughput (streaming should be relatively stable)
        if stats.peak_throughput > 0.0 && stats.average_throughput > 0.0 {
            let variance_ratio = stats.peak_throughput / stats.average_throughput;
            if variance_ratio < 4.0 {
                // Less variance indicates streaming
                confidence += 0.15;
            }
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::VideoStreaming,
            confidence,
        }
    }

    fn detect_download_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let download_ratio = if stats.bytes_uploaded + stats.bytes_downloaded > 0 {
            stats.bytes_downloaded as f64
                / (stats.bytes_uploaded + stats.bytes_downloaded) as f64
        } else {
            0.0
        };

        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();

        // Domain-based detection
        if host.contains("cdn")
            || host.contains("download")
            || host.contains("files")
            || host.contains("github")
            || host.contains("releases")
        {
            confidence += 0.2;
        }

        // Very high download ratio (>94%)
        if download_ratio > 0.94 {
            confidence += 0.4;
        }

        // High sustained throughput
        if stats.average_throughput > 5_000_000.0 {
            confidence += 0.3;
        }

        // Large total download size
        match stats.bytes_downloaded {
            10_000_000..=100_000_000 => confidence += 0.2, // 10-100MB
            100_000_001.. => confidence += 0.3,            // >100MB
            _ => {}
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::FileDownload,
            confidence,
        }
    }

    fn detect_upload_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let upload_ratio = if stats.bytes_uploaded + stats.bytes_downloaded > 0 {
            stats.bytes_uploaded as f64
                / (stats.bytes_uploaded + stats.bytes_downloaded) as f64
        } else {
            0.0
        };

        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();

        // Domain-based detection
        if host.contains("upload")
            || host.contains("cloud")
            || host.contains("drive")
            || host.contains("storage")
            || host.contains("backup")
        {
            confidence += 0.2;
        }

        // High upload ratio (>75%)
        if upload_ratio > 0.75 {
            confidence += 0.4;
        }

        // Sustained upload throughput
        if stats.average_throughput > 2_000_000.0 {
            confidence += 0.3;
        }

        // Large upload size
        if stats.bytes_uploaded > 20_000_000 {
            // 20MB+
            confidence += 0.3;
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::FileUpload,
            confidence,
        }
    }

    fn detect_gaming_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();
        let port = sess.destination.port();

        // Gaming-related domains and ports
        if host.contains("game")
            || host.contains("steam")
            || host.contains("riot")
            || host.contains("blizzard")
            || host.contains("xbox")
            || host.contains("playstation")
        {
            confidence += 0.3;
        }

        // Common gaming ports
        if matches!(port, 3478..=3480 | 27000..=28000 | 7777..=7784) {
            confidence += 0.2;
        }

        // High request frequency with low latency requirements
        if stats.request_frequency > 20.0 {
            confidence += 0.3;
        }

        // Low overall throughput but highly bidirectional
        if stats.average_throughput < 1_000_000.0 && stats.is_bidirectional {
            confidence += 0.3;
        }

        // Gaming sessions tend to be long
        if stats.connection_duration.as_secs() > 600 {
            // 10+ minutes
            confidence += 0.2;
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::Gaming,
            confidence,
        }
    }

    fn detect_voip_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let upload_download_ratio = if stats.bytes_downloaded > 0 {
            stats.bytes_uploaded as f64 / stats.bytes_downloaded as f64
        } else {
            f64::INFINITY
        };

        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();

        // VoIP service domains
        if host.contains("skype")
            || host.contains("zoom")
            || host.contains("teams")
            || host.contains("discord")
            || host.contains("webex")
            || host.contains("voip")
        {
            confidence += 0.3;
        }

        // Balanced upload/download (0.4 to 2.5 ratio for VoIP)
        if upload_download_ratio > 0.4 && upload_download_ratio < 2.5 {
            confidence += 0.4;
        }

        // Voice codec throughput range
        if stats.average_throughput > 16_000.0
            && stats.average_throughput < 320_000.0
        {
            confidence += 0.3;
        }

        // Call duration patterns
        match stats.connection_duration.as_secs() {
            60..=3600 => confidence += 0.3, // 1 minute to 1 hour
            3601.. => confidence += 0.2,    // Very long calls
            _ => {}
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::VoiceCall,
            confidence,
        }
    }

    fn detect_video_call_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let upload_download_ratio = if stats.bytes_downloaded > 0 {
            stats.bytes_uploaded as f64 / stats.bytes_downloaded as f64
        } else {
            f64::INFINITY
        };

        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();

        // Video call service domains
        if host.contains("zoom")
            || host.contains("teams")
            || host.contains("meet")
            || host.contains("webex")
            || host.contains("facetime")
            || host.contains("hangouts")
        {
            confidence += 0.3;
        }

        // Balanced but higher bandwidth than voice
        if upload_download_ratio > 0.2 && upload_download_ratio < 5.0 {
            confidence += 0.3;
        }

        // Video call throughput range
        if stats.average_throughput > 200_000.0
            && stats.average_throughput < 15_000_000.0
        {
            confidence += 0.4;
        }

        // Video call duration patterns
        if stats.connection_duration.as_secs() > 120 {
            confidence += 0.3;
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::VideoCall,
            confidence,
        }
    }

    fn detect_web_browsing_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let mut confidence = 0.0;
        let port = sess.destination.port();
        let host = sess.destination.host().to_lowercase();

        // HTTP/HTTPS ports get strong signal
        if port == 80 || port == 443 {
            confidence += 0.4;
        }

        // Common web domains
        if host.contains("www")
            || host.contains("com")
            || host.contains("org")
            || host.contains("net")
            || host.ends_with(".io")
        {
            confidence += 0.1;
        }

        // Web browsing download preference
        let download_ratio = if stats.bytes_uploaded + stats.bytes_downloaded > 0 {
            stats.bytes_downloaded as f64
                / (stats.bytes_uploaded + stats.bytes_downloaded) as f64
        } else {
            0.0
        };

        if download_ratio > 0.65 && download_ratio < 0.93 {
            confidence += 0.3;
        }

        // Web browsing throughput characteristics
        if stats.average_throughput > 50_000.0
            && stats.average_throughput < 8_000_000.0
        {
            confidence += 0.2;
        }

        // Browsing sessions are typically shorter
        if stats.connection_duration.as_secs() < 1800 {
            // Less than 30 minutes
            confidence += 0.1;
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::WebBrowsing,
            confidence,
        }
    }

    fn detect_messaging_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();

        // Messaging service domains
        if host.contains("whatsapp")
            || host.contains("telegram")
            || host.contains("signal")
            || host.contains("messenger")
            || host.contains("slack")
            || host.contains("discord")
        {
            confidence += 0.3;
        }

        // Very low sustained throughput
        if stats.average_throughput < 100_000.0 {
            confidence += 0.4;
        }

        // Bidirectional but low volume
        if stats.is_bidirectional
            && stats.bytes_uploaded + stats.bytes_downloaded < 5_000_000
        {
            // Less than 5MB total
            confidence += 0.3;
        }

        // Messaging can have long idle connections
        if stats.connection_duration.as_secs() > 300 {
            confidence += 0.3;
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::Messaging,
            confidence,
        }
    }

    /// Calculate adjustment factor based on total data transferred
    fn calculate_data_size_factor(&self, stats: &TrafficStats) -> f64 {
        let total_bytes = stats.bytes_uploaded + stats.bytes_downloaded;

        match total_bytes {
            0..=1_000_000 => 1.0,           // Small data: standard weights
            1_000_001..=100_000_000 => 1.2, // Medium data: slightly favor stability
            100_000_001..=1_000_000_000 => 1.5, // Large data: favor stability more
            _ => 2.0,                       /* Very large data: heavily favor
                                              * stability */
        }
    }

    #[instrument(skip(self))]
    /// returns (actual_http_round_trip_time,
    /// overall_round_trip_time_including_tls_handshake)
    pub async fn url_test(
        &self,
        outbound: OutboundNode,
        url: &str,
        timeout_dur: Option<Duration>,
    ) -> io::Result<(Duration, Duration)> {
        let flight = self.begin_probe(outbound.identity(), url);
        self.url_test_inner(outbound, url, timeout_dur, Some(flight))
            .await
    }

    async fn url_test_inner(
        &self,
        outbound: OutboundNode,
        url: &str,
        timeout_dur: Option<Duration>,
        flight: Option<ProbeFlightGuard>,
    ) -> io::Result<(Duration, Duration)> {
        trace!("started");
        let name = outbound.name().to_owned();
        let name_clone = name.clone();
        let default_timeout = Duration::from_secs(5);
        let probe_timeout = timeout_dur.unwrap_or(default_timeout);

        let outbound_ref = outbound.clone();
        let dns_resolver = self.dns_resolver.clone();
        let tester = async move {
            let name = name_clone;

            let uri = url
                .parse::<http::Uri>()
                .map_err(|e| new_io_error(format!("invalid url: {url}: {e}")))?;

            let host = uri
                .host()
                .ok_or(new_io_error(format!("invalid url: {url}: no host found")))?
                .to_owned();
            let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
                None => 80,
                Some(s) => match s {
                    "http" => 80,
                    "https" => 443,
                    _ => {
                        return Err(new_io_error(format!(
                            "invalid url: {url}: unsupported scheme {s}"
                        )));
                    }
                },
            });

            let sess = Session {
                destination: (host.to_owned(), port)
                    .try_into()
                    .expect("must be valid destination"),
                iface: get_default_outbound_interface(),
                so_mark: self.fw_mark,
                ..Default::default()
            };

            let (stream, connect_delay) = timeout(
                probe_timeout,
                TimedFuture::new(pin!(outbound.connect_stream(&sess, dns_resolver))),
            )
            .await
            .context("URL test timeout")
            .into_io()?;
            let stream = stream?;

            let req = Request::get(url)
                .header(hyper::header::HOST, host.as_str())
                .header("Connection", "Close")
                .version(hyper::Version::HTTP_11)
                .body(Empty::<Bytes>::new())
                .unwrap();

            let mut tls_handshake_delay = None;
            let (_conn_guard, resp) = match uri.scheme() {
                Some(scheme) if scheme == &http::uri::Scheme::HTTP => {
                    let io = TokioIo::new(stream);
                    let (mut sender, conn) = timeout(
                        probe_timeout,
                        hyper::client::conn::http1::handshake(io),
                    )
                    .await
                    .map_err(|_| new_io_error("HTTP handshake timed out"))?
                    .map_err(|e| {
                        new_io_error(format!("failed to handshake: {e}"))
                    })?;

                    let connection_name = name.clone();
                    let conn_handle = spawn(async move {
                        if let Err(err) = conn.await {
                            warn!(outbound = %connection_name, error = ?err,
                                "HTTP connection error");
                        }
                    });

                    (
                        AbortTaskOnDrop(conn_handle.abort_handle()),
                        TimedFuture::new(sender.send_request(req).boxed()),
                    )
                }
                Some(scheme) if scheme == &http::uri::Scheme::HTTPS => {
                    let mut tls_config = rustls::ClientConfig::builder()
                        .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                        .with_no_client_auth();

                    if std::env::var("SSLKEYLOGFILE").is_ok() {
                        debug!("Enabling TLS key logging");
                        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
                    }

                    let connector =
                        tokio_rustls::TlsConnector::from(Arc::new(tls_config));

                    let (stream, delay) = timeout(
                        probe_timeout,
                        TimedFuture::new(connector.connect(
                            host.try_into().expect("must be valid SNI"),
                            stream,
                        )),
                    )
                    .await?;

                    let stream = stream?;

                    let io = TokioIo::new(stream);

                    let (mut sender, conn) = timeout(
                        probe_timeout,
                        hyper::client::conn::http1::handshake(io),
                    )
                    .await
                    .map_err(|_| new_io_error("HTTPS handshake timed out"))?
                    .map_err(|e| {
                        new_io_error(format!("failed to handshake: {e}"))
                    })?;

                    let connection_name = name.clone();
                    let conn_handle = spawn(async move {
                        if let Err(err) = conn.await {
                            warn!(outbound = %connection_name, error = ?err,
                                "HTTP connection error");
                        }
                    });

                    tls_handshake_delay = Some(delay);

                    (
                        AbortTaskOnDrop(conn_handle.abort_handle()),
                        TimedFuture::new(sender.send_request(req).boxed()),
                    )
                }
                _ => {
                    return Err(new_io_error(format!(
                        "invalid url: {url}: unsupported scheme"
                    )));
                }
            };

            let delay = match timeout(probe_timeout, resp).await {
                Ok((res, delay)) => match res {
                    Ok(res) => {
                        trace!(
                            delay = ?delay,
                            status = ?res.status(),
                            "success"
                        );
                        Ok(delay)
                    }
                    Err(e) => {
                        warn!(
                            e = ?e,
                            "failed"
                        );
                        Err(new_io_error(format!(
                            "urltest for proxy {name} failed: {e}"
                        )))
                    }
                },
                Err(_) => {
                    warn!("timed out");
                    Err(new_io_error(format!("timeout for {url}").as_str()))
                }
            }?;

            Ok((
                delay,
                (connect_delay + tls_handshake_delay.unwrap_or_default() + delay),
            ))
        };

        let result = tester.await;

        self.report_probe_result(
            &outbound_ref,
            url,
            flight,
            result.is_ok(),
            Some(DelayHistory {
                time: Utc::now(),
                delay: result
                    .as_ref()
                    .map(|(actual, _)| *actual)
                    .unwrap_or_default(),
            }),
        )
        .await;

        result
    }

    /// Based on session characteristics and traffic statistics.
    pub async fn get_site_tuning(
        &self, sess: &Session, traffic_stats: Option<&TrafficStats>,
    ) -> SiteTuning {

        // Attempt intelligent pattern detection if traffic statistics are available
        if let Some(stats) = traffic_stats {
            let pattern = self.analyze_traffic_pattern(stats, sess).await;

            // Only use pattern-specific tuning if confidence is high enough
            if pattern.confidence > 0.6 {
                // Apply pattern-specific tuning parameters optimized for each
                // traffic type
                let mut tuning = match pattern.pattern_type {
                    // Gaming: Ultra-low latency critical, high packet loss penalty
                    TrafficPatternType::Gaming => SiteTuning {
                        delay_weight: Some(0.1),
                        packet_loss_weight: Some(8000.0),
                        rtt_weight: Some(0.1),
                        alive_penalty: Some(20000.0),
                    },
                    // Voice calls: Low latency important, moderate packet loss
                    // sensitivity
                    TrafficPatternType::VoiceCall => SiteTuning {
                        delay_weight: Some(0.2),
                        packet_loss_weight: Some(6000.0),
                        rtt_weight: Some(0.2),
                        alive_penalty: Some(15000.0),
                    },
                    // Video calls: Balance between latency and stability
                    TrafficPatternType::VideoCall => SiteTuning {
                        delay_weight: Some(0.4),
                        packet_loss_weight: Some(5000.0),
                        rtt_weight: Some(0.3),
                        alive_penalty: Some(12000.0),
                    },
                    // Video streaming: Favor stability over low latency
                    TrafficPatternType::VideoStreaming => SiteTuning {
                        delay_weight: Some(0.5),
                        packet_loss_weight: Some(4000.0),
                        rtt_weight: Some(0.4),
                        alive_penalty: Some(10000.0),
                    },
                    // Web browsing: Balanced approach for general usage
                    TrafficPatternType::WebBrowsing => SiteTuning {
                        delay_weight: Some(0.6),
                        packet_loss_weight: Some(2000.0),
                        rtt_weight: Some(0.5),
                        alive_penalty: Some(6000.0),
                    },
                    // Messaging: Moderate latency tolerance, low bandwidth
                    TrafficPatternType::Messaging => SiteTuning {
                        delay_weight: Some(0.8),
                        packet_loss_weight: Some(1500.0),
                        rtt_weight: Some(0.4),
                        alive_penalty: Some(5000.0),
                    },
                    // File upload: Prioritize connection stability over speed
                    TrafficPatternType::FileUpload => SiteTuning {
                        delay_weight: Some(1.2),
                        packet_loss_weight: Some(800.0),
                        rtt_weight: Some(0.8),
                        alive_penalty: Some(4000.0),
                    },
                    // File download: Maximum stability for large transfers
                    TrafficPatternType::FileDownload => SiteTuning {
                        delay_weight: Some(1.5),
                        packet_loss_weight: Some(500.0),
                        rtt_weight: Some(1.0),
                        alive_penalty: Some(3000.0),
                    },
                    // Unknown patterns: Use fallback logic
                    _ => self.get_fallback_tuning(sess),
                };

                // Apply data size scaling factor for large transfers
                // Larger transfers benefit more from stable connections
                let data_size_factor = self.calculate_data_size_factor(stats);
                if let Some(ref mut delay_weight) = tuning.delay_weight {
                    *delay_weight *= data_size_factor;
                }
                return tuning;
            }
        }

        // Fallback to protocol and port-based tuning when no traffic data
        // is available or pattern confidence is too low
        self.get_fallback_tuning(sess)
    }

    /// Fallback tuning based on protocol and port
    fn get_fallback_tuning(&self, sess: &Session) -> SiteTuning {
        let is_udp = matches!(sess.network, crate::session::Network::Udp);
        let port = sess.destination.port();

        if is_udp {
            // UDP: games, VoIP, real-time - prioritize low latency
            SiteTuning {
                delay_weight: Some(0.3),
                packet_loss_weight: Some(3000.0),
                rtt_weight: Some(0.3),
                alive_penalty: Some(15000.0),
            }
        } else if port == 80 || port == 443 {
            // HTTP/HTTPS: balance latency and stability
            SiteTuning {
                delay_weight: Some(0.7),
                packet_loss_weight: Some(2000.0),
                rtt_weight: Some(0.7),
                alive_penalty: Some(8000.0),
            }
        } else if matches!(port, 21 | 22 | 115 | 989 | 990) {
            // FTP/SFTP: prioritize stability for file transfers
            SiteTuning {
                delay_weight: Some(1.2),
                packet_loss_weight: Some(1000.0),
                rtt_weight: Some(1.2),
                alive_penalty: Some(5000.0),
            }
        } else {
            // Default balanced tuning
            SiteTuning::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::proxy::{OutboundNode, AnyStream};
    use crate::{
        app::{dns::MockClashResolver, remote_content_manager},
        config::internal::proxy::PROXY_DIRECT,
        proxy::{ProxyStream, direct, mocks::MockDummyOutboundHandler},
        tests::initialize,
    };
    use futures::TryFutureExt;
    use httpmock::{Method::GET, MockServer};
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    #[tokio::test]
    async fn test_proxy_manager_alive() {
        initialize();

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/generate_204");
            then.status(204);
        });
        let url = server.url("/generate_204");

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver
            .expect_resolve()
            .returning(|_, _| Ok(Some(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST))));
        mock_resolver.expect_ipv6().return_const(false);

        let manager =
            remote_content_manager::ProxyManager::new(Arc::new(mock_resolver), None);

        let mock_handler = Arc::new(direct::Handler::new(PROXY_DIRECT));

        manager
            .url_test(OutboundNode::protocol(mock_handler.clone()), &url, None)
            .await
            .expect("test failed");

        assert!(manager.alive(PROXY_DIRECT));
        assert!(
            manager
                .last_delay(PROXY_DIRECT)
                .is_some_and(|x| x.as_nanos() > 0)
        );
        assert!(!manager.delay_history(PROXY_DIRECT).await.is_empty());

        manager.report_alive(PROXY_DIRECT, false, None).await;
        assert!(!manager.alive(PROXY_DIRECT));

        for _ in 0..10 {
            manager
                .url_test(OutboundNode::protocol(mock_handler.clone()), &url, None)
                .await
                .expect("test failed");
        }

        assert!(manager.alive(PROXY_DIRECT));
        assert!(
            manager
                .last_delay(PROXY_DIRECT)
                .is_some_and(|x| x.as_nanos() > 0)
        );
        assert_eq!(manager.delay_history(PROXY_DIRECT).await.len(), 10);
    }

    impl ProxyStream for tokio_test::io::Mock {}
    #[tokio::test]
    async fn test_proxy_manager_timeout() {
        initialize();

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|_, _| {
            Ok(Some(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))))
        });

        let manager =
            remote_content_manager::ProxyManager::new(Arc::new(mock_resolver), None);

        let mut mock_handler = MockDummyOutboundHandler::new();
        mock_handler
            .expect_name()
            .return_const(PROXY_DIRECT.to_owned());
        mock_handler.expect_connect_stream().returning(|_, _| {
            Ok(AnyStream::dynamic(
                tokio_test::io::Builder::new()
                    .wait(Duration::from_secs(10))
                    .build(),
            ))
        });

        let mock_handler = Arc::new(mock_handler);

        let result = manager
            .url_test(
                OutboundNode::protocol(mock_handler.clone()),
                "http://www.gstatic.com/generate_204",
                Some(Duration::from_secs(3)),
            )
            .map_err(|x| assert!(x.to_string().contains("timeout")))
            .await;

        assert!(result.is_err());
        assert!(!manager.alive(PROXY_DIRECT));
        assert_eq!(manager.last_delay(PROXY_DIRECT), None);
        assert_eq!(manager.delay_history(PROXY_DIRECT).await.len(), 1);
    }

    #[tokio::test]
    async fn delay_metrics_include_failed_samples_and_trim_old_history() {
        use crate::proxy::utils::test_utils::noop::NoopResolver;

        let manager = remote_content_manager::ProxyManager::new(
            Arc::new(NoopResolver), None,
        );
        assert_eq!(manager.delay_metrics("test"), None);
        manager.report_alive("test", true, None).await;
        assert_eq!(manager.delay_metrics("test"), None);
        manager.report_delay("test", true, Duration::from_millis(100)).await;
        manager.report_delay("test", false, Duration::ZERO).await;
        assert_eq!(manager.delay_metrics("test"), Some((0.5, 50.0)));
        for _ in 0..10 {
            manager.report_delay("test", true, Duration::from_millis(200)).await;
        }
        assert_eq!(manager.delay_metrics("test"), Some((0.0, 200.0)));
    }

    #[tokio::test]
    async fn route_notifications_filter_members_and_health_metrics() {
        use crate::proxy::utils::test_utils::noop::NoopResolver;

        let manager = remote_content_manager::ProxyManager::new(Arc::new(NoopResolver), None);
        let mut alive = manager.route_changes("a", false).subscribe();
        let mut delay = manager.route_changes("a", true).subscribe();
        manager.report_alive("other", false, None).await;
        manager.report_alive("a", true, None).await;
        assert!(!alive.has_changed().unwrap());
        assert!(!delay.has_changed().unwrap());
        manager.report_delay("a", true, Duration::from_millis(20)).await;
        assert!(!alive.has_changed().unwrap());
        assert!(delay.has_changed().unwrap());
        delay.borrow_and_update();
        manager.report_delay("a", true, Duration::from_millis(20)).await;
        assert!(!delay.has_changed().unwrap());
        manager.report_alive("a", false, None).await;
        assert!(alive.has_changed().unwrap());
        assert!(delay.has_changed().unwrap());
        alive.borrow_and_update();
        delay.borrow_and_update();
        manager.report_alive("a", false, None).await;
        assert!(!alive.has_changed().unwrap());
        assert!(!delay.has_changed().unwrap());
    }

    #[tokio::test]
    async fn check_with_concurrency_bounds_parallelism_and_deduplicates() {
        use crate::proxy::utils::test_utils::noop::NoopResolver;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

        let manager = remote_content_manager::ProxyManager::new(
            Arc::new(NoopResolver),
            None,
        );
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let total_calls = Arc::new(AtomicUsize::new(0));

        let make_node = |name: &str| {
            let mut mock = MockDummyOutboundHandler::new();
            let name_owned = name.to_owned();
            mock.expect_name().return_const(name_owned);
            let in_flight = in_flight.clone();
            let max_seen = max_seen.clone();
            let total_calls = total_calls.clone();
            mock.expect_connect_stream().returning(move |_, _| {
                total_calls.fetch_add(1, Ordering::SeqCst);
                let cur = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(cur, Ordering::SeqCst);
                let in_flight_drop = in_flight.clone();
                let (client, mut server) = duplex(1024);
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = server.read(&mut buf).await;
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    let _ = server
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = server.shutdown().await;
                    in_flight_drop.fetch_sub(1, Ordering::SeqCst);
                });
                Ok(AnyStream::new(client))
            });
            OutboundNode::protocol(Arc::new(mock))
        };

        let n1 = make_node("p1");
        let n2 = make_node("p2");
        let n3 = make_node("p3");
        let n4 = make_node("p4");
        let n5 = make_node("p5");
        // Include a duplicate of p1 to verify per-batch deduplication.
        let list = vec![n1.clone(), n2, n3, n4, n5, n1];

        let results = manager
            .check_with_concurrency(
                &list,
                "http://example.com/generate_204",
                Some(Duration::from_secs(2)),
                2,
            )
            .await;

        assert_eq!(results.len(), 6);
        assert!(results.iter().all(|r| r.is_ok()));
        assert_eq!(total_calls.load(Ordering::SeqCst), 5);
        assert!(
            max_seen.load(Ordering::SeqCst) <= 2,
            "expected max concurrency <= 2, saw {}",
            max_seen.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn stale_probe_result_does_not_overwrite_newer_generation() {
        use crate::proxy::utils::test_utils::noop::NoopResolver;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt, duplex},
            sync::Notify,
        };

        let manager = remote_content_manager::ProxyManager::new(
            Arc::new(NoopResolver),
            None,
        );
        let old_started = Arc::new(Notify::new());
        let release_old = Arc::new(Notify::new());
        let attempt = Arc::new(AtomicUsize::new(0));

        let mut mock = MockDummyOutboundHandler::new();
        mock.expect_name().return_const("same-name".to_owned());
        {
            let old_started = old_started.clone();
            let release_old = release_old.clone();
            let attempt = attempt.clone();
            mock.expect_connect_stream().returning(move |_, _| {
                let n = attempt.fetch_add(1, Ordering::SeqCst);
                let (client, mut server) = duplex(1024);
                if n == 0 {
                    let old_started = old_started.clone();
                    let release_old = release_old.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 512];
                        let _ = server.read(&mut buf).await;
                        old_started.notify_one();
                        release_old.notified().await;
                        // Close without writing HTTP response so old probe fails.
                        drop(server);
                    });
                } else {
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
                }
                Ok(AnyStream::new(client))
            });
        }

        let node = OutboundNode::protocol(Arc::new(mock));
        let old_mgr = manager.clone();
        let old_node = node.clone();
        let old_task = tokio::spawn(async move {
            old_mgr
                .url_test(
                    old_node,
                    "http://example.com/generate_204",
                    Some(Duration::from_secs(2)),
                )
                .await
        });
        old_started.notified().await;

        // Newer probe for the same node instance and URL succeeds first.
        let new_res = manager
            .url_test(
                node,
                "http://example.com/generate_204",
                Some(Duration::from_secs(2)),
            )
            .await;
        assert!(new_res.is_ok());
        assert!(manager.alive("same-name"));
        let newer_delay = manager.last_delay("same-name");
        assert!(newer_delay.is_some());

        // Now let the older probe finish with failure; it must NOT overwrite
        // the newer alive/delay state.
        release_old.notify_one();
        let old_res = old_task.await.unwrap();
        assert!(old_res.is_err());
        assert!(manager.alive("same-name"));
        assert_eq!(manager.last_delay("same-name"), newer_delay);
        assert_eq!(manager.delay_history("same-name").await.len(), 1);
    }

    #[tokio::test]
    async fn concurrent_probes_with_distinct_urls_or_instances_do_not_suppress_each_other() {
        use crate::proxy::utils::test_utils::noop::NoopResolver;
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt, duplex},
            sync::Notify,
        };

        let manager = remote_content_manager::ProxyManager::new(
            Arc::new(NoopResolver),
            None,
        );
        let first_started = Arc::new(Notify::new());
        let release_first = Arc::new(Notify::new());

        let mut mock_a = MockDummyOutboundHandler::new();
        mock_a.expect_name().return_const("shared-name".to_owned());
        {
            let first_started = first_started.clone();
            let release_first = release_first.clone();
            mock_a.expect_connect_stream().returning(move |_, _| {
                let (client, mut server) = duplex(1024);
                let first_started = first_started.clone();
                let release_first = release_first.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = server.read(&mut buf).await;
                    first_started.notify_one();
                    release_first.notified().await;
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

        let mut mock_b = MockDummyOutboundHandler::new();
        mock_b.expect_name().return_const("shared-name".to_owned());
        mock_b.expect_connect_stream().returning(|_, _| {
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

        let node_a = OutboundNode::protocol(Arc::new(mock_a));
        let node_b = OutboundNode::protocol(Arc::new(mock_b));

        // Start probe for (node_a, url-1) and pause it mid-flight.
        let mgr_a = manager.clone();
        let task_a = tokio::spawn(async move {
            mgr_a
                .url_test(
                    node_a,
                    "http://one.example/generate_204",
                    Some(Duration::from_secs(2)),
                )
                .await
        });
        first_started.notified().await;

        // Distinct instance with the same name probes another URL and finishes first.
        manager
            .url_test(
                node_b,
                "http://two.example/generate_204",
                Some(Duration::from_secs(2)),
            )
            .await
            .unwrap();
        assert_eq!(manager.delay_history("shared-name").await.len(), 1);

        // Release the first probe: because its (instance, url) key differs,
        // its result must NOT be suppressed.
        release_first.notify_one();
        task_a.await.unwrap().unwrap();
        assert_eq!(manager.delay_history("shared-name").await.len(), 2);
    }

    #[tokio::test]
    async fn runtime_probe_budget_caps_parallelism_across_concurrent_batches() {
        use crate::proxy::utils::test_utils::noop::NoopResolver;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

        let manager = remote_content_manager::ProxyManager::with_concurrency(
            Arc::new(NoopResolver),
            None,
            2,
        );
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let make_node = |name: &str| {
            let mut mock = MockDummyOutboundHandler::new();
            mock.expect_name().return_const(name.to_owned());
            let in_flight = in_flight.clone();
            let max_seen = max_seen.clone();
            mock.expect_connect_stream().returning(move |_, _| {
                let cur = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(cur, Ordering::SeqCst);
                let in_flight_drop = in_flight.clone();
                let (client, mut server) = duplex(1024);
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = server.read(&mut buf).await;
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    let _ = server
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = server.shutdown().await;
                    in_flight_drop.fetch_sub(1, Ordering::SeqCst);
                });
                Ok(AnyStream::new(client))
            });
            OutboundNode::protocol(Arc::new(mock))
        };

        let batch1: Vec<OutboundNode> = (0..4).map(|i| make_node(&format!("b1-{i}"))).collect();
        let batch2: Vec<OutboundNode> = (0..4).map(|i| make_node(&format!("b2-{i}"))).collect();

        let (r1, r2) = tokio::join!(
            manager.check_with_concurrency(
                &batch1,
                "http://one.example/generate_204",
                Some(Duration::from_secs(2)),
                4,
            ),
            manager.check_with_concurrency(
                &batch2,
                "http://two.example/generate_204",
                Some(Duration::from_secs(2)),
                4,
            ),
        );
        assert!(r1.iter().all(|r| r.is_ok()));
        assert!(r2.iter().all(|r| r.is_ok()));
        assert!(
            max_seen.load(Ordering::SeqCst) <= 2,
            "runtime budget must bound total in-flight probes across concurrent batches, saw {}",
            max_seen.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn cancelling_queued_probe_does_not_invalidate_active_probe() {
        use crate::proxy::utils::test_utils::noop::NoopResolver;
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt, duplex},
            sync::Notify,
        };

        // Concurrency budget of 1 forces the second batch to queue on the
        // runtime semaphore while the first probe is active.
        let manager = remote_content_manager::ProxyManager::with_concurrency(
            Arc::new(NoopResolver),
            None,
            1,
        );
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());

        let mut mock = MockDummyOutboundHandler::new();
        mock.expect_name().return_const("queued-cancel".to_owned());
        {
            let started = started.clone();
            let release = release.clone();
            mock.expect_connect_stream().returning(move |_, _| {
                let (client, mut server) = duplex(1024);
                let started = started.clone();
                let release = release.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = server.read(&mut buf).await;
                    started.notify_one();
                    release.notified().await;
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
        let node = OutboundNode::protocol(Arc::new(mock));
        let url = "http://example.com/generate_204";

        let mgr1 = manager.clone();
        let node1 = node.clone();
        let active_batch = tokio::spawn(async move {
            mgr1.check_with_concurrency(
                &[node1],
                url,
                Some(Duration::from_secs(2)),
                1,
            )
            .await
        });
        started.notified().await;

        // Start a second batch for the same (node, url), let it queue on the
        // semaphore, and then cancel it before it can acquire a permit.
        let mgr2 = manager.clone();
        let node2 = node.clone();
        let queued_batch = tokio::spawn(async move {
            mgr2.check_with_concurrency(
                &[node2],
                url,
                Some(Duration::from_secs(2)),
                1,
            )
            .await
        });
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        queued_batch.abort();
        let _ = queued_batch.await;

        // Release the active probe: its result must still commit.
        release.notify_one();
        let results = active_batch.await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());

        let (alive, delay) = manager.alive_and_last_delay_for(&node, Some(url));
        assert!(alive);
        assert!(
            delay.is_some(),
            "cancelling a queued probe must not discard the active probe's result"
        );
        assert_eq!(manager.delay_history("queued-cancel").await.len(), 1);
    }

    #[tokio::test]
    async fn adhoc_probe_urls_are_bounded_and_expire_without_evicting_configured_targets() {
        use crate::proxy::utils::test_utils::noop::NoopResolver;
        use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

        let manager = remote_content_manager::ProxyManager::new(
            Arc::new(NoopResolver),
            None,
        )
        .with_ephemeral_limits(4, Duration::from_millis(80));

        let mut mock = MockDummyOutboundHandler::new();
        mock.expect_name().return_const("long-lived".to_owned());
        mock.expect_connect_stream().returning(|sess, _| {
            if sess.destination.host().starts_with("fail-") {
                return Err(std::io::Error::other("simulated probe failure"));
            }
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
        let node = OutboundNode::protocol(Arc::new(mock));

        let configured_url = "http://configured.example/generate_204";
        manager.register_probe_url(configured_url);
        manager
            .url_test(node.clone(), configured_url, Some(Duration::from_secs(2)))
            .await
            .unwrap();
        assert_eq!(manager.target_state.len(), 1);

        // Flood 20 distinct ad-hoc URLs (both succeeding and failing).
        for i in 0..20 {
            let url = if i % 2 == 0 {
                format!("http://adhoc-{i}.example/generate_204")
            } else {
                format!("http://fail-{i}.example/generate_204")
            };
            let _ = manager
                .url_test(node.clone(), &url, Some(Duration::from_secs(2)))
                .await;
        }
        manager.prune_dead_targets();

        assert_eq!(
            manager.target_state.len(),
            1,
            "ad-hoc request URLs must not accumulate in persistent target_state"
        );
        assert!(
            manager.ephemeral_target_state.entry_count() <= 4,
            "ephemeral ad-hoc URL cache must remain bounded by max_capacity, got {}",
            manager.ephemeral_target_state.entry_count()
        );
        let (alive, delay) =
            manager.alive_and_last_delay_for(&node, Some(configured_url));
        assert!(alive);
        assert!(delay.is_some());

        // After TTL elapses, ad-hoc URL entries expire while configured target remains.
        tokio::time::sleep(Duration::from_millis(120)).await;
        manager.prune_dead_targets();
        assert_eq!(
            manager.ephemeral_target_state.entry_count(),
            0,
            "expired ad-hoc URL entries must be reclaimed"
        );
        assert_eq!(manager.target_state.len(), 1);
        let (alive, delay) =
            manager.alive_and_last_delay_for(&node, Some(configured_url));
        assert!(alive);
        assert!(delay.is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_promotion_and_probing_share_single_state_without_losing_history() {
        use super::DelayHistory;
        use crate::proxy::utils::test_utils::noop::NoopResolver;
        use chrono::Utc;
        use tokio::sync::Barrier;

        let manager = remote_content_manager::ProxyManager::new(
            Arc::new(NoopResolver),
            None,
        );
        let mut mock = MockDummyOutboundHandler::new();
        mock.expect_name().return_const("promote-race".to_owned());
        let node = OutboundNode::protocol(Arc::new(mock));

        for iter in 0..32 {
            let url = format!("http://promote-{iter}.example/generate_204");
            let initial_delay = Duration::from_millis(42);
            // Seed an ephemeral entry with a known sample (alive=false, 42ms)
            // so any accidental replacement with an empty ProxyState (alive=true,
            // delay=None) is immediately detected.
            manager
                .report_probe_result(
                    &node,
                    &url,
                    None,
                    false,
                    Some(DelayHistory {
                        time: Utc::now(),
                        delay: initial_delay,
                    }),
                )
                .await;
            assert!(
                manager
                    .target_state
                    .get(&(node.identity(), url.clone()))
                    .is_none()
            );

            let barrier = Arc::new(Barrier::new(16));
            let mut promoters = Vec::new();
            let mut writers = Vec::new();
            let mut readers = Vec::new();

            for _ in 0..8 {
                let manager = manager.clone();
                let node = node.clone();
                let url = url.clone();
                let barrier = barrier.clone();
                promoters.push(tokio::spawn(async move {
                    barrier.wait().await;
                    manager
                        .route_changes_for(&node, Some(&url), true)
                        .identity()
                }));
            }

            for _ in 0..4 {
                let manager = manager.clone();
                let node = node.clone();
                let url = url.clone();
                let barrier = barrier.clone();
                writers.push(tokio::spawn(async move {
                    barrier.wait().await;
                    let entry = manager.get_or_create_target_state(&node, &url, false);
                    Arc::as_ptr(&entry) as usize
                }));
            }

            for _ in 0..4 {
                let manager = manager.clone();
                let node = node.clone();
                let url = url.clone();
                let barrier = barrier.clone();
                readers.push(tokio::spawn(async move {
                    barrier.wait().await;
                    manager.alive_and_last_delay_for(&node, Some(&url))
                }));
            }

            let mut change_ids = Vec::with_capacity(8);
            for task in promoters {
                change_ids.push(task.await.unwrap());
            }
            let first_change_id = change_ids[0];
            assert!(
                change_ids.iter().all(|&id| id == first_change_id),
                "all concurrent promotions must return the same RouteChange object"
            );

            let persistent_entry = manager
                .target_state
                .get(&(node.identity(), url.clone()))
                .expect("promoted target must exist in persistent target_state")
                .value()
                .clone();
            let persistent_ptr = Arc::as_ptr(&persistent_entry) as usize;
            assert_eq!(
                persistent_entry.state.delay_changes.identity(),
                first_change_id
            );

            for task in writers {
                assert_eq!(
                    task.await.unwrap(),
                    persistent_ptr,
                    "concurrent probe writes must share the exact same TargetProxyState"
                );
            }

            for task in readers {
                assert_eq!(
                    task.await.unwrap(),
                    (false, Some(initial_delay)),
                    "concurrent readers must never observe a missing or reset state during promotion"
                );
            }

            assert_eq!(
                manager.alive_and_last_delay_for(&node, Some(&url)),
                (false, Some(initial_delay)),
                "promoted persistent state must preserve pre-existing alive status and delay history"
            );
            assert!(
                manager
                    .ephemeral_target_state
                    .get(&(node.identity(), url))
                    .is_none(),
                "ephemeral entry must be invalidated after promotion"
            );
        }

        // Verify warm ephemeral hits bypass the striped lock completely:
        // holding the stripe mutex on the same thread would deadlock if the
        // non-pinned fast path attempted to acquire it.
        let warm_url = "http://warm-ephemeral.example/generate_204";
        let initial = manager.get_or_create_target_state(&node, warm_url, false);
        let stripe_guard =
            manager.lock_target_key(&(node.identity(), warm_url.to_owned()));
        let fast_hit = manager.get_or_create_target_state(&node, warm_url, false);
        drop(stripe_guard);
        assert!(Arc::ptr_eq(&initial, &fast_hit));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_probe_results_commit_target_and_dashboard_state_in_same_order() {
        use super::DelayHistory;
        use crate::proxy::utils::test_utils::noop::NoopResolver;
        use chrono::Utc;
        use tokio::sync::Barrier;

        let manager = remote_content_manager::ProxyManager::new(
            Arc::new(NoopResolver),
            None,
        );
        let mut mock = MockDummyOutboundHandler::new();
        mock.expect_name().return_const("order-node".to_owned());
        let node = OutboundNode::protocol(Arc::new(mock));
        let url = "http://order.example/generate_204";
        manager.register_probe_url(url);

        for _ in 0..64 {
            let older_flight = manager.begin_probe(node.identity(), url);
            let newer_flight = manager.begin_probe(node.identity(), url);
            let barrier = Arc::new(Barrier::new(2));

            let m1 = manager.clone();
            let n1 = node.clone();
            let b1 = barrier.clone();
            let t1 = tokio::spawn(async move {
                b1.wait().await;
                m1.report_probe_result(
                    &n1,
                    url,
                    Some(older_flight),
                    false,
                    Some(DelayHistory {
                        time: Utc::now(),
                        delay: Duration::from_millis(500),
                    }),
                )
                .await;
            });

            let m2 = manager.clone();
            let n2 = node.clone();
            let b2 = barrier.clone();
            let t2 = tokio::spawn(async move {
                b2.wait().await;
                m2.report_probe_result(
                    &n2,
                    url,
                    Some(newer_flight),
                    true,
                    Some(DelayHistory {
                        time: Utc::now(),
                        delay: Duration::from_millis(12),
                    }),
                )
                .await;
            });

            t1.await.unwrap();
            t2.await.unwrap();

            // Regardless of thread scheduling, target state and dashboard
            // name-aggregated state must both reflect the newer probe result.
            assert_eq!(
                manager.alive_and_last_delay_for(&node, Some(url)),
                (true, Some(Duration::from_millis(12)))
            );
            assert_eq!(
                manager.alive_and_last_delay(node.name()),
                (true, Some(Duration::from_millis(12)))
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ephemeral_eviction_between_concurrent_commits_preserves_dashboard_order() {
        use super::DelayHistory;
        use crate::proxy::utils::test_utils::noop::NoopResolver;
        use chrono::Utc;
        use tokio::sync::Barrier;

        // Capacity 1 forces frequent eviction & recreation of ephemeral entries.
        let manager = remote_content_manager::ProxyManager::new(
            Arc::new(NoopResolver),
            None,
        )
        .with_ephemeral_limits(1, Duration::from_secs(60));
        let mut mock = MockDummyOutboundHandler::new();
        mock.expect_name().return_const("evict-order-node".to_owned());
        let node = OutboundNode::protocol(Arc::new(mock));

        for iter in 0..32 {
            let url = format!("http://adhoc-order-{iter}.example/generate_204");
            let other_url = format!("http://adhoc-evict-{iter}.example/generate_204");
            let older_flight = manager.begin_probe(node.identity(), &url);
            let newer_flight = manager.begin_probe(node.identity(), &url);
            let barrier = Arc::new(Barrier::new(3));

            let m1 = manager.clone();
            let n1 = node.clone();
            let u1 = url.clone();
            let b1 = barrier.clone();
            let t1 = tokio::spawn(async move {
                b1.wait().await;
                m1.report_probe_result(
                    &n1,
                    &u1,
                    Some(older_flight),
                    false,
                    Some(DelayHistory {
                        time: Utc::now(),
                        delay: Duration::from_millis(500),
                    }),
                )
                .await;
            });

            let m2 = manager.clone();
            let n2 = node.clone();
            let u2 = url.clone();
            let b2 = barrier.clone();
            let t2 = tokio::spawn(async move {
                b2.wait().await;
                m2.report_probe_result(
                    &n2,
                    &u2,
                    Some(newer_flight),
                    true,
                    Some(DelayHistory {
                        time: Utc::now(),
                        delay: Duration::from_millis(15),
                    }),
                )
                .await;
            });

            let m3 = manager.clone();
            let n3 = node.clone();
            let b3 = barrier.clone();
            let evictor = tokio::spawn(async move {
                b3.wait().await;
                let _ = m3.get_or_create_target_state(&n3, &other_url, false);
                m3.ephemeral_target_state.run_pending_tasks();
            });

            t1.await.unwrap();
            t2.await.unwrap();
            evictor.await.unwrap();

            assert_eq!(
                manager.alive_and_last_delay(node.name()),
                (true, Some(Duration::from_millis(15))),
                "evicting and recreating ephemeral target state must not let older probe overwrite dashboard state"
            );
        }
    }

    #[test]
    fn dependent_versions_deduplicate_and_prune_by_threshold_and_bump() {
        use super::{DEPENDENT_PRUNE_MIN_THRESHOLD, DependentVersions};
        use std::sync::atomic::{AtomicU64, Ordering};

        let mut deps = DependentVersions::new();
        let live_a = Arc::new(AtomicU64::new(0));
        let live_b = Arc::new(AtomicU64::new(0));

        // Duplicate registration deduplicates in place.
        deps.register(Arc::downgrade(&live_a));
        deps.register(Arc::downgrade(&live_a));
        deps.register(Arc::downgrade(&live_b));
        assert_eq!(deps.entries.len(), 2);

        // Insert dead weak refs up to the prune threshold without probing:
        // hitting the threshold sweeps dead entries and sets next threshold.
        for _ in 0..(DEPENDENT_PRUNE_MIN_THRESHOLD - 2) {
            let transient = Arc::new(AtomicU64::new(0));
            let weak = Arc::downgrade(&transient);
            drop(transient);
            deps.register(weak);
        }
        assert_eq!(deps.entries.len(), 2);
        assert_eq!(deps.prune_threshold, DEPENDENT_PRUNE_MIN_THRESHOLD);

        // With 20 live entries + enough dead entries to cross threshold,
        // prune keeps all live entries and raises threshold to live * 2.
        let extra_live: Vec<_> =
            (0..20).map(|_| Arc::new(AtomicU64::new(0))).collect();
        for c in &extra_live {
            deps.register(Arc::downgrade(c));
        }
        for _ in 0..10 {
            let transient = Arc::new(AtomicU64::new(0));
            let weak = Arc::downgrade(&transient);
            drop(transient);
            deps.register(weak);
        }
        assert_eq!(deps.entries.len(), 22);
        assert_eq!(deps.prune_threshold, 44);

        // Drop extra_live and bump: increments remaining live counters,
        // prunes expired entries, and lowers prune_threshold back to minimum.
        drop(extra_live);
        deps.bump_all();
        assert_eq!(live_a.load(Ordering::SeqCst), 1);
        assert_eq!(live_b.load(Ordering::SeqCst), 1);
        assert_eq!(deps.entries.len(), 2);
        assert_eq!(deps.prune_threshold, DEPENDENT_PRUNE_MIN_THRESHOLD);
    }

    #[test]
    fn dependent_versions_shrinks_oversized_capacity_after_pruning() {
        use super::{DEPENDENT_PRUNE_MIN_THRESHOLD, DependentVersions};
        use std::sync::atomic::{AtomicU64, Ordering};

        let mut deps = DependentVersions::new();
        let survivor = Arc::new(AtomicU64::new(0));
        deps.register(Arc::downgrade(&survivor));

        let transient: Vec<_> =
            (0..4096).map(|_| Arc::new(AtomicU64::new(0))).collect();
        for c in &transient {
            deps.register(Arc::downgrade(c));
        }
        assert_eq!(deps.entries.len(), 4097);
        let peak_capacity = deps.entries.capacity();
        assert!(peak_capacity >= 4097);

        // Drop 4096 dependents and notify: surviving counter increments and
        // table capacity shrinks well below the historical peak.
        drop(transient);
        deps.bump_all();
        assert_eq!(survivor.load(Ordering::SeqCst), 1);
        assert_eq!(deps.entries.len(), 1);
        assert_eq!(deps.prune_threshold, DEPENDENT_PRUNE_MIN_THRESHOLD);
        assert!(
            deps.entries.capacity() <= DEPENDENT_PRUNE_MIN_THRESHOLD * 2,
            "expected capacity to shrink near threshold after pruning from {peak_capacity}, got {}",
            deps.entries.capacity()
        );

        // Repeat and drop all entries: empty oversized table shrinks to 0.
        let transient: Vec<_> =
            (0..256).map(|_| Arc::new(AtomicU64::new(0))).collect();
        for c in &transient {
            deps.register(Arc::downgrade(c));
        }
        assert!(deps.entries.capacity() >= 257);
        drop(transient);
        drop(survivor);
        deps.bump_all();
        assert!(deps.entries.is_empty());
        assert_eq!(deps.entries.capacity(), 0);
    }

}
