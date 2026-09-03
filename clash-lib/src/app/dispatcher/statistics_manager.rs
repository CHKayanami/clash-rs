use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{Arc, atomic::Ordering},
};

use chrono::Utc;
use dashmap::DashMap;
use lru::LruCache;
use memory_stats::memory_stats;
use portable_atomic::AtomicU64;
use serde::Serialize;
use tokio::sync::oneshot::Sender;

use crate::session::Session;

/// Per-user traffic since the last drain.  Both upload and download are in
/// bytes.
#[derive(Serialize, Clone, Debug, Default)]
pub struct UserTraffic {
    pub upload: u64,
    pub download: u64,
}

pub use crate::session::ProxyChain;

fn serialize_id_as_string<S>(id: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.collect_str(id)
}

#[derive(Serialize, Default)]
pub struct TrackerInfo {
    #[serde(rename = "id", serialize_with = "serialize_id_as_string")]
    pub id: u64,
    #[serde(rename = "metadata")]
    pub session_holder: Session,
    #[serde(rename = "upload")]
    pub upload_total: AtomicU64,
    #[serde(rename = "download")]
    pub download_total: AtomicU64,
    #[serde(skip)]
    pub start_time: chrono::DateTime<Utc>,
    #[serde(rename = "start")]
    pub start_time_str: String,
    #[serde(rename = "chains")]
    pub proxy_chain_holder: ProxyChain,
    #[serde(rename = "rule")]
    pub rule: String,
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,

    /// Per-user byte counters, separate from `upload_total`/`download_total`.
    /// Only incremented when `session_holder.inbound_user` is set.
    /// Swapped to 0 on drain — never touched by `snapshot()`.
    #[serde(skip)]
    pub user_upload: AtomicU64,
    #[serde(skip)]
    pub user_download: AtomicU64,
}

impl TrackerInfo {
    pub fn new(
        sess: &Session,
        rule: Option<&Box<dyn crate::app::router::RuleMatcher>>,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: sess.id,
            session_holder: sess.clone(),
            start_time: now,
            start_time_str: now.to_rfc3339(),
            rule: rule.map(|r| r.type_name().to_string()).unwrap_or_default(),
            rule_payload: rule.map(|r| r.payload()).unwrap_or_default(),
            proxy_chain_holder: sess.proxy_chain.clone(),
            ..Default::default()
        }
    }
}

impl Clone for TrackerInfo {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            session_holder: self.session_holder.clone(),
            upload_total: AtomicU64::new(self.upload_total.load(Ordering::Relaxed)),
            download_total: AtomicU64::new(
                self.download_total.load(Ordering::Relaxed),
            ),
            start_time: self.start_time,
            start_time_str: self.start_time_str.clone(),
            rule: self.rule.clone(),
            rule_payload: self.rule_payload.clone(),
            proxy_chain_holder: self.proxy_chain_holder.clone(),
            user_upload: AtomicU64::new(self.user_upload.load(Ordering::Relaxed)),
            user_download: AtomicU64::new(
                self.user_download.load(Ordering::Relaxed),
            ),
        }
    }
}

#[derive(Clone, Default)]
pub enum TrafficTracker {
    #[default]
    Noop,
    Active {
        tracker: Arc<TrackerInfo>,
        manager: Arc<Manager>,
        has_user: bool,
    },
}

impl TrafficTracker {
    pub fn new(tracker: Arc<TrackerInfo>, manager: Arc<Manager>) -> Self {
        let has_user = tracker.session_holder.inbound_user.is_some();
        Self::Active {
            tracker,
            manager,
            has_user,
        }
    }

    pub fn noop() -> Self {
        Self::Noop
    }

    #[inline(always)]
    pub fn push_upload(&self, n: usize) {
        if let Self::Active {
            tracker,
            manager,
            has_user,
        } = self
        {
            tracker.upload_total.fetch_add(n as u64, Ordering::Relaxed);
            if *has_user {
                tracker.user_upload.fetch_add(n as u64, Ordering::Relaxed);
            }
            manager.push_uploaded(n);
        }
    }

    #[inline(always)]
    pub fn push_download(&self, n: usize) {
        if let Self::Active {
            tracker,
            manager,
            has_user,
        } = self
        {
            tracker
                .download_total
                .fetch_add(n as u64, Ordering::Relaxed);
            if *has_user {
                tracker.user_download.fetch_add(n as u64, Ordering::Relaxed);
            }
            manager.push_downloaded(n);
        }
    }
}

/// RAII Drop Guard that ensures a connection is untracked from `Manager`
/// even if the holding future / task is cancelled or aborted.
pub struct TrackGuard {
    id: u64,
    manager: Arc<Manager>,
}

impl TrackGuard {
    pub fn new(id: u64, manager: Arc<Manager>) -> Self {
        Self { id, manager }
    }
}

impl Drop for TrackGuard {
    fn drop(&mut self) {
        self.manager.untrack(self.id);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    download_total: u64,
    upload_total: u64,
    connections: Vec<Arc<TrackerInfo>>,
    memory: usize,
}



#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowKey {
    pub dst_host: String,
    pub dst_port: u16,
    pub is_tcp: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ClosedFlowEntry {
    pub conn_count: usize,
    pub upload_total: u64,
    pub download_total: u64,
    pub src_ips: Vec<std::net::IpAddr>,
    pub rule: String,
    pub rule_payload: String,
    pub chains: Vec<String>,
    pub country: Option<String>,
    pub asn: Option<String>,
    pub last_seen: chrono::DateTime<Utc>,
}

/// The close notifier is an `Option` so that [`Manager::close`] can *take* it
/// (a `oneshot::Sender` is consumed by `send`) without removing the map entry.
/// Removal — and the byte accounting that goes with it — stays the exclusive
/// job of [`Manager::untrack`], which runs from the tracker's `Drop`.
type ConnectionMap = DashMap<u64, (Arc<TrackerInfo>, Option<Sender<()>>)>;

enum StatsCommand {
    ConnectionClosed {
        info: Arc<TrackerInfo>,
        upload: u64,
        download: u64,
    },
    GetClosedFlows(
        tokio::sync::oneshot::Sender<HashMap<FlowKey, ClosedFlowEntry>>,
    ),
    DrainUserStats(tokio::sync::oneshot::Sender<HashMap<String, UserTraffic>>),
    #[cfg(test)]
    InjectClosedUserBytes {
        user: String,
        upload: u64,
        download: u64,
    },
}

pub struct Manager {
    connections: ConnectionMap,
    tx: tokio::sync::mpsc::UnboundedSender<StatsCommand>,
    upload_temp: AtomicU64,
    download_temp: AtomicU64,
    upload_blip: AtomicU64,
    download_blip: AtomicU64,
    upload_total: AtomicU64,
    download_total: AtomicU64,
}

impl Manager {
    pub fn new() -> Arc<Self> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(Self::run_actor(rx));

        let v = Arc::new(Self {
            connections: DashMap::new(),
            tx,
            upload_temp: AtomicU64::new(0),
            download_temp: AtomicU64::new(0),
            upload_blip: AtomicU64::new(0),
            download_blip: AtomicU64::new(0),
            upload_total: AtomicU64::new(0),
            download_total: AtomicU64::new(0),
        });
        // Hold a *weak* reference: a strong one would make the ticker task own
        // the Manager it ticks, so the Arc count could never reach zero and the
        // Manager (plus its task) would live for the whole process. With a Weak
        // the task exits on the first tick after the last owner goes away.
        let c = Arc::downgrade(&v);
        tokio::spawn(async move {
            Self::kick_off(c).await;
        });
        v
    }

    async fn run_actor(mut rx: tokio::sync::mpsc::UnboundedReceiver<StatsCommand>) {
        const MAX_CLOSED_FLOWS: usize = 500;
        let mut closed_flows: LruCache<FlowKey, ClosedFlowEntry> =
            LruCache::new(NonZeroUsize::new(MAX_CLOSED_FLOWS).unwrap());
        let mut user_period_stats: HashMap<String, UserTraffic> = HashMap::new();

        while let Some(cmd) = rx.recv().await {
            match cmd {
                StatsCommand::ConnectionClosed {
                    info,
                    upload,
                    download,
                } => {
                    if let Some(ref user) = info.session_holder.inbound_user
                        && (upload > 0 || download > 0)
                    {
                        let entry = user_period_stats
                            .entry(user.clone())
                            .or_insert_with(UserTraffic::default);
                        entry.upload += upload;
                        entry.download += download;
                    }

                    Self::record_closed_flow(&mut closed_flows, &info);
                }
                StatsCommand::GetClosedFlows(reply) => {
                    let mut snapshot = HashMap::with_capacity(closed_flows.len());
                    for (k, v) in closed_flows.iter() {
                        snapshot.insert(k.clone(), v.clone());
                    }
                    let _ = reply.send(snapshot);
                }
                StatsCommand::DrainUserStats(reply) => {
                    let drained = std::mem::take(&mut user_period_stats);
                    let _ = reply.send(drained);
                }
                #[cfg(test)]
                StatsCommand::InjectClosedUserBytes {
                    user,
                    upload,
                    download,
                } => {
                    let entry = user_period_stats.entry(user).or_default();
                    entry.upload += upload;
                    entry.download += download;
                }
            }
        }
    }

    fn record_closed_flow(
        closed_flows: &mut LruCache<FlowKey, ClosedFlowEntry>,
        info: &TrackerInfo,
    ) {
        let dst_host = info.session_holder.destination.host();
        let dst_port = info.session_holder.destination.port();
        let is_tcp =
            matches!(info.session_holder.network, crate::session::Network::Tcp);
        let conn_upload = info.upload_total.load(Ordering::Relaxed);
        let conn_download = info.download_total.load(Ordering::Relaxed);
        let src_ip = info.session_holder.source.ip();

        let key = FlowKey {
            dst_host,
            dst_port,
            is_tcp,
        };

        const MAX_SRC_IPS: usize = 32;

        if let Some(entry) = closed_flows.get_mut(&key) {
            entry.conn_count += 1;
            entry.upload_total += conn_upload;
            entry.download_total += conn_download;
            if entry.src_ips.len() < MAX_SRC_IPS && !entry.src_ips.contains(&src_ip)
            {
                entry.src_ips.push(src_ip);
            }
            if info.start_time > entry.last_seen {
                entry.last_seen = info.start_time;
            }
            if entry.rule.is_empty() && !info.rule.is_empty() {
                entry.rule = info.rule.clone();
            }
            if entry.rule_payload.is_empty() && !info.rule_payload.is_empty() {
                entry.rule_payload = info.rule_payload.clone();
            }
            if entry.chains.is_empty() {
                let c = info.proxy_chain_holder.snapshot();
                if !c.is_empty() {
                    entry.chains = c;
                }
            }
            if entry.country.is_none() {
                entry.country = info.session_holder.country.clone();
            }
            if entry.asn.is_none() {
                entry.asn = info.session_holder.asn.clone();
            }
        } else {
            let chains = info.proxy_chain_holder.snapshot();
            closed_flows.push(
                key,
                ClosedFlowEntry {
                    conn_count: 1,
                    upload_total: conn_upload,
                    download_total: conn_download,
                    src_ips: vec![src_ip],
                    rule: info.rule.clone(),
                    rule_payload: info.rule_payload.clone(),
                    chains,
                    country: info.session_holder.country.clone(),
                    asn: info.session_holder.asn.clone(),
                    last_seen: info.start_time,
                },
            );
        }
    }

    pub fn track(&self, id: u64, item: Arc<TrackerInfo>, close_notify: Sender<()>) {
        self.connections.insert(id, (item, Some(close_notify)));
    }

    /// Untrack a connection.
    /// This method is not async because it is called in Drop.
    /// Non-blocking: pushes an event to the Actor channel.
    pub fn untrack(&self, id: u64) {
        let removed = self.connections.remove(&id);

        if let Some((_, (info, _))) = removed {
            let upload = info.user_upload.swap(0, Ordering::Relaxed);
            let download = info.user_download.swap(0, Ordering::Relaxed);
            let _ = self.tx.send(StatsCommand::ConnectionClosed {
                info,
                upload,
                download,
            });
        }
    }

    /// Return `Arc<TrackerInfo>` for every currently-active connection.
    /// Unlike `snapshot()`, this preserves the full `session_holder` so
    /// callers can access destination, source, and network fields directly.
    pub fn active_connections_snapshot(&self) -> Vec<Arc<TrackerInfo>> {
        self.connections
            .iter()
            .map(|r| r.value().0.clone())
            .collect()
    }

    /// Return a snapshot of pre-aggregated recently closed flows.
    pub async fn closed_flows_snapshot(
        &self,
    ) -> HashMap<FlowKey, ClosedFlowEntry> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if self.tx.send(StatsCommand::GetClosedFlows(reply_tx)).is_ok() {
            reply_rx.await.unwrap_or_default()
        } else {
            HashMap::new()
        }
    }

    /// Return per-user traffic accumulated since the last call (for both closed
    /// and currently-active connections) and reset all counters.
    ///
    /// Called by the `/user-stats` REST endpoint so FAC can poll for deltas.
    pub async fn drain_user_stats(&self) -> HashMap<String, UserTraffic> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let mut result =
            if self.tx.send(StatsCommand::DrainUserStats(reply_tx)).is_ok() {
                reply_rx.await.unwrap_or_default()
            } else {
                HashMap::new()
            };

        // Include bytes from still-active connections by atomically swapping
        // their user counters to 0. upload_total/download_total are untouched
        // so /connections keeps seeing the correct cumulative values.
        for r in self.connections.iter() {
            let (info, _) = r.value();
            if let Some(ref user) = info.session_holder.inbound_user {
                let upload = info.user_upload.swap(0, Ordering::Relaxed);
                let download = info.user_download.swap(0, Ordering::Relaxed);
                if upload > 0 || download > 0 {
                    let entry = result.entry(user.clone()).or_default();
                    entry.upload += upload;
                    entry.download += download;
                }
            }
        }

        result
    }

    /// Signal a connection to close.
    ///
    /// This deliberately does **not** remove the map entry. The tracker sees the
    /// signal on its next poll, returns `BrokenPipe`/EOF, and is dropped — and
    /// its `Drop` calls [`Manager::untrack`], which is what flushes the final
    /// per-user bytes into `user_period_stats` and pushes the flow into
    /// `closed_flows`. Removing the entry here would make that `untrack` a no-op
    /// and silently lose both.
    pub fn close(&self, id: u64) {
        if let Some(mut entry) = self.connections.get_mut(&id)
            && let Some(close_notify) = entry.value_mut().1.take()
        {
            let _ = close_notify.send(());
        }
    }

    pub fn close_all(&self) {
        let keys: Vec<u64> = self.connections.iter().map(|r| *r.key()).collect();
        for key in keys {
            self.close(key);
        }
    }

    pub fn push_uploaded(&self, n: usize) {
        self.upload_temp
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        self.upload_total
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn push_downloaded(&self, n: usize) {
        self.download_temp
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        self.download_total
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn now(&self) -> (u64, u64) {
        (
            self.upload_blip.load(std::sync::atomic::Ordering::Relaxed),
            self.download_blip
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    pub fn traffic_summary(&self) -> (u64, u64, u64, u64, usize) {
        (
            self.upload_blip.load(std::sync::atomic::Ordering::Relaxed),
            self.download_blip
                .load(std::sync::atomic::Ordering::Relaxed),
            self.upload_total.load(std::sync::atomic::Ordering::Relaxed),
            self.download_total
                .load(std::sync::atomic::Ordering::Relaxed),
            self.connections.len(),
        )
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut connections = Vec::with_capacity(self.connections.len());
        for r in self.connections.iter() {
            connections.push(r.value().0.clone());
        }

        Snapshot {
            download_total: self
                .download_total
                .load(std::sync::atomic::Ordering::Relaxed),
            upload_total: self
                .upload_total
                .load(std::sync::atomic::Ordering::Relaxed),
            connections,
            memory: self.memory_usage(),
        }
    }

    /// Shrink connection map capacity immediately if capacity is bloated.
    pub fn maybe_shrink(&self) {
        let len = self.connections.len();
        let capacity = self.connections.capacity();
        if capacity > 512 && capacity > len.saturating_mul(4) {
            self.shrink_connections(capacity, len);
        }
    }

    fn shrink_connections(&self, capacity: usize, len: usize) {
        tracing::debug!(
            "shrinking connections DashMap from capacity {} (active len: {})",
            capacity,
            len
        );
        self.connections.shrink_to_fit();
    }

    #[allow(dead_code)]
    pub fn reset_statistic(&self) {
        self.upload_temp.store(0, Ordering::Relaxed);
        self.upload_blip.store(0, Ordering::Relaxed);
        self.upload_total.store(0, Ordering::Relaxed);
        self.download_temp.store(0, Ordering::Relaxed);
        self.download_blip.store(0, Ordering::Relaxed);
        self.download_total.store(0, Ordering::Relaxed);
    }

    pub fn memory_usage(&self) -> usize {
        memory_stats().map(|x| x.physical_mem).unwrap_or(0)
    }

    /// Test helper: directly populate `user_period_stats` to simulate closed
    /// connections without going through the full `Tracked` machinery.
    #[cfg(test)]
    pub async fn inject_closed_user_bytes(
        &self,
        user: &str,
        upload: u64,
        download: u64,
    ) {
        let _ = self.tx.send(StatsCommand::InjectClosedUserBytes {
            user: user.to_string(),
            upload,
            download,
        });
        // Yield to allow the actor to process the message before test assertions.
        tokio::task::yield_now().await;
    }

    async fn kick_off(this: std::sync::Weak<Self>) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        let mut shrink_controller = ShrinkController::new();

        loop {
            ticker.tick().await;
            // Last owner gone — nothing left to tick for.
            let Some(me) = this.upgrade() else { break };
            let up_blip = me.upload_temp.swap(0, Ordering::Relaxed);
            let down_blip = me.download_temp.swap(0, Ordering::Relaxed);

            me.upload_blip.store(up_blip, Ordering::Relaxed);
            me.download_blip.store(down_blip, Ordering::Relaxed);

            let len = me.connections.len();
            let capacity = me.connections.capacity();
            let total_traffic_rate = up_blip.saturating_add(down_blip);

            if shrink_controller.should_shrink(len, capacity, total_traffic_rate) {
                me.shrink_connections(capacity, len);
            }
        }
    }
}

/// Controller to safely trigger DashMap shrinkage only during genuine, sustained idle periods,
/// preventing thrashing and lock contention during traffic bursts.
#[derive(Debug)]
struct ShrinkController {
    /// Consecutive seconds during which connection count and capacity met the shrink criteria.
    low_watermark_seconds: u32,
    /// Seconds elapsed since the last shrink operation (cooldown tracking).
    cooldown_seconds: u32,
}

impl ShrinkController {
    /// Minimum consecutive seconds of low connection count and low traffic required before shrinking.
    const REQUIRED_IDLE_SECONDS: u32 = 60;
    /// Minimum seconds between consecutive shrink operations to prevent thrashing.
    const COOLDOWN_SECONDS: u32 = 300;
    /// Maximum traffic rate (upload + download) in bytes/sec to still be considered an idle period (512 KB/s).
    const MAX_IDLE_TRAFFIC_BYTES_PER_SEC: u64 = 512 * 1024;

    fn new() -> Self {
        Self {
            low_watermark_seconds: 0,
            // Initialize with cooldown satisfied so first shrink after a peak isn't unnecessarily delayed.
            cooldown_seconds: Self::COOLDOWN_SECONDS,
        }
    }

    /// Evaluates conditions on each 1-second tick and returns true if shrinking should be performed.
    fn should_shrink(&mut self, len: usize, capacity: usize, current_traffic_rate: u64) -> bool {
        self.cooldown_seconds = self.cooldown_seconds.saturating_add(1);

        // If capacity is not bloated, reset idle period counter.
        if capacity <= 512 || capacity <= len.saturating_mul(4) {
            self.low_watermark_seconds = 0;
            return false;
        }

        // If there is significant active network throughput, we are not in an idle window.
        if current_traffic_rate > Self::MAX_IDLE_TRAFFIC_BYTES_PER_SEC {
            self.low_watermark_seconds = 0;
            return false;
        }

        self.low_watermark_seconds = self.low_watermark_seconds.saturating_add(1);

        if self.cooldown_seconds >= Self::COOLDOWN_SECONDS
            && self.low_watermark_seconds >= Self::REQUIRED_IDLE_SECONDS
        {
            self.cooldown_seconds = 0;
            self.low_watermark_seconds = 0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_drain_user_stats_empty() {
        let mgr = Manager::new();
        let stats = mgr.drain_user_stats().await;
        assert!(stats.is_empty(), "fresh manager should have no user stats");
    }

    #[tokio::test]
    async fn test_drain_user_stats_returns_closed_connection_bytes() {
        let mgr = Manager::new();
        mgr.inject_closed_user_bytes("user1", 1000, 2000).await;

        let stats = mgr.drain_user_stats().await;
        let u = stats.get("user1").expect("user1 not found");
        assert_eq!(u.upload, 1000);
        assert_eq!(u.download, 2000);
    }

    #[tokio::test]
    async fn test_drain_user_stats_resets_on_read() {
        let mgr = Manager::new();
        mgr.inject_closed_user_bytes("user1", 500, 750).await;

        let first = mgr.drain_user_stats().await;
        assert!(!first.is_empty());

        let second = mgr.drain_user_stats().await;
        assert!(
            second.is_empty(),
            "second drain should be empty after reset"
        );
    }

    #[tokio::test]
    async fn test_drain_user_stats_multiple_users() {
        let mgr = Manager::new();
        mgr.inject_closed_user_bytes("alice", 100, 200).await;
        mgr.inject_closed_user_bytes("bob", 300, 400).await;

        let stats = mgr.drain_user_stats().await;
        assert_eq!(stats.len(), 2);
        assert_eq!(stats["alice"].upload, 100);
        assert_eq!(stats["alice"].download, 200);
        assert_eq!(stats["bob"].upload, 300);
        assert_eq!(stats["bob"].download, 400);
    }

    #[tokio::test]
    async fn test_drain_user_stats_accumulates_across_connections() {
        let mgr = Manager::new();
        // Same user closes two separate connections before a drain.
        mgr.inject_closed_user_bytes("user1", 100, 200).await;
        mgr.inject_closed_user_bytes("user1", 50, 80).await;

        let stats = mgr.drain_user_stats().await;
        let u = stats.get("user1").expect("user1 not found");
        assert_eq!(u.upload, 150, "upload should be sum of both connections");
        assert_eq!(
            u.download, 280,
            "download should be sum of both connections"
        );
    }

    #[tokio::test]
    async fn test_closed_flows_pre_aggregation() {
        use crate::session::SocksAddr;
        use std::net::SocketAddr;

        let mgr = Manager::new();

        let mut sess1 = Session::default();
        sess1.destination = SocksAddr::Domain("example.com".into(), 443);
        sess1.source = "192.168.1.10:12345".parse::<SocketAddr>().unwrap();
        sess1.country = Some("US".into());
        sess1.asn = Some("Cloudflare".into());

        let tracker1 = Arc::new(TrackerInfo::new(&sess1, None));
        tracker1.upload_total.store(100, Ordering::Relaxed);
        tracker1.download_total.store(200, Ordering::Relaxed);

        let (close_tx1, _) = tokio::sync::oneshot::channel();
        mgr.track(sess1.id, tracker1, close_tx1);

        let mut sess2 = Session::default();
        sess2.destination = SocksAddr::Domain("example.com".into(), 443);
        sess2.source = "192.168.1.20:12346".parse::<SocketAddr>().unwrap();

        let tracker2 = Arc::new(TrackerInfo::new(&sess2, None));
        tracker2.upload_total.store(300, Ordering::Relaxed);
        tracker2.download_total.store(400, Ordering::Relaxed);

        let (close_tx2, _) = tokio::sync::oneshot::channel();
        mgr.track(sess2.id, tracker2, close_tx2);

        // Untrack both (they close)
        mgr.untrack(sess1.id);
        mgr.untrack(sess2.id);

        tokio::task::yield_now().await;

        let closed = mgr.closed_flows_snapshot().await;
        let key = FlowKey {
            dst_host: "example.com".into(),
            dst_port: 443,
            is_tcp: true,
        };

        let entry = closed.get(&key).expect("flow key should exist");
        assert_eq!(entry.conn_count, 2);
        assert_eq!(entry.upload_total, 400);
        assert_eq!(entry.download_total, 600);
        assert_eq!(entry.src_ips.len(), 2);
        assert_eq!(entry.country.as_deref(), Some("US"));
        assert_eq!(entry.asn.as_deref(), Some("Cloudflare"));
    }

    #[tokio::test]
    async fn test_connections_maybe_shrink() {
        let mgr = Manager::new();
        // Insert 2000 connections to force DashMap growth
        for i in 0..2000u64 {
            let mut sess = Session::default();
            sess.id = i;
            let tracker = Arc::new(TrackerInfo::new(&sess, None));
            let (tx, _) = tokio::sync::oneshot::channel();
            mgr.track(i, tracker, tx);
        }

        let cap_before = mgr.connections.capacity();
        assert!(cap_before >= 2000, "capacity should expand to accommodate 2000 items");

        // Remove 1990 connections, keeping only 10 live
        for i in 0..1990u64 {
            mgr.untrack(i);
        }
        assert_eq!(mgr.connections.len(), 10);

        // Before shrink, capacity remains high due to tombstone retention
        assert!(mgr.connections.capacity() > 512);

        // Trigger adaptive shrink
        mgr.maybe_shrink();

        let cap_after = mgr.connections.capacity();
        assert!(
            cap_after < cap_before,
            "capacity should shrink significantly (before: {}, after: {})",
            cap_before,
            cap_after
        );
        assert!(
            cap_after <= 512,
            "capacity should be shrunk near active count, got {}",
            cap_after
        );
    }

    #[test]
    fn test_shrink_controller_logic() {
        let mut controller = ShrinkController::new();

        // 1. Not bloated: capacity <= 512 or <= len * 4 -> should NOT shrink
        for _ in 0..100 {
            assert!(!controller.should_shrink(200, 500, 0));
        }

        // 2. Bloated, but high traffic -> should NOT shrink
        for _ in 0..100 {
            assert!(!controller.should_shrink(10, 2048, 1024 * 1024));
        }

        // 3. Bloated and low traffic, but before 60s threshold -> should NOT shrink
        for _ in 0..59 {
            assert!(!controller.should_shrink(10, 2048, 100));
        }

        // 4. Exactly at 60s of sustained low traffic & bloated capacity -> TRIGGER shrink!
        assert!(controller.should_shrink(10, 2048, 100));

        // 5. Immediately after shrinking, cooldown is active (300s) -> should NOT shrink
        for _ in 0..299 {
            assert!(!controller.should_shrink(10, 2048, 100));
        }

        // 6. After cooldown finishes and 60s sustained idle -> can trigger again
        assert!(controller.should_shrink(10, 2048, 100));
    }
}


