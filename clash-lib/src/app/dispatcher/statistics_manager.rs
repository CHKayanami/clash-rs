use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, atomic::Ordering},
};

use chrono::Utc;
use dashmap::DashMap;
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
    #[serde(rename = "start")]
    pub start_time: chrono::DateTime<Utc>,
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
        Self {
            id: sess.id,
            session_holder: sess.clone(),
            start_time: chrono::Utc::now(),
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
        if let Self::Active { tracker, manager, has_user } = self {
            tracker.upload_total.fetch_add(n as u64, Ordering::Relaxed);
            if *has_user {
                tracker.user_upload.fetch_add(n as u64, Ordering::Relaxed);
            }
            manager.push_uploaded(n);
        }
    }

    #[inline(always)]
    pub fn push_download(&self, n: usize) {
        if let Self::Active { tracker, manager, has_user } = self {
            tracker.download_total.fetch_add(n as u64, Ordering::Relaxed);
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

/// The close notifier is an `Option` so that [`Manager::close`] can *take* it
/// (a `oneshot::Sender` is consumed by `send`) without removing the map entry.
/// Removal — and the byte accounting that goes with it — stays the exclusive
/// job of [`Manager::untrack`], which runs from the tracker's `Drop`.
type ConnectionMap = DashMap<u64, (Arc<TrackerInfo>, Option<Sender<()>>)>;

pub struct Manager {
    connections: ConnectionMap,
    closed_flows: Mutex<VecDeque<Arc<TrackerInfo>>>,
    upload_temp: AtomicU64,
    download_temp: AtomicU64,
    upload_blip: AtomicU64,
    download_blip: AtomicU64,
    upload_total: AtomicU64,
    download_total: AtomicU64,
    /// Bytes accumulated from **closed** connections, keyed by inbound_user.
    /// Drained (and reset) by [`Manager::drain_user_stats`].
    user_period_stats: Mutex<HashMap<String, UserTraffic>>,
}

impl Manager {
    pub fn new() -> Arc<Self> {
        let v = Arc::new(Self {
            connections: DashMap::new(),
            closed_flows: Mutex::new(VecDeque::new()),
            upload_temp: AtomicU64::new(0),
            download_temp: AtomicU64::new(0),
            upload_blip: AtomicU64::new(0),
            download_blip: AtomicU64::new(0),
            upload_total: AtomicU64::new(0),
            download_total: AtomicU64::new(0),
            user_period_stats: Mutex::new(HashMap::new()),
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

    pub fn track(&self, id: u64, item: Arc<TrackerInfo>, close_notify: Sender<()>) {
        self.connections
            .insert(id, (item, Some(close_notify)));
    }

    /// Untrack a connection.
    /// This method is not async because it is called in Drop.
    /// When the connection has an inbound_user, its final byte counts are
    /// accumulated into `user_period_stats` so they survive connection close.
    pub fn untrack(&self, id: u64) {
        let removed = self.connections.remove(&id);

        if let Some((_, (info, _))) = removed {
            // Atomically take the remaining user-accounting bytes.
            // upload_total/download_total are left intact for /connections.
            let upload = info.user_upload.swap(0, Ordering::Relaxed);
            let download = info.user_download.swap(0, Ordering::Relaxed);
            if let Some(ref user) = info.session_holder.inbound_user
                && (upload > 0 || download > 0)
            {
                let mut stats = self.user_period_stats.lock().unwrap();
                let entry = stats
                    .entry(user.clone())
                    .or_insert_with(UserTraffic::default);
                entry.upload += upload;
                entry.download += download;
            }

            // Push to the closed_flows ring buffer (cap 1000).
            let mut ring = self.closed_flows.lock().unwrap();
            ring.push_back(info);
            if ring.len() > 1000 {
                ring.pop_front();
            }
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

    /// Return a snapshot of recently closed connections (up to 1000 entries).
    pub fn closed_flows_snapshot(&self) -> Vec<Arc<TrackerInfo>> {
        let ring = self.closed_flows.lock().unwrap();
        ring.iter().cloned().collect()
    }

    /// Return per-user traffic accumulated since the last call (for both closed
    /// and currently-active connections) and reset all counters.
    ///
    /// Called by the `/user-stats` REST endpoint so FAC can poll for deltas.
    pub async fn drain_user_stats(&self) -> HashMap<String, UserTraffic> {
        // Drain the closed-connection accumulator.
        let mut result: HashMap<String, UserTraffic> = {
            let mut stats = self.user_period_stats.lock().unwrap();
            std::mem::take(&mut *stats)
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
        let keys: Vec<u64> =
            self.connections.iter().map(|r| *r.key()).collect();
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

    pub async fn snapshot(&self) -> Snapshot {
        let connections: Vec<Arc<TrackerInfo>> = self
            .connections
            .iter()
            .map(|r| r.value().0.clone())
            .collect();

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
        let mut stats = self.user_period_stats.lock().unwrap();
        let entry = stats.entry(user.to_string()).or_default();
        entry.upload += upload;
        entry.download += download;
    }

    async fn kick_off(this: std::sync::Weak<Self>) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            ticker.tick().await;
            // Last owner gone — nothing left to tick for.
            let Some(me) = this.upgrade() else { break };
            me.upload_blip
                .store(me.upload_temp.swap(0, Ordering::Relaxed), Ordering::Relaxed);
            me.download_blip.store(
                me.download_temp.swap(0, Ordering::Relaxed),
                Ordering::Relaxed,
            );
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
}
