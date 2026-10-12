use std::sync::{Arc, atomic::Ordering};
use portable_atomic::AtomicU64;
use crate::app::dispatcher::Manager;

#[derive(Default)]
pub(crate) struct UserTrafficCounters {
    pub(crate) upload: AtomicU64,
    pub(crate) download: AtomicU64,
}

/// Shared user counters survive worker exit until the next statistics drain.
/// Packet processing uses cached counters and never locks the user registry.
pub(super) struct UdpTraffic {
    manager: Arc<Manager>,
    user: Option<Arc<UserTrafficCounters>>,
}

impl UdpTraffic {
    pub(super) fn new(manager: Arc<Manager>, user: Option<&Arc<str>>) -> Self {
        let user = user.map(|user| manager.udp_user_counters(user));
        Self { manager, user }
    }

    pub(super) fn push_upload(&self, n: usize) {
        self.manager.push_uploaded(n);
        if let Some(user) = &self.user { user.upload.fetch_add(n as u64, Ordering::Relaxed); }
    }

    pub(super) fn push_download(&self, n: usize) {
        self.manager.push_downloaded(n);
        if let Some(user) = &self.user { user.download.fetch_add(n as u64, Ordering::Relaxed); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{app::dispatcher::{TrackerInfo, TrafficTracker}, session::Session};
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn shared_user_counters_survive_worker_exit_and_are_reclaimed() {
        let manager = Manager::new();
        let user: Arc<str> = Arc::from("test-user");
        let first = UdpTraffic::new(manager.clone(), Some(&user));
        let second = UdpTraffic::new(manager.clone(), Some(&user));
        assert!(Arc::ptr_eq(first.user.as_ref().unwrap(), second.user.as_ref().unwrap()));
        let counters = Arc::downgrade(first.user.as_ref().unwrap());
        first.push_upload(5);
        second.push_download(7);
        let stats = manager.drain_user_stats().await;
        assert_eq!(stats["test-user"].upload, 5);
        assert_eq!(stats["test-user"].download, 7);
        assert!(manager.active_connections_snapshot().is_empty());
        assert_eq!(manager.traffic_summary().4, 0);
        first.push_upload(3);
        drop(first);
        drop(second);
        let stats = manager.drain_user_stats().await;
        assert_eq!(stats["test-user"].upload, 3);
        assert_eq!(stats["test-user"].download, 0);
        assert!(counters.upgrade().is_none());
        assert!(manager.drain_user_stats().await.is_empty());
    }

    #[tokio::test]
    async fn udp_and_tcp_user_traffic_merge_without_double_counting() {
        let manager = Manager::new();
        let user: Arc<str> = Arc::from("test-user");
        let udp = UdpTraffic::new(manager.clone(), Some(&user));
        let sess = Session { inbound_user: Some(user), ..Session::default() };
        let info = Arc::new(TrackerInfo::new(&sess, None));
        let (tx, _) = oneshot::channel();
        manager.track(sess.id, info.clone(), tx);
        let tcp = TrafficTracker::new(info, manager.clone());
        tcp.push_upload(11);
        tcp.push_download(13);
        udp.push_upload(5);
        udp.push_download(7);
        let snapshot = serde_json::to_value(manager.snapshot()).unwrap();
        assert_eq!(snapshot["uploadTotal"], 16);
        assert_eq!(snapshot["downloadTotal"], 20);
        assert_eq!(snapshot["connections"].as_array().unwrap().len(), 1);
        let stats = manager.drain_user_stats().await;
        assert_eq!(stats["test-user"].upload, 16);
        assert_eq!(stats["test-user"].download, 20);
        manager.untrack(sess.id);
        drop(udp);
        assert!(manager.drain_user_stats().await.is_empty());
        assert_eq!(manager.traffic_summary().4, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_worker_exit_and_user_drains_preserve_all_bytes() {
        let manager = Manager::new();
        let user: Arc<str> = Arc::from("test-user");
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let manager = manager.clone();
            let user = user.clone();
            tasks.push(tokio::spawn(async move {
                for _ in 0..128 {
                    let traffic = UdpTraffic::new(manager.clone(), Some(&user));
                    traffic.push_upload(1);
                    traffic.push_download(2);
                    drop(traffic);
                    tokio::task::yield_now().await;
                }
            }));
        }
        let mut upload = 0;
        let mut download = 0;
        while tasks.iter().any(|task| !task.is_finished()) {
            for (_, traffic) in manager.drain_user_stats().await {
                upload += traffic.upload;
                download += traffic.download;
            }
        }
        for task in tasks { task.await.unwrap(); }
        for (_, traffic) in manager.drain_user_stats().await {
            upload += traffic.upload;
            download += traffic.download;
        }
        assert_eq!(upload, 1024);
        assert_eq!(download, 2048);
        assert!(manager.drain_user_stats().await.is_empty());
        assert!(manager.active_connections_snapshot().is_empty());
    }

}
