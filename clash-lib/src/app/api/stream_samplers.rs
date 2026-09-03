use std::{
    collections::HashMap,
    sync::{Arc, Weak},
    time::Duration,
};

use parking_lot::Mutex;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use super::handlers::flows::build_flow_records;
use crate::app::dispatcher::StatisticsManager;

const CHANNEL_CAPACITY: usize = 16;
pub const FLOW_SAMPLER_INTERVAL: Duration = Duration::from_secs(5);

struct ConnectionSamplerGuard {
    samplers: Weak<StreamSamplers>,
    interval: Duration,
    tx: broadcast::Sender<Arc<str>>,
    active: bool,
}

impl Drop for ConnectionSamplerGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(samplers) = self.samplers.upgrade() {
            let mut conns = samplers.connections.lock();
            if let Some(sender) = conns.get(&self.interval)
                && sender.same_channel(&self.tx)
            {
                conns.remove(&self.interval);
            }
        }
    }
}

struct FlowSamplerGuard {
    samplers: Weak<StreamSamplers>,
    key: (usize, bool),
    tx: broadcast::Sender<Arc<str>>,
    active: bool,
}

impl Drop for FlowSamplerGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(samplers) = self.samplers.upgrade() {
            let mut flows = samplers.flows.lock();
            if let Some(sender) = flows.get(&self.key)
                && sender.same_channel(&self.tx)
            {
                flows.remove(&self.key);
            }
        }
    }
}

/// Unified API stream samplers managing background broadcast tasks.
///
/// Ensures all WebSocket clients sharing identical parameters (interval or
/// query parameters) subscribe to a single shared background polling/aggregation
/// task, avoiding redundant DashMap scans, sorting, and JSON serializations.
pub struct StreamSamplers {
    connections: Mutex<HashMap<Duration, broadcast::Sender<Arc<str>>>>,
    flows: Mutex<HashMap<(usize, bool), broadcast::Sender<Arc<str>>>>,
}

impl StreamSamplers {
    pub fn new() -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
            flows: Mutex::new(HashMap::new()),
        }
    }

    /// Subscribe to connection snapshots at the given interval.
    ///
    /// If an active sampler task with the same `interval` already exists,
    /// this subscribes directly to its broadcast channel. The passed `mgr`
    /// is used when initializing the underlying sampler task.
    pub fn subscribe_connections(
        self: &Arc<Self>,
        mgr: Arc<StatisticsManager>,
        interval: Duration,
    ) -> broadcast::Receiver<Arc<str>> {
        let mut conns = self.connections.lock();
        if let Some(sender) = conns.get(&interval) {
            sender.subscribe()
        } else {
            let (tx, rx) = broadcast::channel(CHANNEL_CAPACITY);
            conns.insert(interval, tx.clone());
            drop(conns);
            self.spawn_connection_sampler(mgr, interval, tx);
            rx
        }
    }

    fn spawn_connection_sampler(
        self: &Arc<Self>,
        mgr: Arc<StatisticsManager>,
        interval: Duration,
        tx: broadcast::Sender<Arc<str>>,
    ) {
        let samplers = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut guard = ConnectionSamplerGuard {
                samplers: samplers.clone(),
                interval,
                tx: tx.clone(),
                active: true,
            };

            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut buf = Vec::with_capacity(8192);

            loop {
                ticker.tick().await;
                if tx.receiver_count() == 0 {
                    if let Some(s) = samplers.upgrade() {
                        let mut conns = s.connections.lock();
                        if let Some(sender) = conns.get(&interval)
                            && sender.same_channel(&tx)
                            && sender.receiver_count() == 0
                        {
                            conns.remove(&interval);
                            guard.active = false;
                            break;
                        }
                    } else {
                        break;
                    }
                }

                let snapshot = mgr.snapshot();
                buf.clear();
                if let Err(e) = serde_json::to_writer(&mut buf, &snapshot) {
                    warn!("failed to serialize connection snapshot: {}", e);
                    continue;
                }
                let Ok(body) = std::str::from_utf8(&buf) else { continue };
                let frame: Arc<str> = Arc::from(body);
                let _ = tx.send(frame);
            }
            debug!("connection sampler task for {:?} stopped", interval);
        });
    }

    /// Subscribe to aggregated flows records at fixed 5s intervals.
    ///
    /// If an active sampler task with the same `(top, include_closed)` key exists,
    /// this subscribes directly to its broadcast channel. The passed `mgr`
    /// is used when initializing the underlying sampler task.
    pub fn subscribe_flows(
        self: &Arc<Self>,
        mgr: Arc<StatisticsManager>,
        top: usize,
        include_closed: bool,
    ) -> broadcast::Receiver<Arc<str>> {
        let key = (top, include_closed);
        let mut flows = self.flows.lock();
        if let Some(sender) = flows.get(&key) {
            sender.subscribe()
        } else {
            let (tx, rx) = broadcast::channel(CHANNEL_CAPACITY);
            flows.insert(key, tx.clone());
            drop(flows);
            self.spawn_flow_sampler(mgr, key, tx);
            rx
        }
    }

    fn spawn_flow_sampler(
        self: &Arc<Self>,
        mgr: Arc<StatisticsManager>,
        key: (usize, bool),
        tx: broadcast::Sender<Arc<str>>,
    ) {
        let (top, include_closed) = key;
        let samplers = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut guard = FlowSamplerGuard {
                samplers: samplers.clone(),
                key,
                tx: tx.clone(),
                active: true,
            };

            let mut ticker = tokio::time::interval(FLOW_SAMPLER_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut buf = Vec::with_capacity(4096);

            loop {
                ticker.tick().await;
                if tx.receiver_count() == 0 {
                    if let Some(s) = samplers.upgrade() {
                        let mut flows = s.flows.lock();
                        if let Some(sender) = flows.get(&key)
                            && sender.same_channel(&tx)
                            && sender.receiver_count() == 0
                        {
                            flows.remove(&key);
                            guard.active = false;
                            break;
                        }
                    } else {
                        break;
                    }
                }

                let records = build_flow_records(&mgr, top, include_closed).await;
                buf.clear();
                if let Err(e) = serde_json::to_writer(&mut buf, &records) {
                    warn!("failed to serialize flow records: {}", e);
                    continue;
                }
                let Ok(body) = std::str::from_utf8(&buf) else { continue };
                let frame: Arc<str> = Arc::from(body);
                let _ = tx.send(frame);
            }
            debug!("flow sampler task for {:?} stopped", key);
        });
    }

    #[cfg(test)]
    pub fn active_connection_samplers_count(&self) -> usize {
        self.connections.lock().len()
    }

    #[cfg(test)]
    pub fn active_flow_samplers_count(&self) -> usize {
        self.flows.lock().len()
    }
}

impl Default for StreamSamplers {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dispatcher::Manager;

    #[tokio::test]
    async fn test_stream_samplers_connections_broadcast() {
        let mgr = Manager::new();
        let samplers = Arc::new(StreamSamplers::new());
        let interval = Duration::from_millis(50);

        let mut sub1 = samplers.subscribe_connections(mgr.clone(), interval);
        let mut sub2 = samplers.subscribe_connections(mgr.clone(), interval);

        assert_eq!(samplers.active_connection_samplers_count(), 1);

        let frame1 = tokio::time::timeout(Duration::from_millis(300), sub1.recv())
            .await
            .expect("sub1 timed out")
            .expect("sub1 recv error");

        let frame2 = tokio::time::timeout(Duration::from_millis(300), sub2.recv())
            .await
            .expect("sub2 timed out")
            .expect("sub2 recv error");

        assert_eq!(frame1, frame2);
        assert!(frame1.contains("\"connections\":[]"));

        drop(sub1);
        drop(sub2);

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            samplers.active_connection_samplers_count(),
            0,
            "sampler should unregister after all receivers are dropped"
        );
    }
}

