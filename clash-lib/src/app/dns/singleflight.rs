use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::broadcast;

use super::response::ResponseTemplate;

pub const MAX_ACTIVE_FLIGHTS: usize = 2048;
pub const MAX_WAITERS_PER_FLIGHT: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FlightKey {
    Query(Arc<[u8]>),
    Refresh(Arc<[u8]>),
}

impl FlightKey {
    pub fn is_refresh(&self) -> bool {
        matches!(self, Self::Refresh(_))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlightCounters {
    pub leaders: u64,
    pub waiters: u64,
    pub refreshes: u64,
    pub rejections: u64,
    pub amplification_avoided: u64,
    pub aborts: u64,
    pub retries: u64,
}

#[derive(Default)]
struct CounterSet {
    leaders: AtomicU64,
    waiters: AtomicU64,
    refreshes: AtomicU64,
    rejections: AtomicU64,
    amplification_avoided: AtomicU64,
    aborts: AtomicU64,
    retries: AtomicU64,
}

struct FlightEntry {
    sender: broadcast::Sender<Arc<ResponseTemplate>>,
    state: FlightState,
}

enum FlightState {
    Running,
    Published(Arc<ResponseTemplate>),
}

#[derive(Clone, Default)]
pub struct Singleflight {
    entries: Arc<Mutex<HashMap<FlightKey, FlightEntry>>>,
    counters: Arc<CounterSet>,
}

pub enum FlightRole {
    Leader(FlightLeader),
    Waiter(FlightWaiter),
    Ready(Arc<ResponseTemplate>),
    Rejected,
}

pub struct FlightWaiter {
    receiver: broadcast::Receiver<Arc<ResponseTemplate>>,
    counters: Arc<CounterSet>,
}

pub struct FlightLeader {
    key: Option<FlightKey>,
    entries: Arc<Mutex<HashMap<FlightKey, FlightEntry>>>,
    counters: Arc<CounterSet>,
}

impl Singleflight {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn acquire(&self, key: FlightKey) -> FlightRole {
        let mut entries = lock(&self.entries);
        if let Some(entry) = entries.get(&key) {
            if let FlightState::Published(template) = &entry.state {
                self.counters.waiters.fetch_add(1, Ordering::Relaxed);
                return FlightRole::Ready(Arc::clone(template));
            }
            if entry.sender.receiver_count() >= MAX_WAITERS_PER_FLIGHT {
                self.counters.rejections.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    saturation = "waiters",
                    action = "reject",
                    "DNS singleflight saturated"
                );
                return FlightRole::Rejected;
            }
            self.counters.waiters.fetch_add(1, Ordering::Relaxed);
            self.counters
                .amplification_avoided
                .fetch_add(1, Ordering::Relaxed);
            return FlightRole::Waiter(FlightWaiter {
                receiver: entry.sender.subscribe(),
                counters: Arc::clone(&self.counters),
            });
        }
        if entries.len() >= MAX_ACTIVE_FLIGHTS {
            self.counters.rejections.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                saturation = "keys",
                action = "reject",
                "DNS singleflight saturated"
            );
            return FlightRole::Rejected;
        }
        let (sender, _) = broadcast::channel(1);
        let is_refresh = key.is_refresh();
        entries.insert(
            key.clone(),
            FlightEntry {
                sender,
                state: FlightState::Running,
            },
        );
        if is_refresh {
            self.counters.refreshes.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.leaders.fetch_add(1, Ordering::Relaxed);
        }
        FlightRole::Leader(FlightLeader {
            key: Some(key),
            entries: Arc::clone(&self.entries),
            counters: Arc::clone(&self.counters),
        })
    }

    pub fn counters(&self) -> FlightCounters {
        FlightCounters {
            leaders: self.counters.leaders.load(Ordering::Relaxed),
            waiters: self.counters.waiters.load(Ordering::Relaxed),
            refreshes: self.counters.refreshes.load(Ordering::Relaxed),
            rejections: self.counters.rejections.load(Ordering::Relaxed),
            amplification_avoided: self.counters.amplification_avoided.load(Ordering::Relaxed),
            aborts: self.counters.aborts.load(Ordering::Relaxed),
            retries: self.counters.retries.load(Ordering::Relaxed),
        }
    }

    pub fn active_len(&self) -> usize {
        lock(&self.entries).len()
    }
}

impl FlightWaiter {
    pub async fn receive(mut self) -> Option<Arc<ResponseTemplate>> {
        match self.receiver.recv().await {
            Ok(template) => Some(template),
            Err(_) => {
                self.counters.retries.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(reason = "leader_unavailable", "DNS singleflight retry");
                None
            }
        }
    }
}

impl FlightLeader {
    pub fn publish(&mut self, template: Arc<ResponseTemplate>) {
        let Some(key) = self.key.as_ref() else {
            return;
        };
        if let Some(entry) = lock(&self.entries).get_mut(key) {
            entry.state = FlightState::Published(Arc::clone(&template));
            let _ = entry.sender.send(template);
        }
    }
}

impl Drop for FlightLeader {
    fn drop(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        let aborted = lock(&self.entries)
            .remove(&key)
            .is_some_and(|entry| matches!(entry.state, FlightState::Running));
        if aborted {
            self.counters.aborts.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(role = "leader", "DNS singleflight cancelled");
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
