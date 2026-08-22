use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::oneshot;

use super::response::ResponseTemplate;

pub const NUM_SHARDS: usize = 32;
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
    waiters: Vec<oneshot::Sender<Arc<ResponseTemplate>>>,
    state: FlightState,
}

enum FlightState {
    Running,
    Published(Arc<ResponseTemplate>),
}

#[derive(Default)]
struct Shard {
    entries: Mutex<HashMap<FlightKey, FlightEntry>>,
}

struct SingleflightInner {
    shards: [Shard; NUM_SHARDS],
    active_count: AtomicUsize,
    counters: Arc<CounterSet>,
}

impl SingleflightInner {
    #[inline]
    fn shard_idx(&self, key: &FlightKey) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) & (NUM_SHARDS - 1)
    }
}

#[derive(Clone)]
pub struct Singleflight {
    inner: Arc<SingleflightInner>,
}

impl Default for Singleflight {
    fn default() -> Self {
        Self::new()
    }
}

pub enum FlightRole {
    Leader(FlightLeader),
    Waiter(FlightWaiter),
    Ready(Arc<ResponseTemplate>),
    Rejected,
}

pub struct FlightWaiter {
    receiver: oneshot::Receiver<Arc<ResponseTemplate>>,
    counters: Arc<CounterSet>,
}

pub struct FlightLeader {
    key: Option<FlightKey>,
    inner: Arc<SingleflightInner>,
    shard_idx: usize,
}

impl Singleflight {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(SingleflightInner {
                shards: std::array::from_fn(|_| Shard::default()),
                active_count: AtomicUsize::new(0),
                counters: Arc::new(CounterSet::default()),
            }),
        }
    }

    pub fn acquire(&self, key: FlightKey) -> FlightRole {
        let shard_idx = self.inner.shard_idx(&key);
        let mut entries = lock(&self.inner.shards[shard_idx].entries);

        if let Some(entry) = entries.get_mut(&key) {
            if let FlightState::Published(template) = &entry.state {
                self.inner.counters.waiters.fetch_add(1, Ordering::Relaxed);
                return FlightRole::Ready(Arc::clone(template));
            }
            if entry.waiters.len() >= MAX_WAITERS_PER_FLIGHT {
                self.inner
                    .counters
                    .rejections
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    saturation = "waiters",
                    action = "reject",
                    "DNS singleflight saturated"
                );
                return FlightRole::Rejected;
            }
            let (tx, rx) = oneshot::channel();
            entry.waiters.push(tx);
            self.inner.counters.waiters.fetch_add(1, Ordering::Relaxed);
            self.inner
                .counters
                .amplification_avoided
                .fetch_add(1, Ordering::Relaxed);
            return FlightRole::Waiter(FlightWaiter {
                receiver: rx,
                counters: Arc::clone(&self.inner.counters),
            });
        }

        if self.inner.active_count.load(Ordering::Relaxed) >= MAX_ACTIVE_FLIGHTS {
            self.inner
                .counters
                .rejections
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                saturation = "keys",
                action = "reject",
                "DNS singleflight saturated"
            );
            return FlightRole::Rejected;
        }

        let is_refresh = key.is_refresh();
        entries.insert(
            key.clone(),
            FlightEntry {
                waiters: Vec::new(),
                state: FlightState::Running,
            },
        );
        self.inner.active_count.fetch_add(1, Ordering::Relaxed);

        if is_refresh {
            self.inner.counters.refreshes.fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner.counters.leaders.fetch_add(1, Ordering::Relaxed);
        }

        FlightRole::Leader(FlightLeader {
            key: Some(key),
            inner: Arc::clone(&self.inner),
            shard_idx,
        })
    }

    pub fn counters(&self) -> FlightCounters {
        FlightCounters {
            leaders: self.inner.counters.leaders.load(Ordering::Relaxed),
            waiters: self.inner.counters.waiters.load(Ordering::Relaxed),
            refreshes: self.inner.counters.refreshes.load(Ordering::Relaxed),
            rejections: self.inner.counters.rejections.load(Ordering::Relaxed),
            amplification_avoided: self
                .inner
                .counters
                .amplification_avoided
                .load(Ordering::Relaxed),
            aborts: self.inner.counters.aborts.load(Ordering::Relaxed),
            retries: self.inner.counters.retries.load(Ordering::Relaxed),
        }
    }

    pub fn active_len(&self) -> usize {
        self.inner.active_count.load(Ordering::Relaxed)
    }
}

impl FlightWaiter {
    pub async fn receive(self) -> Option<Arc<ResponseTemplate>> {
        match self.receiver.await {
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
        let mut entries = lock(&self.inner.shards[self.shard_idx].entries);
        if let Some(entry) = entries.get_mut(key) {
            entry.state = FlightState::Published(Arc::clone(&template));
            let waiters = std::mem::take(&mut entry.waiters);
            for tx in waiters {
                let _ = tx.send(Arc::clone(&template));
            }
        }
    }
}

impl Drop for FlightLeader {
    fn drop(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        let mut entries = lock(&self.inner.shards[self.shard_idx].entries);
        if let Some(entry) = entries.remove(&key) {
            self.inner.active_count.fetch_sub(1, Ordering::Relaxed);
            if matches!(entry.state, FlightState::Running) {
                self.inner.counters.aborts.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(role = "leader", "DNS singleflight cancelled");
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::query::{DnsName, QType, QueryContext, build_dns_query_wire_with_id};
    use crate::app::dns::response::build_dns_ip_response;

    fn make_test_template() -> (QueryContext, Arc<ResponseTemplate>) {
        let name = DnsName::from_domain("example.com").unwrap();
        let query_bytes = build_dns_query_wire_with_id(0x1234, &name, QType::A);
        let query = QueryContext::parse(&query_bytes).unwrap();
        let resp_bytes =
            build_dns_ip_response(&query_bytes, &["1.2.3.4".parse().unwrap()], 60).unwrap();
        let template = Arc::new(ResponseTemplate::validate(&query, &resp_bytes).unwrap());
        (query, template)
    }

    #[tokio::test]
    async fn test_singleflight_leader_waiter_coalesce_and_publish() {
        let sf = Singleflight::new();
        let (_query, template) = make_test_template();
        let key = FlightKey::Query(Arc::from(b"example.com" as &[u8]));

        let leader_role = sf.acquire(key.clone());
        let mut leader = match leader_role {
            FlightRole::Leader(leader) => leader,
            _ => panic!("expected leader"),
        };

        assert_eq!(sf.active_len(), 1);

        // 注册两个 Waiter
        let waiter1 = match sf.acquire(key.clone()) {
            FlightRole::Waiter(w) => w,
            _ => panic!("expected waiter1"),
        };
        let waiter2 = match sf.acquire(key.clone()) {
            FlightRole::Waiter(w) => w,
            _ => panic!("expected waiter2"),
        };

        // Leader 发布结果
        leader.publish(Arc::clone(&template));

        // 两个 Waiter 均应收到相同的 template
        let res1 = waiter1.receive().await.expect("waiter1 should receive");
        let res2 = waiter2.receive().await.expect("waiter2 should receive");
        assert!(Arc::ptr_eq(&res1, &template));
        assert!(Arc::ptr_eq(&res2, &template));

        // 发布后新来的请求应直接为 Ready
        match sf.acquire(key.clone()) {
            FlightRole::Ready(ready_tmpl) => {
                assert!(Arc::ptr_eq(&ready_tmpl, &template));
            }
            _ => panic!("expected ready"),
        }

        // Leader 结束
        drop(leader);
        assert_eq!(sf.active_len(), 0);

        let counters = sf.counters();
        assert_eq!(counters.leaders, 1);
        assert_eq!(counters.waiters, 3); // 2 个 Waiter + 1 个 Ready
        assert_eq!(counters.amplification_avoided, 2);
        assert_eq!(counters.aborts, 0);
    }

    #[tokio::test]
    async fn test_singleflight_leader_abort() {
        let sf = Singleflight::new();
        let key = FlightKey::Query(Arc::from(b"abort.com" as &[u8]));

        let leader_role = sf.acquire(key.clone());
        let leader = match leader_role {
            FlightRole::Leader(leader) => leader,
            _ => panic!("expected leader"),
        };

        let waiter = match sf.acquire(key.clone()) {
            FlightRole::Waiter(w) => w,
            _ => panic!("expected waiter"),
        };

        drop(leader);
        assert_eq!(sf.active_len(), 0);

        let res = waiter.receive().await;
        assert!(res.is_none());

        let counters = sf.counters();
        assert_eq!(counters.leaders, 1);
        assert_eq!(counters.waiters, 1);
        assert_eq!(counters.aborts, 1);
        assert_eq!(counters.retries, 1);
    }

    #[tokio::test]
    async fn test_singleflight_waiter_saturation() {
        let sf = Singleflight::new();
        let key = FlightKey::Query(Arc::from(b"saturated.com" as &[u8]));

        let leader_role = sf.acquire(key.clone());
        let _leader = match leader_role {
            FlightRole::Leader(leader) => leader,
            _ => panic!("expected leader"),
        };

        let mut waiters = Vec::new();
        for _ in 0..MAX_WAITERS_PER_FLIGHT {
            match sf.acquire(key.clone()) {
                FlightRole::Waiter(w) => waiters.push(w),
                _ => panic!("expected waiter"),
            }
        }

        // 超出最大 Waiter 数，应当被拒绝
        match sf.acquire(key.clone()) {
            FlightRole::Rejected => {}
            _ => panic!("expected rejected on waiter saturation"),
        }

        assert_eq!(sf.counters().rejections, 1);
    }

    #[tokio::test]
    async fn test_singleflight_key_saturation() {
        let sf = Singleflight::new();
        let mut leaders = Vec::new();

        for i in 0..MAX_ACTIVE_FLIGHTS {
            let key = FlightKey::Query(Arc::from(format!("flight-{}.com", i).into_bytes()));
            match sf.acquire(key) {
                FlightRole::Leader(l) => leaders.push(l),
                _ => panic!("expected leader"),
            }
        }

        assert_eq!(sf.active_len(), MAX_ACTIVE_FLIGHTS);

        // 超出最大活跃 Flight 数，应当被拒绝
        let overflow_key = FlightKey::Query(Arc::from(b"overflow.com" as &[u8]));
        match sf.acquire(overflow_key) {
            FlightRole::Rejected => {}
            _ => panic!("expected rejected on key saturation"),
        }

        assert_eq!(sf.counters().rejections, 1);
    }

    #[tokio::test]
    async fn test_singleflight_refresh_counter() {
        let sf = Singleflight::new();
        let key = FlightKey::Refresh(Arc::from(b"refresh.com" as &[u8]));

        let leader_role = sf.acquire(key);
        let leader = match leader_role {
            FlightRole::Leader(leader) => leader,
            _ => panic!("expected leader"),
        };

        assert_eq!(sf.counters().refreshes, 1);
        assert_eq!(sf.counters().leaders, 0);
        drop(leader);
    }

    #[tokio::test]
    async fn test_singleflight_concurrent_shards() {
        let sf = Singleflight::new();
        let mut handles = Vec::new();

        for i in 0..64 {
            let sf_clone = sf.clone();
            handles.push(tokio::spawn(async move {
                let key = FlightKey::Query(Arc::from(format!("concurrent-{}.com", i % 8).into_bytes()));
                match sf_clone.acquire(key) {
                    FlightRole::Leader(leader) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        drop(leader);
                    }
                    FlightRole::Waiter(waiter) => {
                        let _ = waiter.receive().await;
                    }
                    FlightRole::Ready(_) | FlightRole::Rejected => {}
                }
            }));
        }

        for h in handles {
            let _ = h.await;
        }

        assert_eq!(sf.active_len(), 0);
    }
}
