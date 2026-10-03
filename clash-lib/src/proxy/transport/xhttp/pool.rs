use std::{io, ops::RangeInclusive, sync::{Arc, Weak, atomic::{AtomicUsize, Ordering}}, time::Duration};
use parking_lot::Mutex;
use tokio::{sync::Notify, task::JoinHandle, time::{Instant, sleep_until}};
use crate::config::internal::proxy::XHttpReuseSettings;
use super::{connection::{ConnectionFactory, HttpTransport}, options::Options, range::{invalid, range}};

struct Settings {
    enabled: bool,
    concurrency: usize,
    connections: usize,
    reuses: RangeInclusive<u32>,
    requests: RangeInclusive<u32>,
    lifetime: RangeInclusive<u32>,
    keep_alive: Option<Duration>,
}

impl Settings {
    fn new(config: Option<&XHttpReuseSettings>) -> io::Result<Self> {
        let empty = XHttpReuseSettings::default();
        let configured = config.unwrap_or(&empty);
        let keep_alive = match configured.h_keep_alive_period.unwrap_or(0) {
            -1 => None,
            0 => Some(Duration::from_secs(45)),
            value if value > 0 && value <= 86_400 => Some(Duration::from_secs(value as u64)),
            _ => return Err(invalid("XHTTP h-keep-alive-period must be -1, 0 or positive seconds")),
        };
        Ok(Self {
            enabled: config.is_some(),
            concurrency: rand::random_range(range(configured.max_concurrency.as_deref(), 0..=0, 0..=65_536, "max concurrency")?) as usize,
            connections: rand::random_range(range(configured.max_connections.as_deref(), 0..=0, 0..=4096, "max connections")?) as usize,
            reuses: range(configured.c_max_reuse_times.as_deref(), 0..=0, 0..=u32::MAX, "connection reuse count")?,
            requests: range(configured.h_max_request_times.as_deref(), 0..=0, 0..=u32::MAX, "request count")?,
            lifetime: range(configured.h_max_reusable_secs.as_deref(), 0..=0, 0..=31_536_000, "connection lifetime")?,
            keep_alive,
        })
    }
}

struct Entry {
    key: String,
    transport: Arc<HttpTransport>,
    users: AtomicUsize,
    uses: AtomicUsize,
    reuses: usize,
    requests: usize,
    expires: Option<Instant>,
    expiry_task: Mutex<Option<JoinHandle<()>>>,
}
impl Drop for Entry {
    fn drop(&mut self) {
        if let Some(task) = self.expiry_task.get_mut().take() { task.abort(); }
    }
}
impl Entry {
    fn reusable(&self) -> bool {
        (self.reuses == 0 || self.uses.load(Ordering::Acquire) <= self.reuses)
            && (self.requests == 0 || self.uses.load(Ordering::Acquire) < self.requests)
            && self.expires.is_none_or(|expiry| Instant::now() < expiry)
    }
}

struct State {
    settings: Settings,
    entries: Mutex<Vec<Arc<Entry>>>,
    changed: Notify,
}
impl State {
    fn prune(&self) {
        self.entries.lock().retain(|entry| entry.users.load(Ordering::Acquire) != 0 || entry.reusable());
    }
}

pub(super) struct Lease {
    entry: Arc<Entry>,
    pool: Weak<State>,
}
impl Lease {
    pub(super) fn transport(&self) -> Arc<HttpTransport> { self.entry.transport.clone() }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.entry.users.fetch_sub(1, Ordering::AcqRel);
        if let Some(pool) = self.pool.upgrade() {
            pool.prune();
            pool.changed.notify_waiters();
        }
    }
}

pub(super) struct Pool(Arc<State>);
impl Pool {
    pub(super) fn new(settings: Option<&XHttpReuseSettings>) -> io::Result<Self> {
        Ok(Self(Arc::new(State { settings: Settings::new(settings)?, entries: Mutex::new(Vec::new()), changed: Notify::new() })))
    }

    pub(super) async fn acquire(&self, options: Arc<Options>, factory: ConnectionFactory) -> Lease {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(lease) = self.try_acquire(options.clone(), factory.clone()) { return lease; }
            changed.await;
        }
    }

    fn try_acquire(&self, options: Arc<Options>, factory: ConnectionFactory) -> Option<Lease> {
        let settings = &self.0.settings;
        let mut entries = self.0.entries.lock();
        entries.retain(|entry| entry.users.load(Ordering::Acquire) != 0 || entry.reusable());
        if settings.enabled {
            let count = entries.iter().filter(|entry| entry.key == factory.key && entry.reusable()).count();
            let expand = settings.connections != 0 && count < settings.connections;
            let picked = entries.iter().enumerate().filter(|(_, entry)| !expand && entry.key == factory.key && entry.reusable()
                && (settings.concurrency == 0 || entry.users.load(Ordering::Acquire) < settings.concurrency))
                .min_by_key(|(_, entry)| entry.users.load(Ordering::Acquire)).map(|(index, _)| index);
            if let Some(index) = picked {
                // Counters and reservations are updated under the pool mutex.
                let entry = &mut entries[index];
                // A lease keeps the entry alive, so its usage counter is atomic.
                entry.users.fetch_add(1, Ordering::AcqRel);
                entry.uses.fetch_add(1, Ordering::AcqRel);
                return Some(Lease { entry: entry.clone(), pool: Arc::downgrade(&self.0) });
            }
            if settings.connections != 0 && count >= settings.connections { return None; }
        }
        let seconds = rand::random_range(settings.lifetime.clone());
        let entry = Arc::new(Entry {
            key: factory.key.clone(), transport: Arc::new(HttpTransport::new(options, factory, settings.keep_alive)),
            users: AtomicUsize::new(1), uses: AtomicUsize::new(1),
            reuses: rand::random_range(settings.reuses.clone()) as usize,
            requests: rand::random_range(settings.requests.clone()) as usize,
            expires: (seconds != 0).then(|| Instant::now() + Duration::from_secs(seconds as u64)),
            expiry_task: Mutex::new(None),
        });
        if settings.enabled {
            entries.push(entry.clone());
            if let Some(expiry) = entry.expires {
                let pool = Arc::downgrade(&self.0);
                let task = tokio::spawn(async move {
                    sleep_until(expiry).await;
                    if let Some(pool) = pool.upgrade() { pool.prune(); pool.changed.notify_waiters(); }
                });
                *entry.expiry_task.lock() = Some(task);
            }
        }
        Some(Lease { entry, pool: Arc::downgrade(&self.0) })
    }
}
