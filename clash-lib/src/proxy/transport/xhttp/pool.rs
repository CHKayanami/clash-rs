use std::{
    io,
    ops::RangeInclusive,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
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
    tasks: AtomicUsize,
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
    fn in_use(&self) -> bool {
        self.users.load(Ordering::SeqCst) != 0 || self.tasks.load(Ordering::SeqCst) != 0
    }

    fn reusable_at(&self, now: Instant) -> bool {
        let uses = self.uses.load(Ordering::Acquire);
        (self.reuses == 0 || uses <= self.reuses)
            && (self.requests == 0 || uses < self.requests)
            && self.expires.is_none_or(|expiry| now < expiry)
    }

    fn reusable(&self) -> bool {
        self.reusable_at(Instant::now())
    }
}

struct State {
    settings: Settings,
    entries: Mutex<Vec<Arc<Entry>>>,
    keep_idle: AtomicBool,
    changed: Notify,
}
impl State {
    fn prune(&self) -> bool {
        let keep_idle = self.keep_idle.load(Ordering::SeqCst);
        let evicted = {
            let mut entries = self.entries.lock();
            let now = Instant::now();
            let mut evicted = Vec::new();
            let mut i = 0;
            while i < entries.len() {
                if entries[i].in_use() || (keep_idle && entries[i].reusable_at(now)) {
                    i += 1;
                } else {
                    evicted.push(entries.swap_remove(i));
                }
            }
            evicted
        };
        let removed = !evicted.is_empty();
        drop(evicted);
        removed
    }

    fn close_idle(&self) {
        let evicted = {
            let mut entries = self.entries.lock();
            let mut evicted = Vec::new();
            let mut i = 0;
            while i < entries.len() {
                if entries[i].in_use() {
                    i += 1;
                } else {
                    evicted.push(entries.swap_remove(i));
                }
            }
            evicted
        };
        drop(evicted);
        self.changed.notify_waiters();
    }
}

pub(super) struct TaskLease {
    entry: Arc<Entry>,
    pool: Weak<State>,
}
impl Clone for TaskLease {
    fn clone(&self) -> Self {
        self.entry.tasks.fetch_add(1, Ordering::SeqCst);
        Self { entry: self.entry.clone(), pool: self.pool.clone() }
    }
}
impl Drop for TaskLease {
    fn drop(&mut self) {
        let prev_tasks = self.entry.tasks.fetch_sub(1, Ordering::SeqCst);
        if prev_tasks == 1
            && self.entry.users.load(Ordering::SeqCst) == 0
            && let Some(pool) = self.pool.upgrade()
            && (!pool.keep_idle.load(Ordering::SeqCst) || !self.entry.reusable())
            && pool.prune()
        {
            pool.changed.notify_waiters();
        }
    }
}

pub(super) struct Lease {
    entry: Arc<Entry>,
    pool: Weak<State>,
}
impl Lease {
    pub(super) fn transport(&self) -> Arc<HttpTransport> { self.entry.transport.clone() }

    pub(super) fn task_lease(&self) -> TaskLease {
        self.entry.tasks.fetch_add(1, Ordering::SeqCst);
        TaskLease { entry: self.entry.clone(), pool: self.pool.clone() }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.entry.users.fetch_sub(1, Ordering::SeqCst);
        if let Some(pool) = self.pool.upgrade() {
            pool.prune();
            pool.changed.notify_waiters();
        }
    }
}

pub(super) struct Pool(Arc<State>);
impl Pool {
    pub(super) fn new(settings: Option<&XHttpReuseSettings>) -> io::Result<Self> {
        Ok(Self(Arc::new(State {
            settings: Settings::new(settings)?,
            entries: Mutex::new(Vec::new()),
            keep_idle: AtomicBool::new(true),
            changed: Notify::new(),
        })))
    }

    pub(super) fn set_keep_idle(&self, keep: bool) {
        self.0.keep_idle.store(keep, Ordering::SeqCst);
        if !keep && self.0.settings.enabled {
            self.0.prune();
            self.0.changed.notify_waiters();
        }
    }

    pub(super) fn close_idle_connections(&self) {
        if self.0.settings.enabled {
            self.0.close_idle();
        }
    }

    pub(super) async fn acquire(&self, options: Arc<Options>, factory: ConnectionFactory) -> Lease {
        if !self.0.settings.enabled {
            return self.standalone_lease(options, factory);
        }
        loop {
            // `changed` only uses `notify_waiters()`, so constructing `Notified`
            // before scanning captures any broadcast during `try_acquire` without
            // registering on the waiter list on the fast path.
            let changed = self.0.changed.notified();
            if let Some(lease) = self.try_acquire(options.clone(), factory.clone()) { return lease; }
            changed.await;
        }
    }

    fn standalone_lease(&self, options: Arc<Options>, factory: ConnectionFactory) -> Lease {
        let entry = Arc::new(Entry {
            key: factory.key.clone(),
            transport: Arc::new(HttpTransport::new(options, factory, self.0.settings.keep_alive)),
            users: AtomicUsize::new(1),
            tasks: AtomicUsize::new(0),
            uses: AtomicUsize::new(1),
            reuses: 0,
            requests: 0,
            expires: None,
            expiry_task: Mutex::new(None),
        });
        Lease { entry, pool: Weak::new() }
    }

    fn try_acquire(&self, options: Arc<Options>, factory: ConnectionFactory) -> Option<Lease> {
        let settings = &self.0.settings;
        let mut evicted = Vec::new();
        let lease = {
            let mut entries = self.0.entries.lock();
            let keep_idle = self.0.keep_idle.load(Ordering::SeqCst);
            let now = Instant::now();
            let mut count = 0usize;
            let mut best_index: Option<usize> = None;
            let mut best_users = usize::MAX;
            let mut i = 0;
            while i < entries.len() {
                let entry = &entries[i];
                let users = entry.users.load(Ordering::SeqCst);
                let in_use = users != 0 || entry.tasks.load(Ordering::SeqCst) != 0;
                if !in_use && !keep_idle {
                    evicted.push(entries.swap_remove(i));
                    continue;
                }
                let same_key = entry.key == factory.key;
                if !in_use || same_key {
                    let reusable = entry.reusable_at(now);
                    if !in_use && !reusable {
                        evicted.push(entries.swap_remove(i));
                        continue;
                    }
                    if same_key && reusable {
                        count += 1;
                        if (settings.concurrency == 0 || users < settings.concurrency)
                            && users < best_users
                        {
                            best_users = users;
                            best_index = Some(i);
                        }
                    }
                }
                i += 1;
            }
            let expand = settings.connections != 0 && count < settings.connections;
            if !expand && let Some(index) = best_index {
                // Counters and reservations are updated under the pool mutex.
                let entry = &entries[index];
                // A lease keeps the entry alive, so its usage counter is atomic.
                entry.users.fetch_add(1, Ordering::AcqRel);
                entry.uses.fetch_add(1, Ordering::AcqRel);
                let lease = Lease { entry: entry.clone(), pool: Arc::downgrade(&self.0) };
                drop(entries);
                drop(evicted);
                return Some(lease);
            }
            if settings.connections != 0 && count >= settings.connections {
                drop(entries);
                drop(evicted);
                return None;
            }
            let seconds = rand::random_range(settings.lifetime.clone());
            let entry = Arc::new(Entry {
                key: factory.key.clone(),
                transport: Arc::new(HttpTransport::new(options, factory, settings.keep_alive)),
                users: AtomicUsize::new(1),
                tasks: AtomicUsize::new(0),
                uses: AtomicUsize::new(1),
                reuses: rand::random_range(settings.reuses.clone()) as usize,
                requests: rand::random_range(settings.requests.clone()) as usize,
                expires: (seconds != 0).then(|| now + Duration::from_secs(seconds as u64)),
                expiry_task: Mutex::new(None),
            });
            entries.push(entry.clone());
            if let Some(expiry) = entry.expires {
                let pool = Arc::downgrade(&self.0);
                let task = tokio::spawn(async move {
                    sleep_until(expiry).await;
                    if let Some(pool) = pool.upgrade() { pool.prune(); pool.changed.notify_waiters(); }
                });
                *entry.expiry_task.lock() = Some(task);
            }
            Lease { entry, pool: Arc::downgrade(&self.0) }
        };
        drop(evicted);
        Some(lease)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::internal::proxy::XHttpOpt;

    #[tokio::test]
    async fn task_lease_prunes_only_when_last_task_and_zero_users() {
        let pool = Pool::new(Some(&XHttpReuseSettings::default())).unwrap();
        pool.set_keep_idle(false);
        let opts = Arc::new(
            Options::new(&XHttpOpt::default(), "example.test", false, false, None).unwrap(),
        );
        let factory = ConnectionFactory {
            key: "k".into(),
            dial: Arc::new(|| Box::pin(async { Err(io::Error::other("unused")) })),
        };

        let lease = pool.acquire(opts, factory).await;
        let t1 = lease.task_lease();
        let t2 = t1.clone();
        let t3 = t1.clone();
        assert_eq!(pool.0.entries.lock().len(), 1);

        // Dropping non-final TaskLeases while users > 0 keeps entry in pool.
        drop(t1);
        drop(t2);
        assert_eq!(pool.0.entries.lock().len(), 1);

        // Dropping the user Lease while a TaskLease remains still keeps entry alive.
        drop(lease);
        assert_eq!(pool.0.entries.lock().len(), 1);

        // Dropping the final TaskLease with users == 0 and keep_idle == false prunes it.
        drop(t3);
        assert_eq!(pool.0.entries.lock().len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn last_task_lease_removing_expired_entry_notifies_waiters() {
        use std::future::pending;
        use tokio::time::{advance, timeout};

        let pool = Pool::new(Some(&XHttpReuseSettings {
            max_connections: Some("1".into()),
            max_concurrency: Some("1".into()),
            h_max_reusable_secs: Some("1".into()),
            ..Default::default()
        }))
        .unwrap();
        let opts = Arc::new(
            Options::new(&XHttpOpt::default(), "example.test", false, false, None).unwrap(),
        );
        let factory = ConnectionFactory {
            key: "k".into(),
            dial: Arc::new(|| Box::pin(async { Err(io::Error::other("unused")) })),
        };

        let lease = pool.acquire(opts, factory).await;
        let t1 = lease.task_lease();
        let t2 = t1.clone();
        // Replace the expiry task with a pending task to represent an expiry
        // notification that has not yet been scheduled when the entry expires.
        {
            let entries = pool.0.entries.lock();
            if let Some(old) = entries[0].expiry_task.lock().replace(tokio::spawn(pending())) {
                old.abort();
            }
        }
        drop(lease);

        advance(Duration::from_secs(2)).await;
        assert_eq!(pool.0.entries.lock().len(), 1);

        let waiter = pool.0.changed.notified();
        tokio::pin!(waiter);
        waiter.as_mut().enable();

        // Non-final TaskLease takes the fast path without waking waiters.
        drop(t1);
        assert!(timeout(Duration::from_millis(10), waiter.as_mut()).await.is_err());

        // Dropping the final TaskLease removes the expired entry (aborting its
        // pending `expiry_task`) and must wake waiters itself.
        drop(t2);
        assert_eq!(pool.0.entries.lock().len(), 0);
        timeout(Duration::from_millis(10), waiter)
            .await
            .expect("final TaskLease removing an expired entry must wake waiters");
    }

    #[tokio::test]
    async fn unpooled_acquire_uses_standalone_entry_without_locking_or_notifying() {
        use tokio::time::timeout;

        let pool = Pool::new(None).unwrap();
        let opts = Arc::new(
            Options::new(&XHttpOpt::default(), "example.test", false, false, None).unwrap(),
        );
        let factory = ConnectionFactory {
            key: "k".into(),
            dial: Arc::new(|| Box::pin(async { Err(io::Error::other("unused")) })),
        };

        let waiter = pool.0.changed.notified();
        tokio::pin!(waiter);
        waiter.as_mut().enable();

        let lease = pool.acquire(opts, factory).await;
        assert!(pool.0.entries.lock().is_empty());
        let weak_entry = Arc::downgrade(&lease.entry);
        let task = lease.task_lease();

        drop(lease);
        assert!(weak_entry.upgrade().is_some());

        drop(task);
        assert!(weak_entry.upgrade().is_none());
        assert!(timeout(Duration::from_millis(10), waiter).await.is_err());
    }
}
