use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use super::{InMemStore, Store};
use crate::app::profile::{FakeIpOperation, ThreadSafeCacheFile};

enum FakeIpCommand {
    Operation(FakeIpOperation),
    Operations(Vec<FakeIpOperation>),
    DeleteBatch {
        items: Vec<(String, Option<String>)>,
    },
}

fn flush_pending(
    pending: &mut Vec<FakeIpOperation>,
    mut commit: impl FnMut(&[FakeIpOperation]) -> anyhow::Result<()>,
) -> bool {
    match commit(pending) {
        Ok(()) => {
            pending.clear();
            true
        }
        Err(e) => {
            warn!(
                "failed to persist fake-ip batch, retaining for retry: {}",
                e
            );
            false
        }
    }
}

// Bound retries after channel closure so a permanently failing database cannot
// keep the worker (and its database handle) alive forever.
async fn flush_on_close(
    pending: &mut Vec<FakeIpOperation>,
    mut commit: impl FnMut(&[FakeIpOperation]) -> anyhow::Result<()>,
) {
    const MAX_ATTEMPTS: usize = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        if flush_pending(pending, &mut commit) {
            return;
        }
        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }
    error!(
        attempts = MAX_ATTEMPTS,
        pending_operations = pending.len(),
        "fake-ip worker exiting with unpersisted operations after final flush failed"
    );
}

// Reconcile indexes independently: removing an obsolete host key must not
// remove an IP mapping that is still retained (and vice versa).
fn reconciliation_operations(
    host_to_ip: &HashMap<String, String>,
    ip_to_host: &HashMap<String, String>,
    desired_hosts: &HashMap<String, String>,
    desired_ips: &HashMap<String, String>,
) -> Vec<FakeIpOperation> {
    let ips: Vec<_> = ip_to_host
        .keys()
        .filter(|ip| !desired_ips.contains_key(*ip))
        .cloned()
        .collect();
    let host_keys: Vec<_> = host_to_ip
        .keys()
        .filter(|key| !desired_hosts.contains_key(*key))
        .cloned()
        .collect();
    let mut operations = Vec::new();
    if !ips.is_empty() || !host_keys.is_empty() {
        operations.push(FakeIpOperation::Prune { ips, host_keys });
    }
    for (host_key, ip) in desired_hosts {
        let Some(host) = desired_ips.get(ip) else {
            continue;
        };
        if ip_to_host.get(ip) != Some(host) || host_to_ip.get(host_key) != Some(ip) {
            operations.push(FakeIpOperation::Put {
                ip: ip.clone(),
                host: host.clone(),
                host_key: host_key.clone(),
            });
        }
    }
    operations
}

pub struct FileStore {
    cache: InMemStore,
    file: ThreadSafeCacheFile,
    tx: Option<mpsc::UnboundedSender<FakeIpCommand>>,
    pending: parking_lot::Mutex<Vec<FakeIpOperation>>,
    // Keep persistent commands in the same order as in-memory mutations.
    mutations: parking_lot::Mutex<()>,
    initial_v4_offset: u32,
    initial_v6_offset: u128,
}

impl FileStore {
    pub fn new(
        store: ThreadSafeCacheFile,
        ipnet: ipnet::Ipv4Net,
        ipnet6: ipnet::Ipv6Net,
    ) -> anyhow::Result<Self> {
        Self::with_capacity(store, super::DEFAULT_CACHE_CAPACITY, ipnet, ipnet6)
    }

    /// Total mapping budget across IPv4 and IPv6, also enforced on restore.
    pub fn with_capacity(
        store: ThreadSafeCacheFile,
        capacity: usize,
        ipnet: ipnet::Ipv4Net,
        ipnet6: ipnet::Ipv6Net,
    ) -> anyhow::Result<Self> {
        let (min_v4, max_v4) =
            super::compute_v4_range(&ipnet).unwrap_or((u32::MAX, 0));
        let (prefix_v6, prefix_len_v6, min_host_v6, max_host_v6) =
            super::compute_v6_range(&ipnet6).unwrap_or(([0; 16], 128, 1, 0));
        let mask_v6 = super::v6_prefix_mask(prefix_len_v6);
        let prefix_u128_v6 = u128::from_be_bytes(prefix_v6) & mask_v6;

        let is_valid_v4 = |v4: Ipv4Addr| -> bool {
            if v4.is_broadcast() || v4.is_multicast() {
                return false;
            }
            let u = u32::from(v4);
            u >= min_v4 && u <= max_v4
        };

        let is_valid_v6 = |v6: Ipv6Addr| -> bool {
            if v6.is_multicast() {
                return false;
            }
            let u = u128::from(v6);
            if u & mask_v6 != prefix_u128_v6 {
                return false;
            }
            let host_id = u & !mask_v6;
            host_id >= min_host_v6 && host_id <= max_host_v6
        };

        let (host_to_ip, ip_to_host) = store.get_fake_ip_tables()?;
        let (v4_capacity, v6_capacity) = super::cache_capacities(
            capacity,
            max_v4.checked_sub(min_v4).map_or(0, |n| u128::from(n) + 1),
            max_host_v6
                .checked_sub(min_host_v6)
                .map_or(0, |n| n.saturating_add(1)),
        );
        let cache = InMemStore::with_capacities(v4_capacity, v6_capacity);

        let mut max_v4_offset: Option<u32> = None;
        let mut max_v6_offset: Option<u128> = None;
        let is_valid = |ip: IpAddr| match ip {
            IpAddr::V4(ip) => is_valid_v4(ip),
            IpAddr::V6(ip) => is_valid_v6(ip),
        };
        // Normalize legacy host entries first, then let the IP index win
        // conflicts, as in the previous two-pass restore.
        let mut candidates: HashMap<IpAddr, (&str, bool)> = HashMap::new();
        for (host_key, ip_str) in &host_to_ip {
            let Ok(ip) = ip_str.parse::<IpAddr>() else {
                continue;
            };
            if !is_valid(ip) {
                continue;
            }
            let host = if let Some(host) = host_key.strip_suffix("#v4") {
                if !ip.is_ipv4() {
                    continue;
                }
                host
            } else if let Some(host) = host_key.strip_suffix("#v6") {
                if !ip.is_ipv6() {
                    continue;
                }
                host
            } else {
                host_key.as_str()
            };
            candidates.insert(ip, (host, false));
        }
        for (ip_str, host) in &ip_to_host {
            let Ok(ip) = ip_str.parse::<IpAddr>() else {
                continue;
            };
            if !is_valid(ip) {
                continue;
            }
            match ip {
                IpAddr::V4(ip) => {
                    let offset = u32::from(ip) - min_v4;
                    max_v4_offset =
                        Some(max_v4_offset.map_or(offset, |m| m.max(offset)));
                }
                IpAddr::V6(ip) => {
                    let offset = (u128::from(ip) & !mask_v6) - min_host_v6;
                    max_v6_offset =
                        Some(max_v6_offset.map_or(offset, |m| m.max(offset)));
                }
            }
            candidates.insert(ip, (host, true));
        }
        let mut desired_hosts = HashMap::new();
        let mut desired_ips = HashMap::new();
        let mut v4_count = 0;
        let mut v6_count = 0;
        // Choose retained mappings before populating the cache, so restoration
        // never triggers runtime batch eviction. Prefer authoritative IP entries.
        for authoritative in [true, false] {
            for (&ip, &(host, from_ip_table)) in &candidates {
                if from_ip_table != authoritative {
                    continue;
                }
                let (count, capacity) = if ip.is_ipv4() {
                    (&mut v4_count, v4_capacity)
                } else {
                    (&mut v6_count, v6_capacity)
                };
                if *count >= capacity {
                    continue;
                }
                let host_key = Self::make_host_key(host, ip.is_ipv6());
                if desired_hosts.contains_key(&host_key) {
                    continue;
                }
                cache.put_with_evictions(ip, host);
                let ip_str = ip.to_string();
                desired_hosts.insert(host_key, ip_str.clone());
                desired_ips.insert(ip_str, host.to_owned());
                *count += 1;
            }
        }
        let valid_count = v4_count + v6_count;
        let mut initial_pending = reconciliation_operations(
            &host_to_ip,
            &ip_to_host,
            &desired_hosts,
            &desired_ips,
        );
        // Release startup snapshots before spawning the worker.
        drop(candidates);
        drop(host_to_ip);
        drop(ip_to_host);
        drop(desired_hosts);
        drop(desired_ips);
        if !initial_pending.is_empty() {
            flush_pending(&mut initial_pending, |ops| {
                store.apply_fake_ip_batch(ops)
            });
        }
        info!("loaded {} fake-ip entries from cache file", valid_count);

        let pool_size_v4 = (max_v4 - min_v4).saturating_add(1);
        let initial_v4_offset = if pool_size_v4 > 0 {
            max_v4_offset.map(|o| (o + 1) % pool_size_v4).unwrap_or(0)
        } else {
            0
        };

        let pool_size_v6 = (max_host_v6 - min_host_v6).saturating_add(1);
        let initial_v6_offset = if pool_size_v6 > 0 {
            max_v6_offset.map(|o| (o + 1) % pool_size_v6).unwrap_or(0)
        } else {
            0
        };

        // 启动后台异步定时批量持久化 Worker
        let tx = if tokio::runtime::Handle::try_current().is_ok() {
            let (tx, mut rx) = mpsc::unbounded_channel::<FakeIpCommand>();
            let file_clone = store.clone();
            let mut pending = std::mem::take(&mut initial_pending);
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(2));
                interval.tick().await;
                let mut retrying = false;
                loop {
                    tokio::select! {
                        cmd = rx.recv() => {
                            let force = match cmd {
                                Some(FakeIpCommand::Operation(op)) => { pending.push(op); false }
                                Some(FakeIpCommand::Operations(ops)) => { pending.extend(ops); false }
                                Some(FakeIpCommand::DeleteBatch { items }) => {
                                    pending.extend(items.into_iter().map(|(ip, host_key)| FakeIpOperation::Delete { ip, host_key }));
                                    true
                                }
                                None => {
                                    flush_on_close(&mut pending, |ops| file_clone.apply_fake_ip_batch(ops)).await;
                                    break;
                                }
                            };
                            if !retrying && (force || pending.len() >= 512) {
                                retrying = !flush_pending(&mut pending, |ops| file_clone.apply_fake_ip_batch(ops));
                            }
                        }
                        _ = interval.tick() => {
                            retrying = !flush_pending(&mut pending, |ops| file_clone.apply_fake_ip_batch(ops));
                        }
                    }
                }
            });
            Some(tx)
        } else {
            None
        };

        Ok(Self {
            cache,
            pending: parking_lot::Mutex::new(initial_pending),
            mutations: parking_lot::Mutex::new(()),
            file: store,
            tx,
            initial_v4_offset,
            initial_v6_offset,
        })
    }

    fn submit_operation(&self, operation: FakeIpOperation) {
        if let Some(tx) = &self.tx {
            if let Err(e) = tx.send(FakeIpCommand::Operation(operation)) {
                warn!("fake-ip persistence worker unavailable: {}", e);
            }
        } else {
            let mut pending = self.pending.lock();
            pending.push(operation);
            flush_pending(&mut pending, |ops| self.file.apply_fake_ip_batch(ops));
        }
    }

    fn submit(&self, operations: Vec<FakeIpOperation>) {
        if let Some(tx) = &self.tx {
            if let Err(e) = tx.send(FakeIpCommand::Operations(operations)) {
                warn!("fake-ip persistence worker unavailable: {}", e);
            }
        } else {
            let mut pending = self.pending.lock();
            pending.extend(operations);
            flush_pending(&mut pending, |ops| self.file.apply_fake_ip_batch(ops));
        }
    }

    fn put(&self, ip: IpAddr, host: &str) {
        let _mutation = self.mutations.lock();
        let (retained, removed) = self.cache.put_with_evictions(ip, host);
        let put = retained.then(|| FakeIpOperation::Put {
            ip: ip.to_string(),
            host: host.to_owned(),
            host_key: Self::make_host_key(host, ip.is_ipv6()),
        });
        if removed.is_empty() {
            if let Some(put) = put {
                self.submit_operation(put);
            }
            return;
        }
        let mut operations: Vec<_> = removed
            .into_iter()
            .map(|(ip, host)| FakeIpOperation::Delete {
                ip: ip.to_string(),
                host_key: Some(Self::make_host_key(&host, ip.is_ipv6())),
            })
            .collect();
        operations.extend(put);
        self.submit(operations);
    }

    fn make_host_key(host: &str, is_v6: bool) -> String {
        if is_v6 {
            format!("{}#v6", host)
        } else {
            format!("{}#v4", host)
        }
    }
}

impl Store for FileStore {
    fn get_by_host(&self, host: &str) -> Option<IpAddr> {
        self.cache.get_by_host(host)
    }

    fn get_v6_by_host(&self, host: &str) -> Option<IpAddr> {
        self.cache.get_v6_by_host(host)
    }

    fn get_by_ip(&self, ip: IpAddr) -> Option<String> {
        self.cache.get_by_ip(ip)
    }

    fn put_by_ip(&self, ip: IpAddr, host: &str) {
        self.put(ip, host);
    }

    #[cfg(test)]
    fn del_by_ip(&self, ip: IpAddr) {
        let _mutation = self.mutations.lock();
        let host = self.cache.get_by_ip(ip);
        self.cache.del_by_ip(ip);

        let host_key = host
            .as_deref()
            .map(|h| Self::make_host_key(h, ip.is_ipv6()));

        self.submit_operation(FakeIpOperation::Delete {
            ip: ip.to_string(),
            host_key,
        });
    }

    fn evict_batch(&self, ip: IpAddr) -> Option<IpAddr> {
        let _mutation = self.mutations.lock();
        let removed = self.cache.evict_with_entries(ip);
        let victim = removed.first().map(|(ip, _)| *ip);
        if !removed.is_empty() {
            self.submit(
                removed
                    .into_iter()
                    .map(|(ip, host)| FakeIpOperation::Delete {
                        ip: ip.to_string(),
                        host_key: Some(Self::make_host_key(&host, ip.is_ipv6())),
                    })
                    .collect(),
            );
        }
        victim
    }

    fn exist(&self, ip: IpAddr) -> bool {
        self.cache.exist(ip)
    }

    fn copy_to(&self, #[allow(unused)] store: &dyn Store) {
        // NO-OP
    }

    fn search_by_wildcard_limited(
        &self,
        pattern: &str,
        limit: usize,
    ) -> (usize, Vec<(IpAddr, String)>) {
        self.cache.search_by_wildcard_limited(pattern, limit)
    }

    fn del_by_wildcard(&self, pattern: &str) -> usize {
        let _mutation = self.mutations.lock();
        let pattern = pattern.trim();
        let items = self.cache.take_by_wildcard(pattern);

        if items.is_empty() {
            return 0;
        }

        let count = items.len();
        let mut deletes = Vec::with_capacity(count);

        for (ip, host) in items {
            let host_key = Self::make_host_key(&host, ip.is_ipv6());
            deletes.push((ip.to_string(), Some(host_key)));
        }

        if let Some(tx) = &self.tx {
            if let Err(e) = tx.send(FakeIpCommand::DeleteBatch { items: deletes }) {
                warn!(
                    "failed to send fakeip delete batch to background worker: {}",
                    e
                );
            }
        } else {
            let mut pending = self.pending.lock();
            pending.extend(
                deletes
                    .into_iter()
                    .map(|(ip, host_key)| FakeIpOperation::Delete { ip, host_key }),
            );
            flush_pending(&mut pending, |ops| self.file.apply_fake_ip_batch(ops));
        }

        count
    }

    fn initial_offset_v4(&self, _min: u32, _max: u32) -> u32 {
        self.initial_v4_offset
    }

    fn initial_offset_v6(
        &self,
        _prefix: &[u8; 16],
        _prefix_len: u8,
        _min_host: u128,
        _max_host: u128,
    ) -> u128 {
        self.initial_v6_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconciliation_leaves_unchanged_mappings_and_repairs_only_differences() {
        let hosts = HashMap::from([
            ("stable.com#v4".into(), "198.18.0.2".into()),
            ("stable.com".into(), "198.18.0.2".into()),
            ("legacy.com".into(), "198.18.0.3".into()),
        ]);
        let ips = HashMap::from([("198.18.0.2".into(), "stable.com".into())]);
        let desired_hosts = HashMap::from([
            ("stable.com#v4".into(), "198.18.0.2".into()),
            ("legacy.com#v4".into(), "198.18.0.3".into()),
        ]);
        let desired_ips = HashMap::from([
            ("198.18.0.2".into(), "stable.com".into()),
            ("198.18.0.3".into(), "legacy.com".into()),
        ]);
        assert!(
            reconciliation_operations(
                &desired_hosts,
                &desired_ips,
                &desired_hosts,
                &desired_ips,
            )
            .is_empty()
        );
        let operations =
            reconciliation_operations(&hosts, &ips, &desired_hosts, &desired_ips);
        assert_eq!(operations.len(), 2);
        match &operations[0] {
            FakeIpOperation::Prune { ips, host_keys } => {
                assert!(ips.is_empty());
                assert_eq!(host_keys.len(), 2);
                assert!(host_keys.iter().any(|key| key == "stable.com"));
                assert!(host_keys.iter().any(|key| key == "legacy.com"));
            }
            _ => panic!("expected independent index pruning"),
        }
        assert!(
            matches!(&operations[1], FakeIpOperation::Put { host, .. } if host == "legacy.com")
        );
    }

    #[test]
    fn restore_repairs_conflicting_indexes_and_noncanonical_ipv6() {
        let dir = tempfile::tempdir().unwrap();
        let file = ThreadSafeCacheFile::new(
            dir.path().join("conflicts.db").to_str().unwrap(),
            true,
        )
        .unwrap();
        file.set_ip_to_host("198.18.0.2", "winner.com");
        file.set_host_to_ip("wrong.com#v4", "198.18.0.2");
        file.set_host_to_ip("winner.com#v4", "198.18.0.3");
        file.set_host_to_ip("winner.com", "198.18.0.2");
        file.set_host_to_ip("fallback.com#v4", "198.18.0.4");
        file.set_ip_to_host("fc00:0:0:0:0:0:0:2", "v6.com");
        file.set_host_to_ip("v6.com#v6", "fc00:0:0:0:0:0:0:2");
        file.set_host_to_ip("bad-family.com#v6", "198.18.0.5");
        let store = FileStore::new(
            file.clone(),
            "198.18.0.0/16".parse().unwrap(),
            "fc00::/64".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.get_by_host("winner.com"),
            Some("198.18.0.2".parse().unwrap())
        );
        assert_eq!(
            store.get_by_host("fallback.com"),
            Some("198.18.0.4".parse().unwrap())
        );
        assert_eq!(store.get_by_host("wrong.com"), None);
        assert_eq!(store.get_by_host("bad-family.com"), None);
        assert!(!store.exist("198.18.0.3".parse().unwrap()));
        let (hosts, ips) = file.get_fake_ip_tables().unwrap();
        assert_eq!(hosts.len(), 3);
        assert_eq!(ips.len(), 3);
        assert_eq!(hosts.get("v6.com#v6").map(String::as_str), Some("fc00::2"));
        assert!(!ips.contains_key("fc00:0:0:0:0:0:0:2"));
        for (ip, host) in ips {
            let address: IpAddr = ip.parse().unwrap();
            assert_eq!(
                hosts.get(&FileStore::make_host_key(&host, address.is_ipv6())),
                Some(&ip)
            );
            assert_eq!(store.get_by_ip(address), Some(host));
        }
    }

    #[test]
    fn restore_fills_capacity_without_runtime_batch_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let file = ThreadSafeCacheFile::new(
            dir.path().join("full-restore.db").to_str().unwrap(),
            true,
        )
        .unwrap();
        let puts: Vec<_> = (2..=22)
            .map(|i| FakeIpOperation::Put {
                ip: format!("198.18.0.{i}"),
                host: format!("{i}.com"),
                host_key: format!("{i}.com#v4"),
            })
            .collect();
        file.apply_fake_ip_batch(&puts).unwrap();
        let store = FileStore::with_capacity(
            file.clone(),
            40,
            "198.18.0.0/16".parse().unwrap(),
            "fc00::/64".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(store.search_by_wildcard_limited("*", 0).0, 20);
        let (hosts, ips) = file.get_fake_ip_tables().unwrap();
        assert_eq!(hosts.len(), 20);
        assert_eq!(ips.len(), 20);
    }

    #[tokio::test(start_paused = true)]
    async fn final_flush_stops_after_three_failed_attempts() {
        let mut pending = vec![FakeIpOperation::Delete {
            ip: "198.18.0.2".into(),
            host_key: None,
        }];
        let mut attempts = 0;
        let started = tokio::time::Instant::now();
        flush_on_close(&mut pending, |_| {
            attempts += 1;
            Err(anyhow::anyhow!("read-only filesystem"))
        })
        .await;
        assert_eq!(attempts, 3);
        assert_eq!(pending.len(), 1);
        assert_eq!(started.elapsed(), std::time::Duration::from_secs(4));
    }

    #[tokio::test(start_paused = true)]
    async fn final_flush_stops_as_soon_as_retry_succeeds() {
        let mut pending = vec![FakeIpOperation::Delete {
            ip: "198.18.0.2".into(),
            host_key: None,
        }];
        let mut attempts = 0;
        flush_on_close(&mut pending, |ops| {
            assert_eq!(ops.len(), 1);
            attempts += 1;
            if attempts == 1 {
                Err(anyhow::anyhow!("temporary failure"))
            } else {
                Ok(())
            }
        })
        .await;
        assert_eq!(attempts, 2);
        assert!(pending.is_empty());
    }

    #[test]
    fn restore_prunes_history_to_family_budgets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bounded.db");
        let file = ThreadSafeCacheFile::new(path.to_str().unwrap(), true).unwrap();
        let mut puts = Vec::new();
        for i in 2..=7 {
            for (ip, host, suffix) in [
                (format!("198.18.0.{i}"), format!("v4-{i}.com"), "v4"),
                (format!("fc00::{i}"), format!("v6-{i}.com"), "v6"),
            ] {
                puts.push(FakeIpOperation::Put {
                    ip,
                    host_key: format!("{host}#{suffix}"),
                    host,
                });
            }
        }
        file.apply_fake_ip_batch(&puts).unwrap();
        let store = FileStore::with_capacity(
            file.clone(),
            4,
            "198.18.0.0/16".parse().unwrap(),
            "fc00::/64".parse().unwrap(),
        )
        .unwrap();
        let (count, entries) = store.search_by_wildcard_limited("*", usize::MAX);
        assert_eq!(count, 4);
        assert_eq!(entries.iter().filter(|(ip, _)| ip.is_ipv4()).count(), 2);
        assert_eq!(entries.iter().filter(|(ip, _)| ip.is_ipv6()).count(), 2);
        let (hosts, ips) = file.get_fake_ip_tables().unwrap();
        assert_eq!(hosts.len(), 4);
        assert_eq!(ips.len(), 4);
        for (ip, host) in &entries {
            assert_eq!(
                file.get_fake_ip(&ip.to_string()).as_deref(),
                Some(host.as_str())
            );
            assert_eq!(
                file.get_fake_ip(&FileStore::make_host_key(host, ip.is_ipv6()))
                    .as_deref(),
                Some(ip.to_string().as_str())
            );
        }
        drop(store);
        drop(file);
        let file = ThreadSafeCacheFile::new(path.to_str().unwrap(), true).unwrap();
        let reloaded = FileStore::with_capacity(
            file,
            4,
            "198.18.0.0/16".parse().unwrap(),
            "fc00::/64".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(reloaded.search_by_wildcard_limited("*", 0).0, 4);
        for (ip, host) in entries {
            assert_eq!(reloaded.get_by_ip(ip), Some(host));
        }
    }

    #[test]
    fn legacy_host_only_history_is_normalized_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let file = ThreadSafeCacheFile::new(
            dir.path().join("legacy-capacity.db").to_str().unwrap(),
            true,
        )
        .unwrap();
        for i in 2..=7 {
            file.set_host_to_ip(
                &format!("legacy-{i}.com"),
                &format!("198.18.0.{i}"),
            );
        }
        let store = FileStore::with_capacity(
            file.clone(),
            4,
            "198.18.0.0/16".parse().unwrap(),
            "fc00::/64".parse().unwrap(),
        )
        .unwrap();
        let (count, retained) = store.search_by_wildcard_limited("*", usize::MAX);
        assert_eq!(count, 2);
        let (hosts, ips) = file.get_fake_ip_tables().unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(ips.len(), 2);
        assert!(hosts.keys().all(|key| key.ends_with("#v4")));
        for (ip, host) in retained {
            assert_eq!(store.get_by_host(&host), Some(ip));
            assert_eq!(
                file.get_fake_ip(&ip.to_string()).as_deref(),
                Some(host.as_str())
            );
        }
    }

    #[test]
    fn batch_eviction_is_persisted_and_stays_evicted_after_restore() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("batch-eviction.db");
        let file = ThreadSafeCacheFile::new(path.to_str().unwrap(), true).unwrap();
        let v4_net = "198.18.0.0/16".parse().unwrap();
        let v6_net = "fc00::/64".parse().unwrap();
        let store =
            FileStore::with_capacity(file.clone(), 40, v4_net, v6_net).unwrap();
        // Insert in a known order instead of relying on database restore order.
        for i in 2..=21 {
            store.put_by_ip(
                format!("198.18.0.{i}").parse().unwrap(),
                &format!("{i}.com"),
            );
        }
        store.put_by_ip("fc00::2".parse().unwrap(), "v6.com");
        store.put_by_ip("198.18.0.22".parse().unwrap(), "new.com");
        for i in 2..=3 {
            assert_eq!(file.get_fake_ip(&format!("198.18.0.{i}")), None);
            assert_eq!(file.get_fake_ip(&format!("{i}.com#v4")), None);
        }
        let (hosts, ips) = file.get_fake_ip_tables().unwrap();
        assert_eq!(hosts.len(), 20); // 19 IPv4 + 1 IPv6
        assert_eq!(ips.len(), 20);
        assert_eq!(store.search_by_wildcard_limited("*", 0).0, 20);
        drop(store);
        drop(file);
        let file = ThreadSafeCacheFile::new(path.to_str().unwrap(), true).unwrap();
        let reloaded = FileStore::with_capacity(file, 40, v4_net, v6_net).unwrap();
        assert_eq!(reloaded.search_by_wildcard_limited("*", 0).0, 20);
        assert_eq!(reloaded.get_by_host("2.com"), None);
        assert_eq!(reloaded.get_by_host("3.com"), None);
        assert_eq!(
            reloaded.get_by_host("new.com").unwrap().to_string(),
            "198.18.0.22"
        );
        assert_eq!(
            reloaded.get_v6_by_host("v6.com").unwrap().to_string(),
            "fc00::2"
        );
        // The explicit eviction path used by an exhausted IP pool must also
        // remove every selected mapping from both persistent indexes.
        let (_, before) = reloaded.search_by_wildcard_limited("*", usize::MAX);
        let victim = reloaded.evict_batch("198.18.0.2".parse().unwrap()).unwrap();
        assert!(!reloaded.exist(victim));
        let removed: Vec<_> = before
            .into_iter()
            .filter(|(ip, _)| !reloaded.exist(*ip))
            .collect();
        assert_eq!(removed.len(), 2);
        for (ip, host) in removed {
            assert_eq!(reloaded.file.get_fake_ip(&ip.to_string()), None);
            assert_eq!(
                reloaded
                    .file
                    .get_fake_ip(&FileStore::make_host_key(&host, false)),
                None
            );
        }
        assert_eq!(reloaded.file.get_fake_ip_tables().unwrap().0.len(), 18);
        assert_eq!(
            reloaded.get_v6_by_host("v6.com").unwrap().to_string(),
            "fc00::2"
        );
    }

    #[test]
    fn runtime_eviction_removes_both_persisted_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let file = ThreadSafeCacheFile::new(
            dir.path().join("eviction.db").to_str().unwrap(),
            true,
        )
        .unwrap();
        let store = FileStore::with_capacity(
            file.clone(),
            2,
            "198.18.0.0/16".parse().unwrap(),
            "fc00::/64".parse().unwrap(),
        )
        .unwrap();
        let first: IpAddr = "198.18.0.2".parse().unwrap();
        let second: IpAddr = "198.18.0.3".parse().unwrap();
        let v6: IpAddr = "fc00::2".parse().unwrap();
        store.put_by_ip(v6, "same.com");
        store.put_by_ip(first, "same.com");
        store.put_by_ip(second, "next.com");
        assert!(!store.exist(first));
        assert_eq!(file.get_fake_ip(&first.to_string()), None);
        assert_eq!(file.get_fake_ip("same.com#v4"), None);
        assert_eq!(file.get_fake_ip("same.com#v6").as_deref(), Some("fc00::2"));
        store.put_by_ip(second, "renamed.com");
        assert_eq!(file.get_fake_ip("next.com#v4"), None);
        assert_eq!(
            file.get_fake_ip("renamed.com#v4").as_deref(),
            Some("198.18.0.3")
        );
        let (hosts, ips) = file.get_fake_ip_tables().unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(ips.len(), 2);
    }

    #[tokio::test]
    async fn queued_evictions_are_persisted_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let file = ThreadSafeCacheFile::new(
            dir.path().join("async-eviction.db").to_str().unwrap(),
            true,
        )
        .unwrap();
        let store = FileStore::with_capacity(
            file.clone(),
            2,
            "198.18.0.0/16".parse().unwrap(),
            "fc00::/64".parse().unwrap(),
        )
        .unwrap();
        store.put_by_ip("198.18.0.2".parse().unwrap(), "old.com");
        store.put_by_ip("198.18.0.3".parse().unwrap(), "new.com");
        store.put_by_ip("fc00::2".parse().unwrap(), "v6.com");
        assert_eq!(store.del_by_wildcard("v6.com"), 1); // triggers flush
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if file.get_fake_ip("new.com#v4").is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let (hosts, ips) = file.get_fake_ip_tables().unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(ips.len(), 1);
        assert_eq!(file.get_fake_ip("old.com#v4"), None);
        assert_eq!(file.get_fake_ip("198.18.0.3").as_deref(), Some("new.com"));
    }

    #[test]
    fn failed_batch_is_retained_until_commit_succeeds() {
        let mut pending = vec![FakeIpOperation::Delete {
            ip: "198.18.0.1".into(),
            host_key: None,
        }];
        assert!(!flush_pending(&mut pending, |_| Err(anyhow::anyhow!(
            "disk full"
        ))));
        assert_eq!(pending.len(), 1);
        pending.push(FakeIpOperation::Put {
            ip: "198.18.0.1".into(),
            host: "new.com".into(),
            host_key: "new.com#v4".into(),
        });
        assert!(flush_pending(&mut pending, |ops| {
            assert!(matches!(ops[0], FakeIpOperation::Delete { .. }));
            assert!(matches!(ops[1], FakeIpOperation::Put { .. }));
            Ok(())
        }));
        assert!(pending.is_empty());
    }
}
