use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use tracing::{debug, info, warn};

const TABLE_SELECTED: TableDefinition<&str, &str> = TableDefinition::new("selected");
const TABLE_IP_TO_HOST: TableDefinition<&str, &str> =
    TableDefinition::new("ip_to_host");
const TABLE_HOST_TO_IP: TableDefinition<&str, &str> =
    TableDefinition::new("host_to_ip");
const TABLE_SMART_STATS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("smart_stats");

pub enum FakeIpOperation {
    // Startup reconciliation removes each index independently before repairs.
    Prune {
        ips: Vec<String>,
        host_keys: Vec<String>,
    },
    Put {
        ip: String,
        host: String,
        host_key: String,
    },
    Delete {
        ip: String,
        host_key: Option<String>,
    },
}

#[derive(Clone)]
pub struct ThreadSafeCacheFile {
    db: Arc<Database>,
    store_selected: bool,
}

impl ThreadSafeCacheFile {
    pub fn new(path: &str, store_selected: bool) -> anyhow::Result<Self> {
        let db_path = Path::new(path);
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let mut db = match open_or_init_db(path) {
            Ok(db) => db,
            Err(redb::DatabaseError::Storage(redb::StorageError::Corrupted(
                reason,
            ))) => {
                warn!("cache database is corrupt: {}", reason);
                reset_corrupt_db(path)?;
                Database::create(path)?
            }
            Err(e) => return Err(e.into()),
        };

        let write_txn = db.begin_write()?;
        write_txn.open_table(TABLE_SELECTED)?;
        write_txn.open_table(TABLE_IP_TO_HOST)?;
        write_txn.open_table(TABLE_HOST_TO_IP)?;
        write_txn.open_table(TABLE_SMART_STATS)?;
        write_txn.commit()?;

        // 启动时整理压缩数据库以回收碎片和空闲空间
        let size_before = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        match db.compact() {
            Ok(true) => {
                let size_after = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                info!(
                    "compacted cache database at {}: {} -> {} bytes",
                    path, size_before, size_after
                );
            }
            Ok(false) => {
                debug!("cache database at {} does not require compaction", path);
            }
            Err(e) => {
                warn!("failed to compact cache database at {}: {}", path, e);
            }
        }

        Ok(Self {
            db: Arc::new(db),
            store_selected,
        })
    }

    pub fn store_selected(&self) -> bool {
        self.store_selected
    }

    pub fn with_store_selected(&self, store_selected: bool) -> Self {
        Self {
            db: self.db.clone(),
            store_selected,
        }
    }

    pub fn set_selected(&self, group: &str, server: &str) {
        if !self.store_selected {
            return;
        }
        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut table) = write_txn.open_table(TABLE_SELECTED) {
                if let Err(e) = table.insert(group, server) {
                    warn!("failed to set selected for {}: {}", group, e);
                }
            }
            if let Err(e) = write_txn.commit() {
                warn!("failed to commit selected write: {}", e);
            }
        }
    }

    pub fn get_selected(&self, group: &str) -> Option<String> {
        if !self.store_selected {
            return None;
        }
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(TABLE_SELECTED).ok()?;
        table.get(group).ok()?.map(|v| v.value().to_string())
    }

    pub fn get_selected_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if !self.store_selected {
            return map;
        }
        if let Ok(read_txn) = self.db.begin_read() {
            if let Ok(table) = read_txn.open_table(TABLE_SELECTED) {
                if let Ok(iter) = table.iter() {
                    for item in iter.flatten() {
                        map.insert(
                            item.0.value().to_string(),
                            item.1.value().to_string(),
                        );
                    }
                }
            }
        }
        map
    }

    pub fn set_ip_to_host(&self, ip: &str, host: &str) {
        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut table) = write_txn.open_table(TABLE_IP_TO_HOST) {
                let _ = table.insert(ip, host);
            }
            let _ = write_txn.commit();
        }
    }

    pub fn set_host_to_ip(&self, host: &str, ip: &str) {
        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut table) = write_txn.open_table(TABLE_HOST_TO_IP) {
                let _ = table.insert(host, ip);
            }
            let _ = write_txn.commit();
        }
    }

    pub fn get_fake_ip(&self, ip_or_host: &str) -> Option<String> {
        let read_txn = self.db.begin_read().ok()?;
        if let Ok(table) = read_txn.open_table(TABLE_IP_TO_HOST) {
            if let Some(val) = table.get(ip_or_host).ok().flatten() {
                return Some(val.value().to_string());
            }
        }
        if let Ok(table) = read_txn.open_table(TABLE_HOST_TO_IP) {
            if let Some(val) = table.get(ip_or_host).ok().flatten() {
                return Some(val.value().to_string());
            }
        }
        None
    }

    pub fn delete_fake_ip_pair(&self, ip: &str, host: &str) {
        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut t1) = write_txn.open_table(TABLE_IP_TO_HOST) {
                let _ = t1.remove(ip);
            }
            if let Ok(mut t2) = write_txn.open_table(TABLE_HOST_TO_IP) {
                let _ = t2.remove(host);
            }
            let _ = write_txn.commit();
        }
    }

    pub fn get_fake_ip_tables(
        &self,
    ) -> anyhow::Result<(HashMap<String, String>, HashMap<String, String>)> {
        use anyhow::Context;

        let read_txn = self.db.begin_read().context("read fake-ip snapshot")?;
        let read_table = |definition: TableDefinition<&str, &str>| -> anyhow::Result<HashMap<String, String>> {
            let table = read_txn.open_table(definition)?;
            let mut entries = HashMap::new();
            for item in table.iter()? {
                let (key, value) = item?;
                entries.insert(key.value().to_owned(), value.value().to_owned());
            }
            Ok(entries)
        };
        let host_to_ip =
            read_table(TABLE_HOST_TO_IP).context("read host_to_ip table")?;
        let ip_to_host =
            read_table(TABLE_IP_TO_HOST).context("read ip_to_host table")?;
        Ok((host_to_ip, ip_to_host))
    }

    pub fn apply_fake_ip_batch(
        &self,
        commands: &[FakeIpOperation],
    ) -> anyhow::Result<()> {
        if commands.is_empty() {
            return Ok(());
        }
        let write_txn = self.db.begin_write()?;
        {
            let mut ip_table = write_txn.open_table(TABLE_IP_TO_HOST)?;
            let mut host_table = write_txn.open_table(TABLE_HOST_TO_IP)?;
            for command in commands {
                match command {
                    FakeIpOperation::Prune { ips, host_keys } => {
                        for ip in ips {
                            ip_table.remove(ip.as_str())?;
                        }
                        for key in host_keys {
                            host_table.remove(key.as_str())?;
                        }
                    }
                    FakeIpOperation::Put { ip, host, host_key } => {
                        ip_table.insert(ip.as_str(), host.as_str())?;
                        host_table.insert(host_key.as_str(), ip.as_str())?;
                    }
                    FakeIpOperation::Delete { ip, host_key } => {
                        ip_table.remove(ip.as_str())?;
                        if let Some(key) = host_key {
                            host_table.remove(key.as_str())?;
                        }
                    }
                }
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn set_smart_stats(
        &self,
        group_name: &str,
        stats: crate::proxy::group::smart::state::SmartStateData,
    ) {
        if let Ok(bytes) = serde_json::to_vec(&stats) {
            if let Ok(write_txn) = self.db.begin_write() {
                if let Ok(mut table) = write_txn.open_table(TABLE_SMART_STATS) {
                    let _ = table.insert(group_name, bytes.as_slice());
                }
                let _ = write_txn.commit();
            }
        }
    }

    pub fn get_smart_stats(
        &self,
        group_name: &str,
    ) -> Option<crate::proxy::group::smart::state::SmartStateData> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(TABLE_SMART_STATS).ok()?;
        let raw = table.get(group_name).ok()??;
        serde_json::from_slice(raw.value()).ok()
    }
}

fn open_or_init_db(path: &str) -> Result<Database, redb::DatabaseError> {
    let p = Path::new(path);
    if p.exists() {
        // Test opening as redb
        match Database::open(path) {
            Ok(db) => Ok(db),
            Err(redb::DatabaseError::DatabaseAlreadyOpen) => {
                Err(redb::DatabaseError::DatabaseAlreadyOpen)
            }
            Err(e) => {
                // Check if it's a legacy YAML cache file
                if let Ok(content) = fs::read_to_string(path) {
                    if let Ok(legacy_map) = yaml_serde::from_str::<
                        HashMap<String, HashMap<String, String>>,
                    >(&content)
                    {
                        info!(
                            "migrating legacy yaml cache file at {} to redb...",
                            path
                        );
                        let backup_path = format!("{}.legacy-yaml", path);
                        fs::rename(path, &backup_path)?;
                        let db = Database::create(path)?;
                        migrate_legacy_json(
                            &db,
                            &serde_json::to_value(&legacy_map)
                                .expect("string maps are serializable"),
                        )
                        .map_err(|e| {
                            redb::DatabaseError::from(std::io::Error::other(e))
                        })?;
                        return Ok(db);
                    }
                }
                Err(e)
            }
        }
    } else {
        Database::create(path)
    }
}

fn migrate_legacy_json(
    db: &Database,
    legacy: &serde_json::Value,
) -> Result<(), redb::Error> {
    let write_txn = db.begin_write()?;
    for (name, definition) in [
        ("selected", TABLE_SELECTED),
        ("ip_to_host", TABLE_IP_TO_HOST),
        ("host_to_ip", TABLE_HOST_TO_IP),
    ] {
        if let Some(values) = legacy.get(name).and_then(|v| v.as_object()) {
            let mut table = write_txn.open_table(definition)?;
            for (key, value) in values {
                if let Some(value) = value.as_str() {
                    table.insert(key.as_str(), value)?;
                }
            }
        }
    }
    write_txn.commit()?;
    debug!("legacy cache data imported into redb successfully");
    Ok(())
}

fn reset_corrupt_db(path: &str) -> std::io::Result<()> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let corrupt_path = format!("{}.corrupt-{}", path, ts);
    warn!("moving corrupt database {} to {}", path, corrupt_path);
    fs::rename(path, corrupt_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn fake_ip_snapshot_rejects_missing_tables_without_modification() {
        for definition in [TABLE_HOST_TO_IP, TABLE_IP_TO_HOST] {
            let dir = tempdir().unwrap();
            let cache = ThreadSafeCacheFile::new(
                dir.path().join("incomplete.db").to_str().unwrap(),
                true,
            )
            .unwrap();
            cache
                .apply_fake_ip_batch(&[FakeIpOperation::Put {
                    ip: "198.18.0.2".into(),
                    host: "retained.com".into(),
                    host_key: "retained.com#v4".into(),
                }])
                .unwrap();
            let txn = cache.db.begin_write().unwrap();
            txn.delete_table(definition).unwrap();
            txn.commit().unwrap();
            assert!(cache.get_fake_ip_tables().is_err());
            // The other half of the snapshot must not be pruned or repaired.
            let txn = cache.db.begin_read().unwrap();
            if let Ok(table) = txn.open_table(TABLE_HOST_TO_IP) {
                assert_eq!(
                    table.get("retained.com#v4").unwrap().unwrap().value(),
                    "198.18.0.2"
                );
            } else {
                let table = txn.open_table(TABLE_IP_TO_HOST).unwrap();
                assert_eq!(
                    table.get("198.18.0.2").unwrap().unwrap().value(),
                    "retained.com"
                );
            }
        }
    }

    #[test]
    fn test_open_database_twice_preserves_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("locked.db");
        let cache = ThreadSafeCacheFile::new(path.to_str().unwrap(), true).unwrap();
        cache.set_selected("PROXY", "Node");
        assert!(ThreadSafeCacheFile::new(path.to_str().unwrap(), true).is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        drop(cache);
        let reopened =
            ThreadSafeCacheFile::new(path.to_str().unwrap(), true).unwrap();
        assert_eq!(reopened.get_selected("PROXY").as_deref(), Some("Node"));
    }

    #[test]
    fn test_failed_batch_does_not_commit_partial_changes() {
        let dir = tempdir().unwrap();
        let cache = ThreadSafeCacheFile::new(
            dir.path().join("failure.db").to_str().unwrap(),
            true,
        )
        .unwrap();
        let txn = cache.db.begin_write().unwrap();
        txn.delete_table(TABLE_HOST_TO_IP).unwrap();
        txn.open_table(TableDefinition::<&str, u64>::new("host_to_ip"))
            .unwrap();
        txn.commit().unwrap();
        assert!(
            cache
                .apply_fake_ip_batch(&[FakeIpOperation::Put {
                    ip: "198.18.0.1".into(),
                    host: "example.com".into(),
                    host_key: "example.com#v4".into(),
                }])
                .is_err()
        );
        assert_eq!(cache.get_fake_ip("198.18.0.1"), None);
    }

    #[test]
    fn test_batch_preserves_ip_reuse_order() {
        let dir = tempdir().unwrap();
        let cache = ThreadSafeCacheFile::new(
            dir.path().join("order.db").to_str().unwrap(),
            true,
        )
        .unwrap();
        let put = |host: &str| FakeIpOperation::Put {
            ip: "198.18.0.1".into(),
            host: host.into(),
            host_key: format!("{host}#v4"),
        };
        cache
            .apply_fake_ip_batch(&[
                put("old.com"),
                FakeIpOperation::Delete {
                    ip: "198.18.0.1".into(),
                    host_key: Some("old.com#v4".into()),
                },
                put("new.com"),
            ])
            .unwrap();
        assert_eq!(cache.get_fake_ip("198.18.0.1").as_deref(), Some("new.com"));
        assert_eq!(
            cache.get_fake_ip("new.com#v4").as_deref(),
            Some("198.18.0.1")
        );
        assert_eq!(cache.get_fake_ip("old.com#v4"), None);
        cache
            .apply_fake_ip_batch(&[
                put("new.com"),
                FakeIpOperation::Delete {
                    ip: "198.18.0.1".into(),
                    host_key: Some("new.com#v4".into()),
                },
            ])
            .unwrap();
        assert_eq!(cache.get_fake_ip("198.18.0.1"), None);
        assert_eq!(cache.get_fake_ip("new.com#v4"), None);
    }

    #[test]
    fn test_selected_crud() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_cache.db");
        let path_str = db_path.to_str().unwrap();

        let cache = ThreadSafeCacheFile::new(path_str, true).unwrap();
        assert_eq!(cache.get_selected("PROXY"), None);

        cache.set_selected("PROXY", "Node-1");
        assert_eq!(cache.get_selected("PROXY"), Some("Node-1".to_string()));

        cache.set_selected("PROXY", "Node-2");
        assert_eq!(cache.get_selected("PROXY"), Some("Node-2".to_string()));

        let map = cache.get_selected_map();
        assert_eq!(map.get("PROXY"), Some(&"Node-2".to_string()));
    }

    #[test]
    fn test_reload_shares_database_with_independent_selection_policy() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let original = ThreadSafeCacheFile::new(path.to_str().unwrap(), true).unwrap();
        original.set_selected("PROXY", "Node-1");

        let disabled = original.with_store_selected(false);
        disabled.set_selected("PROXY", "Node-2");
        assert_eq!(disabled.get_selected("PROXY"), None);
        assert_eq!(original.get_selected("PROXY").as_deref(), Some("Node-1"));

        let enabled = disabled.with_store_selected(true);
        assert_eq!(enabled.get_selected("PROXY").as_deref(), Some("Node-1"));
        enabled.set_selected("PROXY", "Node-3");
        assert_eq!(original.get_selected("PROXY").as_deref(), Some("Node-3"));
    }

    #[test]
    fn test_store_selected_disabled() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_cache_disabled.db");
        let path_str = db_path.to_str().unwrap();

        let cache = ThreadSafeCacheFile::new(path_str, false).unwrap();
        cache.set_selected("PROXY", "Node-1");
        assert_eq!(cache.get_selected("PROXY"), None);
        assert!(cache.get_selected_map().is_empty());
    }

    #[test]
    fn test_fake_ip_crud() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_fakeip.db");
        let path_str = db_path.to_str().unwrap();

        let cache = ThreadSafeCacheFile::new(path_str, true).unwrap();
        cache.set_ip_to_host("198.18.0.1", "google.com");
        cache.set_host_to_ip("google.com#v4", "198.18.0.1");

        assert_eq!(
            cache.get_fake_ip("198.18.0.1"),
            Some("google.com".to_string())
        );
        assert_eq!(
            cache.get_fake_ip("google.com#v4"),
            Some("198.18.0.1".to_string())
        );

        cache.delete_fake_ip_pair("198.18.0.1", "google.com#v4");
        assert_eq!(cache.get_fake_ip("198.18.0.1"), None);
        assert_eq!(cache.get_fake_ip("google.com#v4"), None);
    }

    #[test]
    fn test_persistence_across_instances() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_persist.db");
        let path_str = db_path.to_str().unwrap();

        {
            let cache = ThreadSafeCacheFile::new(path_str, true).unwrap();
            cache.set_selected("AUTO", "HK-01");
            cache.set_ip_to_host("198.18.0.2", "github.com");
        }

        // Reopen database from disk
        {
            let cache = ThreadSafeCacheFile::new(path_str, true).unwrap();
            assert_eq!(cache.get_selected("AUTO"), Some("HK-01".to_string()));
            assert_eq!(
                cache.get_fake_ip("198.18.0.2"),
                Some("github.com".to_string())
            );
        }
    }

    #[test]
    fn test_legacy_yaml_migration() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("legacy.db");
        let path_str = db_path.to_str().unwrap();

        let yaml_content = r#"
selected:
  PROXY: "Legacy-Node"
ip_to_host:
  "198.18.0.99": "legacy.com"
host_to_ip:
  "legacy.com#v4": "198.18.0.99"
"#;
        fs::write(&db_path, yaml_content).unwrap();

        let cache = ThreadSafeCacheFile::new(path_str, true).unwrap();
        assert_eq!(cache.get_selected("PROXY"), Some("Legacy-Node".to_string()));
        assert_eq!(
            cache.get_fake_ip("198.18.0.99"),
            Some("legacy.com".to_string())
        );
        assert_eq!(
            cache.get_fake_ip("legacy.com#v4"),
            Some("198.18.0.99".to_string())
        );
    }

    #[test]
    fn test_startup_compaction() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("compaction.db");
        let path_str = db_path.to_str().unwrap();

        {
            let cache = ThreadSafeCacheFile::new(path_str, true).unwrap();
            // 写入较多数据制造页面占用
            for i in 0..1000 {
                cache.set_ip_to_host(
                    &format!("198.18.0.{}", i),
                    &format!("host-{}.com", i),
                );
                cache.set_host_to_ip(
                    &format!("host-{}.com#v4", i),
                    &format!("198.18.0.{}", i),
                );
            }
            // 删除大部分数据制造空闲死页（碎片）
            for i in 100..1000 {
                cache.delete_fake_ip_pair(
                    &format!("198.18.0.{}", i),
                    &format!("host-{}.com#v4", i),
                );
            }
            cache.set_selected("PROXY", "Node-Main");
        }

        let size_before = fs::metadata(&db_path).unwrap().len();

        // 重新启动打开数据库，触发 startup compaction
        let cache = ThreadSafeCacheFile::new(path_str, true).unwrap();
        let size_after = fs::metadata(&db_path).unwrap().len();

        // 验证碎片被成功压缩，文件尺寸减小或维持紧凑
        assert!(size_after <= size_before);

        // 验证未删除的数据完好保留
        assert_eq!(cache.get_selected("PROXY"), Some("Node-Main".to_string()));
        assert_eq!(
            cache.get_fake_ip("198.18.0.0"),
            Some("host-0.com".to_string())
        );
        assert_eq!(cache.get_fake_ip("198.18.0.500"), None);
    }
}
