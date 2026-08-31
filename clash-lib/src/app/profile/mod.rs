use std::{collections::HashMap, path::Path, sync::Arc};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use tracing::{debug, error, info, warn};

const TABLE_SELECTED: TableDefinition<&str, &str> = TableDefinition::new("selected");
const TABLE_IP_TO_HOST: TableDefinition<&str, &str> =
    TableDefinition::new("ip_to_host");
const TABLE_HOST_TO_IP: TableDefinition<&str, &str> =
    TableDefinition::new("host_to_ip");
const TABLE_SMART_STATS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("smart_stats");

#[derive(Clone)]
pub struct ThreadSafeCacheFile {
    db: Arc<Database>,
    store_selected: bool,
}

impl ThreadSafeCacheFile {
    pub fn new(path: &str, store_selected: bool) -> Self {
        let db_path = Path::new(path);
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }

        let db = match open_or_init_db(path) {
            Ok(db) => Arc::new(db),
            Err(e) => {
                error!(
                    "failed to open cache database at {}: {}, resetting",
                    path, e
                );
                reset_corrupt_db(path);
                Arc::new(
                    Database::create(path)
                        .expect("failed to create fresh cache database"),
                )
            }
        };

        // Ensure default tables exist
        if let Ok(write_txn) = db.begin_write() {
            let _ = write_txn.open_table(TABLE_SELECTED);
            let _ = write_txn.open_table(TABLE_IP_TO_HOST);
            let _ = write_txn.open_table(TABLE_HOST_TO_IP);
            let _ = write_txn.open_table(TABLE_SMART_STATS);
            let _ = write_txn.commit();
        }

        Self { db, store_selected }
    }

    pub fn store_selected(&self) -> bool {
        self.store_selected
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
    ) -> (HashMap<String, String>, HashMap<String, String>) {
        let mut host_to_ip = HashMap::new();
        let mut ip_to_host = HashMap::new();
        if let Ok(read_txn) = self.db.begin_read() {
            if let Ok(table) = read_txn.open_table(TABLE_HOST_TO_IP) {
                if let Ok(iter) = table.iter() {
                    for item in iter.flatten() {
                        host_to_ip.insert(
                            item.0.value().to_string(),
                            item.1.value().to_string(),
                        );
                    }
                }
            }
            if let Ok(table) = read_txn.open_table(TABLE_IP_TO_HOST) {
                if let Ok(iter) = table.iter() {
                    for item in iter.flatten() {
                        ip_to_host.insert(
                            item.0.value().to_string(),
                            item.1.value().to_string(),
                        );
                    }
                }
            }
        }
        (host_to_ip, ip_to_host)
    }

    pub fn apply_fake_ip_batch(
        &self,
        puts: &[(String, String, String)],
        deletes: &[(String, Option<String>)],
    ) {
        if puts.is_empty() && deletes.is_empty() {
            return;
        }
        if let Ok(write_txn) = self.db.begin_write() {
            let t1 = write_txn.open_table(TABLE_IP_TO_HOST).ok();
            let t2 = write_txn.open_table(TABLE_HOST_TO_IP).ok();
            if let (Some(mut ip_table), Some(mut host_table)) = (t1, t2) {
                for (ip, host, host_key) in puts {
                    let _ = ip_table.insert(ip.as_str(), host.as_str());
                    let _ = host_table.insert(host_key.as_str(), ip.as_str());
                }
                for (ip, host_key) in deletes {
                    let _ = ip_table.remove(ip.as_str());
                    if let Some(hk) = host_key {
                        let _ = host_table.remove(hk.as_str());
                    }
                }
            }
            let _ = write_txn.commit();
        }
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
                if let Ok(content) = std::fs::read_to_string(path) {
                    if let Ok(legacy_map) =
                        serde_yaml::from_str::<serde_json::Value>(&content)
                    {
                        info!(
                            "migrating legacy yaml cache file at {} to redb...",
                            path
                        );
                        let backup_path = format!("{}.legacy-yaml", path);
                        let _ = std::fs::rename(path, &backup_path);
                        let db = Database::create(path)?;
                        migrate_legacy_json(&db, &legacy_map);
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

fn migrate_legacy_json(db: &Database, legacy: &serde_json::Value) {
    if let Ok(write_txn) = db.begin_write() {
        if let Some(selected) = legacy.get("selected").and_then(|v| v.as_object()) {
            if let Ok(mut table) = write_txn.open_table(TABLE_SELECTED) {
                for (k, v) in selected {
                    if let Some(val) = v.as_str() {
                        let _ = table.insert(k.as_str(), val);
                    }
                }
            }
        }
        if let Some(ip_to_host) =
            legacy.get("ip_to_host").and_then(|v| v.as_object())
        {
            if let Ok(mut table) = write_txn.open_table(TABLE_IP_TO_HOST) {
                for (k, v) in ip_to_host {
                    if let Some(val) = v.as_str() {
                        let _ = table.insert(k.as_str(), val);
                    }
                }
            }
        }
        if let Some(host_to_ip) =
            legacy.get("host_to_ip").and_then(|v| v.as_object())
        {
            if let Ok(mut table) = write_txn.open_table(TABLE_HOST_TO_IP) {
                for (k, v) in host_to_ip {
                    if let Some(val) = v.as_str() {
                        let _ = table.insert(k.as_str(), val);
                    }
                }
            }
        }
        let _ = write_txn.commit();
        debug!("legacy cache data imported into redb successfully");
    }
}

fn reset_corrupt_db(path: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let corrupt_path = format!("{}.corrupt-{}", path, ts);
    warn!("moving corrupt database {} to {}", path, corrupt_path);
    let _ = std::fs::rename(path, corrupt_path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_selected_crud() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_cache.db");
        let path_str = db_path.to_str().unwrap();

        let cache = ThreadSafeCacheFile::new(path_str, true);
        assert_eq!(cache.get_selected("PROXY"), None);

        cache.set_selected("PROXY", "Node-1");
        assert_eq!(cache.get_selected("PROXY"), Some("Node-1".to_string()));

        cache.set_selected("PROXY", "Node-2");
        assert_eq!(cache.get_selected("PROXY"), Some("Node-2".to_string()));

        let map = cache.get_selected_map();
        assert_eq!(map.get("PROXY"), Some(&"Node-2".to_string()));
    }

    #[test]
    fn test_store_selected_disabled() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_cache_disabled.db");
        let path_str = db_path.to_str().unwrap();

        let cache = ThreadSafeCacheFile::new(path_str, false);
        cache.set_selected("PROXY", "Node-1");
        assert_eq!(cache.get_selected("PROXY"), None);
        assert!(cache.get_selected_map().is_empty());
    }

    #[test]
    fn test_fake_ip_crud() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_fakeip.db");
        let path_str = db_path.to_str().unwrap();

        let cache = ThreadSafeCacheFile::new(path_str, true);
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
            let cache = ThreadSafeCacheFile::new(path_str, true);
            cache.set_selected("AUTO", "HK-01");
            cache.set_ip_to_host("198.18.0.2", "github.com");
        }

        // Reopen database from disk
        {
            let cache = ThreadSafeCacheFile::new(path_str, true);
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
        std::fs::write(&db_path, yaml_content).unwrap();

        let cache = ThreadSafeCacheFile::new(path_str, true);
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
}
