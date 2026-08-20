use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use parking_lot::{Mutex, RwLock};
use tracing::{debug, error, info};

pub type ThreadSafeDnsCollector = Arc<DnsCollector>;

pub struct DnsCollector {
    file_path: PathBuf,
    seen: RwLock<HashSet<String>>,
    pending_writes: Mutex<Vec<(String, String)>>,
    has_new: AtomicBool,
}

impl DnsCollector {
    pub fn new(file_path: PathBuf) -> std::io::Result<Arc<Self>> {
        let mut seen = HashSet::new();

        if file_path.exists() {
            if let Ok(file) = File::open(&file_path) {
                let reader = BufReader::new(file);
                // `flatten()` would spin forever if `lines()` keeps yielding
                // the same `Err` (e.g. a mid-file I/O error); stop instead.
                for line in reader.lines().map_while(Result::ok) {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let parts: Vec<&str> = trimmed
                        .split(|c: char| c.is_whitespace() || c == ',')
                        .filter(|s| !s.is_empty())
                        .collect();
                    if let Some(domain) = parts.first() {
                        seen.insert(domain.to_lowercase());
                    }
                }
            }
        }

        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
        {
            let _ = writeln!(file, "# {}", now);
            let _ = file.flush();
        }

        info!(
            "DNS collector initialized with file {:?}, loaded {} existing records",
            file_path,
            seen.len()
        );

        let collector = Arc::new(Self {
            file_path,
            seen: RwLock::new(seen),
            pending_writes: Mutex::new(Vec::new()),
            has_new: AtomicBool::new(false),
        });

        let weak_collector = Arc::downgrade(&collector);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Some(collector) = weak_collector.upgrade() {
                    collector.flush_if_needed().await;
                } else {
                    break;
                }
            }
        });

        Ok(collector)
    }

    pub fn record(&self, domain: &str, is_fake_ip: bool) {
        let domain_clean = domain.trim().trim_end_matches('.').to_lowercase();
        if domain_clean.is_empty()
            || domain_clean.parse::<std::net::IpAddr>().is_ok()
        {
            return;
        }

        // 快路径：读锁无竞争检查（99%+ 的重复 DNS 请求在此直接返回，不触发写锁）
        if self.seen.read().contains(&domain_clean) {
            return;
        }

        // 慢路径：仅新域名触发写锁并放入待写入队列
        let mut seen = self.seen.write();
        if seen.insert(domain_clean.clone()) {
            let kind = if is_fake_ip { "fakeip" } else { "realip" };
            self.pending_writes
                .lock()
                .push((domain_clean, kind.to_string()));
            self.has_new.store(true, Ordering::Release);
        }
    }

    pub async fn flush_if_needed(&self) {
        if !self.has_new.swap(false, Ordering::AcqRel) {
            return;
        }

        let to_write = {
            let mut pending = self.pending_writes.lock();
            std::mem::take(&mut *pending)
        };

        if to_write.is_empty() {
            return;
        }

        let path = self.file_path.clone();
        tokio::task::spawn_blocking(move || {
            let result = OpenOptions::new().create(true).append(true).open(&path);

            match result {
                Ok(mut file) => {
                    for (domain, kind) in to_write {
                        if let Err(e) = writeln!(file, "{} {}", domain, kind) {
                            error!(
                                "Failed to write to DNS collect file {:?}: {}",
                                path, e
                            );
                        }
                    }
                    if let Err(e) = file.flush() {
                        error!("Failed to flush DNS collect file {:?}: {}", path, e);
                    } else {
                        debug!("Successfully flushed DNS records to {:?}", path);
                    }
                }
                Err(e) => {
                    error!("Failed to open DNS collect file {:?}: {}", path, e);
                }
            }
        })
        .await
        .ok();
    }

    #[cfg(test)]
    pub fn seen_count(&self) -> usize {
        self.seen.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_dns_collector_deduplication() {
        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path().to_path_buf();

        let collector = DnsCollector::new(file_path.clone()).unwrap();

        // Record some domains
        collector.record("example.com", true);
        collector.record("EXAMPLE.COM.", true); // Duplicate, uppercase, trailing dot
        collector.record("google.com", false);
        collector.record("127.0.0.1", false); // IP literal, should be ignored

        assert_eq!(collector.seen_count(), 2);

        // Flush manually
        collector.flush_if_needed().await;

        let content = std::fs::read_to_string(&file_path).unwrap();
        let lines: Vec<&str> = content
            .lines()
            .filter(|l| !l.trim().starts_with('#') && !l.trim().is_empty())
            .collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.contains(&"example.com fakeip"));
        assert!(lines.contains(&"google.com realip"));

        // Second flush without new items should not change file
        collector.flush_if_needed().await;
        let content2 = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, content2);
    }

    #[tokio::test]
    async fn test_dns_collector_existing_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path().to_path_buf();

        std::fs::write(&file_path, "existing.com realip\nanother.org fakeip\n")
            .unwrap();

        let collector = DnsCollector::new(file_path.clone()).unwrap();
        assert_eq!(collector.seen_count(), 2);

        // Record duplicate existing domain
        collector.record("existing.com", true);
        // Record new domain
        collector.record("newdomain.com", false);

        assert_eq!(collector.seen_count(), 3);

        collector.flush_if_needed().await;

        let content = std::fs::read_to_string(&file_path).unwrap();
        let lines: Vec<&str> = content
            .lines()
            .filter(|l| !l.trim().starts_with('#') && !l.trim().is_empty())
            .collect();
        assert_eq!(lines.len(), 3);
        assert!(lines.contains(&"newdomain.com realip"));
    }
}
