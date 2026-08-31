use std::net::IpAddr;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::{InMemStore, Store};
use crate::app::profile::ThreadSafeCacheFile;

enum FakeIpCommand {
    Put {
        ip: IpAddr,
        host: String,
        host_key: String,
    },
    Delete {
        ip: IpAddr,
        host_key: Option<String>,
    },
}

pub struct FileStore {
    cache: InMemStore,
    file: ThreadSafeCacheFile,
    tx: Option<mpsc::UnboundedSender<FakeIpCommand>>,
}

impl FileStore {
    pub fn new(store: ThreadSafeCacheFile) -> Self {
        Self::with_capacity(store, 10_000)
    }

    pub fn with_capacity(store: ThreadSafeCacheFile, capacity: usize) -> Self {
        let (host_to_ip, ip_to_host) = store.get_fake_ip_tables();
        let total_entries = ip_to_host.len();
        let cache = InMemStore::new(capacity.max(total_entries.max(host_to_ip.len())));

        // 预热 host_to_ip 表
        for (host_key, ip_str) in host_to_ip {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                if let Some(host) = host_key.strip_suffix("#v4") {
                    if ip.is_ipv4() {
                        cache.put_by_host(host, ip);
                    }
                } else if let Some(host) = host_key.strip_suffix("#v6") {
                    if ip.is_ipv6() {
                        cache.put_by_host(host, ip);
                    }
                } else {
                    // 兼容旧格式无后缀 key
                    cache.put_by_host(&host_key, ip);
                }
            }
        }

        // 预热 ip_to_host 表
        for (ip_str, host) in ip_to_host {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                cache.put_by_ip(ip, &host);
            }
        }

        info!("loaded {} fake-ip entries from cache file", total_entries);

        // 启动后台异步定时批量持久化 Worker
        let tx = if tokio::runtime::Handle::try_current().is_ok() {
            let (tx, mut rx) = mpsc::unbounded_channel::<FakeIpCommand>();
            let file_clone = store.clone();
            tokio::spawn(async move {
                let mut puts = Vec::new();
                let mut deletes = Vec::new();
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
                // 消耗初始立即触发的 tick
                interval.tick().await;

                loop {
                    tokio::select! {
                        cmd = rx.recv() => {
                            match cmd {
                                Some(FakeIpCommand::Put {
                                    ip,
                                    host,
                                    host_key,
                                }) => {
                                    puts.push((ip.to_string(), host, host_key));
                                }
                                Some(FakeIpCommand::Delete { ip, host_key }) => {
                                    deletes.push((ip.to_string(), host_key));
                                }
                                None => {
                                    // 通道已关闭（FileStore 被 drop），将剩余未刷盘数据写入并退出
                                    if !puts.is_empty() || !deletes.is_empty() {
                                        file_clone.apply_fake_ip_batch(&puts, &deletes);
                                    }
                                    break;
                                }
                            }

                            // 达到批次上限（512 条）时提前触发落盘
                            if puts.len() + deletes.len() >= 512 {
                                file_clone.apply_fake_ip_batch(&puts, &deletes);
                                puts.clear();
                                deletes.clear();
                            }
                        }
                        _ = interval.tick() => {
                            // 定时刷盘：若有待写入数据，在一个 redb 写事务中提交
                            if !puts.is_empty() || !deletes.is_empty() {
                                file_clone.apply_fake_ip_batch(&puts, &deletes);
                                puts.clear();
                                deletes.clear();
                            }
                        }
                    }
                }
            });
            Some(tx)
        } else {
            None
        };

        Self {
            cache,
            file: store,
            tx,
        }
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

    fn put_by_host(&self, host: &str, ip: IpAddr) {
        self.cache.put_by_host(host, ip);
        let host_key = Self::make_host_key(host, ip.is_ipv6());

        if let Some(tx) = &self.tx {
            if let Err(e) = tx.send(FakeIpCommand::Put {
                ip,
                host: host.to_string(),
                host_key,
            }) {
                warn!("failed to send fakeip put command to background worker: {}", e);
            }
        } else {
            self.file.apply_fake_ip_batch(
                &[(ip.to_string(), host.to_string(), host_key)],
                &[],
            );
        }
    }

    fn get_by_ip(&self, ip: IpAddr) -> Option<String> {
        self.cache.get_by_ip(ip)
    }

    fn put_by_ip(&self, ip: IpAddr, host: &str) {
        self.cache.put_by_ip(ip, host);
        let host_key = Self::make_host_key(host, ip.is_ipv6());

        if let Some(tx) = &self.tx {
            if let Err(e) = tx.send(FakeIpCommand::Put {
                ip,
                host: host.to_string(),
                host_key,
            }) {
                warn!("failed to send fakeip put command to background worker: {}", e);
            }
        } else {
            self.file.apply_fake_ip_batch(
                &[(ip.to_string(), host.to_string(), host_key)],
                &[],
            );
        }
    }

    fn del_by_ip(&self, ip: IpAddr) {
        let host = self.cache.get_by_ip(ip);
        self.cache.del_by_ip(ip);

        let host_key = host.as_deref().map(|h| Self::make_host_key(h, ip.is_ipv6()));

        if let Some(tx) = &self.tx {
            if let Err(e) = tx.send(FakeIpCommand::Delete { ip, host_key }) {
                warn!("failed to send fakeip del command to background worker: {}", e);
            }
        } else {
            self.file.apply_fake_ip_batch(&[], &[(ip.to_string(), host_key)]);
        }
    }

    fn exist(&self, ip: IpAddr) -> bool {
        self.cache.exist(ip)
    }

    fn copy_to(&self, #[allow(unused)] store: &dyn Store) {
        // NO-OP
    }
}
