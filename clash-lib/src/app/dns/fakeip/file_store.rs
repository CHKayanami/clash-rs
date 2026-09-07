use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    initial_v4_offset: u32,
    initial_v6_offset: u128,
}

impl FileStore {
    pub fn new(
        store: ThreadSafeCacheFile,
        ipnet: ipnet::Ipv4Net,
        ipnet6: ipnet::Ipv6Net,
    ) -> Self {
        Self::with_capacity(store, 10_000, ipnet, ipnet6)
    }

    pub fn with_capacity(
        store: ThreadSafeCacheFile,
        capacity: usize,
        ipnet: ipnet::Ipv4Net,
        ipnet6: ipnet::Ipv6Net,
    ) -> Self {
        let (min_v4, max_v4) = super::compute_v4_range(&ipnet).unwrap_or((u32::MAX, 0));
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

        let (host_to_ip, ip_to_host) = store.get_fake_ip_tables();
        let total_entries = ip_to_host.len();
        let cache = InMemStore::new(capacity.max(total_entries.max(host_to_ip.len())));

        let mut max_v4_offset: Option<u32> = None;
        let mut max_v6_offset: Option<u128> = None;
        let mut stale_deletes = Vec::new();
        let mut valid_count = 0;

        // 预热 host_to_ip 表并过滤旧网段
        for (host_key, ip_str) in host_to_ip {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                let is_valid = match ip {
                    IpAddr::V4(v4) => is_valid_v4(v4),
                    IpAddr::V6(v6) => is_valid_v6(v6),
                };

                if is_valid {
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
                } else {
                    stale_deletes.push((ip_str, Some(host_key)));
                }
            } else {
                stale_deletes.push((ip_str, Some(host_key)));
            }
        }

        // 预热 ip_to_host 表并计算最大 offset
        for (ip_str, host) in ip_to_host {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                let is_valid = match ip {
                    IpAddr::V4(v4) => {
                        if is_valid_v4(v4) {
                            let offset = u32::from(v4) - min_v4;
                            max_v4_offset = Some(max_v4_offset.map_or(offset, |m| m.max(offset)));
                            true
                        } else {
                            false
                        }
                    }
                    IpAddr::V6(v6) => {
                        if is_valid_v6(v6) {
                            let host_id = (u128::from(v6)) & !mask_v6;
                            let offset = host_id - min_host_v6;
                            max_v6_offset = Some(max_v6_offset.map_or(offset, |m| m.max(offset)));
                            true
                        } else {
                            false
                        }
                    }
                };

                if is_valid {
                    cache.put_by_ip(ip, &host);
                    valid_count += 1;
                } else {
                    let host_key = Self::make_host_key(&host, ip.is_ipv6());
                    stale_deletes.push((ip_str, Some(host_key)));
                }
            } else {
                stale_deletes.push((ip_str, None));
            }
        }

        // 若存在不属于当前网段的历史条目，批量物理修剪清除
        if !stale_deletes.is_empty() {
            let stale_count = stale_deletes.len();
            store.apply_fake_ip_batch(&[], &stale_deletes);
            info!(
                "loaded {} valid fake-ip entries, pruned {} stale entries from cache file",
                valid_count, stale_count
            );
        } else {
            info!("loaded {} fake-ip entries from cache file", total_entries);
        }

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
            initial_v4_offset,
            initial_v6_offset,
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
