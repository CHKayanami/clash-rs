use std::net::IpAddr;

use async_trait::async_trait;
use moka::sync::Cache;

use super::Store;

pub struct InMemStore {
    itoh: Cache<IpAddr, String>,
    htoi: Cache<String, IpAddr>,
}

impl InMemStore {
    pub fn new(size: usize) -> Self {
        Self {
            itoh: Cache::builder().max_capacity(size as u64).build(),
            htoi: Cache::builder().max_capacity(size as u64).build(),
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

#[async_trait]
impl Store for InMemStore {
    async fn get_by_host(&self, host: &str) -> Option<std::net::IpAddr> {
        let v4_key = Self::make_host_key(host, false);
        if let Some(ip) = self.htoi.get(&v4_key) {
            let _ = self.itoh.get(&ip);
            return Some(ip);
        }
        None
    }

    async fn get_v6_by_host(&self, host: &str) -> Option<std::net::IpAddr> {
        let v6_key = Self::make_host_key(host, true);
        if let Some(ip) = self.htoi.get(&v6_key) {
            let _ = self.itoh.get(&ip);
            return Some(ip);
        }
        None
    }

    async fn put_by_host(&self, host: &str, ip: std::net::IpAddr) {
        let key = Self::make_host_key(host, ip.is_ipv6());
        self.htoi.insert(key, ip);
        self.itoh.insert(ip, host.to_string());
    }

    async fn get_by_ip(&self, ip: std::net::IpAddr) -> Option<String> {
        if let Some(h) = self.itoh.get(&ip) {
            let key = Self::make_host_key(&h, ip.is_ipv6());
            let _ = self.htoi.get(&key);
            return Some(h);
        }
        None
    }

    async fn put_by_ip(&self, ip: std::net::IpAddr, host: &str) {
        let key = Self::make_host_key(host, ip.is_ipv6());
        self.itoh.insert(ip, host.to_string());
        self.htoi.insert(key, ip);
    }

    async fn del_by_ip(&self, ip: std::net::IpAddr) {
        if let Some(host) = self.itoh.get(&ip) {
            self.itoh.invalidate(&ip);
            let key = Self::make_host_key(&host, ip.is_ipv6());
            self.htoi.invalidate(&key);
        }
    }

    async fn exist(&self, ip: std::net::IpAddr) -> bool {
        self.itoh.contains_key(&ip)
    }

    async fn copy_to(&self, #[allow(unused)] store: &dyn Store) {
        // TODO: copy
        // NOTE: use file based persistence store
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_mem_store_basic() {
        let store = InMemStore::new(100);
        let host = "example.com";
        let ip_v4: IpAddr = "192.168.1.1".parse().unwrap();
        let ip_v6: IpAddr = "fd00::1".parse().unwrap();

        store.put_by_host(host, ip_v4).await;
        store.put_by_host(host, ip_v6).await;

        assert_eq!(store.get_by_host(host).await, Some(ip_v4));
        assert_eq!(store.get_v6_by_host(host).await, Some(ip_v6));

        assert_eq!(store.get_by_ip(ip_v4).await, Some(host.to_string()));
        assert_eq!(store.get_by_ip(ip_v6).await, Some(host.to_string()));

        assert!(store.exist(ip_v4).await);
        assert!(store.exist(ip_v6).await);

        store.del_by_ip(ip_v4).await;
        assert!(!store.exist(ip_v4).await);
        assert_eq!(store.get_by_host(host).await, None);
        assert_eq!(store.get_v6_by_host(host).await, Some(ip_v6));
    }
}
