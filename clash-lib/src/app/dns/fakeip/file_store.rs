use async_trait::async_trait;

use crate::app::profile::ThreadSafeCacheFile;

use super::Store;

pub struct FileStore(ThreadSafeCacheFile);

impl FileStore {
    pub fn new(store: ThreadSafeCacheFile) -> Self {
        Self(store)
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
impl Store for FileStore {
    // The family filter is applied on the suffixed key too, not just on the
    // legacy unsuffixed fallback: this store is backed by a file that outlives
    // upgrades, so a stale or hand-edited entry must not make `FakeDns::lookup`
    // hand back an address of the wrong family.
    async fn get_by_host(&self, host: &str) -> Option<std::net::IpAddr> {
        let key = Self::make_host_key(host, false);
        if let Some(ip) = self
            .0
            .get_fake_ip(&key)
            .await
            .and_then(|ip| ip.parse().ok())
            .filter(|ip: &std::net::IpAddr| ip.is_ipv4())
        {
            Some(ip)
        } else {
            self.0
                .get_fake_ip(host)
                .await
                .and_then(|ip| ip.parse().ok())
                .filter(|ip: &std::net::IpAddr| ip.is_ipv4())
        }
    }

    async fn get_v6_by_host(&self, host: &str) -> Option<std::net::IpAddr> {
        let key = Self::make_host_key(host, true);
        if let Some(ip) = self
            .0
            .get_fake_ip(&key)
            .await
            .and_then(|ip| ip.parse().ok())
            .filter(|ip: &std::net::IpAddr| ip.is_ipv6())
        {
            Some(ip)
        } else {
            self.0
                .get_fake_ip(host)
                .await
                .and_then(|ip| ip.parse().ok())
                .filter(|ip: &std::net::IpAddr| ip.is_ipv6())
        }
    }

    async fn put_by_host(&self, host: &str, ip: std::net::IpAddr) {
        let key = Self::make_host_key(host, ip.is_ipv6());
        self.0.set_host_to_ip(&key, &ip.to_string()).await;
    }

    async fn get_by_ip(&self, ip: std::net::IpAddr) -> Option<String> {
        self.0.get_fake_ip(&ip.to_string()).await
    }

    async fn put_by_ip(&self, ip: std::net::IpAddr, host: &str) {
        let key = Self::make_host_key(host, ip.is_ipv6());
        self.0.set_ip_to_host(&ip.to_string(), host).await;
        self.0.set_host_to_ip(&key, &ip.to_string()).await;
    }

    async fn del_by_ip(&self, ip: std::net::IpAddr) {
        if let Some(host) = self.get_by_ip(ip).await {
            let host_key = Self::make_host_key(&host, ip.is_ipv6());
            self.0.delete_fake_ip_pair(&ip.to_string(), &host_key).await;
        }
    }

    async fn exist(&self, ip: std::net::IpAddr) -> bool {
        self.0.get_fake_ip(&ip.to_string()).await.is_some()
    }

    async fn copy_to(&self, #[allow(unused)] store: &dyn Store) {
        // NO-OP
    }
}
