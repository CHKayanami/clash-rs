use bytes::Bytes;
use http::uri::Authority;
use serde::Deserialize;
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    path::Path,
};

mod handler;
mod encrypted;
mod framing;
mod prepared;

pub use prepared::PreparedDnsListener;
pub use handler::{DNSError, DnsListener, get_dns_listener};

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct DoHConfig {
    pub addr: SocketAddr,
    pub ca_cert: DnsServerCert,
    pub ca_key: DnsServerKey,
    pub hostname: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct DoH3Config {
    pub addr: SocketAddr,
    pub ca_cert: DnsServerCert,
    pub ca_key: DnsServerKey,
    pub hostname: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct DoTConfig {
    pub addr: SocketAddr,
    pub ca_cert: DnsServerCert,
    pub ca_key: DnsServerKey,
}

pub type DnsServerKey = Option<String>;
pub type DnsServerCert = Option<String>;

#[derive(Debug, Default, Clone)]
pub struct DNSListenAddr {
    pub udp: Option<SocketAddr>,
    pub tcp: Option<SocketAddr>,
    pub doh: Option<DoHConfig>,
    pub dot: Option<DoTConfig>,
    pub doh3: Option<DoH3Config>,
}

impl DNSListenAddr {
    pub fn is_empty(&self) -> bool {
        self.udp.is_none() && self.tcp.is_none() && self.doh.is_none()
            && self.dot.is_none() && self.doh3.is_none()
    }

    pub fn validate(&self) -> Result<(), DNSError> {
        for (protocol, cert, key) in [
            self.doh.as_ref().map(|c| ("DoH", &c.ca_cert, &c.ca_key)),
            self.dot.as_ref().map(|c| ("DoT", &c.ca_cert, &c.ca_key)),
            self.doh3.as_ref().map(|c| ("DoH3", &c.ca_cert, &c.ca_key)),
        ].into_iter().flatten() {
            if cert.as_ref().is_none_or(|s| s.is_empty())
                || key.as_ref().is_none_or(|s| s.is_empty())
            {
                return Err(DNSError::Configuration(format!(
                    "{protocol} listener requires both ca-cert and ca-key",
                )));
            }
        }
        for hostname in [
            self.doh.as_ref().and_then(|c| c.hostname.as_deref()),
            self.doh3.as_ref().and_then(|c| c.hostname.as_deref()),
        ].into_iter().flatten() {
            if hostname.parse::<Authority>().is_err() || hostname.contains('@') {
                return Err(DNSError::Configuration("invalid DNS listener hostname".into()));
            }
        }
        Ok(())
    }

    pub fn resolve_certificate_paths(&mut self, cwd: &Path) {
        let resolve = |path: &mut Option<String>| {
            if let Some(value) = path
                && !value.contains("-----BEGIN") && Path::new(&*value).is_relative()
            {
                *value = cwd.join(&*value).to_string_lossy().into_owned();
            }
        };
        for (cert, key) in [
            self.doh.as_mut().map(|c| (&mut c.ca_cert, &mut c.ca_key)),
            self.dot.as_mut().map(|c| (&mut c.ca_cert, &mut c.ca_key)),
            self.doh3.as_mut().map(|c| (&mut c.ca_cert, &mut c.ca_key)),
        ].into_iter().flatten() {
            resolve(cert);
            resolve(key);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsIngress {
    Udp,
    Tcp,
    Dot,
    Doh,
    Doh3,
}

#[cfg_attr(test, mockall::automock)]
pub trait DnsMessageExchanger: Send + Sync + 'static {
    fn ipv6(&self) -> bool;
    fn exchange(
        &self,
        message: Bytes,
        source_ip: Option<IpAddr>,
        ingress: DnsIngress,
    ) -> impl Future<Output = Result<Vec<u8>, DNSError>> + Send;
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::OnceLock;

    static CRYPTO_PROVIDER_LOCK: OnceLock<()> = OnceLock::new();

    pub(crate) fn setup_default_crypto_provider() {
        CRYPTO_PROVIDER_LOCK.get_or_init(|| {
            #[cfg(feature = "aws-lc-rs")]
            {
                let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            }
            #[cfg(feature = "ring")]
            {
                let _ = rustls::crypto::ring::default_provider().install_default();
            }
        });
    }
}
