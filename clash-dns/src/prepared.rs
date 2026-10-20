use crate::{DNSListenAddr, DNSError, DnsListener, DnsMessageExchanger};
use crate::encrypted::PreparedEncrypted;
use crate::handler::{MAX_CONCURRENT_UDP_QUERIES, MAX_TCP_CONNECTIONS, TCP_REQUEST_TIMEOUT, start_listener};

/// Validated listener configuration with certificates retained in memory.
/// Preparing does not bind sockets or start background tasks.
#[derive(Clone, Default)]
pub struct PreparedDnsListener {
    pub(crate) listen: DNSListenAddr,
    pub(crate) encrypted: PreparedEncrypted,
}

impl PreparedDnsListener {
    pub fn new(listen: DNSListenAddr) -> Result<Self, DNSError> {
        listen.validate()?;
        let encrypted = PreparedEncrypted::new(&listen)?;
        Ok(Self { listen, encrypted })
    }

    pub fn is_empty(&self) -> bool { self.listen.is_empty() }

    pub async fn bind<X: DnsMessageExchanger + Clone>(
        &self, exchanger: X,
    ) -> Result<DnsListener, DNSError> {
        start_listener(self.clone(), exchanger, MAX_CONCURRENT_UDP_QUERIES,
            MAX_TCP_CONNECTIONS, TCP_REQUEST_TIMEOUT).await
    }
}
