use crate::app::dns::ThreadSafeDNSResolver;
use tracing::debug;

pub async fn exchange_with_resolver<'a>(
    resolver: &'a ThreadSafeDNSResolver,
    req: &'a [u8],
    _enhanced: bool,
) -> Result<Vec<u8>, watfaq_dns::DNSError> {
    match resolver.exchange(req).await {
        Ok(m) => Ok(m),
        Err(e) => {
            debug!("dns resolve error: {}", e);
            Err(watfaq_dns::DNSError::QueryFailed(e.to_string()))
        }
    }
}
