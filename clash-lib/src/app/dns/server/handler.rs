use bytes::Bytes;
use std::net::IpAddr;
use crate::app::dns::ThreadSafeDNSResolver;
use crate::app::dns::query::{IngressProfile, QueryContext};
use crate::app::dns::response::{ResponseTemplate, build_dns_refused};
use tracing::debug;

pub async fn exchange_with_resolver(
    resolver: &ThreadSafeDNSResolver,
    req: Bytes,
    ingress: IngressProfile,
    source_ip: Option<IpAddr>,
) -> Result<Vec<u8>, watfaq_dns::DNSError> {
    let query = match QueryContext::parse(req.clone(), ingress) {
        Ok(query) => query,
        Err(_) => return Ok(build_dns_refused(&req)),
    };
    match resolver.exchange(&query, source_ip).await {
        Ok(message) => {
            if let IngressProfile::Udp { advertised_size } = query.ingress()
                && message.len() > usize::from(advertised_size)
            {
                return ResponseTemplate::validate(&query, &message)
                    .and_then(|template| template.render(&query))
                    .map_err(|error| watfaq_dns::DNSError::QueryFailed(error.to_string()));
            }
            Ok(message)
        },
        Err(e) => {
            debug!("dns resolve error: {}", e);
            Err(watfaq_dns::DNSError::QueryFailed(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::app::dns::MockClashResolver;
    use crate::app::dns::query::{DnsName, QType};
    use crate::app::dns::response::build_dns_ip_response;

    #[tokio::test]
    async fn ingress_preserves_peer_and_limits_only_udp_responses() {
        let source = "192.0.2.1".parse::<IpAddr>().unwrap();
        let mut resolver = MockClashResolver::new();
        resolver.expect_exchange()
            .times(2)
            .withf(move |query, peer| {
                query.qdomain() == Some("ingress.test") && *peer == Some(source)
            })
            .returning(|query, _| {
                let ips = vec!["192.0.2.2".parse().unwrap(); 80];
                Ok(build_dns_ip_response(query, &ips, 60).unwrap())
            });
        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        let query = QueryContext::new(
            DnsName::from_domain("ingress.test").unwrap(), QType::A,
        );
        let udp = exchange_with_resolver(
            &resolver, Bytes::copy_from_slice(query.wire()),
            IngressProfile::Udp { advertised_size: 512 }, Some(source),
        ).await.unwrap();
        assert!(udp.len() <= 512);
        assert_ne!(udp[2] & 2, 0);
        assert_eq!(&udp[..2], &query.wire()[..2]);
        let tcp = exchange_with_resolver(
            &resolver, Bytes::copy_from_slice(query.wire()), IngressProfile::Tcp, Some(source),
        ).await.unwrap();
        assert!(tcp.len() > 512);
        assert_eq!(tcp[2] & 2, 0);
        assert_eq!(u16::from_be_bytes([tcp[6], tcp[7]]), 80);
    }
}
