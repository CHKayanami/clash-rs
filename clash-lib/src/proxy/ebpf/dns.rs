use crate::app::dns::query::IngressProfile;
use bytes::Bytes;
use tracing::{debug, warn};

use crate::app::dns::ThreadSafeDNSResolver;

/// Handle intercepted TCP DNS stream in eBPF transparent proxy.
pub async fn handle_tcp_dns(
    mut stream: tokio::net::TcpStream,
    resolver: ThreadSafeDNSResolver,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let source_ip = stream.peer_addr().ok().map(|peer| peer.ip());
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    debug!("error reading TCP DNS length prefix: {e}");
                }
                break;
            }
        }
        let length = u16::from_be_bytes(len_buf) as usize;
        if length == 0 || length > 4096 {
            debug!("invalid TCP DNS message length: {length}");
            break;
        }
        let mut query_buf = vec![0u8; length];
        if let Err(e) = stream.read_exact(&mut query_buf).await {
            debug!("error reading TCP DNS message body: {e}");
            break;
        }

        match crate::app::dns::exchange_with_resolver(
            &resolver, Bytes::from(query_buf), IngressProfile::Tcp, source_ip,
        )
            .await
        {
            Ok(resp_bytes) => {
                let resp_len = (resp_bytes.len() as u16).to_be_bytes();
                if let Err(e) = stream.write_all(&resp_len).await {
                    debug!("failed to write TCP DNS response length: {e}");
                    break;
                }
                if let Err(e) = stream.write_all(&resp_bytes).await {
                    debug!("failed to write TCP DNS response body: {e}");
                    break;
                }
                if let Err(e) = stream.flush().await {
                    debug!("failed to flush TCP DNS response: {e}");
                    break;
                }
            }
            Err(e) => {
                warn!("failed to exchange TCP DNS query with resolver: {e}");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};
    use crate::app::dns::MockClashResolver;
    use crate::app::dns::framing::{read_length_prefixed, write_length_prefixed};
    use crate::app::dns::query::{DnsName, QType, QueryContext};
    use crate::app::dns::response::build_dns_ip_response;

    #[tokio::test]
    async fn tcp_dns_keeps_large_response_and_supplies_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut resolver = MockClashResolver::new();
        resolver.expect_exchange()
            .times(1)
            .withf(|query, source| {
                query.ingress() == IngressProfile::Tcp
                    && *source == Some("127.0.0.1".parse::<IpAddr>().unwrap())
            })
            .returning(|query, _| {
                Ok(build_dns_ip_response(
                    query, &vec!["192.0.2.1".parse().unwrap(); 80], 60,
                ).unwrap())
            });
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let server = tokio::spawn(handle_tcp_dns(stream, Arc::new(resolver)));
        let query = QueryContext::new(DnsName::from_domain("tcp.test").unwrap(), QType::A);
        write_length_prefixed(&mut client, query.wire()).await.unwrap();
        let response = read_length_prefixed(&mut client, Duration::from_secs(2)).await.unwrap();
        assert!(response.len() > 512);
        assert_eq!(response[2] & 2, 0);
        assert_eq!(&response[..2], &query.wire()[..2]);
        drop(client);
        server.await.unwrap();
    }
}
