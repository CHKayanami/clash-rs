#[allow(unused_imports)]
use std::net::IpAddr;
#[allow(unused_imports)]
use std::sync::Arc;

#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};

#[allow(unused_imports)]
use super::offloader::{DirectOffloader, RoutingAction};
#[allow(unused_imports)]
use super::utils::is_reserved_ip;
#[allow(unused_imports)]
use crate::app::dispatcher::Dispatcher;
#[allow(unused_imports)]
use crate::app::dns::ThreadSafeDNSResolver;

/// Extract IPs and minimum valid TTL from a DNS response message.
#[allow(dead_code)]
pub fn extract_ips_and_min_ttl(resp: &hickory_proto::op::Message) -> (Vec<IpAddr>, u32) {
    use hickory_proto::rr::RData;
    let mut ips = Vec::new();
    let mut min_ttl = u32::MAX;
    for record in &resp.answers {
        let mut matched = false;
        match &record.data {
            RData::A(a) => {
                let ip = IpAddr::V4(a.0);
                if !is_reserved_ip(ip) {
                    ips.push(ip);
                    matched = true;
                }
            }
            RData::AAAA(aaaa) => {
                let ip = IpAddr::V6(aaaa.0);
                if !is_reserved_ip(ip) {
                    ips.push(ip);
                    matched = true;
                }
            }
            _ => {}
        }
        if matched {
            let ttl = record.ttl;
            if ttl > 0 && ttl < min_ttl {
                min_ttl = ttl;
            }
        }
    }
    let effective_ttl = if min_ttl == u32::MAX || min_ttl == 0 {
        300
    } else {
        min_ttl.clamp(10, 86400)
    };
    (ips, effective_ttl)
}

/// Handle intercepted TCP DNS stream in eBPF transparent proxy.
#[cfg(target_os = "linux")]
pub async fn handle_tcp_dns(
    mut stream: tokio::net::TcpStream,
    resolver: ThreadSafeDNSResolver,
    dispatcher: Arc<Dispatcher>,
    offloader: Option<DirectOffloader>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

        match hickory_proto::op::Message::from_vec(&query_buf) {
            Ok(msg) => {
                trace!("eBPF intercepted TCP DNS query: {:?}", msg);
                match crate::app::dns::exchange_with_resolver(&resolver, &msg, true).await {
                    Ok(mut resp) => {
                        resp.metadata.id = msg.metadata.id;

                        // Async Direct Offload observation
                        if let Some(offloader) = &offloader {
                            let (ips, ttl_secs) = extract_ips_and_min_ttl(&resp);
                            if !ips.is_empty() {
                                let router = dispatcher.router().clone();
                                let offloader = offloader.clone();
                                let query_name = msg.queries.first().map(|q| q.name().to_utf8()).unwrap_or_default();
                                tokio::spawn(async move {
                                    let domain_clean = query_name.trim_end_matches('.');
                                    if !domain_clean.is_empty() {
                                        let is_direct = router.is_domain_direct(domain_clean).await;
                                        let action = if is_direct {
                                            RoutingAction::Direct
                                        } else {
                                            RoutingAction::Proxy
                                        };
                                        offloader.observe(
                                            domain_clean.to_string(),
                                            ips,
                                            action,
                                            std::time::Duration::from_secs(ttl_secs as u64),
                                        ).await;
                                    }
                                });
                            }
                        }

                        match resp.to_vec() {
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
                                warn!("failed to serialize TCP DNS response: {e}");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("failed to exchange TCP DNS query with resolver: {e}");
                        break;
                    }
                }
            }
            Err(e) => {
                warn!("failed to parse TCP DNS query message: {e}");
                break;
            }
        }
    }
}
