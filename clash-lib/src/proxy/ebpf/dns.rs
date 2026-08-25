#[allow(unused_imports)]
use tracing::{debug, warn};

#[allow(unused_imports)]
use crate::app::dns::ThreadSafeDNSResolver;

/// Handle intercepted TCP DNS stream in eBPF transparent proxy.
#[cfg(target_os = "linux")]
pub async fn handle_tcp_dns(
    mut stream: tokio::net::TcpStream,
    resolver: ThreadSafeDNSResolver,
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

        match crate::app::dns::exchange_with_resolver(&resolver, &query_buf, true)
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
