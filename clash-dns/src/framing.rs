use std::{io::ErrorKind, net::SocketAddr, time::Duration};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use tracing::debug;
use crate::{DNSError, DnsIngress, DnsMessageExchanger};

pub(crate) async fn serve_stream<S, X>(
    mut stream: S,
    peer: SocketAddr,
    exchanger: X,
    request_timeout: Duration,
    ingress: DnsIngress,
) where
    X: DnsMessageExchanger,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut out_buf = Vec::with_capacity(512);
    loop {
        // A whole request deadline also bounds partial frames, stalled
        // exchanges and peers that stop reading responses.
        let result = timeout(request_timeout, async {
            let mut len_buf = [0u8; 2];
            if let Err(e) = stream.read_exact(&mut len_buf).await {
                if e.kind() == ErrorKind::UnexpectedEof {
                    return Ok::<bool, DNSError>(false);
                }
                return Err(e.into());
            }
            let msg_len = u16::from_be_bytes(len_buf) as usize;
            if msg_len == 0 {
                return Ok::<bool, DNSError>(false);
            }
            let mut req = vec![0; msg_len];
            stream.read_exact(&mut req).await?;
            let resp = exchanger.exchange(
                Bytes::from(req), Some(peer.ip()), ingress,
            ).await?;
            let resp_len = u16::try_from(resp.len()).map_err(|_| {
                DNSError::QueryFailed("DNS TCP response exceeds frame size".into())
            })?;
            out_buf.clear();
            out_buf.extend_from_slice(&resp_len.to_be_bytes());
            out_buf.extend_from_slice(&resp);
            stream.write_all(&out_buf).await?;
            stream.flush().await?;
            Ok(true)
        }).await;
        match result {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => break,
            Ok(Err(e)) => {
                debug!("DNS stream query from {} failed: {}", peer, e);
                break;
            }
            Err(_) => {
                debug!("DNS stream request from {} timed out", peer);
                break;
            }
        }
    }
}
