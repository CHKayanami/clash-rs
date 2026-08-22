//! Shared DNS stream framing helpers (RFC 7766 length-prefix).

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

/// Write a length-prefixed DNS message and read the response from `stream`.
pub async fn exchange_length_prefixed<S>(
    stream: &mut S,
    raw_query: &[u8],
    query_timeout: Duration,
) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(query_timeout, async {
        write_length_prefixed(stream, raw_query).await?;
        let mut response = Vec::new();
        read_length_prefixed_into(stream, &mut response, None).await?;
        Ok::<_, anyhow::Error>(response)
    })
    .await
    .map_err(|_| anyhow::anyhow!("DNS stream exchange timed out after {query_timeout:?}"))?
}

pub async fn write_length_prefixed<S>(stream: &mut S, raw_query: &[u8]) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let len = u16::try_from(raw_query.len())
        .map_err(|_| anyhow::anyhow!("DNS message too large for stream framing"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(raw_query).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_length_prefixed<S>(
    stream: &mut S,
    query_timeout: Duration,
) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    read_length_prefixed_into(stream, &mut buffer, Some(query_timeout)).await?;
    Ok(buffer)
}

/// Read one RFC 7766 frame into reusable storage.
pub async fn read_length_prefixed_into<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    query_timeout: Option<Duration>,
) -> anyhow::Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    read_exact_stage(
        stream,
        &mut len_buf,
        query_timeout,
        "DNS stream read length timed out",
    )
    .await?;
    let message_len = usize::from(u16::from_be_bytes(len_buf));
    if message_len == 0 {
        anyhow::bail!("invalid DNS stream message length {message_len}");
    }
    buffer.resize(message_len, 0);
    read_exact_stage(
        stream,
        buffer,
        query_timeout,
        "DNS stream read body timed out",
    )
    .await
}

async fn read_exact_stage<S>(
    stream: &mut S,
    buffer: &mut [u8],
    stage_timeout: Option<Duration>,
    timeout_message: &'static str,
) -> anyhow::Result<()>
where
    S: AsyncRead + Unpin,
{
    if let Some(duration) = stage_timeout {
        timeout(duration, stream.read_exact(buffer))
            .await
            .map_err(|_| anyhow::anyhow!(timeout_message))??;
    } else {
        stream.read_exact(buffer).await?;
    }
    Ok(())
}
