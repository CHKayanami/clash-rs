use std::time::Duration;

const MAX_IDLE_STREAMS: usize = 4;

pub enum IdlePoolState {
    Open,
    Closed,
}

pub async fn idle_pool_exchange<S, Dial, DialFut>(
    lifecycle: &tokio::sync::RwLock<IdlePoolState>,
    idle: &parking_lot::Mutex<Vec<S>>,
    dial: Dial,
    raw_query: &[u8],
    query_timeout: Duration,
) -> anyhow::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    Dial: FnOnce() -> DialFut,
    DialFut: std::future::Future<Output = anyhow::Result<S>>,
{
    let lifecycle = lifecycle.read().await;
    match *lifecycle {
        IdlePoolState::Open => {}
        IdlePoolState::Closed => anyhow::bail!("DNS transport pool is closed"),
    }
    let taken = idle.lock().pop();
    let mut stream = match taken {
        Some(s) => s,
        None => dial().await?,
    };
    let resp =
        crate::app::dns::framing::exchange_length_prefixed(&mut stream, raw_query, query_timeout).await?;
    let mut guard = idle.lock();
    if guard.len() < MAX_IDLE_STREAMS {
        guard.push(stream);
    }
    drop(lifecycle);
    Ok(resp)
}

pub async fn close_idle_pool<S>(
    lifecycle: &tokio::sync::RwLock<IdlePoolState>,
    idle: &parking_lot::Mutex<Vec<S>>,
    timeout: Duration,
) where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let mut lifecycle = lifecycle.write().await;
    match *lifecycle {
        IdlePoolState::Closed => return,
        IdlePoolState::Open => *lifecycle = IdlePoolState::Closed,
    }
    let streams = std::mem::take(&mut *idle.lock());
    for mut stream in streams {
        let _ = tokio::time::timeout(timeout, stream.shutdown()).await;
    }
}
