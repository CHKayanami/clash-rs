/// Uniform retry-once wrapper for all transports: on failure, run `reset`
/// (drop the cached session/connection) and retry the exchange once.
pub async fn exchange_with_retry<Once, Fut, Reset, ResetFut>(
    label: &'static str,
    once: Once,
    reset: Reset,
) -> anyhow::Result<Vec<u8>>
where
    Once: Fn() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Vec<u8>>>,
    Reset: FnOnce() -> ResetFut,
    ResetFut: std::future::Future<Output = ()>,
{
    match once().await {
        Ok(resp) => Ok(resp),
        Err(first) => {
            tracing::debug!(
                transport = label,
                error_kind = "exchange_failed",
                "DNS transport reset before retry: {first}"
            );
            reset().await;
            once()
                .await
                .map_err(|e| anyhow::anyhow!("{label} failed after retry: {e} (first: {first})"))
        }
    }
}
