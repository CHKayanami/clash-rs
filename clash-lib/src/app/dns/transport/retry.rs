#[derive(Debug, thiserror::Error)]
#[error("DNS connection failed: {0}")]
pub(crate) struct ConnectionFailure(#[source] pub anyhow::Error);

pub async fn exchange_with_retry<Once, Fut>(
    label: &'static str,
    once: Once,
) -> anyhow::Result<Vec<u8>>
where
    Once: Fn() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Vec<u8>>>,
{
    match once().await {
        Ok(response) => Ok(response),
        Err(first) if first.is::<ConnectionFailure>() => {
            tracing::debug!(
                transport = label,
                "DNS connection failed; retrying: {first}"
            );
            once().await.map_err(|error| {
                error.context(format!("{label} retry failed (first: {first})"))
            })
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn only_connection_failures_are_retried() {
        let attempts = AtomicUsize::new(0);
        let result = exchange_with_retry("test", || {
            attempts.fetch_add(1, Ordering::Relaxed);
            async { Err(anyhow::anyhow!("request timed out")) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        let result = exchange_with_retry("test", || {
            let attempt = attempts.fetch_add(1, Ordering::Relaxed);
            async move {
                if attempt == 1 {
                    Err(ConnectionFailure(anyhow::anyhow!("connection closed"))
                        .into())
                } else {
                    Ok(vec![1])
                }
            }
        })
        .await;
        assert_eq!(result.unwrap(), vec![1]);
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
    }
}
