use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use crate::app::dns::ThreadSafeDNSResolver;

type ResolutionFuture = Pin<Box<dyn Future<Output = io::Result<SocketAddr>> + Send>>;

/// The future is Send but need not be Sync. The mutex provides the datagram's
/// required Sync bound; polling uses exclusive get_mut(), never locking.
/// Keeping the query in its originating task preserves its waker and task
/// context, and dropping the datagram immediately cancels the query.
pub(super) struct PendingResolution(Mutex<ResolutionFuture>);

impl PendingResolution {
    fn new(
        query: impl Future<Output = io::Result<SocketAddr>> + Send + 'static,
    ) -> Self {
        Self(Mutex::new(Box::pin(query)))
    }
}

impl Future for PendingResolution {
    type Output = io::Result<SocketAddr>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut()
            .0
            .get_mut()
            .expect("resolution mutex is never locked")
            .as_mut()
            .poll(cx)
    }
}

/// Poll the resolver in the caller's task. Hosts/cache hits complete inline;
/// pending queries are retained across polls without spawning or restarting.
pub(super) fn poll_resolve_destination(
    cx: &mut Context<'_>,
    pending: &mut Option<PendingResolution>,
    resolver: &ThreadSafeDNSResolver,
    domain: &Arc<str>,
    port: u16,
    ipv6: bool,
) -> Poll<io::Result<SocketAddr>> {
    let query = pending.get_or_insert_with(|| {
        let resolver = resolver.clone();
        let domain = domain.clone();
        PendingResolution::new(async move {
            let ip = if ipv6 {
                resolver.resolve(&domain, false).await
            } else {
                resolver
                    .resolve_v4(&domain, false)
                    .await
                    .map(|ip| ip.map(IpAddr::V4))
            }
            .map_err(|err| {
                io::Error::other(format!("resolve {domain} failed: {err}"))
            })?;
            ip.map(|ip| SocketAddr::new(ip, port)).ok_or_else(|| {
                io::Error::other(format!("resolve domain failed: {domain}"))
            })
        })
    });
    let result = Pin::new(query).poll(cx);
    if result.is_ready() {
        *pending = None;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::MockClashResolver;

    #[tokio::test]
    async fn wake_during_first_poll_keeps_the_query_in_the_same_task() {
        tokio::spawn(async {
            let task_id = tokio::task::id();
            let mut first_poll = true;
            let mut query =
                PendingResolution::new(futures::future::poll_fn(move |cx| {
                    assert_eq!(tokio::task::id(), task_id);
                    if first_poll {
                        first_poll = false;
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok("127.0.0.1:53".parse().unwrap()))
                    }
                }));
            let address = (&mut query).await.unwrap();
            assert_eq!(address, "127.0.0.1:53".parse().unwrap());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn dropping_pending_resolution_cancels_it_immediately() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(dropped.clone());
        let mut query = PendingResolution::new(async move {
            let _guard = guard;
            std::future::pending::<io::Result<SocketAddr>>().await
        });
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(Pin::new(&mut query).poll(&mut cx).is_pending());
        drop(query);
        assert!(dropped.load(Ordering::Relaxed));
    }

    #[test]
    fn pending_resolution_satisfies_datagram_thread_safety_bounds() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PendingResolution>();
    }

    #[tokio::test]
    async fn pending_resolution_is_reused_and_cleared_on_error() {
        let mut dns = MockClashResolver::new();
        dns.expect_resolve_v4()
            .times(1)
            .returning(|_, _| Ok(Some("127.0.0.1".parse().unwrap())));
        let resolver: ThreadSafeDNSResolver = Arc::new(dns);
        let domain = Arc::from("example.com");
        let notify = Arc::new(tokio::sync::Notify::new());
        let query_notify = notify.clone();
        let mut pending = Some(PendingResolution::new(async move {
            query_notify.notified().await;
            Err(io::Error::other("temporary resolution failure"))
        }));
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(
            poll_resolve_destination(
                &mut cx,
                &mut pending,
                &resolver,
                &domain,
                53,
                false,
            )
            .is_pending()
        );
        notify.notify_one();
        let result = futures::future::poll_fn(|cx| {
            poll_resolve_destination(cx, &mut pending, &resolver, &domain, 53, false)
        })
        .await;
        assert!(result.is_err());
        assert!(pending.is_none());
        let result = poll_resolve_destination(
            &mut cx,
            &mut pending,
            &resolver,
            &domain,
            53,
            false,
        );
        assert!(matches!(result, Poll::Ready(Ok(_))));
        assert!(pending.is_none());
    }

    #[tokio::test]
    async fn ready_resolution_does_not_spawn_or_cache_an_address() {
        let mut dns = MockClashResolver::new();
        // A later lookup can see a changed/expired DNS cache entry; no second
        // cache in the datagram association may keep returning the old address.
        dns.expect_resolve_v4()
            .with(
                mockall::predicate::eq("example.com"),
                mockall::predicate::eq(false),
            )
            .times(1)
            .returning(|_, _| Ok(Some("127.0.0.1".parse().unwrap())));
        dns.expect_resolve_v4()
            .times(1)
            .returning(|_, _| Ok(Some("127.0.0.2".parse().unwrap())));
        let resolver: ThreadSafeDNSResolver = Arc::new(dns);
        let domain = Arc::from("example.com");
        let mut pending = None;
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        for ip in ["127.0.0.1", "127.0.0.2"] {
            let result = poll_resolve_destination(
                &mut cx,
                &mut pending,
                &resolver,
                &domain,
                53,
                false,
            );
            assert!(
                matches!(result, Poll::Ready(Ok(addr)) if addr == format!("{ip}:53").parse::<SocketAddr>().unwrap())
            );
            assert!(pending.is_none());
        }
    }
}
