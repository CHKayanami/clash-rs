use std::{future::pending, sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};
use tokio::{sync::oneshot, time::timeout};
use tokio_util::sync::CancellationToken;
use super::PacketPipeline;
use crate::Error;

struct Dropped(Arc<AtomicUsize>);
impl Drop for Dropped {
    fn drop(&mut self) { self.0.fetch_add(1, Ordering::Relaxed); }
}

#[tokio::test]
async fn cancellation_joins_all_packet_stages() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut pipeline = PacketPipeline::default();
    let mut started = Vec::new();
    for name in ["reader", "writer", "replies"] {
        let guard = Dropped(dropped.clone());
        let (tx, rx) = oneshot::channel();
        started.push(rx);
        pipeline.spawn(name, async move {
            let _guard = guard;
            tx.send(()).unwrap();
            pending().await
        });
    }
    let token = CancellationToken::new();
    let supervisor = tokio::spawn(pipeline.run(token.clone()));
    for rx in started { rx.await.unwrap(); }
    token.cancel();
    timeout(Duration::from_secs(2), supervisor).await.unwrap().unwrap().unwrap();
    assert_eq!(dropped.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn failed_stage_preserves_error_and_releases_sibling() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let guard = Dropped(dropped.clone());
    let mut pipeline = PacketPipeline::default();
    let (tx, rx) = oneshot::channel();
    pipeline.spawn("writer", async move {
        let _guard = guard;
        tx.send(()).unwrap();
        pending().await
    });
    pipeline.spawn("reader", async move {
        rx.await.unwrap();
        Err(Error::Operation("device failure".to_owned()))
    });
    let error = timeout(Duration::from_secs(2), pipeline.run(CancellationToken::new()))
        .await.unwrap().unwrap_err();
    assert!(matches!(error, Error::Operation(message) if message == "device failure"));
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn panic_and_unexpected_success_stop_the_pipeline() {
    for panics in [false, true] {
        let dropped = Arc::new(AtomicUsize::new(0));
        let guard = Dropped(dropped.clone());
        let mut pipeline = PacketPipeline::default();
        pipeline.spawn("writer", async move {
            let _guard = guard;
            pending().await
        });
        pipeline.spawn("reader", async move {
            if panics { panic!("packet stage panic"); }
            Ok(())
        });
        let error = timeout(Duration::from_secs(2), pipeline.run(CancellationToken::new()))
            .await.unwrap().unwrap_err().to_string();
        assert!(error.contains(if panics { "panic" } else { "exited unexpectedly" }));
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }
}
