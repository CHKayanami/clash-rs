use std::{future::pending, sync::{Arc, atomic::{AtomicUsize, Ordering}, mpsc}, time::Duration};
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
        .await.unwrap().unwrap_err().to_string();
    assert!(error.contains("reader"));
    assert!(error.contains("device failure"));
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reader_progresses_while_writer_is_inside_a_synchronous_call() {
    let mut pipeline = PacketPipeline::default();
    let (started_tx, started_rx) = oneshot::channel();
    let (read_tx, read_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();
    pipeline.spawn("writer", async move {
        started_tx.send(()).unwrap();
        // Model a syscall retaining its worker while another stage needs polling.
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        pending().await
    });
    pipeline.spawn("reader", async move {
        started_rx.await.unwrap();
        read_tx.send(()).unwrap();
        pending().await
    });
    let token = CancellationToken::new();
    let supervisor = tokio::spawn(pipeline.run(token.clone()));
    let observed = timeout(Duration::from_secs(2), read_rx).await;
    token.cancel();
    release_tx.send(()).unwrap();
    timeout(Duration::from_secs(2), supervisor).await.unwrap().unwrap().unwrap();
    assert!(observed.is_ok_and(|result| result.is_ok()));
}
