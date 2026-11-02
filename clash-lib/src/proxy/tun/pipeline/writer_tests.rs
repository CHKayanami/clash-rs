use std::{future::pending, io, sync::{Arc, atomic::{AtomicUsize, Ordering}, mpsc},
    thread, time::Duration};
use tokio::{net::UdpSocket, sync::oneshot, time::{sleep, timeout}};
use tokio_util::sync::CancellationToken;
use super::PacketPipeline;
use crate::Error;

struct Dropped(Arc<AtomicUsize>);
impl Drop for Dropped {
    fn drop(&mut self) { self.0.fetch_add(1, Ordering::Relaxed); }
}

#[tokio::test]
async fn writer_uses_another_thread_and_does_not_block_a_single_thread_runtime() {
    let caller = thread::current().id();
    let dropped = Arc::new(AtomicUsize::new(0));
    let guard = Dropped(dropped.clone());
    let mut pipeline = PacketPipeline::default();
    let (ready_tx, ready_rx) = oneshot::channel();
    let (reader_tx, reader_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();
    pipeline.spawn_writer(async move {
        let _guard = guard;
        ready_tx.send(thread::current().id()).unwrap();
        // Model a synchronous device syscall retaining the entire execution
        // thread. The reader must still progress on a single-thread runtime.
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        pending().await
    });
    pipeline.spawn("reader", async move {
        let writer = ready_rx.await.unwrap();
        reader_tx.send((writer, thread::current().id())).unwrap();
        pending().await
    });
    let cancel = CancellationToken::new();
    let supervisor = tokio::spawn(pipeline.run(cancel.clone()));
    let observed = timeout(Duration::from_secs(2), reader_rx).await;
    cancel.cancel();
    let _ = release_tx.send(());
    timeout(Duration::from_secs(2), supervisor).await.unwrap().unwrap().unwrap();
    let (writer, reader) = observed.unwrap().unwrap();
    assert_ne!(writer, caller);
    assert_eq!(reader, caller);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn writer_accepts_io_registered_on_the_parent_runtime() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (received_tx, received_rx) = oneshot::channel();
    let dropped = Arc::new(AtomicUsize::new(0));
    let guard = Dropped(dropped.clone());
    let mut pipeline = PacketPipeline::default();
    pipeline.spawn_writer(async move {
        let _guard = guard;
        let mut bytes = [0; 16];
        let (size, _) = socket.recv_from(&mut bytes).await?;
        received_tx.send(bytes[..size].to_vec()).unwrap();
        pending().await
    });
    let cancel = CancellationToken::new();
    let supervisor = tokio::spawn(pipeline.run(cancel.clone()));
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(b"cross-runtime", address).await.unwrap();
    let received = timeout(Duration::from_secs(2), received_rx).await;
    cancel.cancel();
    timeout(Duration::from_secs(2), supervisor).await.unwrap().unwrap().unwrap();
    assert_eq!(received.unwrap().unwrap(), b"cross-runtime");
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn aborting_owner_joins_writer_with_pending_io() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let guard = Dropped(dropped.clone());
    let (ready_tx, ready_rx) = oneshot::channel();
    let mut pipeline = PacketPipeline::default();
    pipeline.spawn_writer(async move {
        let _guard = guard;
        ready_tx.send(()).unwrap();
        socket.recv_from(&mut [0; 1]).await?;
        pending().await
    });
    let supervisor = tokio::spawn(pipeline.run(CancellationToken::new()));
    timeout(Duration::from_secs(2), ready_rx).await.unwrap().unwrap();
    supervisor.abort();
    assert!(timeout(Duration::from_secs(2), supervisor).await.unwrap().unwrap_err().is_cancelled());
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn writer_failure_and_unexpected_success_stop_siblings() {
    for panics in [false, true] {
        let dropped = Arc::new(AtomicUsize::new(0));
        let guard = Dropped(dropped.clone());
        let mut pipeline = PacketPipeline::default();
        pipeline.spawn("reader", async move {
            let _guard = guard;
            pending().await
        });
        pipeline.spawn_writer(async move {
            if panics { panic!("writer failed"); }
            Ok(())
        });
        let error = timeout(Duration::from_secs(2), pipeline.run(CancellationToken::new()))
            .await.unwrap().unwrap_err().to_string();
        assert!(error.contains("writer"));
        assert!(error.contains(if panics { "panic" } else { "exited unexpectedly" }));
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn writer_io_error_reaches_supervisor_without_losing_os_error() {
    let mut pipeline = PacketPipeline::default();
    pipeline.spawn_writer(async { Err(Error::Io(io::Error::from_raw_os_error(1234))) });
    let error = timeout(Duration::from_secs(2), pipeline.run(CancellationToken::new()))
        .await.unwrap().unwrap_err();
    let Error::Io(error) = error else { panic!("expected original I/O error, got {error:?}"); };
    assert_eq!(error.raw_os_error(), Some(1234));
}

#[tokio::test]
async fn writer_runtime_supports_timer_backoff() {
    let (ready_tx, ready_rx) = oneshot::channel();
    let mut pipeline = PacketPipeline::default();
    pipeline.spawn_writer(async move {
        sleep(Duration::from_millis(1)).await;
        ready_tx.send(()).unwrap();
        pending().await
    });
    let cancel = CancellationToken::new();
    let supervisor = tokio::spawn(pipeline.run(cancel.clone()));
    let ready = timeout(Duration::from_secs(2), ready_rx).await;
    cancel.cancel();
    timeout(Duration::from_secs(2), supervisor).await.unwrap().unwrap().unwrap();
    ready.unwrap().unwrap();
}
