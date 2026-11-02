//! One OS thread per TUN writer, owned and joined by the packet pipeline.
use std::{future::Future, io, thread::{Builder as ThreadBuilder, JoinHandle}};
use tokio::{runtime::Builder as RuntimeBuilder, sync::oneshot};
use tokio_util::sync::CancellationToken;
use crate::Error;

pub(super) struct WriterThread {
    cancel: CancellationToken,
    thread: Option<JoinHandle<()>>,
    completion: Option<oneshot::Receiver<Result<(), Error>>>,
}

impl WriterThread {
    pub fn spawn<F>(future: F) -> io::Result<Self>
    where F: Future<Output = Result<(), Error>> + Send + 'static {
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let (tx, rx) = oneshot::channel();
        let thread = ThreadBuilder::new().name("clash-tun-write".to_owned()).spawn(move || {
            // run() drops the runtime and writer's device references before
            // publishing completion. The parent runtime stays alive until join.
            let _ = tx.send(run(future, stop));
        })?;
        Ok(Self { cancel, thread: Some(thread), completion: Some(rx) })
    }

    pub async fn finished(&mut self) -> Result<(), Error> {
        // Borrow the receiver across await so cancellation leaves it available
        // for shutdown. Consume it only after a result has actually arrived.
        let result = self.completion.as_mut().expect("writer result not consumed").await;
        self.completion = None;
        result.map_err(|_| Error::Operation("TUN writer thread exited without a result".to_owned()))?
    }

    pub fn cancel(&self) { self.cancel.cancel(); }

    pub async fn shutdown(&mut self) -> Result<(), Error> {
        self.cancel();
        if self.completion.is_some() { let _ = self.finished().await; }
        // Completion follows runtime teardown, so normal shutdown only joins
        // the thread's final return rather than blocking on device I/O.
        self.join()
    }

    fn join(&mut self) -> Result<(), Error> {
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| Error::Operation("TUN writer thread panicked".to_owned()))?;
        }
        Ok(())
    }
}

impl Drop for WriterThread {
    fn drop(&mut self) {
        self.cancel();
        // Owner abort/panic cannot await. Join here as a fallback so the writer
        // cannot outlive device/route guards or accumulate across TUN restarts.
        let _ = self.join();
    }
}

fn run<F>(future: F, cancel: CancellationToken) -> Result<(), Error>
where F: Future<Output = Result<(), Error>> + Send + 'static {
    // Device readiness is registered before moving the writer here. No write
    // path creates Tokio I/O resources; Darwin's ENOBUFS backoff needs timers.
    let runtime = RuntimeBuilder::new_current_thread().enable_time().build()?;
    // Keep the writer inside a Tokio task to retain its existing cooperative
    // budget. Only its execution thread changes; device readiness registration
    // may still belong to the live parent runtime.
    let mut task = runtime.spawn(future);
    runtime.block_on(async move {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                task.abort();
                let _ = task.await;
                Ok(())
            }
            result = &mut task => result.map_err(|error|
                Error::Operation(format!("TUN writer task failed: {error}")))?,
        }
    })
}
